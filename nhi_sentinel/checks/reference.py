"""Reference checks implementing the Check Catalog semantics (see docs/blueprint).

CLD-002 demonstrates the relationship/trust pattern, CLD-009 the ownership/identity pattern,
INV-002 the snapshot completeness pattern. The remaining pilot checks live in pilot.py.
False-positive boundaries from the catalog (AT16) are encoded as pass/unknown cases."""
from __future__ import annotations

from .base import Check, CheckOutcome, register
from ..contracts import CheckStatus


@register
class CLD002OverbroadRoleTrust(Check):
    """Fail: external/account trust broader than approved principals after external-ID,
    subject and condition restrictions (Check Catalog CLD-002)."""
    id = "CLD-002"
    version = "1.0.0"
    title = "Overbroad role trust"
    description = ("Role trust accepts principals outside the approved integration register "
                   "without sufficient binding conditions.")
    dimension = "least_privilege"
    applies_to = ("aws_iam",)

    def run(self, view):
        outcomes = []
        ident_art = self.artifacts_for(view, "collection.identities", "collection.relationships")
        approved = self._approved_register(view)
        for edge in view.edges:
            if edge.relationship != "can_assume":
                continue
            src = next((i for i in view.identities if i.id == edge.src_id), None)
            if src is None:
                continue
            trust = (edge.conditions_json or {}).get("trust_policy", {})
            externals = [p for p in trust.get("principal_arns", []) if ":root" in p or p not in approved]
            conditions = trust.get("conditions", {})
            bound = bool(conditions.get("aws:ExternalId")) or bool(conditions.get("sts:ExternalId"))
            restricted_subject = bool(conditions.get("aws:SourceArn") or conditions.get("sts:SourceArn"))
            approved_external = all(p in approved for p in externals)
            if trust.get("federation_oidc"):
                continue  # CLD-008 territory
            if not externals:
                outcomes.append(self.outcome(
                    target_id=src.id, target_key=src.native_id, status=CheckStatus.PASS,
                    evidence_refs=ident_art,
                    facts={"condition_signature": "trust-within-approve-list",
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited"},
                    ))
                continue
            if approved_external and (bound or restricted_subject):
                outcomes.append(self.outcome(
                    target_id=src.id, target_key=src.native_id, status=CheckStatus.PASS,
                    evidence_refs=ident_art,
                    facts={"condition_signature": "approved-external-bound",
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited"}))
                continue
            if not approved_external:
                # unapproved external principal with no binding -> fail (golden case A)
                outcomes.append(self.outcome(
                    target_id=src.id, target_key=src.native_id, status=CheckStatus.FAIL,
                    evidence_refs=ident_art,
                    facts={"condition_signature": f"unapproved-external|{src.native_id}",
                           "external_principals": externals,
                           "external_id_binding": bound, "subject_restricted": restricted_subject,
                           "impact": "high", "exposure": "untrusted",
                           "effective_privilege": "elevated",
                           "path_certainty": "none", "credential_state": "not_applicable"},
                    reason="Trust accepts an unapproved external principal without external-ID "
                           "or subject binding after evaluated conditions (CLD-002)."))
                continue
            # approved principal but missing binding context -> unknown, not fail (AT16)
            outcomes.append(self.outcome(
                target_id=src.id, target_key=src.native_id, status=CheckStatus.UNKNOWN,
                evidence_refs=ident_art,
                facts={"condition_signature": f"missing-binding-context|{src.native_id}"},
                reason="Approved external trust lacks binding-condition context; "
                       "assurance unavailable rather than assumed safe (AT16)."))
        return outcomes

    def _approved_register(self, view) -> set[str]:
        for a in view.artifacts.values():
            if a.kind == "collection.envelope":
                return set((a.content_json or {}).get("scope", {}).get(
                    "approved_external_principals", []))
        return set()


@register
class CLD009OwnershipCompleteness(Check):
    """Fail: eligible active principal lacks verified business and technical owner (CLD-009).
    Missing owner stays separate from missing discovery coverage (G67 boundary)."""
    id = "CLD-009"
    version = "1.0.0"
    title = "Identity ownership completeness"
    description = "Active in-scope principals require attested business and technical owners."
    dimension = "ownership"
    applies_to = ("aws_iam", "entra", "github", "agent_registry")

    def run(self, view):
        outcomes = []
        ident_art = self.artifacts_for(view, "collection.identities", "collection.ownership")
        for ident in view.identities:
            assertions = view.ownership_for(ident.id)
            has_business = any(a.role == "business" for a in assertions)
            has_technical = any(a.role == "technical" for a in assertions)
            verified = view.verified_owner(ident.id) is not None
            if has_business and has_technical and verified:
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.PASS,
                     evidence_refs=ident_art,
                    facts={"condition_signature": "fully-owned"}))
            elif not assertions:
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.FAIL,
                     evidence_refs=ident_art,
                    facts={"condition_signature": f"unowned|{ident.native_id}",
                           "missing_roles": ["business", "technical"],
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited"},
                    reason="No ownership assertion on record; accountability cannot be "
                           "established (CLD-009). Discovery coverage is reported separately."))
            else:
                missing = [r for r, ok in (("business", has_business), ("technical", has_technical)) if not ok]
                if verified:
                    outcomes.append(self.outcome(
                        target_id=ident.id, target_key=ident.native_id, status=CheckStatus.PASS,
                         evidence_refs=ident_art,
                        facts={"condition_signature": "partially-owned-verified"},
                        reason=None))
                else:
                    outcomes.append(self.outcome(
                        target_id=ident.id, target_key=ident.native_id, status=CheckStatus.FAIL,
                         evidence_refs=ident_art,
                        facts={"condition_signature": f"unverified-owner|{ident.native_id}",
                               "missing_roles": missing,
                               "impact": "low", "exposure": "internal",
                               "effective_privilege": "limited"},
                        reason="Ownership asserted but not verified/current (DC06); "
                               "attestation required."))
        return outcomes


@register
class INV002CollectionPermissionGap(Check):
    """Fail: authorized scope cannot be fully enumerated (page errors / permission denials).
    Gaps are never counted as secure entities or zero findings (INV-002, AT08)."""
    id = "INV-002"
    version = "1.0.0"
    title = "Collection permission gap"
    description = "Collection could not fully enumerate the approved scope for a source."
    dimension = "lifecycle"
    applies_to = ("aws_iam", "entra", "github", "agent_registry")

    def run(self, view):
        outcomes = []
        for snap in view.snapshots:
            env_art = sorted(a.id for a in view.artifacts.values() if a.snapshot_id == snap.id)
            key = f"collection|{snap.source}"
            if snap.state == "partial" or snap.page_errors_json:
                err = "; ".join(e.get("error", "?") for e in snap.page_errors_json[:3])
                outcomes.append(self.outcome(
                    target_id=snap.id, target_key=key, status=CheckStatus.FAIL,
                    evidence_refs=env_art,
                    facts={"condition_signature": f"collection-gap|{snap.source}",
                           "source": snap.source, "completeness": snap.completeness,
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited"},
                    reason=f"Collection for {snap.source} incomplete: {err}. "
                           "Gap is not counted as secure coverage (INV-002)."))
            elif snap.state == "complete":
                outcomes.append(self.outcome(
                    target_id=snap.id, target_key=key, status=CheckStatus.PASS,
                    evidence_refs=env_art, facts={"condition_signature": f"complete|{snap.source}"}))
            elif snap.state == "invalid":
                outcomes.append(self.outcome(
                    target_id=snap.id, target_key=key, status=CheckStatus.ERROR,
                    evidence_refs=env_art, facts={"condition_signature": f"invalid|{snap.source}"},
                    reason="Snapshot invalid; payload rejected at ingest (AR08)."))
        return outcomes
