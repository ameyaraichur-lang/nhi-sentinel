"""Pilot check pack implementing the Check Catalog rows bound by docs/scenario_matrix.md.

Cloud trust and identity: CLD-007 third-party trust governance gap, CLD-008 unconstrained
CI federation. Credentials: KEY-001 exposed secret candidate, KEY-003 credential lifecycle
SLA breach, KEY-007 duplicate enabled credentials. App consent: OAU-001 high-impact app
consent, OAU-004 external app delegated access. CI/CD: CICD-006 overbroad workflow token,
CICD-007 unreviewed action dependency. Agent identity governance: AGI-002 capability
exceeds mission, AGI-004 unregistered observed agent, AGI-005 untrusted MCP endpoint,
AGI-006 delegation privilege amplification, AGI-008 agent without sponsor or retirement,
AGI-011 MCP token audience gap, AGI-014 unrestricted outbound agent tools, AGI-015 no
effective agent kill control. Inventory health: INV-001 stale inventory (INV-002 and the
CLD-002/CLD-009 reference patterns live in reference.py).

Boundary acceptance cases from the catalog are encoded as pass/unknown/not_applicable
outcomes, never as fabricated evidence: secret-candidate validity stays unknown (G23),
missing integration-register context is unknown rather than fail (AT16), multi-tenant
status alone does not fail (OAU-004), and a single baseline snapshot never implies
staleness (INV-001). Checks are pure functions of the validated SnapshotView: no network,
no writes, no invented owners, purposes or validity.
"""
from __future__ import annotations

import re
from datetime import datetime

from .base import Check, register
from ..contracts import CheckStatus
from ..core.db import utcnow
from ..connectors.base import parse_ts

# Static, long-lived credential kinds evaluated against rotation policy (KEY-003/KEY-007).
STATIC_KINDS = {"access_key", "client_secret", "agent_token", "deploy_key"}
DEFAULT_ROTATION_DAYS = 90          # recorded in facts whenever the default is applied
DEFAULT_OVERLAP_DAYS = 0            # rotation overlap window default (KEY-007)
HIGH_IMPACT_APP_SCOPES = {"Mail.ReadWrite", "Files.ReadWrite.All", "Mail.Send",
                          "Directory.ReadWrite.All"}
DEFAULT_MCP_AUDIENCE = "https://tenant.example"   # policy default when extras omit it
DEFAULT_FRESHNESS_DAYS = 7          # INV-001 freshness window default


def _arn_account(principal: str) -> str | None:
    """12-digit account id from an IAM ARN, else None."""
    m = re.search(r"arn:aws:iam::(\d{12}):", str(principal))
    return m.group(1) if m else None


def _refs_or_envelope(check: Check, view, *kinds: str) -> list[str]:
    """Artifact refs for the requested kinds; fall back to the envelope so a fail never
    carries empty evidence (EX04)."""
    refs = check.artifacts_for(view, *kinds)
    return refs or check.artifacts_for(view, "collection.envelope")


# --- cloud: trust governance ----------------------------------------------------------

@register
class CLD007ThirdPartyTrustGovernance(Check):
    """Fail: cross-account trust targets an external account absent from the approved
    integration register, or the trusting role lacks a current owner (CLD-007).
    Register context missing -> unknown, never fail (AT16)."""
    id = "CLD-007"
    version = "1.0.0"
    title = "Third-party trust governance gap"
    description = ("Cross-account relationship lacks a current owner, an approved external "
                   "account in the integration register, or current attestation.")
    dimension = "least_privilege"
    applies_to = ("aws_iam",)

    def run(self, view):
        outcomes = []
        evidence = self.artifacts_for(view, "collection.relationships", "collection.envelope",
                                      "collection.ownership", "collection.identities")
        register = self._integration_register(view)
        for edge in view.edges:
            if edge.relationship != "can_assume":
                continue
            src = next((i for i in view.identities if i.id == edge.src_id), None)
            if src is None:
                continue
            trust = (edge.conditions_json or {}).get("trust_policy", {})
            if trust.get("federation_oidc"):
                continue  # CLD-008 territory
            accounts = sorted({a for p in trust.get("principal_arns", [])
                               for a in [_arn_account(p)] if a})
            if not accounts:
                dst = next((i for i in view.identities if i.id == edge.dst_id), None)
                if dst is not None and dst.id_type == "external_principal" and dst.authority:
                    accounts = [dst.authority]
            if not accounts:
                continue  # no third party on this trust; internal trusts are CLD-002 scope
            if register is None:
                outcomes.append(self.outcome(
                    target_id=src.id, target_key=src.native_id, status=CheckStatus.UNKNOWN,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"missing-register-context|{src.native_id}",
                           "external_accounts": accounts},
                    reason="Envelope scope carries no integration register; third-party trust "
                           "governance cannot be evaluated (AT16: missing context, not fail)."))
                continue
            entries = [register[a] for a in accounts if a in register]
            registered = all(a in register for a in accounts)
            expiry = next((e.get("expires_at") or e.get("valid_to") or e.get("expires")
                           for e in entries if isinstance(e, dict)
                           and (e.get("expires_at") or e.get("valid_to") or e.get("expires"))),
                          None)
            expiry_dt = parse_ts(expiry) if expiry else None
            lapsed = expiry_dt is not None and expiry_dt < utcnow()
            owned = view.verified_owner(src.id) is not None
            facts = {"external_accounts": accounts, "registered": registered,
                     "owner_verified": owned, "register_expiry": expiry}
            if registered and owned and not lapsed:
                outcomes.append(self.outcome(
                    target_id=src.id, target_key=src.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={**facts,
                           "condition_signature": f"registered-owned-trust|{src.native_id}"}))
                continue
            gaps = []
            if not registered:
                gaps.append("external account absent from the integration register")
            if not owned:
                gaps.append("trusting role has no verified current owner")
            if lapsed:
                gaps.append("register attestation expired")
            outcomes.append(self.outcome(
                target_id=src.id, target_key=src.native_id, status=CheckStatus.FAIL,
                evidence_refs=_refs_or_envelope(self, view, "collection.relationships",
                                                "collection.envelope", "collection.ownership"),
                facts={**facts,
                       "condition_signature": f"ungoverned-external-trust|{src.native_id}",
                       "impact": "high", "exposure": "untrusted",
                       "effective_privilege": "elevated", "path_certainty": "none",
                       "credential_state": "not_applicable"},
                reason=f"Trust for {src.native_id} is ungoverned: {'; '.join(gaps)} (CLD-007). "
                       "External account presence alone is never treated as approval."))
        return outcomes

    def _integration_register(self, view) -> dict | None:
        """scope.integrations from the source envelope, normalized account -> entry.
        Entries may be keyed by 12-digit account or full principal ARN; both are indexed.
        Returns None when the register context is absent (unknown, AT16)."""
        for a in view.artifacts.values():
            if a.kind != "collection.envelope":
                continue
            content = a.content_json or {}
            if content.get("source") != "aws_iam":
                continue
            raw = (content.get("scope") or {}).get("integrations")
            if raw is None:
                return None
            reg: dict = {}

            def _index(key, entry):
                reg[str(key)] = entry
                account = _arn_account(key)
                if account:
                    reg.setdefault(account, entry)

            if isinstance(raw, dict):
                for k, v in raw.items():
                    _index(k, v if isinstance(v, dict) else {})
            elif isinstance(raw, list):
                for item in raw:
                    if isinstance(item, str):
                        _index(item, {})
                    elif isinstance(item, dict):
                        key = (item.get("account") or item.get("external_account")
                               or item.get("principal") or item.get("native_id"))
                        if key:
                            _index(key, item)
            return reg
        return None


@register
class CLD008UnconstrainedCIFederation(Check):
    """Fail: OIDC federation trust without an exact subject and audience binding permits
    unapproved repos/branches/environments (CLD-008). Exact binding -> pass."""
    id = "CLD-008"
    version = "1.0.0"
    title = "Unconstrained CI federation"
    description = ("OIDC subject/audience trust permits unapproved repos, branches or "
                   "environments to assume the role.")
    dimension = "least_privilege"
    applies_to = ("aws_iam",)

    def run(self, view):
        outcomes = []
        evidence = self.artifacts_for(view, "collection.relationships", "collection.envelope")
        for edge in view.edges:
            if edge.relationship != "can_assume":
                continue
            src = next((i for i in view.identities if i.id == edge.src_id), None)
            if src is None:
                continue
            fed = ((edge.conditions_json or {}).get("trust_policy") or {}).get("federation_oidc")
            if not fed:
                continue
            subject, audience = self._binding(fed)
            wildcard = "*" in subject
            bound = bool(subject.strip()) and not wildcard and bool(audience.strip())
            if bound:
                outcomes.append(self.outcome(
                    target_id=src.id, target_key=src.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"federation-exact-binding|{src.native_id}",
                           "subject": subject, "audience": audience}))
                continue
            outcomes.append(self.outcome(
                target_id=src.id, target_key=src.native_id, status=CheckStatus.FAIL,
                evidence_refs=_refs_or_envelope(self, view, "collection.relationships",
                                                "collection.envelope"),
                facts={"condition_signature": f"federation-unbound|{src.native_id}",
                       "subject_recorded": subject or None,
                       "audience_recorded": audience or None,
                       "wildcard_subject": wildcard,
                       "impact": "high", "exposure": "untrusted",
                       "effective_privilege": "elevated", "path_certainty": "possible",
                       "credential_state": "not_applicable"},
                reason=f"OIDC federation for {src.native_id} lacks an exact subject/audience "
                       "binding; unapproved repos, forks or branches can assume the role "
                       "(CLD-008)."))
        return outcomes

    def _binding(self, fed: dict) -> tuple[str, str]:
        subject = fed.get("subject") or fed.get("sub") or fed.get("subject_condition") or ""
        if isinstance(subject, dict):  # condition-style subject
            vals = subject.get("StringEquals") or subject.get("StringLike") or ""
            subject = vals if isinstance(vals, str) else ";".join(map(str, vals))
        audience = fed.get("audience") or fed.get("aud") or fed.get("audiences") or ""
        if isinstance(audience, (list, tuple)):
            audience = ";".join(map(str, audience))
        return str(subject), str(audience)


# --- credentials -----------------------------------------------------------------------

@register
class KEY001ExposedSecretCandidate(Check):
    """Fail: sensitive token pattern found in an approved repo (confidence recorded,
    redacted fingerprint only). Validity remains unknown by default — no network
    validation (G23/KEY-001)."""
    id = "KEY-001"
    version = "1.0.0"
    title = "Exposed secret candidate"
    description = ("Sensitive token pattern/context found in an approved repository; "
                   "candidate evidence only, validity untested.")
    dimension = "credential_hygiene"
    applies_to = ("github",)

    def run(self, view):
        outcomes = []
        for art in view.artifacts.values():
            if art.kind != "collection.secret_candidates":
                continue
            candidates = art.content_json if isinstance(art.content_json, list) else []
            for sc in candidates:
                repo, path = str(sc.get("repo", "?")), str(sc.get("path", "?"))
                key = f"{repo}/{path}"
                confidence = sc.get("confidence", "low")
                outcomes.append(self.outcome(
                    target_id=key[:40], target_key=key, status=CheckStatus.FAIL,
                    evidence_refs=[art.id],
                    facts={"condition_signature": f"secret-candidate|{key}|{sc.get('pattern', 'unknown')}",
                           "pattern": sc.get("pattern", "unknown"),
                           "confidence": confidence,
                           "context": sc.get("context", ""),
                           "validity": "untested",   # G23: never claim a candidate is live
                           "impact": "high" if confidence == "high" else "moderate",
                           "exposure": "untrusted",
                           "effective_privilege": "elevated" if confidence == "high" else "limited",
                           "path_certainty": "none",
                           "credential_state": "exposed"},
                    reason=f"Secret candidate ({sc.get('pattern', 'unknown')}, confidence "
                           f"{confidence}) at {key}; validity untested — no network "
                           "validation is performed (G23/KEY-001)."))
        return outcomes


@register
class KEY003CredentialLifecycleSLA(Check):
    """Fail: static credential older than its rotation policy at collection time
    (KEY-003). Identity without any static credential -> not_applicable; the default
    90-day policy is recorded in facts whenever applied."""
    id = "KEY-003"
    version = "1.0.0"
    title = "Credential lifecycle SLA breach"
    description = ("Long-lived credential age violates the approved rotation policy for "
                   "its type and use.")
    dimension = "credential_hygiene"
    applies_to = ("aws_iam", "entra", "github", "agent_registry")

    def run(self, view):
        outcomes = []
        evidence = self.artifacts_for(view, "collection.credentials_metadata")
        for ident in view.identities:
            if ident.id_type == "external_principal":
                continue  # external accounts are trust targets, not managed credentials
            static = [c for c in view.credentials_for(ident.id) if c.kind in STATIC_KINDS]
            if not static:
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id,
                    status=CheckStatus.NOT_APPLICABLE, evidence_refs=evidence,
                    facts={"condition_signature": f"no-static-credential|{ident.native_id}"},
                    reason="No static credential on record; the rotation SLA applies to "
                           "static keys only and federation/short-lived access is not "
                           "evaluated against it (KEY-003)."))
                continue
            collected = self._collected_at(view, ident.provider)
            offenders, missing_ts, ages = [], [], []
            for cred in static:
                policy, source = self._policy_days(ident, cred)
                if cred.created_at is None or collected is None:
                    missing_ts.append(cred.id)
                    continue
                age = (collected - cred.created_at).days
                ages.append({"kind": cred.kind, "age_days": age, "policy_days": policy,
                             "policy_source": source, "status": cred.status})
                if age > policy:
                    offenders.append((cred, age, policy, source))
            if offenders:
                cred, age, policy, source = max(offenders, key=lambda o: o[1])
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.credentials_metadata"),
                    facts={"condition_signature": f"rotation-sla-breach|{ident.native_id}",
                           "age_days": age, "rotation_policy_days": policy,
                           "policy_days_source": source, "credential_kind": cred.kind,
                           "credential_ages": ages,
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited", "path_certainty": "none",
                           "credential_state": "enabled" if cred.status == "enabled"
                                               else "not_applicable"},
                    reason=f"Static {cred.kind} for {ident.native_id} is {age} days old at "
                           f"collection, beyond the {policy}-day rotation policy ({source}) "
                           "(KEY-003)."))
            elif missing_ts:
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.UNKNOWN,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"rotation-age-unavailable|{ident.native_id}"},
                    reason="Static credential creation timestamp unavailable; credential age "
                           "cannot be established (KEY-003)."))
            else:
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"rotation-within-sla|{ident.native_id}",
                           "credential_ages": ages}))
        return outcomes

    def _collected_at(self, view, provider):
        stamps = [s.collected_at for s in view.by_source(provider) if s.collected_at]
        return max(stamps) if stamps else utcnow()

    def _policy_days(self, ident, cred) -> tuple[int, str]:
        days = (cred.attributes_json or {}).get("rotation_policy_days")
        if isinstance(days, (int, float)) and days > 0:
            return int(days), "credential-attribute"
        days = (ident.attributes_json or {}).get("rotation_policy_days")
        if isinstance(days, (int, float)) and days > 0:
            return int(days), "identity-attribute"
        return DEFAULT_ROTATION_DAYS, f"policy-default ({DEFAULT_ROTATION_DAYS} days)"


@register
class KEY007DuplicateEnabledCredentials(Check):
    """Fail: identity retains more than one enabled static credential beyond the approved
    rotation overlap window (KEY-007). Default overlap window is 0 days and is recorded
    in facts whenever applied."""
    id = "KEY-007"
    version = "1.0.0"
    title = "Duplicate enabled credentials"
    description = ("Identity retains unnecessary overlapping credentials beyond the "
                   "approved rotation overlap window.")
    dimension = "credential_hygiene"
    applies_to = ("aws_iam", "entra", "github", "agent_registry")

    def run(self, view):
        outcomes = []
        evidence = self.artifacts_for(view, "collection.credentials_metadata")
        for ident in view.identities:
            if ident.id_type == "external_principal":
                continue
            enabled = sorted(
                (c for c in view.credentials_for(ident.id)
                 if c.status == "enabled" and c.kind in STATIC_KINDS),
                key=lambda c: c.created_at or datetime.min)
            if not enabled:
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id,
                    status=CheckStatus.NOT_APPLICABLE, evidence_refs=evidence,
                    facts={"condition_signature": f"no-enabled-credential|{ident.native_id}"},
                    reason="No enabled static credential on record; duplicate-overlap review "
                           "not applicable (KEY-007)."))
                continue
            if len(enabled) == 1:
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"single-enabled-credential|{ident.native_id}",
                           "enabled_count": 1}))
                continue
            overlap, source = self._overlap_days(ident, enabled)
            if any(c.created_at is None for c in enabled):
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.UNKNOWN,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"overlap-window-unavailable|{ident.native_id}",
                           "enabled_count": len(enabled)},
                    reason="Enabled credentials lack creation timestamps; the rotation overlap "
                           "window cannot be evaluated (KEY-007)."))
                continue
            gaps = [(b.created_at - a.created_at).days
                    for a, b in zip(enabled, enabled[1:])]
            facts = {"condition_signature": f"duplicate-enabled-credentials|{ident.native_id}",
                     "enabled_count": len(enabled), "rotation_overlap_days": overlap,
                     "overlap_source": source, "creation_gap_days": gaps}
            if all(g <= overlap for g in gaps):
                outcomes.append(self.outcome(
                    target_id=ident.id, target_key=ident.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={**facts,
                           "condition_signature": f"within-rotation-overlap|{ident.native_id}"},
                    reason=None))
                continue
            outcomes.append(self.outcome(
                target_id=ident.id, target_key=ident.native_id, status=CheckStatus.FAIL,
                evidence_refs=_refs_or_envelope(self, view, "collection.credentials_metadata"),
                facts={**facts, "impact": "moderate", "exposure": "internal",
                       "effective_privilege": "limited", "path_certainty": "none",
                       "credential_state": "enabled"},
                reason=f"{ident.native_id} holds {len(enabled)} enabled static credentials "
                       f"with creation gaps beyond the {overlap}-day overlap window ({source}) "
                       "(KEY-007)."))
        return outcomes

    def _overlap_days(self, ident, creds) -> tuple[int, str]:
        for cred in creds:
            days = (cred.attributes_json or {}).get("rotation_overlap_days")
            if isinstance(days, (int, float)) and days >= 0:
                return int(days), "credential-attribute"
        days = (ident.attributes_json or {}).get("rotation_overlap_days")
        if isinstance(days, (int, float)) and days >= 0:
            return int(days), "identity-attribute"
        return DEFAULT_OVERLAP_DAYS, f"policy-default ({DEFAULT_OVERLAP_DAYS} days)"


# --- OAuth / app consent ----------------------------------------------------------------

@register
class OAU001HighImpactAppConsent(Check):
    """Fail: application grant allows high-impact roles with no recorded consent purpose
    (OAU-001). Purpose recorded and scope bounded -> pass. Potential exposure alone is
    not evidence of illicit consent."""
    id = "OAU-001"
    version = "1.0.0"
    title = "High-impact app consent"
    description = ("Effective application grant allows high-impact actions and lacks an "
                   "approved purpose.")
    dimension = "least_privilege"
    applies_to = ("entra",)

    def run(self, view):
        evidence = self.artifacts_for(view, "collection.grants", "collection.identities")
        grants = [g for g in view.grants() if not g.get("delegated")]
        if not grants:
            return [self.outcome(
                target_id="collection|entra", target_key="collection|entra",
                status=CheckStatus.NOT_APPLICABLE, evidence_refs=evidence,
                facts={"condition_signature": "no-application-grants"},
                reason="No Entra application grants in the collected evidence; app consent "
                       "review not applicable (OAU-001).")]
        outcomes = []
        for g in grants:
            app = str(g.get("app_native_id", "?"))
            scopes = list(g.get("scopes") or [])
            high = sorted(HIGH_IMPACT_APP_SCOPES.intersection(scopes))
            purpose = (g.get("consent_record") or {}).get("purpose")
            ident = next((i for i in view.identities
                          if i.provider == "entra" and i.native_id == app), None)
            tid = ident.id if ident else app[:40]
            if high and not purpose:
                outcomes.append(self.outcome(
                    target_id=tid, target_key=app, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.grants",
                                                    "collection.identities"),
                    facts={"condition_signature": f"high-impact-consent-no-purpose|{app}",
                           "high_impact_scopes": high, "scopes": scopes,
                           "purpose_recorded": False,
                           "impact": "high", "exposure": "internal",
                           "effective_privilege": "elevated", "path_certainty": "none",
                           "credential_state": "not_applicable"},
                    reason=f"Application grant for {app} includes high-impact roles "
                           f"({', '.join(high)}) with no recorded business purpose in the "
                           "consent record (OAU-001)."))
            elif high:
                outcomes.append(self.outcome(
                    target_id=tid, target_key=app, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"consent-scoped-with-purpose|{app}",
                           "high_impact_scopes": high, "purpose_recorded": True}))
            else:
                outcomes.append(self.outcome(
                    target_id=tid, target_key=app, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"no-high-impact-scope|{app}",
                           "scopes": scopes, "purpose_recorded": bool(purpose)}))
        return outcomes


@register
class OAU004ExternalAppDelegatedAccess(Check):
    """Fail: multi-tenant external app holds effective consent without a verified owner or
    completed risk review (OAU-004). Reviewed + owned -> pass; multi-tenant status alone
    never fails."""
    id = "OAU-004"
    version = "1.0.0"
    title = "External app delegated access"
    description = ("External/multi-tenant app has broad effective consent without a "
                   "current owner or risk review.")
    dimension = "ownership"
    applies_to = ("entra",)

    def run(self, view):
        evidence = self.artifacts_for(view, "collection.grants", "collection.ownership",
                                      "collection.identities")
        grants = view.grants()
        if not grants:
            return [self.outcome(
                target_id="collection|entra", target_key="collection|entra",
                status=CheckStatus.NOT_APPLICABLE, evidence_refs=evidence,
                facts={"condition_signature": "no-grants"},
                reason="No Entra grants in the collected evidence; external app review not "
                       "applicable (OAU-004).")]
        outcomes = []
        for g in grants:
            if not g.get("multi_tenant"):
                continue  # single-tenant apps are not external-access scope (OAU-004)
            app = str(g.get("app_native_id", "?"))
            ident = next((i for i in view.identities
                          if i.provider == "entra" and i.native_id == app), None)
            owned = ident is not None and view.verified_owner(ident.id) is not None
            reviewed = (g.get("consent_record") or {}).get("reviewed") is True
            facts = {"multi_tenant": True, "owner_verified": owned,
                     "risk_reviewed": reviewed,
                     "publisher_domain": g.get("publisher_domain")}
            if owned and reviewed:
                outcomes.append(self.outcome(
                    target_id=ident.id if ident else app[:40], target_key=app,
                    status=CheckStatus.PASS, evidence_refs=evidence,
                    facts={**facts,
                           "condition_signature": f"external-app-owned-reviewed|{app}"}))
                continue
            gaps = []
            if not owned:
                gaps.append("no verified owner assertion")
            if not reviewed:
                gaps.append("consent risk review not completed")
            outcomes.append(self.outcome(
                target_id=ident.id if ident else app[:40], target_key=app,
                status=CheckStatus.FAIL,
                evidence_refs=_refs_or_envelope(self, view, "collection.grants",
                                                "collection.ownership", "collection.identities"),
                facts={**facts,
                       "condition_signature": f"external-app-unattested|{app}",
                       "impact": "high", "exposure": "untrusted",
                       "effective_privilege": "elevated", "path_certainty": "none",
                       "credential_state": "not_applicable"},
                reason=f"Multi-tenant external app {app} retains effective consent with "
                       f"{'; '.join(gaps)} (OAU-004); multi-tenancy alone was not scored."))
        return outcomes


# --- CI/CD --------------------------------------------------------------------------------

def _workflows(view) -> list[dict]:
    out: list[dict] = []
    for a in view.artifacts.values():
        if a.kind == "collection.workflows" and isinstance(a.content_json, list):
            out.extend(w for w in a.content_json if isinstance(w, dict))
    return out


@register
class CICD006OverbroadWorkflowToken(Check):
    """Fail: workflow token permissions exceed build needs — any write permission on an
    untrusted trigger (pull_request_target / fork) (CICD-006). Least privilege on safe
    triggers -> pass."""
    id = "CICD-006"
    version = "1.0.0"
    title = "Overbroad workflow token"
    description = ("Workflow token permissions exceed build task needs, especially write "
                   "on untrusted events.")
    dimension = "least_privilege"
    applies_to = ("github",)

    def run(self, view):
        workflows = _workflows(view)
        if not workflows:
            return [self.outcome(
                target_id="collection|github", target_key="collection|github",
                status=CheckStatus.NOT_APPLICABLE,
                evidence_refs=self.artifacts_for(view, "collection.envelope"),
                facts={"condition_signature": "no-workflow-inventory"},
                reason="No workflow inventory in the collected evidence; workflow token "
                       "review not applicable (CICD-006).")]
        outcomes = []
        for w in workflows:
            key = f"{w.get('repo', '?')}/{w.get('name', '?')}"
            perms = w.get("permissions") or {}
            write_scopes = sorted(s for s, lvl in perms.items()
                                  if isinstance(lvl, str) and "write" in lvl.lower())
            triggers = [t for t in (w.get("triggers") or []) if isinstance(t, str)]
            unsafe = sorted(t for t in triggers
                            if "pull_request_target" in t or "fork" in t.lower())
            if write_scopes and unsafe:
                outcomes.append(self.outcome(
                    target_id=key[:40], target_key=key, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.workflows"),
                    facts={"condition_signature": f"write-on-untrusted-trigger|{key}",
                           "write_permissions": write_scopes, "unsafe_triggers": unsafe,
                           "impact": "high", "exposure": "untrusted",
                           "effective_privilege": "elevated", "path_certainty": "possible",
                           "credential_state": "not_applicable"},
                    reason=f"Workflow {key} holds write token permissions "
                           f"({', '.join(write_scopes)}) and runs on untrusted triggers "
                           f"({', '.join(unsafe)}); a fork pull request can reach the token "
                           "(CICD-006)."))
            else:
                outcomes.append(self.outcome(
                    target_id=key[:40], target_key=key, status=CheckStatus.PASS,
                    evidence_refs=self.artifacts_for(view, "collection.workflows"),
                    facts={"condition_signature": f"workflow-least-privilege|{key}",
                           "write_permissions": write_scopes, "triggers": triggers}))
        return outcomes


@register
class CICD007UnreviewedActionDependency(Check):
    """Fail: workflow executes mutable external action refs without digest pinning
    (CICD-007). Pinned reviewed digests -> pass."""
    id = "CICD-007"
    version = "1.0.0"
    title = "Unreviewed action dependency"
    description = ("Workflow executes mutable external actions/dependencies without an "
                   "approved integrity policy.")
    dimension = "lifecycle"
    applies_to = ("github",)

    def run(self, view):
        workflows = _workflows(view)
        if not workflows:
            return [self.outcome(
                target_id="collection|github", target_key="collection|github",
                status=CheckStatus.NOT_APPLICABLE,
                evidence_refs=self.artifacts_for(view, "collection.envelope"),
                facts={"condition_signature": "no-workflow-inventory"},
                reason="No workflow inventory in the collected evidence; action dependency "
                       "review not applicable (CICD-007).")]
        outcomes = []
        for w in workflows:
            key = f"{w.get('repo', '?')}/{w.get('name', '?')}"
            actions = [a for a in (w.get("actions") or []) if isinstance(a, dict)]
            if not actions:
                outcomes.append(self.outcome(
                    target_id=key[:40], target_key=key, status=CheckStatus.PASS,
                    evidence_refs=self.artifacts_for(view, "collection.workflows"),
                    facts={"condition_signature": f"no-external-actions|{key}"}))
                continue
            unpinned = [str(a.get("ref", "?")) for a in actions if not a.get("pinned")]
            if unpinned:
                outcomes.append(self.outcome(
                    target_id=key[:40], target_key=key, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.workflows"),
                    facts={"condition_signature": f"unpinned-actions|{key}",
                           "unpinned_actions": unpinned,
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "elevated", "path_certainty": "possible",
                           "credential_state": "not_applicable"},
                    reason=f"Workflow {key} runs mutable action refs without digest pinning: "
                           f"{', '.join(unpinned)} (CICD-007)."))
            else:
                outcomes.append(self.outcome(
                    target_id=key[:40], target_key=key, status=CheckStatus.PASS,
                    evidence_refs=self.artifacts_for(view, "collection.workflows"),
                    facts={"condition_signature": f"actions-digest-pinned|{key}",
                           "actions": [str(a.get("ref", "?")) for a in actions]}))
        return outcomes


# --- agent identity governance -------------------------------------------------------------

def _agent_evidence(view) -> list[str]:
    refs = [a.id for a in view.artifacts.values()
            if a.kind in ("collection.agents", "collection.extras", "collection.envelope")]
    return sorted(refs)


@register
class AGI002AgentCapabilityExceedsMission(Check):
    """Fail: agent holds capabilities with no declared mission contract (purpose null)
    (AGI-002). Capabilities within a declared purpose -> pass. Owners/purposes are never
    fabricated."""
    id = "AGI-002"
    version = "1.0.0"
    title = "Agent capability exceeds mission"
    description = ("Granted agent capabilities exceed the sponsor-approved task contract "
                   "or no contract exists.")
    dimension = "least_privilege"
    applies_to = ("agent_registry",)

    def run(self, view):
        outcomes = []
        evidence = _agent_evidence(view)
        for agent in view.agents:
            caps = list(agent.capabilities_json or [])
            if not caps:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"no-capabilities|{agent.native_id}"}))
            elif not agent.purpose:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.agents",
                                                    "collection.extras", "collection.envelope"),
                    facts={"condition_signature": f"capability-without-mission|{agent.native_id}",
                           "capabilities": caps, "purpose_recorded": False,
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited", "path_certainty": "none",
                           "credential_state": "not_applicable"},
                    reason=f"Agent {agent.native_id} holds capabilities ({', '.join(caps)}) "
                           "with no declared mission purpose; proportionality cannot be "
                           "established and none is assumed (AGI-002)."))
            else:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"capabilities-within-purpose|{agent.native_id}",
                           "capabilities": caps, "purpose_recorded": True}))
        return outcomes


@register
class AGI004UnregisteredObservedAgent(Check):
    """Fail: agent observed in runtime/gateway with no matching sponsored registry entry
    (registered=false) (AGI-004). Ownership is reported as unknown, never invented."""
    id = "AGI-004"
    version = "1.0.0"
    title = "Unregistered observed agent"
    description = ("Gateway/runtime observation has no matching current sponsored registry "
                   "identity.")
    dimension = "lifecycle"
    applies_to = ("agent_registry",)

    def run(self, view):
        outcomes = []
        evidence = _agent_evidence(view)
        for agent in view.agents:
            if agent.registered:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"registered-agent|{agent.native_id}"}))
                continue
            attrs = agent.attributes_json or {}
            outcomes.append(self.outcome(
                target_id=agent.id, target_key=agent.native_id, status=CheckStatus.FAIL,
                evidence_refs=_refs_or_envelope(self, view, "collection.agents",
                                                "collection.envelope"),
                facts={"condition_signature": f"unregistered-agent|{agent.native_id}",
                       "observed_via": attrs.get("observed_via", "unknown"),
                       "first_observed": attrs.get("first_observed"),
                       "impact": "high", "exposure": "untrusted",
                       "effective_privilege": "limited", "path_certainty": "none",
                       "credential_state": "unknown"},
                reason=f"Agent {agent.native_id} was observed in runtime but is absent from "
                       "the sponsored registry (AGI-004); its ownership and credential state "
                       "remain unknown and are not fabricated."))
        return outcomes


def _extras_contents(view) -> list[dict]:
    return [a.content_json or {} for a in view.artifacts.values()
            if a.kind == "collection.extras" and isinstance(a.content_json, dict)]


@register
class AGI005UntrustedMCPEndpoint(Check):
    """Fail: configured MCP endpoint lacks required auth for its sensitivity or lacks
    approval/manifest review (AGI-005). Approved + authenticated -> pass; no-auth public
    tools are distinguished from sensitive tools."""
    id = "AGI-005"
    version = "1.0.0"
    title = "Untrusted MCP endpoint"
    description = ("Configured MCP server lacks required auth, approved identity or "
                   "manifest review.")
    dimension = "least_privilege"
    applies_to = ("agent_registry",)

    def run(self, view):
        endpoints = [ep for extras in _extras_contents(view)
                     for ep in (extras.get("mcp_endpoints") or []) if isinstance(ep, dict)]
        if not endpoints:
            return [self.outcome(
                target_id="gateway|mcp-endpoints", target_key="gateway|mcp-endpoints",
                status=CheckStatus.NOT_APPLICABLE, evidence_refs=_agent_evidence(view),
                facts={"condition_signature": "no-mcp-endpoint-inventory"},
                reason="No MCP endpoint inventory in gateway evidence (collection.extras); "
                       "untrusted-endpoint review not applicable (AGI-005).")]
        outcomes = []
        for ep in endpoints:
            url = str(ep.get("endpoint", "?"))
            auth = str(ep.get("auth") or "none").lower()
            approved = ep.get("approved") is True
            sensitivity = str(ep.get("sensitivity") or "unknown").lower()
            no_auth = auth in ("", "none", "null")
            facts = {"auth": auth, "approved": approved, "sensitivity": sensitivity}
            if (not approved) or (no_auth and sensitivity == "sensitive"):
                gaps = []
                if not approved:
                    gaps.append("no approval/manifest review on record")
                if no_auth and sensitivity == "sensitive":
                    gaps.append("sensitive endpoint accepts unauthenticated clients")
                outcomes.append(self.outcome(
                    target_id=url[:40], target_key=url, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.extras",
                                                    "collection.envelope"),
                    facts={**facts,
                           "condition_signature": f"untrusted-mcp-endpoint|{url}",
                           "impact": "high", "exposure": "untrusted",
                           "effective_privilege": "limited", "path_certainty": "none",
                           "credential_state": "not_applicable"},
                    reason=f"MCP endpoint {url} is untrusted: {'; '.join(gaps)} (AGI-005). "
                           "Auth metadata is recorded; raw tokens are never captured."))
            else:
                outcomes.append(self.outcome(
                    target_id=url[:40], target_key=url, status=CheckStatus.PASS,
                    evidence_refs=_agent_evidence(view),
                    facts={**facts,
                           "condition_signature": f"approved-authenticated-mcp|{url}"}))
        return outcomes


@register
class AGI006DelegationAmplification(Check):
    """Fail: child agent capabilities exceed the parent scope (AGI-006). Uses the
    analysis.delegation_chains artifact when resolvable in the view, else recomputes
    from registry parent/child capability sets."""
    id = "AGI-006"
    version = "1.0.0"
    title = "Delegation privilege amplification"
    description = ("Child agent capabilities exceed parent scope, target boundary or "
                   "expiry.")
    dimension = "least_privilege"
    applies_to = ("agent_registry",)

    def run(self, view):
        evidence = self.artifacts_for(view, "collection.agents", "collection.extras",
                                      "analysis.delegation_chains")
        chains = self._chains(view)
        if not chains:
            return [self.outcome(
                target_id="agent|delegation", target_key="agent|delegation",
                status=CheckStatus.NOT_APPLICABLE,
                evidence_refs=evidence or _agent_evidence(view),
                facts={"condition_signature": "no-delegation-relationships"},
                reason="No delegation relationships on record; privilege-amplification "
                       "review not applicable (AGI-006).")]
        outcomes = []
        for chain in chains:
            parent, child = str(chain.get("parent", "?")), str(chain.get("child", "?"))
            excess = chain.get("excess_capabilities")
            certainty = chain.get("certainty", "possible")
            record = next((a for a in view.agents if a.native_id == child), None)
            tid = record.id if record else f"agent|{child}"[:40]
            if excess is None:
                outcomes.append(self.outcome(
                    target_id=tid, target_key=child, status=CheckStatus.UNKNOWN,
                    evidence_refs=evidence or _agent_evidence(view),
                    facts={"condition_signature": f"delegation-parent-caps-unavailable|{child}",
                           "parent": parent, "certainty": certainty},
                    reason=f"Parent capability set for {parent} is unavailable; amplification "
                           "cannot be evaluated and is not assumed safe (AGI-006, AR12: "
                           "possible is never counted as confirmed)."))
            elif excess:
                outcomes.append(self.outcome(
                    target_id=tid, target_key=child, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.agents",
                                                    "collection.extras"),
                    facts={"condition_signature": f"delegation-amplification|{child}",
                           "parent": parent, "child": child,
                           "excess_capabilities": list(excess), "certainty": certainty,
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "elevated", "path_certainty": "possible",
                           "credential_state": "not_applicable"},
                    reason=f"Child {child} holds capabilities beyond parent {parent}: "
                           f"{', '.join(excess)} (AGI-006)."))
            else:
                outcomes.append(self.outcome(
                    target_id=tid, target_key=child, status=CheckStatus.PASS,
                    evidence_refs=evidence or _agent_evidence(view),
                    facts={"condition_signature": f"delegation-within-parent|{child}",
                           "parent": parent, "certainty": certainty}))
        return outcomes

    def _chains(self, view) -> list[dict]:
        art_chains: list[dict] = []
        for a in view.artifacts.values():
            if a.kind == "analysis.delegation_chains" and isinstance(a.content_json, list):
                art_chains.extend(x for x in a.content_json
                                  if isinstance(x, dict) and x.get("child"))
        if art_chains:
            return art_chains
        by_native = {a.native_id: a for a in view.agents}
        chains = []
        for agent in view.agents:
            if not agent.parent_native_id:
                continue
            parent = by_native.get(agent.parent_native_id)
            if parent is None or not parent.capabilities_json:
                chains.append({"parent": agent.parent_native_id, "child": agent.native_id,
                               "parent_caps": None, "certainty": "possible"})
            else:
                chains.append({
                    "parent": agent.parent_native_id, "child": agent.native_id,
                    "parent_caps": sorted(set(parent.capabilities_json)),
                    "child_caps": sorted(set(agent.capabilities_json or [])),
                    "excess_capabilities": sorted(
                        set(agent.capabilities_json or []) - set(parent.capabilities_json)),
                    "certainty": "config-evaluated"})
        return chains


@register
class AGI008AgentWithoutSponsorOrRetirement(Check):
    """Fail: active agent lacks a sponsor or a declared purpose (AGI-008). Both present
    -> pass. Registry fields are never invented."""
    id = "AGI-008"
    version = "1.0.0"
    title = "Agent without sponsor or retirement"
    description = ("Active agent lacks an accountable sponsor, purpose or retirement "
                   "control.")
    dimension = "ownership"
    applies_to = ("agent_registry",)

    def run(self, view):
        outcomes = []
        evidence = _agent_evidence(view)
        for agent in view.agents:
            if agent.lifecycle != "active":
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id,
                    status=CheckStatus.NOT_APPLICABLE, evidence_refs=evidence,
                    facts={"condition_signature": f"agent-inactive|{agent.native_id}",
                           "lifecycle": agent.lifecycle},
                    reason=f"Agent {agent.native_id} lifecycle is '{agent.lifecycle}'; "
                           "sponsor/purpose governance is evaluated for active agents "
                           "(AGI-008)."))
                continue
            missing = [f for f, v in (("sponsor", agent.sponsor), ("purpose", agent.purpose))
                       if not v]
            if missing:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.agents",
                                                    "collection.envelope"),
                    facts={"condition_signature": f"agent-missing-accountability|{agent.native_id}",
                           "missing_fields": missing,
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited", "path_certainty": "none",
                           "credential_state": "not_applicable"},
                    reason=f"Active agent {agent.native_id} lacks "
                           f"{' and '.join(missing)}; the accountable owner is never "
                           "fabricated (AGI-008)."))
            else:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"agent-sponsored|{agent.native_id}"}))
        return outcomes


@register
class AGI011MCPTokenAudienceGap(Check):
    """Fail: oauth-protected MCP endpoint audience does not match the approved tenant
    audience (AGI-011). Matching -> pass; the default audience is recorded whenever the
    policy default is applied."""
    id = "AGI-011"
    version = "1.0.0"
    title = "MCP token audience gap"
    description = ("Sensitive tool auth configuration fails to constrain issuer/audience "
                   "or resource.")
    dimension = "credential_hygiene"
    applies_to = ("agent_registry",)

    def run(self, view):
        extras_list = _extras_contents(view)
        endpoints = [ep for extras in extras_list
                     for ep in (extras.get("mcp_endpoints") or []) if isinstance(ep, dict)]
        if not endpoints:
            return [self.outcome(
                target_id="gateway|mcp-endpoints", target_key="gateway|mcp-endpoints",
                status=CheckStatus.NOT_APPLICABLE, evidence_refs=_agent_evidence(view),
                facts={"condition_signature": "no-mcp-endpoint-inventory"},
                reason="No MCP endpoint inventory in gateway evidence (collection.extras); "
                       "token audience review not applicable (AGI-011).")]
        approved = next((extras.get("approved_audience") for extras in extras_list
                         if extras.get("approved_audience")), None)
        audience_source = "gateway-policy" if approved else \
            f"policy-default ({DEFAULT_MCP_AUDIENCE})"
        approved = approved or DEFAULT_MCP_AUDIENCE
        outcomes = []
        for ep in endpoints:
            url = str(ep.get("endpoint", "?"))
            auth = str(ep.get("auth") or "none").lower()
            if auth != "oauth":
                outcomes.append(self.outcome(
                    target_id=url[:40], target_key=url, status=CheckStatus.NOT_APPLICABLE,
                    evidence_refs=_agent_evidence(view),
                    facts={"condition_signature": f"mcp-no-oauth|{url}", "auth": auth},
                    reason=f"Endpoint {url} does not use oauth bearer tokens; there is no "
                           "token audience to constrain (AGI-011)."))
                continue
            audience = ep.get("audience")
            if audience is None:
                outcomes.append(self.outcome(
                    target_id=url[:40], target_key=url, status=CheckStatus.UNKNOWN,
                    evidence_refs=_agent_evidence(view),
                    facts={"condition_signature": f"mcp-audience-unrecorded|{url}",
                           "approved_audience": approved, "audience_source": audience_source},
                    reason=f"oauth audience for {url} is not recorded; the token constraint "
                           "cannot be verified and is not assumed (AGI-011)."))
            elif audience != approved:
                outcomes.append(self.outcome(
                    target_id=url[:40], target_key=url, status=CheckStatus.FAIL,
                    evidence_refs=_refs_or_envelope(self, view, "collection.extras",
                                                    "collection.envelope"),
                    facts={"condition_signature": f"mcp-audience-mismatch|{url}",
                           "audience": audience, "approved_audience": approved,
                           "audience_source": audience_source,
                           "issuer": ep.get("issuer"),
                           "impact": "high", "exposure": "untrusted",
                           "effective_privilege": "limited", "path_certainty": "possible",
                           "credential_state": "unknown"},
                    reason=f"MCP oauth audience for {url} is '{audience}', not the approved "
                           f"tenant audience '{approved}' ({audience_source}); tokens minted "
                           "for another audience are outside the data boundary (AGI-011)."))
            else:
                outcomes.append(self.outcome(
                    target_id=url[:40], target_key=url, status=CheckStatus.PASS,
                    evidence_refs=_agent_evidence(view),
                    facts={"condition_signature": f"mcp-audience-bound|{url}",
                           "audience": audience, "audience_source": audience_source}))
        return outcomes


@register
class AGI014UnrestrictedOutboundAgentTools(Check):
    """Fail: agent holds net:egress without a non-empty destination allowlist in the
    gateway egress policy (AGI-014). Agents without net:egress -> not_applicable."""
    id = "AGI-014"
    version = "1.0.0"
    title = "Unrestricted outbound agent tools"
    description = ("Agent can transmit sensitive context to destinations outside the "
                   "approved data boundary.")
    dimension = "least_privilege"
    applies_to = ("agent_registry",)

    def run(self, view):
        outcomes = []
        extras_list = _extras_contents(view)
        egress_policy: dict = {}
        for extras in extras_list:
            policy = extras.get("egress_policy")
            if isinstance(policy, dict):
                egress_policy.update(policy)
        evidence = _agent_evidence(view)
        for agent in view.agents:
            caps = list(agent.capabilities_json or [])
            if "net:egress" not in caps:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id,
                    status=CheckStatus.NOT_APPLICABLE, evidence_refs=evidence,
                    facts={"condition_signature": f"no-egress-capability|{agent.native_id}"},
                    reason=f"Agent {agent.native_id} has no outbound capability "
                           "(net:egress absent); egress control not applicable (AGI-014)."))
                continue
            if not extras_list:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.UNKNOWN,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"egress-policy-unavailable|{agent.native_id}"},
                    reason="Gateway egress policy absent from evidence; the destination "
                           "allowlist cannot be verified and is not assumed (AGI-014)."))
                continue
            policy = egress_policy.get(agent.native_id) or {}
            allowlist = policy.get("allowlist") if isinstance(policy, dict) else None
            allowlist = allowlist if isinstance(allowlist, list) else []
            if allowlist:
                outcomes.append(self.outcome(
                    target_id=agent.id, target_key=agent.native_id, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"egress-allowlisted|{agent.native_id}",
                           "allowlist": allowlist}))
                continue
            outcomes.append(self.outcome(
                target_id=agent.id, target_key=agent.native_id, status=CheckStatus.FAIL,
                evidence_refs=_refs_or_envelope(self, view, "collection.extras",
                                                "collection.agents", "collection.envelope"),
                facts={"condition_signature": f"unrestricted-egress|{agent.native_id}",
                       "allowlist_entries": 0, "capabilities": caps,
                       "impact": "high", "exposure": "untrusted",
                       "effective_privilege": "limited", "path_certainty": "possible",
                       "credential_state": "not_applicable"},
                reason=f"Agent {agent.native_id} holds net:egress with an empty or absent "
                       "destination allowlist; its outbound boundary is unbounded (AGI-014). "
                       "Read-only upstream access still requires downstream egress control."))
        return outcomes


@register
class AGI015NoEffectiveAgentKillControl(Check):
    """Fail: gateway reports no effective independent kill control (kill_switch.configured
    false or missing) (AGI-015). Single gateway target; configuration-only evidence is
    labeled as such — a tested claim requires a controlled kill drill."""
    id = "AGI-015"
    version = "1.0.0"
    title = "No effective agent kill control"
    description = ("No independent revoke/disable capability covers delegated identities "
                   "and active tool dispatch.")
    dimension = "detection"
    applies_to = ("agent_registry",)

    TARGET = "gateway|kill-switch"

    def run(self, view):
        extras_list = _extras_contents(view)
        configured = next((extras.get("kill_switch", {}).get("configured")
                           for extras in extras_list
                           if isinstance(extras.get("kill_switch"), dict)
                           and "configured" in extras["kill_switch"]), None)
        if not extras_list:
            return [self.outcome(
                target_id=self.TARGET, target_key=self.TARGET, status=CheckStatus.UNKNOWN,
                evidence_refs=self.artifacts_for(view, "collection.envelope"),
                facts={"condition_signature": "kill-switch-evidence-unavailable"},
                reason="Gateway kill-switch configuration is absent from evidence; the "
                       "control cannot be evaluated and is not assumed (AGI-015).")]
        if configured is True:
            return [self.outcome(
                target_id=self.TARGET, target_key=self.TARGET, status=CheckStatus.PASS,
                evidence_refs=_agent_evidence(view),
                facts={"condition_signature": "kill-switch-configured",
                       "configured": True,
                       "verification": "configuration-only (no controlled kill drill run)"})]
        return [self.outcome(
            target_id=self.TARGET, target_key=self.TARGET, status=CheckStatus.FAIL,
            evidence_refs=_refs_or_envelope(self, view, "collection.extras",
                                            "collection.envelope"),
            facts={"condition_signature": "kill-switch-not-configured",
                   "configured": bool(configured),
                   "verification": "configuration-only (no controlled kill drill run)",
                   "impact": "high", "exposure": "internal",
                   "effective_privilege": "elevated", "path_certainty": "none",
                   "credential_state": "not_applicable"},
            reason="Gateway evidence shows no effective independent kill control covering "
                   "delegated identities and active tool dispatch (AGI-015); the tested "
                   "claim would require a controlled kill drill.")]


# --- inventory health ----------------------------------------------------------------------

@register
class INV001StaleInventory(Check):
    """not_applicable on baseline sources: with no earlier complete snapshot for a source
    there is nothing to measure freshness against, and staleness is never claimed from a
    single observation (INV-001). Freshness anchors only to the latest COMPLETE scan; a
    fresh partial never resets it."""
    id = "INV-001"
    version = "1.0.0"
    title = "Stale inventory"
    description = ("Last complete source snapshot exceeds the approved freshness window.")
    dimension = "lifecycle"
    applies_to = ("aws_iam", "entra", "github", "agent_registry")

    def run(self, view):
        outcomes = []
        for source in sorted({s.source for s in view.snapshots}):
            snaps = sorted(view.by_source(source),
                           key=lambda s: (s.collected_at or s.started_at or datetime.min, s.id))
            snap_ids = {s.id for s in snaps}
            evidence = sorted(a.id for a in view.artifacts.values()
                              if a.snapshot_id in snap_ids and a.kind == "collection.envelope")
            completes = [s for s in snaps if s.state == "complete"]
            latest = completes[-1] if completes else snaps[-1]
            key = f"collection|{source}"
            if len(completes) < 2:
                outcomes.append(self.outcome(
                    target_id=latest.id, target_key=key,
                    status=CheckStatus.NOT_APPLICABLE, evidence_refs=evidence,
                    facts={"condition_signature": f"inventory-baseline|{source}",
                           "source": source, "complete_snapshots": len(completes)},
                    reason=f"Baseline for {source}: no earlier complete snapshot exists to "
                           "measure freshness against, so staleness is not claimed from a "
                           "single observation (INV-001)."))
                continue
            window, wsource = self._window(view, source)
            collected = latest.collected_at
            if collected is None:
                outcomes.append(self.outcome(
                    target_id=latest.id, target_key=key, status=CheckStatus.UNKNOWN,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"inventory-timestamp-missing|{source}"},
                    reason="Latest complete snapshot lacks a collection timestamp; freshness "
                           "cannot be established (INV-001)."))
                continue
            age_days = (utcnow() - collected).days
            if age_days > window:
                outcomes.append(self.outcome(
                    target_id=latest.id, target_key=key, status=CheckStatus.FAIL,
                    evidence_refs=evidence or self.artifacts_for(view, "collection.envelope"),
                    facts={"condition_signature": f"stale-inventory|{source}",
                           "source": source, "age_days": age_days,
                           "freshness_window_days": window, "window_source": wsource,
                           "impact": "moderate", "exposure": "internal",
                           "effective_privilege": "limited", "path_certainty": "none",
                           "credential_state": "not_applicable"},
                    reason=f"Last complete {source} snapshot is {age_days} days old, beyond "
                           f"the {window}-day freshness window ({wsource}) (INV-001)."))
            else:
                outcomes.append(self.outcome(
                    target_id=latest.id, target_key=key, status=CheckStatus.PASS,
                    evidence_refs=evidence,
                    facts={"condition_signature": f"inventory-fresh|{source}",
                           "source": source, "age_days": age_days,
                           "freshness_window_days": window, "window_source": wsource}))
        return outcomes

    def _window(self, view, source) -> tuple[int, str]:
        for a in view.artifacts.values():
            if a.kind != "collection.envelope":
                continue
            content = a.content_json or {}
            if content.get("source") != source:
                continue
            days = (content.get("scope") or {}).get("freshness_window_days")
            if isinstance(days, (int, float)) and days > 0:
                return int(days), "scope-attribute"
        return DEFAULT_FRESHNESS_DAYS, f"policy-default ({DEFAULT_FRESHNESS_DAYS} days)"
