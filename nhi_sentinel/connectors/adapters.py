"""Pilot import adapters (CN01 AWS, CN02 Entra, CN03 GitHub, CN04 agent registry).

Thin normalizers over the shared envelope contract; semantic validation lives in
validate_payload. Fixtures are synthetic and clearly labeled (BG12/UX24).
"""
from __future__ import annotations

from .base import CollectResult, ImportConnector, parse_ts


class AwsIamConnector(ImportConnector):
    """CN01: roles/users/policies/trust/key metadata. No key values, no mutation APIs."""

    source = "aws_iam"
    display_name = "AWS IAM (import)"

    def validate_payload(self, p: dict) -> list[str]:
        errs = []
        for ident in p.get("identities", []):
            if "native_id" not in ident or "authority" not in ident:
                errs.append("aws identity missing native_id/authority")
        for rel in p.get("relationships", []):
            if rel.get("relationship") == "can_assume" and "trust_policy" not in rel.get("conditions", {}):
                errs.append(f"can_assume edge {rel.get('src')} missing trust_policy context")
        return errs

    def normalize(self, p: dict) -> CollectResult:
        r = CollectResult()
        r.identities = [{
            "native_id": i["native_id"], "authority": i.get("authority", "unknown"),
            "display_name": i.get("display_name", i["native_id"]),
            "id_type": i.get("id_type", "role"), "attributes": i.get("attributes", {}),
        } for i in p.get("identities", [])]
        r.credentials = [{
            "identity_native_id": c["identity_native_id"], "kind": c.get("kind", "access_key"),
            "status": c.get("status", "enabled"), "created_at": c.get("created_at"),
            "expires_at": c.get("expires_at"), "last_rotated_at": c.get("last_rotated_at"),
            "attributes": c.get("attributes", {}),
        } for c in p.get("credentials", [])]
        r.ownership = [{
            "identity_native_id": o["identity_native_id"], "owner_email": o.get("owner_email", ""),
            "role": o.get("role", "technical"), "verified": bool(o.get("verified")),
            "purpose": o.get("purpose", ""),
        } for o in p.get("ownership", [])]
        r.relationships = [{
            "src": rel["src"], "dst": rel["dst"],
            "relationship": rel.get("relationship", "can_assume"),
            "conditions": rel.get("conditions", {}),
        } for rel in p.get("relationships", [])]
        return r


class EntraConnector(ImportConnector):
    """CN02: service principals, app grants, credential metadata, owners.

    Sign-in audit 403 must be recorded as page_errors — a consent gap is a gap,
    not absence (CN02 certification note; AT08)."""

    source = "entra"
    display_name = "Entra ID (import)"

    def validate_payload(self, p: dict) -> list[str]:
        errs = []
        for g in p.get("grants", []):
            if "app_native_id" not in g:
                errs.append("grant missing app_native_id")
        return errs

    def normalize(self, p: dict) -> CollectResult:
        r = CollectResult()
        r.identities = [{
            "native_id": i["native_id"], "authority": i.get("authority", "tenant"),
            "display_name": i.get("display_name", i["native_id"]),
            "id_type": i.get("id_type", "service_principal"),
            "attributes": i.get("attributes", {}),
        } for i in p.get("identities", [])]
        r.credentials = [{
            "identity_native_id": c["identity_native_id"], "kind": c.get("kind", "client_secret"),
            "status": c.get("status", "enabled"), "created_at": c.get("created_at"),
            "expires_at": c.get("expires_at"), "last_rotated_at": c.get("last_rotated_at"),
            "attributes": c.get("attributes", {}),
        } for c in p.get("credentials", [])]
        r.ownership = [{
            "identity_native_id": o["identity_native_id"], "owner_email": o.get("owner_email", ""),
            "role": o.get("role", "business"), "verified": bool(o.get("verified")),
            "purpose": o.get("purpose", ""),
        } for o in p.get("ownership", [])]
        r.relationships = [{
            "src": rel["src"], "dst": rel["dst"],
            "relationship": rel.get("relationship", "authenticates_as"),
            "conditions": rel.get("conditions", {}),
        } for rel in p.get("relationships", [])]
        r.grants = [{
            "app_native_id": g["app_native_id"],
            "scopes": g.get("scopes", []),
            "delegated": bool(g.get("delegated", False)),
            "consent_record": g.get("consent_record"),
            "publisher_domain": g.get("publisher_domain"),
            "multi_tenant": bool(g.get("multi_tenant", False)),
        } for g in p.get("grants", [])]
        return r


class GithubConnector(ImportConnector):
    """CN03: app installations, workflows, deploy keys, exposed-secret candidates (CN05 offline,
    validation disabled per G23 — a matched pattern is a candidate with unknown validity)."""

    source = "github"
    display_name = "GitHub (import)"

    def validate_payload(self, p: dict) -> list[str]:
        errs = []
        for w in p.get("workflows", []):
            for field in ("repo", "name", "permissions", "actions"):
                if field not in w:
                    errs.append(f"workflow {w.get('name', '?')} missing {field}")
        return errs

    def normalize(self, p: dict) -> CollectResult:
        r = CollectResult()
        r.identities = [{
            "native_id": i["native_id"], "authority": i.get("authority", "org"),
            "display_name": i.get("display_name", i["native_id"]),
            "id_type": i.get("id_type", "app_installation"), "attributes": i.get("attributes", {}),
        } for i in p.get("identities", [])]
        r.credentials = [{
            "identity_native_id": c["identity_native_id"], "kind": c.get("kind", "deploy_key"),
            "status": c.get("status", "enabled"), "created_at": c.get("created_at"),
            "expires_at": c.get("expires_at"), "last_rotated_at": c.get("last_rotated_at"),
            "attributes": c.get("attributes", {}),
        } for c in p.get("credentials", [])]
        r.ownership = [{
            "identity_native_id": o["identity_native_id"], "owner_email": o.get("owner_email", ""),
            "role": o.get("role", "technical"), "verified": bool(o.get("verified")),
            "purpose": o.get("purpose", ""),
        } for o in p.get("ownership", [])]
        r.relationships = [{
            "src": rel["src"], "dst": rel["dst"],
            "relationship": rel.get("relationship", "can_access"),
            "conditions": rel.get("conditions", {}),
        } for rel in p.get("relationships", [])]
        r.workflows = [{
            "repo": w["repo"], "name": w["name"], "path": w.get("path", ""),
            "permissions": w.get("permissions", {}),
            "actions": w.get("actions", []), "triggers": w.get("triggers", []),
        } for w in p.get("workflows", [])]
        r.secret_candidates = [{
            "repo": sc["repo"], "path": sc.get("path", ""), "pattern": sc.get("pattern", "unknown"),
            "context": sc.get("context", ""), "confidence": sc.get("confidence", "low"),
            "matched_value_fingerprint": sc.get("matched_value", ""),  # value itself never persisted
        } for sc in p.get("secret_candidates", [])]
        return r


class AgentRegistryConnector(ImportConnector):
    """CN04: signed JSON import of agent registry + observed runtime agents (G42)."""

    source = "agent_registry"
    display_name = "Agent registry/gateway (import)"

    KNOWN_CAPS = {
        "read:repo", "read:identity", "read:secret_metadata", "read:evidence",
        "write:ticket", "write:report_draft", "net:egress", "tool:mcp_client",
        "delegate:child", "approve:proposal", "read:graph",
    }

    def validate_payload(self, p: dict) -> list[str]:
        errs = []
        for a in p.get("agents", []):
            caps = set(a.get("capabilities", []))
            unknown = caps - self.KNOWN_CAPS
            if unknown:
                errs.append(f"agent {a.get('native_id')}: unknown capabilities {sorted(unknown)} (schema rejects)")
        return errs

    def normalize(self, p: dict) -> CollectResult:
        r = CollectResult()
        r.agents = [{
            "native_id": a["native_id"], "display_name": a.get("display_name", a["native_id"]),
            "sponsor": a.get("sponsor"), "purpose": a.get("purpose"),
            "runtime": a.get("runtime"), "capabilities": a.get("capabilities", []),
            "parent_native_id": a.get("parent_native_id"),
            "lifecycle": a.get("lifecycle", "active"), "registered": bool(a.get("registered", True)),
            "expires_at": a.get("expires_at"),
            "attributes": a.get("attributes", {}),
        } for a in p.get("agents", [])]
        r.identities = [{
            "native_id": f"agent:{a['native_id']}", "authority": "agent_gateway",
            "display_name": a.get("display_name", a["native_id"]),
            "id_type": "agent_identity", "attributes": {"sponsor": a.get("sponsor")},
        } for a in r.agents]
        r.credentials = [{
            "identity_native_id": f"agent:{c['identity_native_id']}", "kind": c.get("kind", "agent_token"),
            "status": c.get("status", "enabled"), "created_at": c.get("created_at"),
            "expires_at": c.get("expires_at"), "last_rotated_at": c.get("last_rotated_at"),
        } for c in p.get("credentials", [])]
        r.relationships = [{
            "src": rel["src"], "dst": rel["dst"],
            "relationship": rel.get("relationship", "delegates_to"),
            "conditions": rel.get("conditions", {}),
        } for rel in p.get("relationships", [])]
        r.ownership = [{
            "identity_native_id": f"agent:{o['identity_native_id']}",
            "owner_email": o.get("owner_email", ""), "role": o.get("role", "business"),
            "verified": bool(o.get("verified")), "purpose": o.get("purpose", ""),
        } for o in p.get("ownership", [])]
        r.extras = dict(p.get("attributes_extra") or {})
        return r


ADAPTERS: dict[str, type[ImportConnector]] = {
    c.source: c for c in (AwsIamConnector, EntraConnector, GithubConnector, AgentRegistryConnector)
}


def get_adapter(source: str, ctx: CollectionContext) -> ImportConnector:
    cls = ADAPTERS.get(source)
    if cls is None:
        raise FixtureError(f"no certified adapter for source {source}")
    return cls(ctx)
