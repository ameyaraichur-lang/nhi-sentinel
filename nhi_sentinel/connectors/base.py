"""Connector framework (CN01-CN05 pilot: passive, import-based, least privilege).

Adapters consume signed export/import payloads — never live mutation APIs. The base handles
envelope validation, secret redaction (SC11), completeness computation (DC09/G25) and signed
evidence manifests (DC15). Partial collection is preserved as partial — it never implies
deletion or full coverage (AT08).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..core.db import new_id
from ..core.security import digest_of, fingerprint_secret, redact_dict
from ..config import get_settings

ENVELOPE_REQUIRED = {"schema_version", "source", "producer", "collected_at", "scope", "expected_count"}
KNOWN_SOURCES = {"aws_iam", "entra", "github", "agent_registry"}


class FixtureError(ValueError):
    """Schema/validation failure -> snapshot INVALID, run blocked from promoting the payload (AR08)."""


@dataclass
class CollectionContext:
    tenant_id: str
    run_id: str
    scope_hash: str
    connector_id: str
    source: str


@dataclass
class CollectResult:
    """Normalized collection output. All IDs reference native source identifiers."""

    snapshot: dict = field(default_factory=dict)
    identities: list[dict] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    ownership: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    agents: list[dict] = field(default_factory=list)
    workflows: list[dict] = field(default_factory=list)
    secret_candidates: list[dict] = field(default_factory=list)
    grants: list[dict] = field(default_factory=list)
    extras: dict = field(default_factory=dict)   # source-specific config evidence (e.g. gateway policy)
    artifacts: list[dict] = field(default_factory=list)


class ImportConnector:
    """Base class for pilot import connectors. Subclasses implement validate + normalize."""

    source: str = ""
    display_name: str = ""
    schema_min: str = "1.0"

    def __init__(self, ctx: CollectionContext):
        self.ctx = ctx

    # --- public entry point --------------------------------------------------
    def collect(self) -> tuple[CollectResult, list[str]]:
        """Load, validate, redact, normalize. Returns (result, page_errors)."""
        payload = self._load_fixture()
        errors = self.validate_payload(payload)
        if errors:
            raise FixtureError(f"{self.source}: payload rejected: {'; '.join(errors[:5])}")
        redacted, removed = redact_dict(payload)
        result = self.normalize(redacted)
        # Completeness per DC09: page errors and short counts -> partial, never silently complete.
        page_errors = list(payload.get("page_errors") or [])
        seen = len(result.identities)
        expected = payload.get("expected_count")
        if expected is not None and seen < expected and not page_errors:
            page_errors = [{"page": "tail", "error": "enumeration ended before expected_count"}]
        completeness = None
        if expected:
            completeness = round(min(1.0, seen / max(expected, 1)), 4)
        state = "complete" if not page_errors and (expected is None or seen >= expected) else "partial"
        result.snapshot = {
            "snapshot_id": new_id("snp"), "source": self.source, "connector_id": self.ctx.connector_id,
            "scope_hash": self.ctx.scope_hash, "state": state,
            "collected_at": payload.get("collected_at"), "expected_count": expected,
            "seen_count": seen, "completeness": completeness, "page_errors": page_errors,
            "producer": payload.get("producer"), "secrets_redacted": removed,
            "schema_version": payload.get("schema_version"),
        }
        self._build_artifacts(payload, result)
        return result, page_errors

    # --- subclass contract -----------------------------------------------------
    def validate_payload(self, payload: dict) -> list[str]:
        """Semantic source validation. Return list of problems; empty list == accepted."""
        return []

    def normalize(self, payload: dict) -> CollectResult:
        raise NotImplementedError

    # --- internals ---------------------------------------------------------------
    def fixture_path(self) -> Path:
        base = get_settings().fixture_dir
        path = base / f"{self.source}_snapshot.json"
        if not path.exists():
            raise FixtureError(f"{self.source}: fixture snapshot missing at {path.name} (preflight failed)")
        return path

    def _load_fixture(self) -> dict:
        raw = json.loads(self.fixture_path().read_text(encoding="utf-8"))
        missing = ENVELOPE_REQUIRED - set(raw)
        if missing:
            raise FixtureError(f"{self.source}: envelope missing {sorted(missing)}")
        if raw["source"] != self.source:
            raise FixtureError(f"{self.source}: envelope source mismatch ({raw['source']})")
        return raw

    def _build_artifacts(self, payload: dict, result: CollectResult) -> None:
        """Signed manifest artifacts: one per section + envelope (DC15). Content already redacted."""
        stamp = payload.get("collected_at")
        sections = {
            "envelope": {k: payload.get(k) for k in
                         ("schema_version", "source", "producer", "collected_at", "scope", "expected_count")},
            "identities": result.identities,
            "credentials_metadata": [
                {**c, "fingerprint": fingerprint_secret(str(c.get("identity_native_id", "")) + str(c.get("kind", "")),
                                                        self.ctx.tenant_id)}
                for c in result.credentials],
            "ownership": result.ownership,
            "relationships": result.relationships,
        }
        if result.agents:
            sections["agents"] = result.agents
        if result.workflows:
            sections["workflows"] = result.workflows
        if result.secret_candidates:
            sections["secret_candidates"] = result.secret_candidates
        if result.grants:
            sections["grants"] = result.grants
        if result.extras:
            sections["extras"] = result.extras
        for name, content in sections.items():
            artifact = {
                "artifact_id": new_id("art"), "kind": f"collection.{name}",
                "producer": result.snapshot["producer"], "collected_at": stamp,
                "content": content, "redaction_version": "1.0",
            }
            artifact["sha256"] = digest_of(artifact["content"])
            result.artifacts.append(artifact)


def secret_fingerprint(value: str, tenant_id: str) -> str:
    return fingerprint_secret(value, tenant_id)


def parse_ts(value: str | None) -> datetime | None:
    """RFC3339 UTC -> naive UTC datetime (DC08)."""
    if not value:
        return None
    v = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is not None:
        dt = dt.astimezone(tz=None).replace(tzinfo=None) if False else dt
    # normalize to naive UTC
    if dt.tzinfo is not None:
        from datetime import timezone
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt
