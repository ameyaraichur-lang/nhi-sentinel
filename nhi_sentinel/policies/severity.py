"""PS01-PS05 deterministic severity policy. No LLM severity, no unexplained multiplication.

Rules evaluate ordered Critical -> Informational on standard inputs; missing essential
inputs yield UNDETERMINED with the missing list (PS02). Bundle version + input hash are
persisted with every decision (DC14, AT12)."""
from __future__ import annotations

from dataclasses import dataclass

from ..contracts import Severity
from ..core.security import digest_of

POLICY_VERSION = "sev-baseline-1.0.0"

ESSENTIAL = ("impact", "exposure", "effective_privilege")

# Impact ordering used by banding rules
_IMPACT_RANK = {"critical": 3, "high": 2, "moderate": 1, "low": 0}


@dataclass
class SeverityDecisionOut:
    severity: Severity
    rationale: str
    policy_version: str = POLICY_VERSION
    missing: tuple[str, ...] = ()

    @property
    def input_hash(self) -> str:
        return digest_of({"v": POLICY_VERSION})


def decide_severity(inputs: dict, bundle_version: str = POLICY_VERSION) -> SeverityDecisionOut:
    """inputs keys: impact, exposure, effective_privilege, path_certainty, credential_state,
    plus optional check-supplied context (all values lowercase enums or None). AT12: an
    unpinned/unknown policy bundle fails closed to UNDETERMINED."""
    if bundle_version != POLICY_VERSION:
        return SeverityDecisionOut(
            severity=Severity.UNDETERMINED,
            rationale=f"Severity policy bundle '{bundle_version}' is not the pinned version "
                      f"'{POLICY_VERSION}'; fail closed (AT12).",
            missing=("policy_bundle",))
    missing = [k for k in ESSENTIAL if not inputs.get(k)]
    if missing:
        return SeverityDecisionOut(
            severity=Severity.UNDETERMINED,
            rationale=f"Essential severity inputs unavailable: {', '.join(missing)} (PS02).",
            missing=tuple(missing))

    impact = inputs["impact"]
    exposure = inputs["exposure"]
    priv = inputs["effective_privilege"]
    path = inputs.get("path_certainty") or "none"
    cred = inputs.get("credential_state") or "not_applicable"

    if impact not in _IMPACT_RANK:
        return SeverityDecisionOut(Severity.UNDETERMINED, f"Unknown impact value '{impact}'.", missing=("impact",))

    # PS03 critical baseline
    if (path == "confirmed" and exposure == "untrusted" and impact == "critical"
            and priv == "elevated"):
        return SeverityDecisionOut(Severity.CRITICAL,
            "Confirmed effective path from untrusted context to critical asset with elevated privilege (PS03).")
    if cred == "exposed" and priv == "elevated" and impact == "critical":
        return SeverityDecisionOut(Severity.CRITICAL,
            "Confirmed exposed enabled privileged credential (PS03).")

    # PS03 high
    if priv == "elevated" and exposure in ("untrusted", "internal") and _IMPACT_RANK[impact] >= 2:
        return SeverityDecisionOut(Severity.HIGH,
            "Effective elevated unauthorized access with internal or untrusted reach (PS03).")
    if cred == "exposed" and _IMPACT_RANK[impact] >= 2:
        return SeverityDecisionOut(Severity.HIGH,
            "Serious credential exposure with partial path certainty (PS03).")
    if path == "possible" and exposure == "untrusted" and priv == "elevated" and impact == "critical":
        return SeverityDecisionOut(Severity.HIGH,
            "Possible (unconfirmed) path to critical asset from untrusted context (PS03/AR12).")

    # PS04 medium / low
    if _IMPACT_RANK[impact] >= 1 and not (impact == "low"):
        return SeverityDecisionOut(Severity.MEDIUM,
            "Evidenced excessive rights, lifecycle or trust weakness without confirmed high-impact route (PS04).")
    return SeverityDecisionOut(Severity.LOW,
        "Bounded hygiene or governance weakness (PS04).")


# Mapping from check-supplied hints to standard inputs. Checks embed these keys in facts.
STANDARD_KEYS = ("impact", "exposure", "effective_privilege", "path_certainty", "credential_state")


def inputs_from_facts(facts: dict) -> dict:
    return {k: facts.get(k) for k in STANDARD_KEYS}
