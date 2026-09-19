# ADR-0002: Deterministic policy module (OPA-compatible shape) instead of an OPA server

**Status:** accepted for slice 0.1  ·  **Blueprint refs:** AR04, SC16, DC14, PS01–PS05, AT12

Severity and score policies are implemented as versioned, deterministic Python modules
(`nhi_sentinel/policies/`) that record `policy_version` + `input_hash` with every decision
(DC14), fail closed on missing inputs (PS02: `undetermined`, never a guessed low), and keep
severity, assurance and workflow state on separate axes (PS01).

**Why:** the pilot needs reproducible decisions and signed policy versions, not a remote
policy agent. The module boundary (inputs dict → decision + rationale + version + hash)
is exactly what an OPA bundle would expose, so migrating to OPA/Rego later is a mechanical
swap behind `decide_severity()`. The blueprint's caution stands regardless of engine:
OPA-style evaluation gives *reproducibility*, not truth — evidence entailment and analyst
review remain mandatory (G16).

**Consequences:** policy lifecycle (SC16: signed bundles, change approval, no silent
refresh) is currently repository review; per-run version pinning is honored by recording
the version on every decision row.
