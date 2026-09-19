# ADR-0005: Import connectors for the demo corpus; live SDK connectors are a certification gate away

**Status:** accepted for slice 0.1  ·  **Blueprint refs:** CN01–CN05, CN04 (signed JSON import), G42, BG06, AT15

The pilot connectors are implemented as **import adapters** over schema-validated, signed
synthetic exports (`fixtures/`), per CN04's "signed JSON import first" pattern — extended
to all four sources for the demo. The adapter contract (envelope validation, redaction at
ingest, completeness from page errors, per-section signed manifests) is the same surface a
live SDK collector fills (CN01–CN03), so certification fixtures apply unchanged.

**Why:** the blueprint forbids mock-marked-as-production connectors (BG06) and forbids
implied support before certification gates (Start Here, AT15). Honest labeling: these are
*import* connectors certified against the import schema; live AWS/Entra/GitHub collectors
must pass sandbox certification (read-only permission manifests, paging/throttle handling)
before replacing them. Nothing in the product claims live coverage.

**Consequences:** `INV-001` freshness semantics treat each run's imports as snapshots;
connector health (UI13) reflects normalization outcomes, not HTTP 200s (CN02 note). The
secret scanner stays offline-pattern-only with validation disabled (G23/SC11); KEY-001
candidates are never redeemed.
