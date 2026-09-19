# ADR-0003: Zero-build vanilla JS portal for the slice (React parity deferred)

**Status:** accepted for slice 0.1  ·  **Blueprint refs:** D08, VD01–VD16, UX01–UX24, BG09, BG03 ("adapt language packaging")

The blueprint specifies React/TypeScript with a typed generated client. The slice ships a
framework-free ES-module SPA (`web/`) served by FastAPI at `/portal`:

- Hash router, typed-by-convention API client in one module, EventSource for SSE with
  `Last-Event-ID` resumance (UX16), textContent-only rendering (VD13/AT21).
- Design tokens per VD02/VD03 (dark control-room + light theme), status = icon+text
  components (VD04), synthetic-data banner (UX24).

**Why:** the deliverable must run end-to-end on any machine with Python installed — no
Node toolchain, no npm install, no build outputs in the repo. The UX contracts
(states, no fabricated progress, server-authoritative receipts) are properties of the
product, not of React; they are implemented and testable here. React/TS parity is a
mechanical port once B06/B07 (frontend staffing) lands.

**Consequences:** no component library/storybook yet (VD11 lists the target components;
the CSS classes mirror those names). Virtualized tables and the graph canvas (React Flow,
VD09) are deferred; the run board uses a deterministic CSS-grid lane layout and the graph
API exposes bounded paths for the future canvas.
