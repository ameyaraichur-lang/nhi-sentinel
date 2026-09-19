"""Run DAG (Orchestration sheet). Each run is acyclic; retries are task attempts (G06).

Fan-in: a node dispatches only when every parent is terminal (succeeded or skipped) —
draft/quarantined data can never bypass evaluation (G05/AT10). G02 is an external human
gate: the engine parks the run until the report release API completes it (G02/AT13)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class NodeSpec:
    id: str
    title: str
    executor: str                      # deterministic | llm_optional | human_gate
    next_nodes: tuple[str, ...] = ()
    fan_out: str | None = None         # None | "sources" | "checks"
    optional: bool = False


NODES: dict[str, NodeSpec] = {n.id: n for n in [
    NodeSpec("N00", "Scope and readiness", "deterministic", ("N01",)),
    NodeSpec("N01", "Plan", "llm_optional", ("N02",)),  # deterministic validator wraps plan (N01/G)
    NodeSpec("N02", "Collect partitions", "deterministic", ("N03",), fan_out="sources"),
    NodeSpec("N03", "Normalize and coverage", "deterministic", ("N04", "N05")),
    NodeSpec("N04", "Passive checks", "deterministic", ("N06",), fan_out="checks"),
    NodeSpec("N05", "Path analysis", "deterministic", ("N06",)),
    NodeSpec("N06", "Evidence validation", "deterministic", ("N07", "N12")),
    NodeSpec("N07", "Proof proposal", "llm_optional", ("G01",), optional=True),
    NodeSpec("G01", "Human active-proof gate", "human_gate", ("N08",), optional=True),
    NodeSpec("N08", "Execute approved proof", "deterministic", ("N09",), optional=True),
    NodeSpec("N09", "Merge proof result", "deterministic", ("N12",), optional=True),
    NodeSpec("N12", "Evaluate severity", "deterministic", ("N13", "N14", "N15")),
    NodeSpec("N13", "Risk scenarios", "llm_optional", ("N16",), optional=True),
    NodeSpec("N14", "Control evidence mapping", "deterministic", ("N16",)),
    NodeSpec("N15", "Remediation drafts", "llm_optional", ("N16",)),
    NodeSpec("N16", "Report assembly", "deterministic", ("G02",)),
    NodeSpec("G02", "Report release gate", "human_gate", ("N17",)),
    NodeSpec("N17", "Publish", "deterministic", ()),
]}

PARENTS: dict[str, tuple[str, ...]] = {}
for _n in NODES.values():
    for _child in _n.next_nodes:
        # append (not setdefault): setdefault here would keep the () default forever and
        # leave PARENTS empty, disabling fan-in gating entirely (dispatch must wait for
        # every parent to be terminal - G05/AT10)
        PARENTS[_child] = (*PARENTS.get(_child, ()), _n.id)

PROOF_BRANCH = {"N07", "G01", "N08", "N09"}


def ready(node_id: str, terminal_parents: set[str]) -> bool:
    return all(p in terminal_parents for p in PARENTS.get(node_id, ()))


def validate_graph() -> None:
    """Structural invariants (G06/G07): acyclic, fan-in explicit, no orphan nodes."""
    seen, stack = set(), set()

    def visit(nid: str):
        if nid in stack:
            raise ValueError(f"cycle at {nid}")
        if nid in seen:
            return
        stack.add(nid)
        for child in NODES[nid].next_nodes:
            visit(child)
        stack.discard(nid)
        seen.add(nid)

    visit("N00")
    for nid, spec in NODES.items():
        if spec.fan_out and len(spec.next_nodes) != 1:
            raise ValueError(f"fan-out node {nid} must have single fan-in continuation")
    assert "N12" in NODES["N06"].next_nodes and "N16" in NODES["N13"].next_nodes


validate_graph()
