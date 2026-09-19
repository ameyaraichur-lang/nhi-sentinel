/* views/score.js - posture score panel (PS06-PS11): measured dimension bars,
   explicit "unavailable" chips with reasons. Never invents or rounds a score. */
import { el, icon, meterBar, pct, genericChip, sevChip, linkChip } from "../core.js";

export function scorePanel(card, { compact = false } = {}) {
  const wrap = el("div", { class: "stack", style: "gap:10px" });

  if (!card) {
    wrap.appendChild(el("div", { class: "empty-state", style: "padding:18px" },
      el("h3", {}, "No score data yet"),
      el("p", { class: "small" }, "Scores appear after a run completes collection and checks.")));
    return wrap;
  }

  // Aggregate headline: measured => number; unavailable => chip + reason (never zero).
  const head = el("div", { class: "rowflex" });
  if (card.aggregate_status === "measured" && card.observed_scope_score !== null) {
    head.appendChild(el("span", { class: "kpi" }, String(card.observed_scope_score)));
    head.appendChild(el("span", { class: "muted" }, "/ 100 observed-scope score"));
    head.appendChild(genericChip("measured", "ok", "check"));
  } else {
    head.appendChild(genericChip("score unavailable", "warn", "question"));
  }
  wrap.appendChild(head);

  if (card.aggregate_reason) {
    wrap.appendChild(el("p", { class: "small muted", style: "margin:0" }, card.aggregate_reason));
  }
  wrap.appendChild(el("p", { class: "small muted mono", style: "margin:0" },
    `policy ${card.policy_version} \u00B7 weights sum ${card.weights_total}`));

  // Per-dimension bars (measured) or explicit unavailable chip + reason.
  const dims = el("div", {});
  for (const d of card.dimensions || []) {
    const row = el("div", { class: "meter-row" });
    row.appendChild(el("span", {}, d.dimension));
    if (d.status === "measured" && d.pass_rate !== null) {
      row.appendChild(meterBar(d.pass_rate));
      const detail = el("span", { class: "small muted", style: "text-align:right" },
        `${pct(d.pass_rate)} pass`);
      detail.title = `assessed ${d.assessed} of ${d.eligible} eligible; completeness ${d.completeness === null ? "-" : pct(d.completeness)}`;
      row.appendChild(detail);
    } else {
      const unavailable = genericChip("unavailable", "warn", "question");
      if (d.unavailable_reason) unavailable.title = d.unavailable_reason;
      row.appendChild(unavailable);
      row.appendChild(el("span", { class: "small muted", style: "text-align:right" },
        `weight ${Math.round(d.weight * 100)}%`));
    }
    dims.appendChild(row);
    if (d.status !== "measured" && d.unavailable_reason && !compact) {
      dims.appendChild(el("p", { class: "small muted", style: "margin:0 0 6px" },
        `${d.dimension}: ${d.unavailable_reason}`));
    }
  }
  wrap.appendChild(dims);
  return wrap;
}

/** Small summary line of finding counts by severity, worst first. */
export function severityCounts(counts, linkFor) {
  const order = ["critical", "high", "medium", "low", "informational", "undetermined"];
  const out = el("div", { class: "stat-list" });
  let any = false;
  for (const sev of order) {
    const n = counts && counts[sev];
    if (!n) continue;
    any = true;
    const row = el("div", { class: "row" },
      sevChip(sev),
      el("span", { class: "kpi", style: "font-size:18px" }, String(n)));
    if (linkFor) {
      row.appendChild(linkChip(linkFor(sev), "view", "external"));
    }
    out.appendChild(row);
  }
  if (!any) {
    out.appendChild(el("p", { class: "muted small", style: "margin:0" },
      "No findings recorded yet for this tenant."));
  }
  return out;
}

export function scoreIcon() { return icon("overview", 16); }
