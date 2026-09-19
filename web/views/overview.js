/* views/overview.js - UI01 Mission Control: connector health, active runs,
   findings by severity, score summary, reports awaiting release, approvals pending.
   Empty tenant shows an onboarding checklist; never implies "zero risk" (UX20). */
import {
  el, get, icon, runStateChip, hasCap, fmtTime, relTime, emptyState,
  errorState, loadingState, linkChip, genericChip,
} from "../core.js";
import { scorePanel, severityCounts } from "./score.js";

export async function viewOverview(container) {
  const clear = () => { while (container.firstChild) container.removeChild(container.firstChild); };
  container.appendChild(loadingState("Loading mission control\u2026"));
  let data;
  try {
    data = await get("/v1/overview");
  } catch (err) {
    clear();
    container.appendChild(errorState(err, () => viewOverview(container)));
    return null;
  }
  clear();
  renderOverview(container, data);
  // Refresh the small live bits every 30s while the page is open.
  const iv = setInterval(async () => {
    try {
      const fresh = await get("/v1/overview");
      clear();
      renderOverview(container, fresh);
    } catch { /* keep last good view */ }
  }, 30000);
  return () => clearInterval(iv);
}

function renderOverview(container, data) {
  const runs = data.runs || [];
  const hasAnyData = (data.identity_count || 0) > 0 || runs.length > 0;

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Mission control"),
      el("p", {}, "Coverage and freshness first: active missions, confirmed exposure, approvals and connector health.")));
  container.appendChild(head);

  if (!hasAnyData) {
    container.appendChild(onboardingChecklist());
    return;
  }

  const grid = el("div", { class: "card-grid grid-3" });

  // --- active runs -----------------------------------------------------------
  const activeRuns = runs.filter((r) => !["succeeded", "failed", "cancelled", "partial"].includes(r.state));
  const runsCard = el("div", { class: "card" },
    el("h2", {}, icon("runs"), "Active runs"),
    el("p", { class: "card-sub" }, "Missions currently queued, running or awaiting a gate"));
  if (activeRuns.length === 0) {
    runsCard.appendChild(el("p", { class: "muted small" }, "No runs in flight. Latest activity below."));
    const recent = el("div", { class: "stat-list" });
    for (const r of runs.slice(0, 4)) {
      recent.appendChild(el("div", { class: "row" },
        el("a", { class: "mono", href: `#/runs/${r.run_id}` }, r.run_id.slice(0, 18) + "\u2026"),
        runStateChip(r.state)));
    }
    runsCard.appendChild(recent);
  } else {
    const list = el("div", { class: "stat-list" });
    for (const r of activeRuns) {
      list.appendChild(el("div", { class: "row" },
        el("a", { class: "mono", href: `#/runs/${r.run_id}` }, r.run_id.slice(0, 18) + "\u2026"),
        el("span", { class: "muted small" }, `${r.mode} \u00B7 ${relTime(r.created_at)}`),
        runStateChip(r.state)));
    }
    runsCard.appendChild(list);
  }
  runsCard.appendChild(el("div", { class: "mt8" }, el("a", { class: "btn small", href: "#/runs" }, "All runs")));
  grid.appendChild(runsCard);

  // --- findings by severity -----------------------------------------------------
  const sevCard = el("div", { class: "card" },
    el("h2", {}, icon("findings"), "Findings by severity"),
    el("p", { class: "card-sub" }, "Confirmed policy violations from evaluated runs"));
  sevCard.appendChild(severityCounts(data.findings_by_severity, (sev) => `#/findings?severity=${sev}`));
  sevCard.appendChild(el("div", { class: "mt8" }, el("a", { class: "btn small", href: "#/findings" }, "Triage findings")));
  grid.appendChild(sevCard);

  // --- posture score ----------------------------------------------------------------
  const scoreCard = el("div", { class: "card" },
    el("h2", {}, icon("overview"), "Posture score"),
    el("p", { class: "card-sub" }, "Measured dimensions with visible completeness"));
  grid.appendChild(scoreCard);
  const latest = runs[0];

  // --- connectors --------------------------------------------------------------------
  const connCard = el("div", { class: "card" },
    el("h2", {}, icon("connectors"), "Connector health"),
    el("p", { class: "card-sub" }, "State and last complete sync per source"));
  const connList = el("div", { class: "stat-list" });
  for (const c of data.connectors || []) {
    connList.appendChild(el("div", { class: "row" },
      el("span", {}, c.name),
      el("span", { class: "muted small mono" }, c.last_complete_sync ? relTime(c.last_complete_sync) : "never synced"),
      syncChip(c.state)));
  }
  if (!(data.connectors || []).length) connList.appendChild(el("p", { class: "muted small" }, "No connectors configured."));
  connCard.appendChild(connList);
  if (hasCap("connector:preflight")) {
    connCard.appendChild(el("div", { class: "mt8" }, el("a", { class: "btn small", href: "#/connectors" }, "Manage connectors")));
  }
  grid.appendChild(connCard);

  // --- approvals + reports ---------------------------------------------------------------
  const apprCard = el("div", { class: "card" },
    el("h2", {}, icon("approvals"), "Approvals pending"),
    el("div", { class: "kpi-row" },
      el("span", { class: "kpi" }, String(data.proposals_pending ?? 0)),
      el("span", { class: "muted small" }, "proposals awaiting two-person decisions")));
  if (data.proposals_pending > 0) {
    apprCard.appendChild(el("div", { class: "mt8" }, el("a", { class: "btn small", href: "#/approvals" }, "Review approvals")));
  }
  grid.appendChild(apprCard);

  const repCard = el("div", { class: "card" },
    el("h2", {}, icon("reports"), "Reports awaiting release"),
    el("div", { class: "kpi-row" },
      el("span", { class: "kpi" }, String(data.reports_awaiting_release ?? 0)),
      el("span", { class: "muted small" }, "drafts parked at the G02 release gate")));
  repCard.appendChild(el("div", { class: "mt8" }, el("a", { class: "btn small", href: "#/reports" }, "Open reports")));
  grid.appendChild(repCard);

  const invCard = el("div", { class: "card" },
    el("h2", {}, icon("identities"), "Identity inventory"),
    el("div", { class: "kpi-row" },
      el("span", { class: "kpi" }, String(data.identity_count ?? 0)),
      el("span", { class: "muted small" }, "non-human identities observed")));
  invCard.appendChild(el("div", { class: "mt8" }, el("a", { class: "btn small", href: "#/identities" }, "Browse identities")));
  grid.appendChild(invCard);

  container.appendChild(grid);

  // Score panel fetched async (needs latest run id).
  const scoreHost = el("div", { class: "card mt16" });
  container.appendChild(scoreHost);
  if (latest) {
    scoreHost.appendChild(el("h2", {}, icon("overview"), `Score for latest run `));
    scoreHost.appendChild(el("span", { class: "mono small muted" }, latest.run_id));
    get(`/v1/scores?run_id=${encodeURIComponent(latest.run_id)}`).then((card) => {
      scoreHost.appendChild(el("div", { class: "mt8" }, scorePanel(card)));
    }).catch((err) => {
      scoreHost.appendChild(el("div", { class: "mt8" }, scorePanel(null)));
      scoreHost.appendChild(el("p", { class: "small muted" },
        `Score unavailable for the latest run: ${err.code || "error"} - ${err.message || "no data yet"}`));
    });
  } else {
    scoreHost.appendChild(scorePanel(null));
  }
}

function syncChip(state) {
  const map = {
    complete: ["ok", "check", "complete"],
    partial: ["warn", "alert", "partial"],
    error: ["bad", "x", "error"],
    pending: ["neutral", "clock", "pending"],
  };
  const [cls, ic, label] = map[state] || ["warn", "question", state || "unknown"];
  return genericChip(label, cls, ic);
}

function onboardingChecklist() {
  const steps = [
    ["1", "Connect sources", "Connector imports (aws_iam, entra, github, agent registry) appear under Connectors with a passing preflight.", "#/connectors"],
    ["2", "Approve scope", "A scope version with certified passive checks must be approved for the engagement.", "#/runs"],
    ["3", "Launch a passive run", "Start the first assessment from Runs; the swarm board shows live node state.", "#/runs"],
    ["4", "Release the report", "A reviewer releases the assembled draft at the G02 gate; findings and scores appear here.", "#/reports"],
  ];
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", {}, icon("overview"), "No data yet - set up your first assessment"));
  card.appendChild(el("p", { class: "muted" },
    "This workspace shows no collected identities and no runs. Until a scan has completed there is no risk picture to display - an empty state is not a zero-risk statement."));
  const ol = el("ol", { style: "display:flex;flex-direction:column;gap:10px;padding-left:4px" });
  for (const [n, title, desc, href] of steps) {
    ol.appendChild(el("li", { style: "display:flex;gap:12px;align-items:flex-start;list-style:none" },
      el("span", { class: "chip run", style: "min-width:26px;justify-content:center" }, n),
      el("div", {}, el("strong", {}, title), el("div", { class: "muted small" }, desc)),
      el("a", { class: "btn small", href, style: "margin-left:auto" }, "Open")));
  }
  card.appendChild(ol);
  return card;
}
