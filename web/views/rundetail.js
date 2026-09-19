/* views/rundetail.js - UI04 swarm run workspace.
   Left: deterministic phase-lane node board (CSS grid, no canvas lib).
   Right: per-source coverage panel with completeness bars and PARTIAL badges.
   Bottom: chronological SSE event timeline with Last-Event-ID resume (UX16).
   Header: state chip, mode, budget, pause/resume/cancel (If-Match) and the
   emergency stop with confirm dialog - no optimistic stopped labels (UX07/UX08).
   No fake progress bars or particles when no events have arrived (UX02). */
import {
  el, get, post, icon, runStateChip, taskStateChip, genericChip, meterBar,
  fmtTime, fmtDateTime, fmtDuration, toast, toastError, confirmDialog, formDialog,
  hasCap, ApiError, makeTimers,
} from "../core.js";

const SSE_TYPES = [
  "run.created", "run.running", "run.settled", "run.finalized", "run.failed",
  "run.killed", "run.command", "run.gate_released", "run.plan_ready",
  "run.plan_validated", "run.coverage", "run.scope_uncertified_checks_excluded",
  "snapshot.invalid", "snapshot.complete", "snapshot.partial",
  "check.completed", "check.quarantined", "analysis.paths",
  "findings.evaluated", "severity.evaluated", "report.drafted", "report.published",
  "task.state_changed", "task.retry_scheduled", "task.cancelled",
  "task.stale_lease_rejected",
];

/* Phase lanes, left to right (graph.py topology). */
const PHASES = [
  { title: "Plan", nodes: ["N00", "N01"] },
  { title: "Collect", nodes: ["N02", "N03"] },
  { title: "Checks & paths", nodes: ["N04", "N05"] },
  { title: "Evidence", nodes: ["N06"] },
  { title: "Proof branch (dormant)", nodes: ["N07", "G01", "N08", "N09"] },
  { title: "Evaluate", nodes: ["N12", "N13", "N14", "N15"] },
  { title: "Report & release", nodes: ["N16", "G02", "N17"] },
];

const NODE_TITLES = {
  N00: "Scope & readiness", N01: "Plan", N02: "Collect partitions",
  N03: "Normalize & coverage", N04: "Passive checks", N05: "Path analysis",
  N06: "Evidence validation", N07: "Proof proposal", G01: "Active-proof gate",
  N08: "Execute approved proof", N09: "Merge proof result",
  N12: "Evaluate severity", N13: "Risk scenarios", N14: "Control evidence mapping",
  N15: "Remediation drafts", N16: "Report assembly", G02: "Report release gate",
  N17: "Publish",
};

const TERMINAL_TASK = new Set(["succeeded", "failed", "skipped", "cancelled", "unknown"]);
const TERMINAL_RUN = new Set(["cancelled", "partial", "succeeded", "failed"]);

export async function viewRunDetail(container, params) {
  const runId = params[0];
  const timers = makeTimers();
  let disposed = false;
  let es = null;
  let lastSeq = 0;
  let backoff = 800;
  let refreshTimer = 0;

  /* ---- static skeleton ---- */
  const head = el("div", { class: "run-head" });
  const staleBanner = el("div", { class: "stale-banner hidden", role: "alert" },
    icon("alert", 15), "Live connection lost - reconnecting\u2026");
  const gateCallout = el("div", { class: "gate-callout hidden" });
  const layout = el("div", { class: "run-layout" });
  const boardCard = el("div", { class: "board-card" });
  const sideStack = el("div", { class: "stack", style: "gap:16px" });
  const coverageCard = el("div", { class: "card coverage-panel" });
  const infoCard = el("div", { class: "card" });
  sideStack.appendChild(coverageCard);
  sideStack.appendChild(infoCard);
  layout.appendChild(boardCard);
  layout.appendChild(sideStack);

  const timelineCard = el("div", { class: "card timeline-card" });
  const followToggle = el("input", { type: "checkbox", checked: true, id: "follow-live" });
  const followLabel = el("label", { class: "follow-toggle", for: "follow-live" }, followToggle, "Follow live");
  const timeline = el("ol", { class: "timeline", "aria-label": "Run event timeline" });
  timeline.appendChild(el("li", { class: "timeline-empty" },
    "Connected stream will replay this run's events chronologically\u2026"));
  const timelineHost = el("div", {}, timeline);
  timelineCard.appendChild(el("div", { class: "live-note" },
    icon("audit", 14),
    el("strong", {}, "Live events"),
    el("span", { class: "muted small" }, "SSE stream /v1/runs/" + runId + "/events \u00B7 sequence cursor resume"),
    el("span", { style: "flex:1" }),
    followLabel));
  timelineCard.appendChild(timelineHost);

  container.appendChild(head);
  container.appendChild(staleBanner);
  container.appendChild(gateCallout);
  container.appendChild(layout);
  container.appendChild(timelineCard);

  timeline.addEventListener("scroll", () => {
    const nearBottom = timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 48;
    if (!nearBottom && followToggle.checked) followToggle.checked = false; // never steal scroll focus
  });

  /* ---- data refresh ---- */
  let currentRun = null;
  async function refreshData() {
    if (disposed) return;
    let run;
    try {
      run = await get(`/v1/runs/${encodeURIComponent(runId)}`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        container.prepend(el("div", { class: "stale-banner" },
          icon("alert", 15), "Run not found or not visible to this tenant."));
      }
      return;
    }
    currentRun = run;
    renderHead(run);
    renderBoard(run);
    renderCoverage(run);
    renderInfo(run);
    renderGate(run);
  }

  function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(refreshData, 250);
  }

  /* ---- header ---- */
  const stateChipHost = el("span", {});
  const progressMeter = el("div", { class: "run-progress" });
  const cmdRow = el("div", { class: "btn-row" });

  function renderHead(run) {
    runStateChipInto(stateChipHost, run.state);
    const done = run.tasks.filter((t) => TERMINAL_TASK.has(t.state)).length;
    const total = run.tasks.length;
    progressMeter.replaceChildren(
      el("span", { class: "progress-label" }, `${done}/${total} tasks done`),
      meterBar(total ? done / total : null));
    const budgetBits = Object.entries(run.budget || {})
      .map(([k, v]) => `${k}=${v}`).join("  ") || "no budget recorded";
    head.replaceChildren(
      el("div", { style: "min-width:0" },
        el("div", { class: "crumbs" }, el("a", { href: "#/runs" }, "Runs"), " / run"),
        el("div", { class: "run-id mono" }, run.run_id),
        el("div", { class: "meta" },
          `mode ${run.mode} \u00B7 epoch ${run.epoch} \u00B7 started ${fmtDateTime(run.created_at)}`,
          run.finished_at ? ` \u00B7 finished ${fmtDateTime(run.finished_at)} (${fmtDuration(run.created_at, run.finished_at)})` : "")),
      stateChipHost,
      progressMeter,
      el("span", { class: "chip neutral mono", title: `budget: ${budgetBits}` },
        icon("settings", 12), budgetBits.split("  ")[0]),
      el("span", { class: "spacer", style: "flex:1" }),
      cmdRow);
    renderCommands(run);
  }

  function renderCommands(run) {
    cmdRow.replaceChildren();
    const terminal = TERMINAL_RUN.has(run.state) || run.state === "cancel_requested" || run.state === "cancelled";
    if (hasCap("run:command") && !terminal) {
      if (["queued", "running", "blocked"].includes(run.state)) {
        cmdRow.appendChild(commandBtn("Pause", "pause", "iconpause"));
      }
      if (run.state === "paused") {
        cmdRow.appendChild(commandBtn("Resume", "resume", "play"));
      }
      if (run.state !== "cancel_requested") {
        cmdRow.appendChild(commandBtn("Cancel", "cancel", "ban"));
      }
    }
    if (hasCap("run:stop") && run.state !== "cancelled") {
      const btn = el("button", { class: "btn danger solid" }, icon("stop"), "Emergency stop");
      btn.addEventListener("click", onEmergencyStop);
      cmdRow.appendChild(btn);
    }
    if (!hasCap("run:command") && !hasCap("run:stop")) {
      cmdRow.appendChild(el("span", { class: "muted small" },
        "Run controls require operator role."));
    }
  }

  function commandBtn(label, command, ic) {
    const btn = el("button", { class: "btn" }, icon(ic === "iconpause" ? "pause" : ic), label);
    btn.addEventListener("click", () => onCommand(command));
    return btn;
  }

  async function onCommand(command) {
    try {
      const values = await formDialog({
        title: `${command[0].toUpperCase()}${command.slice(1)} run`,
        message: command === "pause"
          ? "Pause stops new dispatch; tasks already dispatched may finish and are reconciled."
          : command === "resume"
            ? "Resume rechecks scope, credentials, budgets and approvals before dispatch continues."
            : "Cancel stops dispatch and cancels pending tasks. This cannot be resumed.",
        fields: [{ name: "reason", label: "Reason (required)", type: "textarea", required: true, min: 3 }],
        submitLabel: command === "cancel" ? "Cancel run" : `Confirm ${command}`,
        danger: command === "cancel",
        onSubmit: async (values) => {
          const out = await post(`/v1/runs/${encodeURIComponent(runId)}/commands`,
            { command, reason: values.reason }, { ifMatch: currentRun.revision });
          toast(`Server acknowledged ${command} (revision ${out.revision}).`, "success", "RUN_COMMAND");
          return true;
        },
      });
      if (values) refreshData();
    } catch (err) {
      toastError(err); // includes REVISION_CONFLICT with server message
      refreshData();
    }
  }

  async function onEmergencyStop() {
    try {
      const confirmed = await confirmDialog({
        title: "Emergency stop",
        message: "The independent kill path denies new dispatch immediately and cancels leases. "
          + "Already-sent provider calls may complete and are reconciled afterwards. "
          + "The stopped state is confirmed by the server before the UI updates.",
        confirmLabel: "Stop everything",
        danger: true,
        requireReason: true,
        reasonHint: "Why is an emergency stop required?",
      });
      if (!confirmed) return;
      const out = await post(`/v1/runs/${encodeURIComponent(runId)}/stop`, { reason: confirmed.reason });
      toast(out.note || "Emergency stop acknowledged by server.", "success", "RUN_STOP");
      await refreshData(); // no optimistic "stopped" label (UX08)
    } catch (err) {
      toastError(err);
      refreshData();
    }
  }

  /* ---- node board ---- */
  function renderBoard(run) {
    const byNode = new Map();
    for (const t of run.tasks) {
      const base = t.node.split(":")[0];
      if (!byNode.has(base)) byNode.set(base, []);
      byNode.get(base).push(t);
    }
    const board = el("div", { class: "board" });
    for (const phase of PHASES) {
      const col = el("div", { class: "phase" });
      col.appendChild(el("div", { class: "phase-head" },
        el("span", {}, phase.title)));
      let anyNode = false;
      for (const nid of phase.nodes) {
        const tasks = byNode.get(nid) || [];
        col.appendChild(nodeCard(nid, tasks));
        anyNode = true;
      }
      if (anyNode) board.appendChild(col);
    }
    // unknown nodes emitted by future engine versions still get a lane
    const known = new Set(PHASES.flatMap((p) => p.nodes));
    const extras = [...byNode.keys()].filter((n) => !known.has(n));
    if (extras.length) {
      const col = el("div", { class: "phase" }, el("div", { class: "phase-head" }, el("span", {}, "Other")));
      for (const n of extras) col.appendChild(nodeCard(n, byNode.get(n)));
      board.appendChild(col);
    }
    boardCard.replaceChildren(
      el("h2", {}, icon("agents"), "Swarm board"),
      el("p", { class: "card-sub" },
        "Deterministic phase lanes. Cards show live task state, attempts and skip reasons - real node state only."),
      el("div", { class: "board-scroll" }, board));
  }

  function nodeCard(nid, tasks) {
    const isGate = nid.startsWith("G");
    const card = el("div", { class: "node-card" });
    const title = NODE_TITLES[nid] || nid;
    const aggregate = aggregateState(tasks);
    card.classList.add(`state-${aggregate || "pending"}`);
    const top = el("div", { class: "node-top" },
      el("span", { class: "node-id mono" }, nid),
      isGate ? el("span", { class: "gate-flag" }, "GATE") : null,
      el("span", { class: "node-title", title }, title));
    card.appendChild(top);
    const stateRow = el("div", { class: "node-state" });
    if (tasks.length === 1) {
      stateRow.appendChild(taskStateChip(tasks[0].state));
      const attempt = tasks[0].attempt || 0;
      if (attempt > 1 || (tasks[0].error && attempt > 0)) {
        stateRow.appendChild(el("span", { class: "attempt" }, `attempt ${Math.max(1, attempt)}`));
      }
    } else if (tasks.length > 1) {
      stateRow.appendChild(aggregateChip(tasks));
      stateRow.appendChild(el("span", { class: "attempt" }, `${tasks.filter((t) => TERMINAL_TASK.has(t.state)).length}/${tasks.length} partitions`));
    } else {
      stateRow.appendChild(taskStateChip("pending"));
      stateRow.appendChild(el("span", { class: "attempt" }, "not yet created"));
    }
    card.appendChild(stateRow);

    const skipTask = tasks.find((t) => t.skip_reason);
    if (skipTask) {
      const sr = el("div", { class: "skip-reason", title: skipTask.skip_reason },
        `skipped: ${skipTask.skip_reason}`);
      card.appendChild(sr);
    }
    const errTask = tasks.find((t) => t.error);
    if (errTask) {
      const er = el("div", { class: "skip-reason", title: errTask.error, style: "color:var(--danger)" },
        `error: ${errTask.error}`);
      card.appendChild(er);
    }

    if (tasks.length > 1) {
      const parts = el("div", { class: "partitions" });
      for (const t of tasks.slice(0, 12)) {
        const row = el("div", { class: "partition", title: t.skip_reason || t.error || t.task_id },
          el("span", { class: "p-name mono" }, t.partition),
          taskStateChip(t.state));
        parts.appendChild(row);
      }
      if (tasks.length > 12) {
        parts.appendChild(el("div", { class: "partition muted small" }, `+${tasks.length - 12} more`));
      }
      card.appendChild(parts);
    }

    if (nid === "G02" && currentRun && currentRun.state === "waiting_approval") {
      card.appendChild(el("div", { class: "mt8" },
        el("a", { class: "btn small primary", href: "#/reports" }, "Review & release")));
    }
    return card;
  }

  function aggregateState(tasks) {
    if (!tasks.length) return "pending";
    const states = new Set(tasks.map((t) => t.state));
    if (tasks.every((t) => t.state === "succeeded" || t.state === "skipped")) return "succeeded";
    if (states.has("failed")) return "failed";
    if (states.has("running") || states.has("leased")) return "running";
    if (states.has("retry_scheduled")) return "retry_scheduled";
    if (tasks.every((t) => t.state === "cancelled")) return "cancelled";
    if (states.has("skipped")) return "skipped";
    return "pending";
  }

  function aggregateChip(tasks) {
    const agg = aggregateState(tasks);
    if (agg === "succeeded" && tasks.some((t) => t.state === "skipped")) {
      return genericChip("done (some skipped)", "ok", "check");
    }
    return taskStateChip(agg === "succeeded" ? "succeeded" : agg);
  }

  function runStateChipInto(host, state) {
    host.replaceChildren(runStateChip(state, { outline: false }));
    const big = host.firstChild;
    if (big) big.style.fontSize = "13.5px";
  }

  /* ---- coverage panel ---- */
  function renderCoverage(run) {
    const card = coverageCard;
    const bits = [el("h2", {}, icon("connectors"), "Coverage")];
    bits.push(el("p", { class: "card-sub" }, "Per-source snapshot completeness. Partial collection is disclosed, never hidden."));
    if (!run.coverage.length) {
      bits.push(el("div", { class: "empty-state", style: "padding:16px" },
        el("h3", {}, "No snapshots yet"),
        el("p", { class: "small" }, "Coverage appears when collection partitions start producing snapshots.")));
    }
    for (const snap of run.coverage) {
      const partial = snap.state === "partial";
      const box = el("div", { class: "coverage-src" });
      const headRow = el("div", { class: "src-head" },
        el("span", { class: "src-name mono" }, snap.source),
        snapshotChip(snap.state));
      box.appendChild(headRow);
      box.appendChild(meterBar(snap.completeness, { tone: partial ? "warn" : "" }));
      const counts = el("div", { class: "counts" },
        `${snap.seen ?? "?"} seen / ${snap.expected ?? "?"} expected`,
        snap.completeness === null || snap.completeness === undefined
          ? "" : ` \u00B7 completeness ${Math.round(snap.completeness * 100)}%`);
      box.appendChild(counts);
      const errs = snap.page_errors || [];
      if (errs.length) {
        box.appendChild(el("span", { class: "chip bad", style: "margin-top:6px" },
          icon("alert", 12), `${errs.length} page error${errs.length > 1 ? "s" : ""}`));
        const ul = el("ul", { class: "page-errors" });
        for (const e of errs.slice(0, 6)) ul.appendChild(el("li", {}, describe(e)));
        box.appendChild(ul);
      }
      bits.push(box);
    }
    card.replaceChildren(...bits);
  }

  function snapshotChip(state) {
    if (state === "complete") return genericChip("COMPLETE", "ok", "check");
    if (state === "partial") return genericChip("PARTIAL", "warn", "alert");
    if (state === "invalid") return genericChip("INVALID", "bad", "x");
    if (state === "pending") return genericChip("PENDING", "neutral", "clock");
    return genericChip((state || "unknown").toUpperCase(), "warn", "question");
  }

  function describe(e) {
    if (typeof e === "string") return e;
    if (e && typeof e === "object") {
      return [e.page, e.error, e.reason, e.message].filter(Boolean).join(" - ") || JSON.stringify(e);
    }
    return String(e);
  }

  function renderInfo(run) {
    const infoBits = [
      el("h2", {}, icon("settings"), "Run details"),
      el("div", { class: "kv", style: "margin-top:8px" },
        el("div", { class: "k" }, "Revision"), el("div", { class: "v mono" }, String(run.revision)),
        el("div", { class: "k" }, "Created"), el("div", { class: "v" }, fmtDateTime(run.created_at)),
        el("div", { class: "k" }, "Budget"), el("div", { class: "v mono small" },
          JSON.stringify(run.budget || {})),
        el("div", { class: "k" }, "Engine"), el("div", { class: "v mono small" },
          (run.versions && run.versions.engine) || "-"),
        el("div", { class: "k" }, "Severity policy"), el("div", { class: "v mono small" },
          (run.versions && run.versions.sev_policy) || "-")),
      run.error ? el("div", { class: "form-error", style: "margin-top:10px" }, run.error) : null,
      run.kill_requested ? el("div", { class: "form-error", style: "margin-top:10px" },
        "Kill flag requested - dispatch is denied.") : null,
    ];
    infoCard.replaceChildren(...infoBits.filter(Boolean));
  }

  function renderGate(run) {
    if (run.state === "waiting_approval") {
      gateCallout.classList.remove("hidden");
      gateCallout.replaceChildren(
        icon("clock", 16),
        el("div", {},
          el("strong", {}, "Parked at human gate G02. "),
          el("span", { class: "muted" },
            "The report is drafted and awaits independent review release. Approvals never come from run counters."),
          el("div", { class: "mt8" }, el("a", { class: "btn small primary", href: "#/reports" }, "Open Reports to release"))));
    } else {
      gateCallout.classList.add("hidden");
    }
  }

  /* ---- timeline ---- */
  function appendTimeline(ev) {
    if (timeline.querySelector(".timeline-empty")) timeline.replaceChildren();
    const cls = ev.type.startsWith("task") ? "k-ev-task"
      : ev.type.startsWith("run") ? "k-ev-run"
      : ev.type.startsWith("report") || ev.type.startsWith("severity") || ev.type.startsWith("findings") ? "k-ev-report"
      : ["snapshot.invalid", "check.quarantined", "task.retry_scheduled", "task.cancelled", "task.stale_lease_rejected"].includes(ev.type) ? "k-ev-warn"
      : "";
    timeline.appendChild(el("li", { class: cls },
      el("span", { class: "t mono" }, fmtTime(ev.timestamp)),
      el("span", { class: "seq mono" }, `#${ev.sequence}`),
      el("span", { class: "etype mono" }, ev.type),
      el("span", { class: "esum" }, summarize(ev.type, ev.payload || {}))));
    if (followToggle.checked) timeline.scrollTop = timeline.scrollHeight;
  }

  function summarize(type, p) {
    switch (type) {
      case "run.created": return `run created (mode ${p.mode}, epoch ${p.epoch})`;
      case "run.running": return "dispatch started";
      case "run.settled": return `run settled: ${p.state}`;
      case "run.finalized": return `run finalized: ${p.state}`;
      case "run.failed": return `run failed: ${p.error || "unknown error"}`;
      case "run.killed": {
        const n = (p.outstanding || []).length;
        return `emergency stop by ${p.actor || "operator"}${n ? `; ${n} in-flight task(s) will be reconciled` : ""}`;
      }
      case "run.command": return `${p.command} requested by ${p.actor}`;
      case "run.gate_released": return `gate ${p.node} ${p.ok ? "released" : "skipped"} - ${p.note || ""}`;
      case "run.plan_ready": return `plan ready: sources ${(p.sources || []).join(", ") || "-"}; checks ${(p.checks || []).length} certified`;
      case "run.plan_validated": return "plan validated by deterministic wrapper";
      case "run.coverage": {
        const bits = (p.coverage || []).map((c) => `${c.source} ${c.state}${c.completeness != null ? ` (${Math.round(c.completeness * 100)}%)` : ""}`);
        return bits.length ? `coverage: ${bits.join("; ")}` : "coverage computed";
      }
      case "run.scope_uncertified_checks_excluded":
        return `uncertified checks excluded: ${(p.excluded || []).join(", ")}`;
      case "snapshot.complete":
      case "snapshot.partial":
        return `${p.source}: snapshot ${type === "snapshot.partial" ? "PARTIAL" : "complete"} - ${p.seen}/${p.expected} seen${p.completeness != null ? `, completeness ${Math.round(p.completeness * 100)}%` : ""}${(p.page_errors || []).length ? `, ${p.page_errors.length} page errors` : ""}`;
      case "snapshot.invalid": return `${p.source || "source"}: snapshot invalid`;
      case "check.completed": return `check ${p.check_id}: ${p.results} result(s) recorded`;
      case "check.quarantined": return `check ${p.check_id || (p.result || {}).check_id}: result quarantined - never promoted to findings`;
      case "analysis.paths": return `${p.chains} delegation chain(s) analyzed (bounded)`;
      case "findings.evaluated": return `${p.promoted} finding(s) promoted, ${p.rejected} rejected by verifier`;
      case "severity.evaluated": return `${p.decisions} severity decision(s) by policy ${p.policy_version}`;
      case "report.drafted": return `report ${p.report_id} drafted - awaiting independent review (G02)`;
      case "report.published": return `report ${p.report_id} v${p.version} published (digest ${String(p.digest || "").slice(0, 12)}\u2026)`;
      case "task.state_changed": return `${p.node} \u2192 ${p.to}${p.attempt ? ` (attempt ${p.attempt})` : ""}`;
      case "task.retry_scheduled": return `${p.node} retry scheduled (attempt ${p.attempt}): ${p.error || ""}`;
      case "task.cancelled": return `${p.task_id} cancelled: ${p.why || ""}`;
      case "task.stale_lease_rejected": return `stale lease rejected for ${p.task_id} (holder may not commit)`;
      default: return safeJson(p);
    }
  }

  function safeJson(obj) {
    try { return JSON.stringify(obj); } catch { return "(unserializable payload)"; }
  }

  /* ---- SSE with Last-Event-ID resume (UX16) ---- */
  function connect() {
    if (disposed) return;
    es = new EventSource(`/v1/runs/${encodeURIComponent(runId)}/events?Last-Event-ID=${lastSeq}`);
    es.onopen = () => {
      backoff = 800;
      staleBanner.classList.add("hidden");
    };
    es.onerror = () => {
      es.close();
      es = null;
      if (disposed) return;
      staleBanner.classList.remove("hidden");
      timers.after(backoff, connect);
      backoff = Math.min(backoff * 2, 10000);
    };
    const onEvent = (e) => {
      let data;
      try { data = JSON.parse(e.data); } catch { return; }
      const seq = Number(e.lastEventId || data.sequence || 0);
      if (seq <= lastSeq) return; // duplicate or out-of-order - ignore (UX16)
      lastSeq = seq;
      appendTimeline(data);
      scheduleRefresh();
    };
    for (const type of SSE_TYPES) es.addEventListener(type, onEvent);
    es.addEventListener("resync", () => {
      toast("Event cursor expired - resynchronizing from the server snapshot.", "info", "RESYNC");
      lastSeq = 0;
      timeline.replaceChildren(el("li", {}, el("span", { class: "esum muted" }, "resynchronizing\u2026")));
      refreshData();
    });
    es.addEventListener("poison", onEvent);
  }

  /* ---- boot ---- */
  await refreshData();
  connect();

  return function teardown() {
    disposed = true;
    clearTimeout(refreshTimer);
    timers.clearAll();
    if (es) { es.close(); es = null; }
  };
}
