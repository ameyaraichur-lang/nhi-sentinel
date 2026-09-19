/* views/findings.js - UI09 triage with severity/assurance/lifecycle facets
   (client-side filter) and an evidence-led detail drawer: facts table,
   severity rationale, evidence refs, lifecycle actions with If-Match + reason,
   "Request retest" (PS15: closure requires a fresh complete retest) and the
   AT30/DC20 risk-exception flow ("Request risk exception" for analyst+;
   accepted findings show a "Risk accepted until <date>" exception chip). */
import {
  el, get, patch, post, icon, sevChip, genericChip, runStateChip, fmtDateTime,
  canMutate, toast, toastError, formDialog, errorState, loadingState,
  emptyState, table, kvTable, shortId,
} from "../core.js";

const SEVERITIES = ["critical", "high", "medium", "low", "informational", "undetermined"];
const ASSURANCES = ["config_supported", "test_supported", "inconclusive", "contradicted"];
const LIFECYCLE = ["open", "triaged", "in_progress", "accepted", "reopened"];

export async function viewFindings(container, params, query) {
  let all = [];
  let total = 0;
  const facets = {
    severity: query.get("severity") || "",
    assurance: "",
    status: "",
    q: "",
  };

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Findings triage"),
      el("p", {}, "Evidence-led findings from evaluated runs. Select a finding for facts, severity rationale and lifecycle actions.")));
  container.appendChild(head);

  const facetBar = el("div", { class: "facets" });
  const tableHost = el("div", {});
  container.appendChild(facetBar);
  container.appendChild(tableHost);

  container.appendChild(loadingState("Loading findings\u2026"));
  try {
    // pull a bounded page set for client-side faceting
    let offset = 0;
    for (let i = 0; i < 5; i++) {
      const page = await get(`/v1/findings?limit=100&offset=${offset}`);
      total = page.total || 0;
      all = all.concat(page.items || []);
      if (all.length >= total || !(page.items || []).length) break;
      offset += 100;
    }
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewFindings(container, params, query)));
    return null;
  }
  container.replaceChildren(head, facetBar, tableHost);

  function buildFacets() {
    facetBar.replaceChildren();
    const group = (label, key, values) => {
      const g = el("div", { class: "facet-group" }, el("span", { class: "label" }, label));
      const mk = (v, text) => {
        const b = el("button", { class: `facet${facets[key] === v ? " on" : ""}` }, text);
        b.addEventListener("click", () => { facets[key] = facets[key] === v ? "" : v; render(); });
        return b;
      };
      g.appendChild(mk("", "All"));
      for (const v of values) {
        g.appendChild(mk(v, v.replace("_", " ")));
      }
      return g;
    };
    facetBar.appendChild(group("Severity:", "severity", SEVERITIES));
    facetBar.appendChild(group("Assurance:", "assurance", ASSURANCES));
    facetBar.appendChild(group("Lifecycle:", "status", LIFECYCLE));
    const search = el("input", {
      type: "text", placeholder: "Search title, check, target\u2026", value: facets.q,
      style: "width:220px", "aria-label": "Search findings",
    });
    search.addEventListener("input", () => { facets.q = search.value; render(); });
    facetBar.appendChild(search);
    const count = el("span", { class: "muted small" });
    facetBar.appendChild(count);
    facetBar._count = count;
  }

  function filtered() {
    const q = facets.q.trim().toLowerCase();
    return all.filter((f) =>
      (!facets.severity || f.severity === facets.severity)
      && (!facets.assurance || f.assurance === facets.assurance)
      && (!facets.status || f.workflow_status === facets.status)
      && (!q || `${f.title} ${f.check_id} ${f.target_key}`.toLowerCase().includes(q)));
  }

  function render() {
    buildFacets();
    const items = filtered().sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, undetermined: 5 };
      return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
    });
    facetBar._count.textContent = `${items.length} of ${all.length} findings (tenant total ${total})`;

    if (!all.length) {
      tableHost.replaceChildren(emptyState({
        glyph: "\u2713",
        title: "No findings yet",
        message: "Findings appear here after a run's checks are evaluated. An empty list is not a zero-risk statement - check coverage on the run workspace.",
      }));
      return;
    }
    if (!items.length) {
      tableHost.replaceChildren(emptyState({
        glyph: "\u2205", title: "No matches",
        message: "No findings match the selected facet combination.", actions: resetBtn(),
      }));
      return;
    }
    const rows = items.map((f) => {
      const tr = el("tr", { class: "clickable", tabindex: "0", "aria-label": `Open finding ${f.finding_id}` },
        el("td", {}, sevChip(f.severity)),
        el("td", {}, el("strong", {}, f.title)),
        el("td", {}, el("span", { class: "mono small" }, f.check_id)),
        el("td", {}, el("span", { class: "mono small" }, shortId(f.target_key, 22))),
        el("td", {}, genericChip(f.assurance.replace("_", " "), f.assurance === "contradicted" ? "bad" : "info")),
        el("td", {}, genericChip(f.workflow_status.replace("_", " "), f.workflow_status === "open" ? "warn" : "neutral")),
        el("td", { class: "num" }, f.occurrence_count > 1
          ? el("span", { class: "chip neutral", title: "duplicate occurrences grouped" }, icon("dot", 10), `x${f.occurrence_count}`)
          : el("span", { class: "muted small" }, "1")),
        el("td", { class: "small muted" }, fmtDateTime(f.updated_at)));
      const open = () => openDrawer(f.finding_id);
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
      return tr;
    });
    tableHost.replaceChildren(table(
      ["Severity", "Title", "Check", "Target", "Assurance", "Lifecycle", "Occurrences", "Updated"],
      rows));
  }

  function resetBtn() {
    const b = el("button", { class: "btn small" }, "Clear facets");
    b.addEventListener("click", () => { facets.severity = ""; facets.assurance = ""; facets.status = ""; facets.q = ""; render(); });
    return b;
  }

  /* ---- detail drawer ---- */
  async function openDrawer(findingId) {
    let f;
    try {
      f = await get(`/v1/findings/${encodeURIComponent(findingId)}`);
    } catch (err) {
      toastError(err);
      return;
    }
    const body = el("div", { class: "stack", style: "gap:14px" });

    body.appendChild(el("div", { class: "rowflex" },
      sevChip(f.severity),
      genericChip(f.assurance.replace("_", " "), "info"),
      genericChip(f.workflow_status.replace("_", " "), f.workflow_status === "open" ? "warn" : "neutral"),
      f.occurrence_count > 1 ? genericChip(`x${f.occurrence_count} occurrences`, "neutral", "dot") : null));

    // AT30/DC20 risk-exception display (AT30): an accepted finding links its
    // exception id and expiry. The expiry lookup is best-effort.
    if (f.exception_id || f.workflow_status === "accepted") {
      const exceptionSlot = el("div", { class: "rowflex" });
      body.appendChild(exceptionSlot);
      fillExceptionChip(exceptionSlot, f);
    }

    body.appendChild(el("p", { class: "muted small" }, f.summary));

    body.appendChild(el("span", { class: "label" }, "Observed facts (severity inputs)"));
    const facts = Object.entries(f.facts || {});
    if (facts.length) {
      body.appendChild(kvTable(facts.map(([k, v]) => [k,
        typeof v === "object" ? JSON.stringify(v) : String(v)])));
    } else {
      body.appendChild(el("p", { class: "muted small" }, "No facts recorded."));
    }

    body.appendChild(el("span", { class: "label" }, "Severity rationale"));
    body.appendChild(el("p", { class: "small", style: "margin-top:0" },
      f.severity_rationale || "Pending policy evaluation (N12)."));

    body.appendChild(el("span", { class: "label" }, "Evidence"));
    const refs = el("div", { class: "claim-refs", style: "margin-top:4px" });
    if (!(f.evidence_refs || []).length) {
      refs.appendChild(el("span", { class: "muted small" }, "No evidence references."));
    }
    for (const ref of f.evidence_refs || []) {
      refs.appendChild(el("a", { class: "chip info", href: `#/evidence/${encodeURIComponent(ref)}` },
        icon("link", 12), ref));
    }
    body.appendChild(refs);

    if ((f.history || []).length) {
      body.appendChild(el("span", { class: "label" }, "Check history"));
      const rows = f.history.map((h) => el("tr", {},
        el("td", { class: "small" }, fmtDateTime(h.observed_at)),
        el("td", {}, genericChip(h.status, h.status === "pass" ? "ok" : h.status === "fail" ? "bad" : "warn")),
        el("td", {}, el("a", { class: "mono small", href: `#/runs/${encodeURIComponent(h.run_id)}` }, shortId(h.run_id, 18)))));
      body.appendChild(table(["Observed", "Result", "Run"], rows));
    }

    // Lifecycle actions
    const actions = el("div", { class: "card", style: "padding:12px" });
    actions.appendChild(el("h3", {}, icon("settings", 14), "Lifecycle actions"));
    if (!canMutate("finding:update")) {
      actions.appendChild(el("p", { class: "muted small", style: "margin:6px 0 0" },
        "Lifecycle updates require the analyst role (finding:update capability)."));
    } else {
      const statusSel = el("select", { style: "max-width:200px", "aria-label": "New lifecycle status" },
        LIFECYCLE.map((s) => el("option", { value: s, selected: s === f.workflow_status },
          s.replace("_", " "))));
      const saveBtn = el("button", { class: "btn small primary" }, "Save status");
      saveBtn.addEventListener("click", () => {
        formDialog({
          title: "Update finding lifecycle",
          message: "Status changes are optimistic-revision guarded; resolution is blocked until a fresh retest (PS15).",
          fields: [{ name: "reason", label: "Reason (required)", type: "textarea", required: true, min: 3 }],
          submitLabel: "Save",
          onSubmit: async (values) => {
            await patch(`/v1/findings/${encodeURIComponent(f.finding_id)}`,
              { workflow_status: statusSel.value, reason: values.reason },
              { ifMatch: f.revision });
            toast("Finding updated.", "success", "FINDING_PATCH");
            render(); // authoritative refetch of the list state
            openDrawer(f.finding_id);
            return true;
          },
        }).catch(toastError);
      });
      const row = el("div", { class: "rowflex" }, statusSel, saveBtn);
      actions.appendChild(row);
      if (f.workflow_status === "resolved") {
        actions.appendChild(el("p", { class: "small muted", style: "margin:8px 0 0" },
          "Resolved findings stay resolved only while retest evidence is fresh."));
      }
    }
    if (canMutate("finding:update")) {
      if (f.workflow_status !== "accepted") {
        const exceptionBtn = el("button", { class: "btn small", style: "margin-top:8px" },
          icon("clock", 13), "Request risk exception");
        exceptionBtn.addEventListener("click", () => requestExceptionDialog(f, () => {
          render();
          openDrawer(f.finding_id);
        }));
        actions.appendChild(exceptionBtn);
      }
    } else if (f.workflow_status !== "accepted") {
      actions.appendChild(el("p", { class: "muted small", style: "margin:8px 0 0" },
        "Risk exceptions are requested by analysts (finding:update capability) and decided by a separate approver (AT30/DC20)."));
    }
    if (canMutate("finding:retest")) {
      const retestBtn = el("button", { class: "btn small", style: "margin-top:8px" },
        icon("refresh"), "Request retest");
      retestBtn.addEventListener("click", async () => {
        try {
          const out = await post(`/v1/findings/${encodeURIComponent(f.finding_id)}/retests`);
          toast(`Retest run created: ${out.retest_run_id}. Closure requires its fresh evidence.`, "success", "RETEST_CREATED", 9000);
          const link = el("a", { class: "btn small primary", href: `#/runs/${out.retest_run_id}` }, "Open retest run");
          retestBtn.replaceWith(el("span", { class: "rowflex" }, link));
        } catch (err) {
          toastError(err);
        }
      });
      actions.appendChild(retestBtn);
    }
    body.appendChild(actions);

    const overlay = el("div", { class: "drawer-overlay" });
    const drawer = el("aside", { class: "drawer", role: "dialog", "aria-label": `Finding ${f.title}` },
      el("div", { class: "drawer-head" },
        el("h2", {}, f.title),
        el("span", { class: "mono small muted" }, f.finding_id),
        closeBtn()),
      el("div", { class: "drawer-body" }, body));
    function closeBtn() {
      const b = el("button", { class: "btn ghost small", "aria-label": "Close details" }, "\u00D7");
      b.addEventListener("click", closeDrawer);
      return b;
    }
    function closeDrawer() {
      overlay.remove();
      drawer.remove();
      document.removeEventListener("keydown", onKey);
    }
    function onKey(e) { if (e.key === "Escape") closeDrawer(); }
    overlay.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", onKey);
    const root = document.getElementById("drawer-root");
    root.replaceChildren(overlay, drawer);
  }

  render();
  // deep link ?f=<finding id> opens the drawer directly
  const focusId = query.get("f");
  if (focusId) openDrawer(focusId);
  return null;
}

/* ---- AT30/DC20 risk exceptions ---- */

/** Best-effort expiry lookup: prefers a finding field, falls back to the
    exceptions list. Never blocks the drawer - renders without a date on failure. */
async function fillExceptionChip(slot, f) {
  let expiresAt = f.exception_expires_at || null;
  if (!expiresAt && f.exception_id) {
    try {
      const list = await get("/v1/exceptions");
      const match = (list || []).find((x) => x.exception_id === f.exception_id);
      if (match) expiresAt = match.expires_at;
    } catch { /* expiry display is optional */ }
  }
  const label = expiresAt
    ? `risk accepted until ${fmtDateTime(expiresAt)}`
    : "risk accepted";
  const chip = el("a", {
    class: "chip ai", href: "#/exceptions", title: `exception ${f.exception_id || "-"}`,
  }, icon("clock", 12), label);
  slot.replaceChildren(chip);
  slot.appendChild(el("span", { class: "mono small muted" }, f.exception_id || ""));
}

function requestExceptionDialog(f, afterSubmit) {
  formDialog({
    title: "Request risk exception",
    message: "A risk acceptance records who accepted the residual risk, until when, and which compensating controls apply. A separate approver must decide - you cannot accept your own exception (AT30/DC20).",
    fields: [
      {
        name: "justification", label: "Justification (required)", type: "textarea", required: true, min: 10,
        placeholder: "Why is the residual risk acceptable? Reference owner input, exposure, exploitability\u2026",
      },
      {
        name: "compensating_controls", label: "Compensating controls", type: "textarea",
        placeholder: "Controls that reduce the risk while the exception is active (e.g. network isolation, extra monitoring)",
      },
      {
        name: "expiry_days", label: "Expiry (days from today, 30-365)", type: "number",
        required: true,
        hint: "Exceptions expire automatically; the finding reopens to triage at expiry. Default target: 90.",
      },
    ],
    submitLabel: "Submit exception request",
    onSubmit: async (values) => {
      const days = Number(values.expiry_days);
      if (!Number.isInteger(days) || days < 30 || days > 365) {
        throw new Error("Expiry must be a whole number of days between 30 and 365.");
      }
      const out = await post("/v1/exceptions", {
        finding_id: f.finding_id,
        justification: values.justification,
        compensating_controls: values.compensating_controls,
        expiry_days: days,
      });
      toast(`Exception ${out.exception_id} requested (${out.status}) - an approver must decide it in #/exceptions.`, "success", "EXCEPTION_REQUESTED", 9000);
      if (typeof afterSubmit === "function") afterSubmit();
      return true;
    },
  }).catch(toastError);
}
