/* views/reports.js - UI14 reports: status chips, grounding summary, draft detail
   with read-only sections, claims with evidence links, limitations panel, score
   card, reviewer release flow (G02: re-auth + review record; blocked while
   unsupported claims exist; author cannot self-release), per-claim feedback and
   the AT32 export flow for released reports (CSV/JSON jobs with sha256 +
   finding_count receipt; CSV formula sanitization happens server-side, SC21). */
import {
  el, get, post, icon, genericChip, fmtDateTime, canMutate, toast, toastError,
  formDialog, errorState, loadingState, emptyState, shortId, session,
} from "../core.js";
import { scorePanel } from "./score.js";

const SECTION_TITLES = {
  executive_summary: "Executive summary",
  posture_score: "Posture score claims",
  scope_and_coverage: "Scope and coverage",
  findings_detail: "Findings detail",
};

export async function viewReports(container) {
  container.appendChild(loadingState("Loading reports\u2026"));
  let reports;
  try {
    reports = await get("/v1/reports");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewReports(container)));
    return null;
  }
  container.replaceChildren();

  container.appendChild(el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Reports"),
      el("p", {}, "Released reports are separate from drafts. A reviewer other than the author releases a draft at gate G02; grounding defects block release."))));

  if (!reports.length) {
    container.appendChild(emptyState({
      glyph: "\u2261", title: "No reports yet",
      message: "A draft report is assembled automatically when a run reaches the reporting stage.",
    }));
    return null;
  }

  const drafts = reports.filter((r) => r.status !== "released");
  const released = reports.filter((r) => r.status === "released");

  const card = el("div", { class: "card" });
  card.appendChild(el("h2", {}, icon("reports"), "All reports"));
  const rows = reports.map((r) => {
    const unsupported = (r.grounding && r.grounding.unsupported) || 0;
    const tr = el("tr", { class: "clickable", tabindex: "0" },
      el("td", {}, el("span", { class: "mono" }, r.report_id)),
      el("td", {}, el("a", { class: "mono small", href: `#/runs/${encodeURIComponent(r.run_id)}` }, shortId(r.run_id, 20))),
      el("td", {}, statusChip(r.status)),
      el("td", {}, `v${r.version}`),
      el("td", {}, groundingCell(r.grounding)),
      el("td", { class: "small muted" }, r.released_at ? fmtDateTime(r.released_at) : "-"));
    tr.addEventListener("click", (e) => {
      if (e.target.closest("a")) return; // let inner links work
      location.hash = `#/reports/${encodeURIComponent(r.report_id)}`;
    });
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") { location.hash = `#/reports/${encodeURIComponent(r.report_id)}`; } });
    return tr;
  });
  const wrap = el("div", { class: "table-wrap" });
  const thead = el("thead", {}, el("tr", {},
    ...["Report", "Run", "Status", "Version", "Grounding", "Released"].map((h) => el("th", {}, h))));
  const tbody = el("tbody", {});
  for (const r of rows) tbody.appendChild(r);
  wrap.appendChild(el("table", { class: "data" }, thead, tbody));
  card.appendChild(wrap);
  container.appendChild(card);
  return null;
}

function groundingCell(g) {
  if (!g) return el("span", { class: "muted small" }, "-");
  const unsupported = g.unsupported || 0;
  return el("span", { class: "rowflex", style: "gap:6px" },
    el("span", { class: "muted small" }, `${g.claims_total ?? "?"} claims`),
    unsupported > 0
      ? genericChip(`${unsupported} unsupported`, "bad", "alert")
      : genericChip("all supported", "ok", "check"));
}

function statusChip(status) {
  const map = {
    draft: ["warn", "clock", "draft"],
    in_review: ["info", "clock", "in review"],
    released: ["ok", "check", "released"],
    superseded: ["neutral", "ban", "superseded"],
  };
  const [cls, ic, label] = map[status] || ["neutral", "question", status];
  return genericChip(label, cls, ic);
}

/* ------------------------------------------------------------ detail -------- */

export async function viewReportDetail(container, params) {
  const id = params[0];
  container.appendChild(loadingState("Loading report\u2026"));
  let r;
  try {
    r = await get(`/v1/reports/${encodeURIComponent(id)}`);
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewReportDetail(container, params)));
    return null;
  }
  container.replaceChildren();

  container.appendChild(el("div", { class: "crumbs" },
    el("a", { href: "#/reports" }, "Reports"), " / ",
    el("span", { class: "mono" }, r.report_id)));

  container.appendChild(el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, (r.content && r.content.title) || "Assessment report"),
      el("p", { class: "mono small" },
        `${r.report_id} \u00B7 v${r.version} \u00B7 template ${(r.content && r.content.template) || "-"} \u00B7 run `,
        el("a", { href: `#/runs/${encodeURIComponent(r.run_id)}` }, shortId(r.run_id, 20)),
        r.released_at ? ` \u00B7 released ${fmtDateTime(r.released_at)}` : "")),
    statusChip(r.status)));

  const grounding = r.grounding || {};
  const unsupported = grounding.unsupported || [];

  // Grounding summary banner (AT13)
  const groundBanner = el("div", {
    class: `card ${unsupported.length ? "" : ""}`, style: "padding:12px 16px",
  });
  groundBanner.appendChild(el("div", { class: "rowflex" },
    unsupported.length
      ? genericChip(`grounding: ${unsupported.length} unsupported claim(s) - release blocked`, "bad", "alert")
      : genericChip(`grounding: ${grounding.claims_supported ?? "?"}/${grounding.claims_total ?? "?"} claims supported`, "ok", "check"),
    el("span", { class: "small muted" }, `validator ${grounding.validator || "-"}`)));
  if (unsupported.length) {
    const ul = el("ul", { class: "page-errors" });
    for (const u of unsupported.slice(0, 8)) {
      ul.appendChild(el("li", { class: "mono small" },
        `${u.claim_id}: bad evidence ${JSON.stringify(u.bad_evidence || [])} bad findings ${JSON.stringify(u.bad_findings || [])}`));
    }
    groundBanner.appendChild(ul);
  }
  container.appendChild(groundBanner);

  const layout = el("div", { class: "run-layout", style: "margin-top:16px" });
  const mainCol = el("div", { class: "stack" });
  const sideCol = el("div", { class: "stack" });
  layout.appendChild(mainCol);
  layout.appendChild(sideCol);
  container.appendChild(layout);

  // Sections: claims grouped read-only
  const bySection = new Map();
  for (const claim of r.claims || []) {
    if (!bySection.has(claim.section)) bySection.set(claim.section, []);
    bySection.get(claim.section).push(claim);
  }
  for (const [section, claims] of bySection) {
    const card = el("div", { class: "card section-claims" },
      el("h2", {}, icon("reports"), SECTION_TITLES[section] || section),
      el("p", { class: "card-sub" }, "Read-only rendering - the released report is immutable; flag issues via claim feedback."));
    for (const claim of claims) {
      card.appendChild(claimRow(r, claim));
    }
    mainCol.appendChild(card);
  }

  // Limitations panel
  const lim = el("div", { class: "card" });
  lim.appendChild(el("h2", {}, icon("alert"), "Limitations"));
  const list = el("ul", { style: "margin:0;padding-left:18px" });
  for (const l of r.limitations || []) list.appendChild(el("li", { class: "small", style: "margin-bottom:6px" }, l));
  lim.appendChild(list);
  mainCol.appendChild(lim);

  // Score card (side)
  const scoreCard = el("div", { class: "card" });
  scoreCard.appendChild(el("h2", {}, icon("overview"), "Posture score"));
  const ps = r.content && r.content.posture_score;
  scoreCard.appendChild(el("div", { class: "mt8" }, scorePanel(ps || null, { compact: true })));
  sideCol.appendChild(scoreCard);

  // Findings index (side)
  const fi = el("div", { class: "card" });
  fi.appendChild(el("h2", {}, icon("findings"), "Findings in this report"));
  for (const f of (r.content && r.content.findings) || []) {
    fi.appendChild(el("div", { class: "rowflex", style: "gap:6px;margin-bottom:6px" },
      genericChip(f.severity, f.severity === "critical" || f.severity === "high" ? "bad" : "warn"),
      el("span", { class: "small" }, `${f.check_id} - ${f.title}`)));
  }
  if (!((r.content && r.content.findings) || []).length) {
    fi.appendChild(el("p", { class: "muted small" }, "No findings included."));
  }
  sideCol.appendChild(fi);

  // Release panel / release receipt
  if (r.status === "released") {
    sideCol.appendChild(el("div", { class: "card" },
      el("h2", {}, icon("check"), "Release receipt"),
      el("div", { class: "kv", style: "margin-top:8px" },
        el("div", { class: "k" }, "Reviewer"), el("div", { class: "v mono small" }, r.reviewer_id || "-"),
        el("div", { class: "k" }, "Review record"), el("div", { class: "v small" }, r.review_record || "-"),
        el("div", { class: "k" }, "Signature"), el("div", { class: "v mono small", style: "overflow-wrap:anywhere" }, r.signature || "-")),
      el("p", { class: "small muted", style: "margin-top:8px" },
        "Signature binds the exact revision digest; claim feedback never mutates a released report (UX23).")));
    sideCol.appendChild(exportPanel(r));
  } else {
    sideCol.appendChild(releasePanel(r, unsupported));
  }
  return null;
}

/* ---- AT32 exports (released reports only) ---- */

function exportPanel(r) {
  const panel = el("div", { class: "card" });
  panel.appendChild(el("h2", {}, icon("external"), "Export"));
  panel.appendChild(el("p", { class: "card-sub" },
    "Export jobs are built from the released, signed revision only - drafts are rejected with EXPORT_NOT_RELEASED (AT32). CSV formula injection is sanitized server-side (SC21)."));

  const result = el("div", { class: "stack", style: "gap:8px" });
  const busy = new Set();

  async function runExport(format) {
    if (busy.has(format)) return;
    busy.add(format);
    const jobCard = el("div", { class: "stack", style: "gap:4px", dataset: { format } },
      el("span", { class: "muted small" }, `Creating ${format.toUpperCase()} export\u2026`));
    // Replace any previous result for this format; keep the other format's result.
    result.replaceChildren(...[...result.children].filter((c) => c.dataset.format !== format), jobCard);
    try {
      const started = await post("/v1/exports", { report_id: r.report_id, format });
      const job = await get(`/v1/exports/${encodeURIComponent(started.export_job_id)}`);
      jobCard.replaceChildren(
        el("div", { class: "rowflex" },
          genericChip(`${job.status} \u00B7 ${job.format.toUpperCase()}`, job.status === "complete" ? "ok" : "warn", job.status === "complete" ? "check" : "clock"),
          el("span", { class: "mono small muted", title: job.export_job_id }, shortId(job.export_job_id, 16))),
        el("div", { class: "kv", style: "font-size:12.5px" },
          el("div", { class: "k" }, "SHA-256"), el("div", { class: "v mono", style: "overflow-wrap:anywhere" }, job.sha256 || "-"),
          el("div", { class: "k" }, "Findings"), el("div", { class: "v" }, String(job.finding_count ?? "-"))),
        job.download_url
          ? el("a", { class: "btn small primary", href: job.download_url }, icon("external", 13),
            `Download ${job.format.toUpperCase()}`)
          : el("span", { class: "muted small" }, "No download URL returned by the server."));
    } catch (err) {
      jobCard.replaceChildren(el("div", { class: "form-error", style: "margin:0" },
        `${err.code || "ERROR"}: ${err.message || String(err)}`));
    } finally {
      busy.delete(format);
    }
  }

  const csvBtn = el("button", { class: "btn small" }, icon("reports", 13), "Export CSV");
  const jsonBtn = el("button", { class: "btn small" }, icon("reports", 13), "Export JSON");
  csvBtn.addEventListener("click", () => runExport("csv"));
  jsonBtn.addEventListener("click", () => runExport("json"));
  panel.appendChild(el("div", { class: "btn-row", style: "margin-bottom:10px" }, csvBtn, jsonBtn));
  panel.appendChild(result);
  return panel;
}

function claimRow(r, claim) {
  const row = el("div", { class: "claim-row" });
  row.appendChild(el("span", { class: "claim-id mono" }, claim.claim_id));
  const body = el("div", { class: "claim-body" });
  body.appendChild(el("div", { class: "claim-text" }, claim.text));
  const refs = el("div", { class: "claim-refs" });
  if ((claim.evidence_refs || []).length) {
    refs.appendChild(el("span", { class: "ref-label" }, "evidence:"));
    for (const ref of claim.evidence_refs) {
      refs.appendChild(el("a", { class: "chip info", href: `#/evidence/${encodeURIComponent(ref)}` },
        icon("link", 12), ref));
    }
  } else {
    refs.appendChild(el("span", { class: "ref-label" }, "no evidence refs on this claim"));
  }
  for (const fid of claim.finding_ids || []) {
    refs.appendChild(el("a", { class: "chip neutral", href: `#/findings?f=${encodeURIComponent(fid)}` },
      icon("findings", 12), "finding"));
  }
  body.appendChild(refs);
  const fb = el("button", { class: "btn ghost small", style: "margin-top:4px" },
    icon("alert", 12), "Flag claim");
  fb.addEventListener("click", () => claimFeedback(r, claim));
  body.appendChild(fb);
  row.appendChild(body);
  return row;
}

function claimFeedback(r, claim) {
  formDialog({
    title: `Flag claim ${claim.claim_id}`,
    message: "Flagging creates an evidence review task. The report is never silently edited - a released report stays immutable and a correction creates a revision (UX23).",
    fields: [
      { name: "reference", label: "What is wrong? (reference)", type: "text", required: true, min: 3, placeholder: "evidence ref, count mismatch, wording\u2026" },
      { name: "comment", label: "Comment (required)", type: "textarea", required: true, min: 3 },
    ],
    submitLabel: "Submit feedback",
    onSubmit: async (values) => {
      const q = new URLSearchParams({
        claim_id: claim.claim_id, reference: values.reference, comment: values.comment,
      });
      const out = await post(`/v1/reports/${encodeURIComponent(r.report_id)}/claim-feedback?${q}`, {});
      toast(out.note || "Review task created; the report text is unchanged.", "success", "CLAIM_FEEDBACK");
      return true;
    },
  }).catch(toastError);
}

function releasePanel(r, unsupported) {
  const panel = el("div", { class: "card release-panel" });
  panel.appendChild(el("h2", {}, icon("approvals"), "Release (gate G02)"));

  const canRelease = canMutate("report:release");
  const isAuthor = session && session.me && session.me.user_id === r.created_by;

  const notes = el("div", { class: "stack", style: "gap:6px;margin:8px 0" });
  if (!canRelease) {
    notes.appendChild(el("p", { class: "small muted", style: "margin:0" },
      "Your role lacks report:release - release is performed by a reviewer."));
  }
  if (isAuthor) {
    notes.appendChild(el("p", { class: "small", style: "margin:0;color:var(--warn)" },
      "You authored this report. The server enforces independent review: the author cannot release their own report (SC05)."));
  }
  if (unsupported.length) {
    notes.appendChild(el("p", { class: "small", style: "margin:0;color:var(--danger)" },
      `Release is disabled while grounding reports ${unsupported.length} unsupported claim(s) (AT13). Resolve the evidence citations first.`));
  }
  panel.appendChild(notes);

  const disabled = !canRelease || isAuthor || unsupported.length > 0;
  const btn = el("button", { class: "btn primary", disabled }, icon("check"), "Submit for release\u2026");
  if (!disabled) {
    btn.addEventListener("click", () => {
      formDialog({
        title: "Submit for release",
        message: "The reviewer signs the exact revision. A digest mismatch (STALE_REVISION) means the draft changed - review the current version.",
        fields: [
          { name: "review_record", label: "Review record (required)", type: "textarea", required: true, min: 10, placeholder: "What was verified during review?" },
          { name: "reauth_password", label: "Re-enter your password to authorize", type: "password", required: true, autocomplete: "current-password" },
        ],
        submitLabel: "Release report",
        note: el("div", { class: "reauth-note" },
          icon("key", 15),
          el("span", {}, el("strong", {}, "Re-enter your password to authorize this release. "),
            el("span", { class: "muted" }, "Re-auth failure returns REAUTH_FAILED; the signature binds the revision digest."))),
        onSubmit: async (values) => {
          const out = await post(`/v1/reports/${encodeURIComponent(r.report_id)}/release`, {
            revision_digest: r.revision_digest,
            review_record: values.review_record,
            reauth_password: values.reauth_password,
          });
          toast(`Report released. ${out.note || ""} The G02 gate completes and the run publishes.`, "success", "REPORT_RELEASED", 9000);
          viewReportDetailRerender(r.report_id);
          return true;
        },
      }).catch(toastError);
    });
  }
  panel.appendChild(btn);
  panel.appendChild(el("p", { class: "small muted", style: "margin:8px 0 0" },
    `Bound revision digest: `, el("span", { class: "mono" }, r.revision_digest || "-")));
  return panel;
}

function viewReportDetailRerender(reportId) {
  // Same-hash navigation does not fire hashchange, so re-render explicitly.
  import("../app.js").then((m) => m.rerender()).catch(() => {});
}
