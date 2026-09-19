/* views/assistant.js - API24/UX12/VD10 "Ask Sentinel" panel: a global right-side
   drawer over a deterministic, citation-backed explainer endpoint. The assistant
   answers with plain text plus citations and can never execute actions, approve
   anything or mutate state (ai_generated:false, model "deterministic-explainer").
   VD10: the affordance is labelled "AI - deterministic, citation-backed" so the
   AI chip never implies agency. */
import {
  el, clear, icon, post, genericChip, toastError, shortId,
} from "../core.js";

/** Derive object context refs from the current hash route, e.g. a finding
    drawer deep-link becomes {type:"finding", id}. Best effort - the server
    resolves citations itself when no refs are supplied. */
function contextRefs() {
  const path = (location.hash || "").replace(/^#/, "");
  const refs = [];
  let m = path.match(/^\/findings\/([^/?]+)/) || path.match(/^\/findings\?.*?f=([^&]+)/);
  if (m) refs.push({ type: "finding", id: decodeURIComponent(m[1]) });
  m = path.match(/^\/reports\/([^/?]+)/);
  if (m) refs.push({ type: "report", id: decodeURIComponent(m[1]) });
  m = path.match(/^\/runs\/([^/?]+)/);
  if (m) refs.push({ type: "run", id: decodeURIComponent(m[1]) });
  m = path.match(/^\/evidence\/([^/?]+)/);
  if (m) refs.push({ type: "evidence", id: decodeURIComponent(m[1]) });
  return refs;
}

function citationHref(c) {
  const id = encodeURIComponent(c.id);
  switch ((c.type || "").toLowerCase()) {
    case "finding": return `#/findings?f=${id}`;
    case "report": return `#/reports/${id}`;
    case "run": return `#/runs/${id}`;
    case "evidence": return `#/evidence/${id}`;
    default: return "#/overview";
  }
}

export function openAssistantDrawer() {
  const root = document.getElementById("drawer-root");
  const overlay = el("div", { class: "drawer-overlay" });
  const drawer = el("aside", { class: "drawer assistant", role: "dialog", "aria-label": "Ask Sentinel assistant" });

  /* ---- head ---- */
  const closeBtn = el("button", { class: "btn ghost small", "aria-label": "Close assistant" }, "\u00D7");
  drawer.appendChild(el("div", { class: "drawer-head" },
    el("h2", {}, "Ask Sentinel"),
    el("span", { class: "chip ai", title: "VD10: deterministic explainer - not a generative agent" },
      "AI \u00B7 deterministic, citation-backed"),
    closeBtn));

  const body = el("div", { class: "drawer-body assistant-body" });

  /* ---- scope note ---- */
  body.appendChild(el("div", { class: "assistant-note" },
    icon("question", 15),
    el("span", {},
      el("strong", {}, "This assistant explains - it does not act. "),
      el("span", { class: "muted" },
        "It cannot execute runs, approve proposals, accept risks or change settings; every claim links to its evidence."))));

  /* ---- context refs ---- */
  const refs = contextRefs();
  if (refs.length) {
    const row = el("div", { class: "rowflex", style: "gap:6px" },
      el("span", { class: "ref-label" }, "context:"));
    for (const r of refs) {
      row.appendChild(genericChip(`${r.type}: ${shortId(r.id, 18)}`, "info"));
    }
    body.appendChild(row);
  }

  /* ---- question form ---- */
  const question = el("textarea", {
    placeholder: "e.g. Why is finding FND-.. high severity? Which evidence supports the posture score?",
    rows: 3, "aria-label": "Your question",
  });
  const askBtn = el("button", { class: "btn ai", type: "submit" }, icon("question", 14), "Ask");
  const askRow = el("div", { class: "rowflex", style: "align-items:flex-start" }, question, askBtn);
  const form = el("form", { class: "assistant-form" }, askRow);
  body.appendChild(form);

  /* ---- answer area ---- */
  const answerArea = el("div", { class: "stack", style: "gap:10px" });
  body.appendChild(answerArea);
  body.appendChild(buildFoot(null));

  function buildFoot(out) {
    // Model + limitations footer (VD10 honesty markers).
    const foot = el("div", { class: "assistant-foot" });
    foot.appendChild(el("div", { class: "mono small" },
      `model: ${(out && out.model) || "deterministic-explainer/1.0"} \u00B7 ai_generated: ${String(Boolean(out && out.ai_generated))}`));
    const lims = (out && out.limitations) || [];
    if (lims.length) {
      const ul = el("ul", { class: "small muted", style: "margin:6px 0 0;padding-left:18px" });
      for (const l of lims) ul.appendChild(el("li", {}, l));
      foot.appendChild(ul);
    }
    return foot;
  }

  function setLoading() {
    clear(answerArea);
    answerArea.appendChild(el("div", { class: "skeleton", role: "status" }, "Consulting the deterministic explainer\u2026"));
  }

  function renderAnswer(out) {
    clear(answerArea);
    const card = el("div", { class: "assistant-answer" });
    const pre = el("div", { class: "assistant-answer-text" });
    pre.textContent = out.answer || "(no answer returned)";
    card.appendChild(pre);
    const cites = out.citations || [];
    if (cites.length) {
      const refsRow = el("div", { class: "claim-refs", style: "margin-top:10px" },
        el("span", { class: "ref-label" }, "citations:"));
      for (const c of cites) {
        refsRow.appendChild(el("a", { class: "chip info", href: citationHref(c), title: c.label || c.id },
          icon("link", 12), c.label || `${c.type} ${shortId(c.id, 14)}`));
      }
      card.appendChild(refsRow);
    } else {
      card.appendChild(el("p", { class: "small muted", style: "margin:8px 0 0" }, "No citations returned."));
    }
    answerArea.appendChild(card);
    body.replaceChild(buildFoot(out), body.lastChild);
  }

  function renderError(err) {
    clear(answerArea);
    answerArea.appendChild(el("div", { class: "form-error", style: "margin:0" },
      `${err.code || "ERROR"}: ${err.message || String(err)}`));
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = question.value.trim();
    if (!q) { question.focus(); return; }
    askBtn.disabled = true;
    setLoading();
    try {
      const out = await post("/v1/assistant/queries", {
        question: q,
        object_refs: refs,
      });
      renderAnswer(out);
    } catch (err) {
      renderError(err);
      toastError(err);
    } finally {
      askBtn.disabled = false;
    }
  });

  function onKey(e) { if (e.key === "Escape") close(); }
  function close() {
    overlay.remove();
    drawer.remove();
    document.removeEventListener("keydown", onKey);
  }
  closeBtn.addEventListener("click", close);
  overlay.addEventListener("click", close);
  document.addEventListener("keydown", onKey);

  drawer.appendChild(body);
  root.replaceChildren(overlay, drawer);
  question.focus();
  return { close };
}
