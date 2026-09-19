/* views/evidence.js - evidence artifact inspector (API20): hash, signature
   validity, redaction version, retention state and escaped content preview.
   Content renders as text/JSON only - no HTML, no image loads (VD13). */
import {
  el, get, icon, genericChip, fmtDateTime, errorState, loadingState,
} from "../core.js";

export async function viewEvidence(container, params) {
  const id = params[0];
  container.appendChild(loadingState("Loading evidence artifact\u2026"));
  let art;
  try {
    art = await get(`/v1/evidence/${encodeURIComponent(id)}`);
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewEvidence(container, params)));
    return null;
  }
  container.replaceChildren();

  container.appendChild(el("div", { class: "crumbs" },
    el("a", { href: "#/overview" }, "Overview"), " / evidence"));

  container.appendChild(el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Evidence artifact"),
      el("p", { class: "mono small" }, art.artifact_id))));

  const grid = el("div", { class: "card-grid grid-2" });

  const meta = el("div", { class: "card" },
    el("h2", {}, icon("link"), "Integrity metadata"),
    el("div", { class: "kv", style: "margin-top:8px" },
      el("div", { class: "k" }, "Kind"), el("div", { class: "v mono small" }, art.kind),
      el("div", { class: "k" }, "Producer"), el("div", { class: "v mono small" }, art.producer),
      el("div", { class: "k" }, "SHA-256"), el("div", { class: "v mono small", style: "overflow-wrap:anywhere" }, art.sha256),
      el("div", { class: "k" }, "Signature"), el("div", { class: "v" },
        art.signature_valid
          ? genericChip("signature valid", "ok", "check")
          : genericChip("SIGNATURE INVALID", "bad", "x")),
      el("div", { class: "k" }, "Redaction"), el("div", { class: "v mono small" }, art.redaction_version || "-"),
      el("div", { class: "k" }, "Collected"), el("div", { class: "v" }, art.collected_at ? fmtDateTime(art.collected_at) : "-"),
      el("div", { class: "k" }, "Received"), el("div", { class: "v" }, fmtDateTime(art.received_at)),
      el("div", { class: "k" }, "Retention"), el("div", { class: "v" }, art.retention_state || "-")));
  grid.appendChild(meta);

  const content = el("div", { class: "card" },
    el("h2", {}, icon("reports"), "Content preview"),
    el("p", { class: "card-sub" },
      "Escaped text rendering only. Binary download uses a separate signed short-lived URL outside the pilot boundary."),
    el("pre", { class: "codeblock" }, safeJson(art.content)));
  grid.appendChild(content);

  container.appendChild(grid);
  return null;
}

function safeJson(value) {
  try { return JSON.stringify(value, null, 2); } catch { return "(unserializable content)"; }
}
