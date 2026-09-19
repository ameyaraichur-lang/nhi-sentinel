/* views/audit.js - UI20 audit trail table + hash-chain verification badge. */
import {
  el, get, icon, genericChip, fmtDateTime, toast, errorState, loadingState,
  emptyState, table, shortId,
} from "../core.js";

export async function viewAudit(container) {
  container.appendChild(loadingState("Loading audit events\u2026"));
  let verifyState = null;
  let data;
  try {
    data = await get("/v1/audit-events?limit=100");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewAudit(container)));
    return null;
  }
  container.replaceChildren();

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Audit trail"),
      el("p", {}, "Append-only, hash-chained tenant audit. Verify recomputes the chain; any mutation or reorder breaks it.")));
  container.appendChild(head);

  // Verify chain card
  const verifyCard = el("div", { class: "card", style: "margin-bottom:16px" });
  const verifyHost = el("div", { class: "rowflex" });
  verifyCard.appendChild(el("h2", {}, icon("audit"), "Chain integrity"));
  verifyCard.appendChild(verifyHost);
  const btn = el("button", { class: "btn primary" }, icon("check"), "Verify chain");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    verifyHost.replaceChildren(el("span", { class: "muted small" }, "recomputing hash chain\u2026"));
    try {
      const out = await get("/v1/audit-verify");
      renderVerify(out);
    } catch (err) {
      verifyHost.replaceChildren(el("span", { class: "small", style: "color:var(--danger)" },
        `${err.code}: ${err.message}`));
    }
    btn.disabled = false;
  });
  verifyHost.appendChild(el("span", { class: "muted small" },
    "Run verification to recompute every entry hash and the prev-linkage."));
  verifyHost.appendChild(el("span", { style: "flex:1" }));
  verifyHost.appendChild(btn);
  container.appendChild(verifyCard);

  function renderVerify(out) {
    verifyHost.replaceChildren(
      out.valid
        ? genericChip("VALID - chain intact", "ok", "check")
        : genericChip("BROKEN", "bad", "x"),
      el("span", { class: "small muted" }, `${out.entries} entries`),
      out.broken_at ? el("span", { class: "mono small", style: "color:var(--danger)" }, `broken at ${out.broken_at}`) : null,
      el("span", { class: "small muted mono", title: "chain head hash" }, `head ${shortId(out.head, 18)}`),
      el("span", { style: "flex:1" }),
      btn);
    toast(out.valid ? "Audit chain verified: intact." : "Audit chain verification FAILED.", out.valid ? "success" : "error", "AUDIT_VERIFY");
  }

  const items = data.items || [];
  if (!items.length) {
    container.appendChild(emptyState({
      glyph: "\u2261", title: "No audit events", message: "Audit entries appear as actions occur.",
    }));
    return null;
  }

  const rows = items.map((a) => el("tr", {},
    el("td", { class: "small muted mono" }, fmtDateTime(a.at)),
    el("td", {}, el("span", { class: "mono small" }, shortId(a.actor, 20))),
    el("td", {}, el("span", { class: "chip neutral" }, a.action)),
    el("td", {}, el("span", { class: "mono small" }, a.object)),
    el("td", { class: "mono small muted", style: "max-width:220px;overflow-wrap:anywhere" }, JSON.stringify(a.detail))));
  container.appendChild(table(["Time", "Actor", "Action", "Object", "Detail"], rows));
  return null;
}
