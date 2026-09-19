/* views/connectors.js - UI13 connector health: state, last complete sync,
   capability manifest, read-only preflight (ok/error + page errors).
   Success is never inferred from HTTP 200 alone - the preflight result shows
   paging/normalization outcomes. */
import {
  el, get, post, icon, genericChip, relTime, canMutate, toast, toastError,
  errorState, loadingState, emptyState, table,
} from "../core.js";

export async function viewConnectors(container) {
  container.appendChild(loadingState("Loading connectors\u2026"));
  let connectors;
  try {
    connectors = await get("/v1/connectors");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewConnectors(container)));
    return null;
  }
  container.replaceChildren();

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Connector health"),
      el("p", {}, "Import sources with last complete sync and permission coverage. Preflight is a read-only check against the approved import payload - no live calls.")));
  container.appendChild(head);

  if (!connectors.length) {
    container.appendChild(emptyState({
      glyph: "\u2699", title: "No connectors configured",
      message: "Configure import connectors to begin collecting identity snapshots.",
    }));
    return null;
  }

  const canPreflight = canMutate("connector:preflight");
  const results = new Map(); // connector_id -> result element

  const rows = connectors.map((c) => {
    const resultCell = el("td", { colSpan: 1 });
    results.set(c.connector_id, resultCell);
    const tr = el("tr", {},
      el("td", {}, el("strong", {}, c.name)),
      el("td", {}, el("span", { class: "mono small" }, c.type)),
      el("td", {}, stateChip(c.state, c.enabled)),
      el("td", { class: "small" }, c.last_complete_sync ? relTime(c.last_complete_sync) : "never completed"),
      el("td", {}, capabilityChips(c.capabilities)),
      el("td", {}, preflightBtn(c)),
      resultCell);
    return tr;
  });

  container.appendChild(table(
    ["Connector", "Type", "State", "Last complete sync", "Read capabilities", "Preflight", "Preflight result"],
    rows));

  function stateChip(state, enabled) {
    if (!enabled) return genericChip("disabled", "neutral", "ban");
    const map = {
      complete: ["ok", "check", "complete"],
      partial: ["warn", "alert", "partial"],
      error: ["bad", "x", "error"],
      preflight_failed: ["bad", "x", "preflight failed"],
      pending: ["neutral", "clock", "pending"],
    };
    const [cls, ic, label] = map[state] || ["warn", "question", state || "unknown"];
    return genericChip(label, cls, ic);
  }

  function capabilityChips(caps) {
    const wrap = el("div", { class: "rowflex", style: "gap:4px" });
    for (const c of (caps || []).slice(0, 4)) wrap.appendChild(genericChip(c, "neutral"));
    if ((caps || []).length > 4) wrap.appendChild(el("span", { class: "muted small" }, `+${caps.length - 4}`));
    return wrap;
  }

  function preflightBtn(c) {
    if (!canPreflight) {
      return el("span", { class: "muted small", title: "Requires connector:preflight capability" }, "-");
    }
    const btn = el("button", { class: "btn small" }, icon("refresh", 13), "Run preflight");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const cell = results.get(c.connector_id);
      cell.replaceChildren(el("span", { class: "muted small" }, "running\u2026"));
      try {
        const out = await post(`/v1/connectors/${encodeURIComponent(c.connector_id)}/preflight`);
        renderResult(cell, out);
      } catch (err) {
        cell.replaceChildren(el("div", { class: "form-error", style: "margin:0" },
          `${err.code}: ${err.message}`));
      }
      btn.disabled = false;
    });
    return btn;
  }

  function renderResult(cell, out) {
    const box = el("div", { class: "stack", style: "gap:4px" });
    if (out.ok) {
      box.appendChild(genericChip(`ok - ${out.identities_seen} identities seen`, "ok", "check"));
      if ((out.page_errors || []).length) {
        box.appendChild(genericChip(`${out.page_errors.length} page errors`, "warn", "alert"));
        const ul = el("ul", { class: "page-errors" });
        for (const e of out.page_errors.slice(0, 4)) ul.appendChild(el("li", {}, typeof e === "string" ? e : JSON.stringify(e)));
        box.appendChild(ul);
      } else {
        box.appendChild(el("span", { class: "small muted" }, "no page errors"));
      }
      box.appendChild(el("span", { class: "small muted" }, out.note || ""));
    } else {
      box.appendChild(genericChip("error", "bad", "x"));
      box.appendChild(el("span", { class: "small", style: "color:var(--danger);overflow-wrap:anywhere" }, out.error || "unknown failure"));
    }
    cell.replaceChildren(box);
  }

  return null;
}
