/* views/agents.js - UI12 agent governance: registry vs observed (shadow badge
   when registered=false), capability chips, sponsor/purpose, suspend/retire
   commands bound to registry_version (operator/admin). */
import {
  el, get, post, icon, genericChip, fmtDateTime, canMutate, toast, toastError,
  formDialog, errorState, loadingState, emptyState, table,
} from "../core.js";

export async function viewAgents(container) {
  container.appendChild(loadingState("Loading agent registry and observed identities\u2026"));
  let data;
  try {
    data = await get("/v1/agents");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewAgents(container)));
    return null;
  }
  container.replaceChildren();

  const items = data.items || [];
  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Agent governance"),
      el("p", {}, "Registry entries versus observed agent identities. A shadow agent is observed but absent from a complete registry - not merely an unknown name.")));
  container.appendChild(head);

  if (!items.length) {
    container.appendChild(emptyState({
      glyph: "\u2699",
      title: "No agents observed",
      message: "No registry entries or observed agent identities yet. Agents appear after a source that publishes an agent registry is collected.",
    }));
    return null;
  }

  const canCommand = canMutate("agent:command");
  const summary = el("div", { class: "rowflex", style: "margin-bottom:12px" },
    genericChip(`${items.filter((a) => a.registered).length} registered`, "ok", "check"),
    genericChip(`${items.filter((a) => !a.registered).length} shadow`, "bad", "alert"),
    canMutate("agent:command") ? null : el("span", { class: "muted small" },
      "Lifecycle commands require operator or tenant admin role."));
  container.appendChild(summary);

  const rows = items.map((a) => {
    const tr = el("tr", {},
      el("td", {},
        el("div", { class: "rowflex", style: "gap:6px" },
          el("span", { class: "mono" }, a.native_id),
          a.shadow ? genericChip("SHADOW", "bad", "alert") : genericChip("registered", "ok", "check"))),
      el("td", {}, a.display_name),
      el("td", {}, a.sponsor || "-"),
      el("td", { class: "small muted", style: "max-width:260px" }, a.purpose || "-"),
      el("td", {}, capabilityChips(a.capabilities)),
      el("td", {}, lifecycleChip(a.lifecycle)),
      el("td", { class: "mono small" }, a.registry_version ?? "-"),
      el("td", { class: "small muted" }, a.expires_at ? fmtDateTime(a.expires_at) : "-"),
      el("td", {}, commandCell(a, canCommand)));
    return tr;
  });

  container.appendChild(table(
    ["Agent", "Display name", "Sponsor", "Purpose", "Capabilities", "Lifecycle", "Registry ver.", "Expires", "Commands"],
    rows));
  container.appendChild(el("p", { class: "small muted", style: "margin-top:10px" },
    data.note || "Suspension revokes leases and child delegation (DC22)."));
  return null;
}

function capabilityChips(caps) {
  const wrap = el("div", { class: "rowflex", style: "gap:4px" });
  const list = Array.isArray(caps) ? caps : Object.keys(caps || {});
  if (!list.length) {
    wrap.appendChild(el("span", { class: "muted small" }, "-"));
  }
  for (const c of list.slice(0, 5)) wrap.appendChild(genericChip(String(c), "neutral"));
  if (list.length > 5) wrap.appendChild(el("span", { class: "muted small" }, `+${list.length - 5}`));
  return wrap;
}

function lifecycleChip(lc) {
  const map = {
    active: ["ok", "check", "active"],
    drafted: ["neutral", "clock", "drafted"],
    approved: ["info", "check", "approved"],
    suspended: ["warn", "pause", "suspended"],
    retired: ["bad", "ban", "retired"],
  };
  const [cls, ic, label] = map[lc] || ["neutral", "question", lc || "unknown"];
  return genericChip(label, cls, ic);
}

function commandCell(a, canCommand) {
  const wrap = el("div", { class: "rowflex", style: "gap:6px" });
  if (!a.registered) {
    wrap.appendChild(el("span", {
      class: "muted small", title: "Observed-but-unregistered agents cannot be commanded; register first.",
    }, "observed only"));
    return wrap;
  }
  if (!canCommand) {
    wrap.appendChild(el("span", { class: "muted small" }, "-"));
    return wrap;
  }
  if (a.lifecycle === "drafted") {
    wrap.appendChild(cmdBtn(a, "approve_activation", "Activate", "check", "primary"));
  }
  if (a.lifecycle !== "suspended" && a.lifecycle !== "retired") {
    wrap.appendChild(cmdBtn(a, "suspend", "Suspend", "pause", "warn"));
  }
  if (a.lifecycle !== "retired") {
    wrap.appendChild(cmdBtn(a, "retire", "Retire", "ban", "danger"));
  }
  return wrap;
}

function cmdBtn(a, command, label, ic, tone) {
  const btn = el("button", { class: `btn small ${tone === "danger" ? "danger" : tone === "primary" ? "primary" : ""}` },
    icon(ic, 13), label);
  btn.addEventListener("click", () => {
    formDialog({
      title: `${label} agent ${a.native_id}`,
      message: command === "suspend"
        ? "Suspension revokes leases and child delegation for this agent (DC22)."
        : command === "retire"
          ? "Retirement is terminal for this registry entry."
          : "Activation grants the declared capabilities to this agent.",
      fields: [{ name: "reason", label: "Reason (required)", type: "textarea", required: true, min: 3 }],
      submitLabel: label,
      danger: command !== "approve_activation",
      onSubmit: async (values) => {
        const out = await post(`/v1/agents/${encodeURIComponent(a.agent_row_id)}/commands`, {
          command, reason: values.reason, registry_version: a.registry_version,
        });
        toast(`Server recorded: lifecycle now "${out.lifecycle}". ${out.note || ""}`, "success", "AGENT_COMMAND");
        viewAgentsInto();
        return true;
      },
    }).catch(toastError);
  });
  return btn;
}

function viewAgentsInto() {
  import("../app.js").then((m) => m.rerender()).catch(() => {});
}
