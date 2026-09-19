/* views/settings.js - UI16 subset: tenant settings with the emergency kill flag
   (admin toggle with confirm + required reason; the flag blocks new dispatch for
   every run, SC18), the S00 governance section (continuous-monitoring
   subscriptions table with admin enable toggles + cadence, retention policy
   version, legal hold) and the IRREVERSIBLE danger-zone tenant offboarding flow
   (type-to-confirm + reason; revokes access and purges evidence content). */
import {
  el, get, post, patch, icon, genericChip, canMutate, toast, toastError,
  confirmDialog, openModal, session, errorState, loadingState, emptyState,
  ApiError, table, shortId,
} from "../core.js";

export async function viewSettings(container) {
  container.appendChild(loadingState("Loading tenant settings\u2026"));
  let settings;
  try {
    settings = await get("/v1/tenant-settings");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewSettings(container)));
    return null;
  }
  container.replaceChildren();

  container.appendChild(el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Settings"),
      el("p", {}, "Tenant governance. Sensitive changes record a before/after diff with reason and actor in the audit chain."))));

  const grid = el("div", { class: "card-grid grid-2" });

  // Read-only facts
  const facts = el("div", { class: "card" },
    el("h2", {}, icon("settings"), "Tenant"));
  facts.appendChild(el("div", { class: "kv", style: "margin-top:8px" },
    el("div", { class: "k" }, "Tenant ID"), el("div", { class: "v mono small" }, settings.tenant_id),
    el("div", { class: "k" }, "Status"), el("div", { class: "v" },
      genericChip(settings.status || "active", settings.status && settings.status !== "active" ? "bad" : "ok")),
    el("div", { class: "k" }, "Legal hold"), el("div", { class: "v" },
      settings.legal_hold ? genericChip("in effect", "warn", "clock") : genericChip("none", "neutral")),
    el("div", { class: "k" }, "Region (read-only)"), el("div", { class: "v" }, settings.region || "-"),
    el("div", { class: "k" }, "Plan (read-only)"), el("div", { class: "v" }, settings.plan || "-"),
    el("div", { class: "k" }, "Synthetic dataset"), el("div", { class: "v" },
      settings.synthetic ? genericChip("yes - demo tenant", "ai") : genericChip("no", "neutral"))));
  grid.appendChild(facts);

  // Kill flag
  const kill = el("div", { class: "card" });
  kill.appendChild(el("h2", {}, icon("alert"), "Emergency kill flag"));
  kill.appendChild(el("p", { class: "card-sub" },
    "When raised, the flag denies new task dispatch for every run in this tenant (SC18). Already-dispatched work is reconciled by the engine."));
  const stateRow = el("div", { class: "rowflex", style: "margin-bottom:10px" },
    settings.kill_flag
      ? genericChip("RAISED - dispatch blocked", "bad", "ban")
      : genericChip("clear - dispatch allowed", "ok", "check"));
  kill.appendChild(stateRow);

  const isAdmin = canMutate("settings:update");
  if (!isAdmin) {
    kill.appendChild(el("p", { class: "muted small", style: "margin:0" },
      "Only the tenant admin can change this setting (settings:update capability)."));
  } else {
    const toggleBtn = el("button", { class: `btn ${settings.kill_flag ? "" : "danger solid"}` },
      icon(settings.kill_flag ? "check" : "ban"),
      settings.kill_flag ? "Clear kill flag" : "Raise kill flag");
    toggleBtn.addEventListener("click", async () => {
      const raising = !settings.kill_flag;
      try {
        const confirmed = await confirmDialog({
          title: raising ? "Raise emergency kill flag" : "Clear emergency kill flag",
          message: raising
            ? "This immediately denies new dispatch for every run in the tenant. The change is audited with your reason."
            : "This re-enables dispatch for all runs in the tenant. The change is audited with your reason.",
          confirmLabel: raising ? "Raise flag" : "Clear flag",
          danger: raising,
          requireReason: true,
          reasonHint: "Reason for the audit record (required)",
        });
        if (!confirmed) return;
        const out = await patch("/v1/tenant-settings", {
          kill_flag: raising, reason: confirmed.reason,
        });
        toast(`Server recorded kill_flag ${JSON.stringify(out.after.kill_flag)}.`, "success", "SETTINGS_PATCH");
        viewSettings(container); // authoritative refetch
      } catch (err) {
        toastError(err);
      }
    });
    kill.appendChild(toggleBtn);
  }
  grid.appendChild(kill);

  container.appendChild(grid);

  // ---- Governance section (S00 continuous monitoring + retention) ----
  container.appendChild(el("h2", { style: "margin:24px 0 10px" }, icon("refresh"), "Governance"));
  container.appendChild(governanceCard(settings, isAdmin));

  // ---- Danger zone (IRREVERSIBLE) ----
  container.appendChild(dangerZoneCard(settings, isAdmin));
  return null;
}

/* ---- S00 subscriptions + retention ---- */

function governanceCard(settings, isAdmin) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h3", {}, icon("clock", 15), "Continuous monitoring subscriptions"));
  card.appendChild(el("p", { class: "card-sub", style: "margin-bottom:10px" },
    "Subscriptions re-evaluate an engagement's scope on a fixed cadence so findings never go stale (S00). Retention policy version: ",
    el("span", { class: "mono" }, settings.retention_policy_version || "-"), "."));

  const host = el("div", { class: "stack", style: "gap:12px" });
  card.appendChild(host);

  async function loadSubscriptions() {
    host.replaceChildren(loadingState("Loading subscriptions\u2026"));
    let subs;
    try {
      subs = await get("/v1/subscriptions");
    } catch (err) {
      host.replaceChildren(el("div", { class: "form-error", style: "margin:0" },
        `${err.code || "ERROR"}: ${err.message || String(err)}`,
        err instanceof ApiError && err.status === 404
          ? el("span", { class: "small", style: "display:block;margin-top:4px" },
            "The subscriptions API is not available on this deployment yet.")
          : null));
      return;
    }
    host.replaceChildren();

    if (!subs.length) {
      host.appendChild(emptyState({
        glyph: "\u2299", title: "No subscriptions",
        message: "Create a subscription so an engagement is re-evaluated on a fixed cadence.",
      }));
    } else {
      const rows = subs.map((s) => subscriptionRow(s, isAdmin, loadSubscriptions));
      host.appendChild(table(["Engagement", "Cadence", "Last run", "Last signature", "Enabled"], rows));
    }

    if (isAdmin) host.appendChild(addSubscriptionForm(loadSubscriptions));
  }

  loadSubscriptions();
  return card;
}

function subscriptionRow(s, isAdmin, reload) {
  const enabledCell = el("td", {});
  if (!isAdmin) {
    enabledCell.appendChild(s.enabled
      ? genericChip("enabled", "ok", "check")
      : genericChip("disabled", "neutral", "ban"));
  } else {
    const toggle = el("input", {
      type: "checkbox", role: "switch", checked: Boolean(s.enabled),
      "aria-label": `Toggle subscription ${s.subscription_id}`,
      style: "width:18px;height:18px;accent-color:var(--primary);cursor:pointer",
    });
    toggle.addEventListener("change", async () => {
      const next = toggle.checked;
      toggle.disabled = true;
      try {
        await patch(`/v1/subscriptions/${encodeURIComponent(s.subscription_id)}`, { enabled: next });
        toast(`Subscription ${shortId(s.subscription_id, 14)} ${next ? "enabled" : "disabled"}.`, "success", "SUBSCRIPTION_PATCH");
      } catch (err) {
        toggle.checked = !next; // revert on server rejection
        toastError(err);
      }
      toggle.disabled = false;
    });
    enabledCell.appendChild(el("label", { class: "rowflex", style: "gap:8px;flex-wrap:nowrap" },
      toggle,
      s.enabled ? genericChip("enabled", "ok", "check") : genericChip("disabled", "neutral", "ban")));
  }
  return el("tr", {},
    el("td", {}, el("span", { class: "mono small" }, s.engagement_id)),
    el("td", {}, `${s.cadence_hours ?? "-"}h`),
    el("td", {}, el("span", { class: "mono small" }, s.last_run_id ? shortId(s.last_run_id, 18) : "-")),
    el("td", {}, el("span", { class: "mono small muted", title: s.last_signature || "" },
      s.last_signature ? `${String(s.last_signature).slice(0, 10)}\u2026` : "-")),
    enabledCell);
}

function addSubscriptionForm(reload) {
  const engagement = el("input", {
    type: "text", placeholder: "engagement id (e.g. ENG-...)",
    "aria-label": "Engagement id for the new subscription", style: "max-width:220px",
  });
  const cadence = el("input", {
    type: "number", min: "1", value: "24",
    "aria-label": "Cadence in hours for the new subscription", style: "max-width:110px",
  });
  const addBtn = el("button", { class: "btn small primary" }, icon("check", 13), "Add subscription");
  addBtn.addEventListener("click", async () => {
    const hours = Number(cadence.value);
    if (!engagement.value.trim()) { engagement.focus(); return; }
    if (!Number.isFinite(hours) || hours < 1) { cadence.focus(); return; }
    addBtn.disabled = true;
    try {
      const out = await post("/v1/subscriptions", {
        engagement_id: engagement.value.trim(), cadence_hours: hours,
      });
      toast(`Subscription ${shortId(out.subscription_id || "", 14)} created.`, "success", "SUBSCRIPTION_CREATED");
      reload();
    } catch (err) {
      toastError(err);
      addBtn.disabled = false;
    }
  });
  return el("div", { class: "rowflex" },
    el("span", { class: "label", style: "margin:0" }, "New (admin):"),
    engagement,
    el("span", { class: "small muted" }, "every"), cadence, el("span", { class: "small muted" }, "h"),
    addBtn);
}

/* ---- danger zone: tenant offboarding ---- */

function dangerZoneCard(settings, isAdmin) {
  const tenantName = (session.me && session.me.tenant_name) || settings.tenant_id;
  const card = el("div", { class: "card danger-zone" });
  card.appendChild(el("h2", {}, icon("alert"), "Danger zone"));
  card.appendChild(el("p", { class: "card-sub" },
    el("strong", { style: "color:var(--danger)" }, "Offboarding is irreversible. "),
    "It revokes every login and session for this tenant, stops all runs and purges evidence content. Governance ledger entries are retained as tombstones."));

  if (!isAdmin) {
    card.appendChild(el("p", { class: "muted small", style: "margin:0" },
      "Only the tenant admin can offboard the tenant (settings:update capability)."));
    return card;
  }

  const btn = el("button", { class: "btn danger solid" }, icon("ban"), "Offboard tenant\u2026");
  btn.addEventListener("click", () => offboardDialog(tenantName));
  card.appendChild(btn);
  return card;
}

function offboardDialog(tenantName) {
  let confirmInput;
  let reasonInput;
  const err = el("div", { class: "form-error hidden" });
  const body = el("div", {},
    el("p", { class: "small", style: "color:var(--danger)" },
      "This action permanently offboards the tenant. It cannot be undone."),
    el("ul", { class: "small muted", style: "margin:0 0 12px;padding-left:18px" },
      el("li", {}, "All logins and sessions for this tenant stop working immediately."),
      el("li", {}, "All runs are stopped and evidence content is purged."),
      el("li", {}, "Append-only ledger entries are retained as offboarding tombstones.")),
    el("label", { class: "field" },
      el("span", { class: "label" }, `Type "${tenantName}" to confirm`),
      confirmInput = el("input", { type: "text", autocomplete: "off", placeholder: tenantName })),
    el("label", { class: "field" },
      el("span", { class: "label" }, "Reason (required)"),
      reasonInput = el("textarea", { placeholder: "Why is this tenant being offboarded?" })),
    err);

  const submitBtn = el("button", { class: "btn danger solid" }, icon("ban"), "Offboard tenant");
  const cancelBtn = el("button", { class: "btn" }, "Cancel");
  const modal = openModal({
    title: "Offboard tenant",
    body, danger: true,
    footer: el("div", { class: "modal-foot" }, cancelBtn, submitBtn),
  });

  cancelBtn.addEventListener("click", () => modal.close(null));
  submitBtn.addEventListener("click", async () => {
    err.classList.add("hidden");
    const confirmation = confirmInput.value.trim();
    const reason = reasonInput.value.trim();
    if (confirmation !== tenantName) {
      err.textContent = `Confirmation must exactly match the tenant name "${tenantName}".`;
      err.classList.remove("hidden");
      confirmInput.focus();
      return;
    }
    if (reason.length < 3) {
      err.textContent = "A reason of at least 3 characters is required.";
      err.classList.remove("hidden");
      reasonInput.focus();
      return;
    }
    submitBtn.disabled = true;
    try {
      const out = await post("/v1/tenant-offboarding", { confirmation, reason });
      toast(`Tenant offboarded (${out.status}); ${out.ledger_entries} ledger entries recorded. Access is revoked.`, "error", "TENANT_OFFBOARDED", 12000);
      modal.close(true);
      // Access is revoked server-side - drop the local session and return to login.
      session.me = null;
      session.csrf = null;
      setTimeout(() => location.reload(), 1800);
    } catch (ex) {
      submitBtn.disabled = false;
      err.textContent = ex instanceof ApiError ? `[${ex.code}] ${ex.message}` : String(ex && ex.message || ex);
      err.classList.remove("hidden");
    }
  });
  setTimeout(() => confirmInput.focus(), 30);
}
