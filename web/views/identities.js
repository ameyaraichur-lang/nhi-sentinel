/* views/identities.js - UI06 identity inventory (paginated, provider filter,
   unowned badges) + UI07 identity detail (credential metadata with fingerprint
   prefix only, ownership assertions, attest-owner form, related findings).
   All source text renders through textContent - XSS canaries stay inert (VD13). */
import {
  el, get, put, icon, sevChip, genericChip, fmtDateTime, canMutate, toast,
  toastError, formDialog, errorState, loadingState, emptyState, table,
} from "../core.js";

/* ------------------------------------------------------------- UI06 list --- */

export async function viewIdentities(container, params, query) {
  const state = { limit: 50, offset: Number(query.get("offset") || 0), provider: query.get("provider") || "" };

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Identity inventory"),
      el("p", {}, "Non-human identities across providers. Unowned identities are flagged; display names are untrusted source text rendered inert.")));
  container.appendChild(head);

  const controls = el("div", { class: "facets" });
  const providerSelect = el("select", { style: "width:200px", "aria-label": "Filter by provider" },
    el("option", { value: "" }, "All providers"));
  providerSelect.addEventListener("change", () => {
    state.provider = providerSelect.value;
    state.offset = 0;
    load();
  });
  controls.appendChild(el("span", { class: "label" }, "Provider:"), providerSelect);
  container.appendChild(controls);

  const host = el("div", {});
  container.appendChild(host);

  async function load() {
    host.replaceChildren(loadingState("Loading identities\u2026"));
    let data;
    try {
      const q = new URLSearchParams({ limit: String(state.limit), offset: String(state.offset) });
      if (state.provider) q.set("provider", state.provider);
      data = await get(`/v1/identities?${q}`);
    } catch (err) {
      host.replaceChildren(errorState(err, load));
      return;
    }
    // provider options from the full unfiltered sweep (fixture-sized)
    if (providerSelect.options.length <= 1) {
      try {
        const all = await get("/v1/identities?limit=100&offset=0");
        const providers = [...new Set((all.items || []).map((i) => i.provider))].sort();
        for (const p of providers) {
          providerSelect.appendChild(el("option", { value: p }, p));
        }
        providerSelect.value = state.provider;
      } catch { /* filter list stays minimal */ }
    }
    renderTable(data);
  }

  function renderTable(data) {
    const total = data.total || 0;
    const from = total === 0 ? 0 : state.offset + 1;
    const to = Math.min(state.offset + data.items.length, total);
    const rows = data.items.map((i) => {
      const unowned = !i.owner_business && !i.owner_technical;
      const tr = el("tr", { class: "clickable", tabindex: "0" },
        el("td", {}, el("span", { class: "mono" }, i.native_id)),
        el("td", {}, i.display_name),
        el("td", {}, el("span", { class: "mono small" }, i.provider)),
        el("td", {}, i.id_type || "-"),
        el("td", {}, i.owner_business
          ? i.owner_business
          : genericChip("no business owner", "warn outline", "question")),
        el("td", {}, i.owner_technical
          ? i.owner_technical
          : genericChip("no technical owner", "warn outline", "question")),
        el("td", {}, unowned ? genericChip("UNOWNED", "bad", "alert") : genericChip("owned", "ok", "check")),
        el("td", { class: "small muted" }, fmtDateTime(i.last_seen)));
      const open = () => { location.hash = `#/identities/${encodeURIComponent(i.identity_id)}`; };
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
      return tr;
    });
    const foot = el("div", { class: "table-foot" },
      el("span", {}, `${from}\u2013${to} of ${total}`),
      el("button", {
        class: "btn small", disabled: state.offset <= 0,
        onClick: () => { state.offset = Math.max(0, state.offset - state.limit); load(); },
      }, "Previous"),
      el("button", {
        class: "btn small", disabled: to >= total,
        onClick: () => { state.offset = state.offset + state.limit; load(); },
      }, "Next"));
    host.replaceChildren(
      data.items.length
        ? table(["Native ID", "Display name", "Provider", "Type", "Business owner", "Technical owner", "Ownership", "Last seen"], rows)
        : emptyState({
          glyph: "\u2205",
          title: state.provider ? "No matches" : "No identities yet",
          message: state.provider
            ? `No identities for provider "${state.provider}". Clear the filter to see all.`
            : "No identities collected yet - run an assessment or check connector health.",
          actions: state.provider
            ? el("button", { class: "btn small", onClick: () => { providerSelect.value = ""; state.provider = ""; load(); } }, "Clear filter")
            : null,
        }),
      foot);
  }

  await load();
  return null;
}

/* ------------------------------------------------------------ UI07 detail --- */

export async function viewIdentityDetail(container, params) {
  const id = params[0];
  container.appendChild(loadingState("Loading identity\u2026"));
  let ident;
  try {
    ident = await get(`/v1/identities/${encodeURIComponent(id)}`);
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewIdentityDetail(container, params)));
    return null;
  }
  container.replaceChildren();

  container.appendChild(el("div", { class: "crumbs" },
    el("a", { href: "#/identities" }, "Identities"), " / ",
    el("span", { class: "mono" }, ident.native_id)));

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, ident.display_name),
      el("p", { class: "mono small" }, `${ident.provider} \u00B7 ${ident.native_id} \u00B7 ${ident.id_type || "unknown type"} \u00B7 authority ${ident.authority || "-"}`)));
  container.appendChild(head);

  const grid = el("div", { class: "card-grid grid-2" });

  // Summary + attributes
  const summary = el("div", { class: "card" },
    el("h2", {}, icon("identities"), "Attributes"));
  const attrs = Object.entries(ident.attributes || {});
  if (attrs.length) {
    const kv = el("div", { class: "kv" });
    for (const [k, v] of attrs) {
      kv.appendChild(el("div", { class: "k mono small" }, k));
      kv.appendChild(el("div", { class: "v" }, typeof v === "object" ? JSON.stringify(v) : String(v)));
    }
    summary.appendChild(kv);
  } else {
    summary.appendChild(el("p", { class: "muted small" }, "No attributes recorded."));
  }
  grid.appendChild(summary);

  // Credentials metadata - fingerprint prefix only, never secret values (DC07/UI07)
  const creds = el("div", { class: "card" },
    el("h2", {}, icon("key"), "Credential metadata"),
    el("p", { class: "card-sub" }, "Metadata only - secret values are never stored or displayed."));
  if (!(ident.credentials || []).length) {
    creds.appendChild(el("p", { class: "muted small" }, "No credentials recorded for this identity."));
  } else {
    const rows = ident.credentials.map((c) => el("tr", {},
      el("td", {}, c.kind),
      el("td", {}, genericChip(c.status, c.status === "enabled" ? "ok" : "warn", c.status === "enabled" ? "check" : "alert")),
      el("td", { class: "small" }, c.expires_at ? fmtDateTime(c.expires_at) : "-"),
      el("td", { class: "small" }, c.last_rotated_at ? fmtDateTime(c.last_rotated_at) : "-"),
      el("td", {}, el("span", { class: "mono small", title: "HMAC fingerprint prefix" }, c.fingerprint))));
    creds.appendChild(table(["Kind", "Status", "Expires", "Last rotated", "Fingerprint"], rows));
  }
  grid.appendChild(creds);

  // Ownership assertions + attest form
  const ownership = el("div", { class: "card" },
    el("h2", {}, icon("approvals"), "Ownership assertions"),
    el("p", { class: "card-sub" }, "Source assertions remain inspectable; different sources may disagree."));
  if (!(ident.ownership_assertions || []).length) {
    ownership.appendChild(el("p", { class: "muted small" }, "No ownership assertions - this identity is unowned."));
  } else {
    const rows = ident.ownership_assertions.map((o) => el("tr", {},
      el("td", {}, o.owner_email),
      el("td", {}, genericChip(o.role, "info")),
      el("td", { class: "mono small" }, o.source),
      el("td", {}, o.verified ? genericChip("verified", "ok", "check") : genericChip("unverified", "warn", "question"))));
    ownership.appendChild(table(["Owner", "Role", "Source", "State"], rows));
  }
  if (canMutate("owner:attest")) {
    const attestBtn = el("button", { class: "btn primary", style: "margin-top:10px" },
      icon("check"), "Attest owner");
    attestBtn.addEventListener("click", () => attestOwner(ident, () => viewIdentityDetail(container, params)));
    ownership.appendChild(attestBtn);
  }
  grid.appendChild(ownership);

  // Related findings
  const related = el("div", { class: "card" },
    el("h2", {}, icon("findings"), "Related findings"));
  if (!(ident.findings || []).length) {
    related.appendChild(el("p", { class: "muted small" }, "No findings reference this identity."));
  } else {
    const rows = ident.findings.map((f) => {
      const tr = el("tr", { class: "clickable", tabindex: "0" },
        el("td", {}, sevChip(f.severity)),
        el("td", {}, el("span", { class: "mono small" }, f.check_id)),
        el("td", {}, el("a", { href: `#/findings?f=${encodeURIComponent(f.finding_id)}` }, "open in triage")));
      return tr;
    });
    related.appendChild(table(["Severity", "Check", ""], rows));
  }
  grid.appendChild(related);

  container.appendChild(grid);
  return null;
}

function attestOwner(ident, onDone) {
  formDialog({
    title: "Attest owner",
    message: `Record a verified ownership assertion for ${ident.native_id}. The assertion is audited and expires after the review window.`,
    fields: [
      { name: "owner_email", label: "Owner email", type: "email", required: true, placeholder: "owner@example.com" },
      {
        name: "role", label: "Role", type: "select",
        options: [{ value: "business", label: "business" }, { value: "technical", label: "technical" }],
      },
      { name: "purpose", label: "Purpose (required)", type: "text", required: true, min: 3, placeholder: "Why this owner is accountable" },
      { name: "review_expiry_days", label: "Review expiry (days)", type: "number", value: "180", hint: "30-365 days" },
    ],
    submitLabel: "Record attestation",
    onSubmit: async (values) => {
      await put(`/v1/identities/${encodeURIComponent(ident.identity_id)}/owners`, {
        owner_email: values.owner_email,
        role: values.role,
        purpose: values.purpose,
        review_expiry_days: Number(values.review_expiry_days) || 180,
      });
      toast("Ownership assertion recorded and verified.", "success", "ATTEST_OK");
      onDone();
      return true;
    },
  }).catch(toastError);
}
