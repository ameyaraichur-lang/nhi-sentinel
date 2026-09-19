/* core.js - shared primitives: safe DOM builder, API client, chips, dialogs, toasts.
   Security rule (VD13): the el() helper renders every string child via textContent.
   There is no innerHTML path anywhere in the SPA. */

export const session = { me: null, csrf: null };

/* ------------------------------------------------------------------ dom --- */

const SVG_NS = "http://www.w3.org/2000/svg";

export function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) applyAttrs(node, attrs);
  appendChildren(node, children);
  return node;
}

export function svgEl(pathSpec, size = 16) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const d of pathSpec) {
    const p = document.createElementNS(SVG_NS, d.t === "circle" ? "circle" : "path");
    if (d.t === "circle") {
      p.setAttribute("cx", d.cx); p.setAttribute("cy", d.cy); p.setAttribute("r", d.r);
    } else {
      p.setAttribute("d", d.d);
    }
    svg.appendChild(p);
  }
  return svg;
}

function applyAttrs(node, attrs) {
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === "value" && (node.tagName === "INPUT" || node.tagName === "SELECT" || node.tagName === "TEXTAREA")) {
      node.value = value;
    } else if (key === "checked" || key === "disabled" || key === "selected" || key === "required" || key === "hidden" || key === "open") {
      node[key] = Boolean(value);
    } else {
      node.setAttribute(key, String(value));
    }
  }
}

function appendChildren(node, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false || child === true) continue;
    if (Array.isArray(child)) { appendChildren(node, child); continue; }
    if (child instanceof Node) { node.appendChild(child); continue; }
    // Strings and numbers become text nodes - never interpreted as HTML (VD13).
    node.appendChild(document.createTextNode(String(child)));
  }
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/* ---------------------------------------------------------------- icons --- */

const I = {
  shield: [{ d: "M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" }],
  check: [{ d: "M20 6L9 17l-5-5" }],
  x: [{ d: "M18 6L6 18" }, { d: "M6 6l12 12" }],
  clock: [{ t: "circle", cx: 12, cy: 12, r: 9 }, { d: "M12 7v5l3 3" }],
  play: [{ d: "M8 5.5v13l10-6.5-10-6.5z" }],
  pause: [{ d: "M8 5v14" }, { d: "M16 5v14" }],
  stop: [{ d: "M12 3l7 4v10l-7 4-7-4V7l7-4z" }],
  square: [{ d: "M7 7h10v10H7z" }],
  alert: [{ d: "M12 3l10 18H2L12 3z" }, { d: "M12 10v4" }, { d: "M12 17.2v.1" }],
  question: [{ t: "circle", cx: 12, cy: 12, r: 9 }, { d: "M9.4 9a2.6 2.6 0 1 1 3.9 2.3c-.8.5-1.3 1-1.3 1.9" }, { d: "M12 17v.1" }],
  dot: [{ t: "circle", cx: 12, cy: 12, r: 4 }],
  skip: [{ d: "M5 4l10 8-10 8V4z" }, { d: "M19 5v14" }],
  sun: [{ t: "circle", cx: 12, cy: 12, r: 4 }, { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" }],
  moon: [{ d: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" }],
  menu: [{ d: "M4 7h16" }, { d: "M4 12h16" }, { d: "M4 17h16" }],
  logout: [{ d: "M9 21H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3" }, { d: "M16 17l5-5-5-5" }, { d: "M21 12H9" }],
  runs: [{ d: "M8 5.5v13l10-6.5-10-6.5z" }],
  overview: [{ d: "M3 12l9-8 9 8" }, { d: "M5 10v10h14V10" }],
  approvals: [{ d: "M9 11l3 3 8-8" }, { d: "M20 12v7a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h11" }],
  identities: [{ t: "circle", cx: 12, cy: 8, r: 4 }, { d: "M4 21v-1a7 7 0 0 1 16 0v1" }],
  findings: [{ d: "M12 3l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" }, { d: "M12 8v4" }, { d: "M12 15.5v.1" }],
  agents: [{ d: "M12 3v3" }, { d: "M6 9h12v8a3 3 0 0 1-3 3H9a3 3 0 0 1-3-3V9z" }, { d: "M9 13v.1M15 13v.1" }, { d: "M3 12h3M18 12h3" }],
  connectors: [{ d: "M9 7V4a3 3 0 0 1 6 0v3" }, { d: "M6 7h12l-1 5a5 5 0 0 1-10 0L6 7z" }, { d: "M12 17v4" }],
  reports: [{ d: "M7 3h7l4 4v14H7z" }, { d: "M14 3v4h4" }, { d: "M10 12h5M10 16h5" }],
  audit: [{ d: "M4 12h3l2 5 3-11 2 6h6" }],
  settings: [{ t: "circle", cx: 12, cy: 12, r: 3.2 }, { d: "M12 2.5l1.2 2.6 2.8-.6 1 2.7 2.7 1-.6 2.8 2.4 1-2.4 1 .6 2.8-2.7 1-1 2.7-2.8-.6L12 21.5l-1.2-2.6-2.8.6-1-2.7-2.7-1 .6-2.8-2.4-1 2.4-1-.6-2.8 2.7-1 1-2.7 2.8.6L12 2.5z" }],
  key: [{ t: "circle", cx: 8, cy: 14, r: 4 }, { d: "M11 11L20 2M16 6l3 3" }],
  refresh: [{ d: "M20 12a8 8 0 1 1-2.3-5.6" }, { d: "M20 4v5h-5" }],
  ban: [{ t: "circle", cx: 12, cy: 12, r: 9 }, { d: "M6 6l12 12" }],
  link: [{ d: "M10 14a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" }, { d: "M14 10a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" }],
  external: [{ d: "M14 4h6v6" }, { d: "M20 4L10 14" }, { d: "M18 13v6H5V6h6" }],
};

export function icon(name, size = 16) {
  const spec = I[name] || I.dot;
  return svgEl(spec, size);
}

/* ------------------------------------------------------------------ api --- */

export class ApiError extends Error {
  constructor(status, code, message, details, correlation) {
    super(message || code || "request failed");
    this.status = status;
    this.code = code || "ERROR";
    this.details = details || null;
    this.correlation = correlation || null;
  }
}

export class OfflineError extends Error {
  constructor() {
    super("Network error - the API is unreachable.");
    this.status = 0;
    this.code = "NETWORK_ERROR";
  }
}

export function onUnauthorized(fn) { _on401 = fn; }
let _on401 = null;

export async function api(method, path, opts = {}) {
  try {
    return await apiOnce(method, path, opts);
  } catch (err) {
    // Self-heal stale CSRF page state (e.g. interrupted login): re-probe the session once
    // and retry the mutation. Never retry auth/login itself.
    if (err && err.status === 403 && err.code === "CSRF_INVALID"
        && !opts.skipAuthRedirect && !path.startsWith("/v1/auth/")) {
      session.csrf = null;
      const me = await apiOnce("GET", "/v1/me", { skipAuthRedirect: true });
      session.me = me;
      session.csrf = me.csrf_token;
      return await apiOnce(method, path, opts);
    }
    throw err;
  }
}

async function apiOnce(method, path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD" && session.csrf) {
    headers["X-CSRF-Token"] = session.csrf;
  }
  if (opts.ifMatch !== undefined && opts.ifMatch !== null) headers["If-Match"] = String(opts.ifMatch);
  let res;
  try {
    res = await fetch(path, {
      method, headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: "same-origin",
    });
  } catch (err) {
    throw new OfflineError();
  }
  if (res.status === 204) return null;
  let data = null;
  try { data = await res.json(); } catch { /* non-json body */ }
  if (!res.ok) {
    const err = data && data.error ? data.error : {};
    if (res.status === 401 && !opts.skipAuthRedirect && _on401) _on401();
    throw new ApiError(res.status, err.code, err.message, err.details, err.correlation_id);
  }
  return data;
}

export function get(path, opts) { return api("GET", path, opts); }
export function post(path, body, opts) { return api("POST", path, { ...opts, body }); }
export function put(path, body, opts) { return api("PUT", path, { ...opts, body }); }
export function patch(path, body, opts) { return api("PATCH", path, { ...opts, body }); }

/* ---------------------------------------------------------------- toasts --- */

export function toast(message, kind = "info", code = null, ms = 6000) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const closeBtn = el("button", { class: "close", "aria-label": "Dismiss notification" }, "\u00D7");
  const box = el("div", {
    class: `toast ${kind}`, role: kind === "error" ? "alert" : "status",
  },
    el("div", { style: "flex:1;min-width:0" },
      code ? el("div", { class: "code mono" }, code) : null,
      el("div", { class: "msg" }, message)),
    closeBtn);
  closeBtn.addEventListener("click", () => box.remove());
  host.appendChild(box);
  setTimeout(() => box.remove(), ms);
}

export function toastError(err) {
  if (err instanceof ApiError) toast(err.message, "error", err.code);
  else if (err instanceof OfflineError) toast(err.message, "error", "NETWORK_ERROR");
  else toast(String(err && err.message || err), "error", "UNEXPECTED");
}

/* --------------------------------------------------------------- dialogs --- */

export function openModal({ title, body, footer, danger = false, onClose = null }) {
  const root = document.getElementById("dialog-root");
  const dlg = el("dialog", { class: `modal${danger ? " danger" : ""}` });
  const prevFocus = document.activeElement;
  let closed = false;
  const close = (result) => {
    if (closed) return;
    closed = true;
    dlg.close();
    dlg.remove();
    if (prevFocus && prevFocus.isConnected) prevFocus.focus();
    if (onClose) onClose(result);
  };
  dlg.appendChild(el("div", { class: "modal-head" },
    danger ? icon("alert", 18) : null,
    el("h2", {}, title),
    el("button", {
      class: "btn ghost small", "aria-label": "Close dialog",
      onClick: () => close(null),
    }, "\u00D7")));
  if (body) dlg.appendChild(body);
  if (footer) {
    const f = el("div", { class: "modal-foot" }, footer);
    dlg.appendChild(f);
  }
  dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
  dlg.addEventListener("click", (e) => { if (e.target === dlg) close(null); });
  root.appendChild(dlg);
  dlg.showModal();
  return { close, dlg };
}

/** Confirm dialog. Resolves true when confirmed. Optional reason field. */
export function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false, requireReason = false, reasonHint = "" }) {
  return new Promise((resolve) => {
    let reasonInput = null;
    const body = el("div", {},
      el("p", { class: "muted" }, message),
      requireReason ? el("label", { class: "field" },
        el("span", { class: "label" }, "Reason (required)"),
        reasonInput = el("textarea", { placeholder: reasonHint || "Explain why this action is needed" })) : null);
    const err = el("div", { class: "form-error hidden" });
    body.appendChild(err);
    const confirmBtn = el("button", { class: `btn ${danger ? "danger solid" : "primary"}` }, confirmLabel);
    const cancelBtn = el("button", { class: "btn" }, "Cancel");
    const modal = openModal({
      title, body, danger,
      footer: el("div", { class: "modal-foot" }, cancelBtn, confirmBtn),
      onClose: () => resolve(false),
    });
    cancelBtn.addEventListener("click", () => modal.close(null));
    confirmBtn.addEventListener("click", () => {
      const reason = reasonInput ? reasonInput.value.trim() : "";
      if (requireReason && reason.length < 3) {
        err.textContent = "A reason of at least 3 characters is required.";
        err.classList.remove("hidden");
        reasonInput.focus();
        return;
      }
      resolve({ reason });
      modal.close(true);
    });
    setTimeout(() => (reasonInput || confirmBtn).focus(), 30);
  });
}

/**
 * Multi-field form dialog. fields: [{name,label,type,password?,placeholder?,required?,min?}]
 * Resolves an object of values or null when cancelled. Inline error surface for
 * server-side codes (SELF_APPROVAL, STALE_APPROVAL, ...).
 */
export function formDialog({ title, message, fields, submitLabel = "Submit", danger = false, note = null, onSubmit }) {
  return new Promise((resolve) => {
    const inputs = {};
    const err = el("div", { class: "form-error hidden" });
    const body = el("div", {});
    if (message) body.appendChild(el("p", { class: "muted" }, message));
    if (note) body.appendChild(note);
    for (const f of fields) {
      let input;
      const id = `fd-${f.name}`;
      if (f.type === "select") {
        input = el("select", {}, f.options.map((o) => el("option", { value: o.value }, o.label)));
      } else if (f.type === "textarea") {
        input = el("textarea", { placeholder: f.placeholder || "", rows: f.rows || 3 });
      } else {
        input = el("input", { type: f.type || "text", placeholder: f.placeholder || "", autocomplete: f.autocomplete || "off" });
      }
      inputs[f.name] = input;
      body.appendChild(el("label", { class: "field", for: id },
        el("span", { class: "label" }, f.label),
        input,
        f.hint ? el("span", { class: "input-hint" }, f.hint) : null));
    }
    body.appendChild(err);
    const submitBtn = el("button", { class: `btn ${danger ? "danger solid" : "primary"}` }, submitLabel);
    const cancelBtn = el("button", { class: "btn" }, "Cancel");
    const modal = openModal({
      title, body, danger,
      footer: el("div", { class: "modal-foot" }, cancelBtn, submitBtn),
      onClose: () => resolve(null),
    });
    cancelBtn.addEventListener("click", () => modal.close(null));
    submitBtn.addEventListener("click", async () => {
      const values = {};
      for (const f of fields) values[f.name] = inputs[f.name].value.trim();
      for (const f of fields) {
        if (f.required && !values[f.name]) {
          showError(f.requiredMessage || `${f.label} is required.`);
          inputs[f.name].focus();
          return;
        }
        if (f.min && values[f.name].length < f.min) {
          showError(`${f.label} must be at least ${f.min} characters.`);
          inputs[f.name].focus();
          return;
        }
      }
      submitBtn.disabled = true;
      try {
        const result = onSubmit ? await onSubmit(values) : values;
        if (result === false) { submitBtn.disabled = false; return; } // inline error shown
        resolve(values);
        modal.close(true);
      } catch (e) {
        submitBtn.disabled = false;
        showError(e);
      }
    });
    function showError(e) {
      const msg = e instanceof ApiError ? `${e.message}` : String(e && e.message || e);
      err.textContent = e instanceof ApiError ? `[${e.code}] ${msg}` : msg;
      err.classList.remove("hidden");
    }
    setTimeout(() => inputs[fields[0].name].focus(), 30);
  });
}

/* ----------------------------------------------------------------- chips --- */

const RUN_STATE_META = {
  queued:        { icon: "clock",  cls: "neutral", label: "Queued" },
  running:       { icon: "dot",    cls: "run",     label: "Running", spin: true },
  blocked:       { icon: "alert",  cls: "warn",    label: "Blocked" },
  waiting_approval: { icon: "clock", cls: "warn",  label: "Waiting approval" },
  pause_requested:  { icon: "pause", cls: "warn",  label: "Pause requested" },
  paused:        { icon: "pause",  cls: "warn",    label: "Paused" },
  cancel_requested: { icon: "ban",  cls: "warn",    label: "Cancel requested" },
  cancelled:     { icon: "x",      cls: "bad",     label: "Cancelled" },
  partial:       { icon: "alert",  cls: "warn",    label: "Partial" },
  succeeded:     { icon: "check",  cls: "ok",      label: "Succeeded" },
  failed:        { icon: "x",      cls: "bad",     label: "Failed" },
};

const TASK_STATE_META = {
  pending:         { icon: "clock",  cls: "neutral", label: "Pending" },
  leased:          { icon: "dot",    cls: "run",     label: "Leased", spin: true },
  running:         { icon: "dot",    cls: "run",     label: "Running", spin: true },
  retry_scheduled: { icon: "refresh", cls: "warn",   label: "Retrying" },
  succeeded:       { icon: "check",  cls: "ok",      label: "Done" },
  failed:          { icon: "x",      cls: "bad",     label: "Failed" },
  skipped:         { icon: "skip",   cls: "neutral", label: "Skipped" },
  cancelled:       { icon: "ban",    cls: "warn",    label: "Cancelled" },
  unknown:         { icon: "question", cls: "warn",  label: "Unknown" },
};

export function runStateChip(state, opts = {}) {
  const meta = RUN_STATE_META[state] || { icon: "question", cls: "neutral", label: state || "Unknown" };
  const ic = icon(meta.icon, 13);
  if (meta.spin) ic.classList.add("spin");
  return el("span", { class: `chip ${meta.cls}${opts.outline ? " outline" : ""}`, "data-state": state || "" }, ic, meta.label);
}

export function taskStateChip(state) {
  const meta = TASK_STATE_META[state] || { icon: "question", cls: "neutral", label: state || "Unknown" };
  const ic = icon(meta.icon, 12);
  if (meta.spin) ic.classList.add("spin");
  return el("span", { class: `chip ${meta.cls}` }, ic, meta.label);
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, undetermined: 5 };
export function sevChip(sev) {
  const label = (sev || "undetermined").replace("_", " ");
  return el("span", { class: `sev-chip sev-${sev || "undetermined"}` },
    icon("findings", 12), label);
}
export function sevRank(sev) { return SEV_ORDER[sev] ?? 9; }

export function genericChip(label, cls = "neutral", iconName = null) {
  const ic = iconName ? icon(iconName, 12) : null;
  return el("span", { class: `chip ${cls}` }, ic, label);
}

export function linkChip(href, label, iconName = "link") {
  return el("a", { class: "chip info", href }, icon(iconName, 12), label);
}

/* ------------------------------------------------------------- formatting --- */

export function fmtTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function fmtDateTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString([], { year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit" });
}

export function relTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 5) return "just now";
  if (s < 90) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export function fmtDuration(isoStart, isoEnd) {
  if (!isoStart) return "-";
  const a = new Date(isoStart).getTime();
  const b = isoEnd ? new Date(isoEnd).getTime() : null;
  const end = b ?? Date.now();
  if (isNaN(a) || isNaN(end)) return "-";
  let s = Math.max(0, Math.round((end - a) / 1000));
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

export function countdown(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return { text: "-", expired: false };
  const diff = d.getTime() - Date.now();
  if (diff <= 0) return { text: "expired", expired: true };
  const mins = Math.floor(diff / 60000);
  const days = Math.floor(mins / 1440);
  const hours = Math.floor((mins % 1440) / 60);
  const rem = mins % 60;
  if (days > 0) return { text: `${days}d ${hours}h remaining`, expired: false };
  if (hours > 0) return { text: `${hours}h ${rem}m remaining`, expired: false };
  return { text: `${rem}m remaining`, expired: false };
}

export function shortId(id, max = 18) {
  if (!id) return "-";
  return String(id).length <= max ? String(id) : `${String(id).slice(0, max - 1)}\u2026`;
}

export function pct(value) {
  if (value === null || value === undefined) return "-";
  return `${Math.round(value * 100)}%`;
}

/* ------------------------------------------------------------------ misc --- */

export function hasCap(cap) {
  const caps = session.me && session.me.capabilities || [];
  return caps.includes(cap) || (caps.includes("read:*") && cap.startsWith("read:"));
}

export function canMutate(cap) {
  const caps = session.me && session.me.capabilities || [];
  return caps.includes(cap);
}

export function emptyState({ glyph = "\u25CB", title, message, actions = null }) {
  return el("div", { class: "empty-state" },
    el("div", { class: "glyph", "aria-hidden": "true" }, glyph),
    el("h3", {}, title),
    el("p", {}, message),
    actions ? el("div", { class: "actions" }, actions) : null);
}

export function loadingState(label = "Loading\u2026") {
  return el("div", { class: "skeleton", role: "status" }, label);
}

export function errorState(err, retry) {
  const isDenied = err instanceof ApiError && err.status === 403;
  const isOffline = err instanceof OfflineError || (err instanceof ApiError && err.status === 0);
  const block = el("div", { class: "state-block" + (isDenied || isOffline ? "" : " bad") });
  block.appendChild(el("h3", {},
    isDenied ? "Permission denied" : isOffline ? "Service unreachable" : "Something went wrong"));
  block.appendChild(el("p", {},
    isDenied ? "Your role does not have access to this view."
      : err instanceof ApiError ? `${err.code}: ${err.message}`
      : String(err.message || err)));
  if (err instanceof ApiError && err.correlation) {
    block.appendChild(el("p", { class: "small mono muted" }, `correlation: ${err.correlation}`));
  }
  if (retry) {
    block.appendChild(el("button", { class: "btn", onClick: retry }, icon("refresh"), "Retry"));
  }
  return block;
}

export function kvTable(pairs) {
  const grid = el("div", { class: "kv" });
  for (const [k, v] of pairs) {
    grid.appendChild(el("div", { class: "k" }, k));
    grid.appendChild(el("div", { class: "v" }, v === null || v === undefined || v === "" ? "-" : v));
  }
  return grid;
}

export function meterBar(fraction, opts = {}) {
  const v = fraction === null || fraction === undefined ? null : Math.max(0, Math.min(1, fraction));
  const cls = opts.tone || (v !== null && v < 0.5 ? "warn" : "");
  const bar = el("div", { class: `meter ${cls}`, role: "meter", "aria-valuemin": "0", "aria-valuemax": "100" },
    el("span", { style: `width:${v === null ? 0 : Math.round(v * 100)}%` }));
  if (v !== null) bar.setAttribute("aria-valuenow", String(Math.round(v * 100)));
  return bar;
}

export function table(heads, rows, opts = {}) {
  const thead = el("thead", {}, el("tr", {}, heads.map((h, i) =>
    el("th", { class: opts.numCols && opts.numCols.includes(i) ? "num" : "" }, h))));
  const tbody = el("tbody", {});
  for (const row of rows) tbody.appendChild(row);
  return el("div", { class: "table-wrap" },
    el("table", { class: "data" }, thead, tbody));
}

/** Interval registry so views can register per-second timers cleared on navigation. */
export function makeTimers() {
  const timers = [];
  return {
    every(ms, fn) { const t = setInterval(fn, ms); timers.push(t); fn(); return t; },
    after(ms, fn) { const t = setTimeout(fn, ms); timers.push(t); return t; },
    clearAll() { for (const t of timers) { clearInterval(t); clearTimeout(t); } timers.length = 0; },
  };
}
