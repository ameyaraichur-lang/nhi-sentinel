/* app.js - NHI Sentinel control-room SPA entry: hash router, app shell,
   login view, theme persistence. Zero build, zero dependencies, offline-capable.

   Rendering contract (VD13): every view builds DOM through core.js el(), so all
   source text (identity display names, evidence payloads, errors) becomes
   textContent and XSS canaries stay inert. No innerHTML anywhere. */
import {
  el, clear, icon, get, post, session, onUnauthorized, toast, toastError,
  hasCap, errorState, fmtDateTime,
} from "./core.js";
import { viewOverview } from "./views/overview.js";
import { viewRuns } from "./views/runs.js";
import { viewRunDetail } from "./views/rundetail.js";
import { viewApprovals } from "./views/approvals.js";
import { viewIdentities, viewIdentityDetail } from "./views/identities.js";
import { viewFindings } from "./views/findings.js";
import { viewExceptions } from "./views/exceptions.js";
import { openAssistantDrawer } from "./views/assistant.js";
import { viewAgents } from "./views/agents.js";
import { viewConnectors } from "./views/connectors.js";
import { viewReports, viewReportDetail } from "./views/reports.js";
import { viewAudit } from "./views/audit.js";
import { viewSettings } from "./views/settings.js";
import { viewEvidence } from "./views/evidence.js";

const viewHost = document.getElementById("view");
let currentTeardown = null;
let renderGeneration = 0;

/* --------------------------------------------------------------- routing --- */

const ROUTES = [
  { re: /^\/overview$/, view: viewOverview, nav: "overview" },
  { re: /^\/runs$/, view: viewRuns, nav: "runs" },
  { re: /^\/runs\/([^/]+)$/, view: viewRunDetail, nav: "runs" },
  { re: /^\/approvals$/, view: viewApprovals, nav: "approvals" },
  { re: /^\/identities$/, view: viewIdentities, nav: "identities" },
  { re: /^\/identities\/([^/]+)$/, view: viewIdentityDetail, nav: "identities" },
  { re: /^\/findings$/, view: viewFindings, nav: "findings" },
  { re: /^\/exceptions$/, view: viewExceptions, nav: "exceptions" },
  { re: /^\/agents$/, view: viewAgents, nav: "agents" },
  { re: /^\/connectors$/, view: viewConnectors, nav: "connectors" },
  { re: /^\/reports$/, view: viewReports, nav: "reports" },
  { re: /^\/reports\/([^/]+)$/, view: viewReportDetail, nav: "reports" },
  { re: /^\/evidence\/([^/]+)$/, view: viewEvidence, nav: null },
  { re: /^\/audit$/, view: viewAudit, nav: "audit" },
  { re: /^\/settings$/, view: viewSettings, nav: "settings" },
];

function currentPath() {
  const hash = location.hash || "#/overview";
  return hash.replace(/^#/, "") || "/overview";
}

export function rerender() {
  navigate();
}

async function navigate() {
  if (!session.me) return; // login view owns the screen
  const gen = ++renderGeneration;
  if (typeof currentTeardown === "function") {
    try { currentTeardown(); } catch { /* teardown must never block routing */ }
    currentTeardown = null;
  }
  closeDrawers();

  const path = currentPath();
  const [pathPart, queryPart] = path.split("?");
  const query = new URLSearchParams(queryPart || "");
  const match = ROUTES.find((r) => r.re.test(pathPart));
  clear(viewHost);
  renderSidebarActive(match ? match.nav : null);

  if (!match) {
    viewHost.appendChild(el("div", { class: "state-block" },
      el("h3", {}, "Page not found"),
      el("p", { class: "muted" }, `No route matches "${pathPart}".`),
      el("a", { class: "btn primary", href: "#/overview" }, "Back to overview")));
    return;
  }
  const params = pathPart.match(match.re).slice(1).map(decodeURIComponent);
  try {
    const t = await match.view(viewHost, params, query);
    if (gen !== renderGeneration) {
      if (typeof t === "function") t(); // superseded mid-render
      return;
    }
    currentTeardown = typeof t === "function" ? t : null;
  } catch (err) {
    console.error("view error", err);
    if (gen === renderGeneration) {
      clear(viewHost);
      viewHost.appendChild(errorState(err, rerender));
      toastError(err);
    }
  }
}

function closeDrawers() {
  const drawerRoot = document.getElementById("drawer-root");
  if (drawerRoot) clear(drawerRoot);
}

window.addEventListener("hashchange", () => {
  if (session.me) navigate();
  else renderLogin();
});

/* ----------------------------------------------------------------- shell --- */

const NAV = [
  { group: "Monitor" },
  { id: "overview", label: "Overview", href: "#/overview", icon: "overview", cap: "read:overview" },
  { id: "runs", label: "Runs", href: "#/runs", icon: "runs", cap: "read:runs" },
  { id: "findings", label: "Findings", href: "#/findings", icon: "findings", cap: "read:findings" },
  { id: "identities", label: "Identities", href: "#/identities", icon: "identities", cap: "read:identities" },
  { id: "agents", label: "Agents", href: "#/agents", icon: "agents", cap: "read:agents" },
  { group: "Act" },
  { id: "approvals", label: "Approvals", href: "#/approvals", icon: "approvals", cap: "read:overview" },
  { id: "exceptions", label: "Exceptions", href: "#/exceptions", icon: "clock", cap: "read:overview" },
  { id: "reports", label: "Reports", href: "#/reports", icon: "reports", cap: "read:reports" },
  { id: "connectors", label: "Connectors", href: "#/connectors", icon: "connectors", cap: "read:connectors" },
  { group: "Govern" },
  { id: "audit", label: "Audit", href: "#/audit", icon: "audit", cap: "read:audit" },
  { id: "settings", label: "Settings", href: "#/settings", icon: "settings", cap: "read:overview" },
];

let sidebarEl = null;

function visibleNav() {
  // Items the current role can reach; the server stays authoritative on 403.
  return NAV.filter((item) => !item.id || hasCap(item.cap));
}

function renderSidebar() {
  sidebarEl = document.getElementById("sidebar");
  clear(sidebarEl);
  sidebarEl.classList.toggle("collapsed", localStorage.getItem("nhi-sidebar") === "collapsed");
  for (const item of visibleNav()) {
    if (item.group) {
      sidebarEl.appendChild(el("div", { class: "nav-group" }, item.group));
      continue;
    }
    const a = el("a", { class: "nav-item", href: item.href, dataNav: item.id },
      icon(item.icon, 17),
      el("span", { class: "nav-label" }, item.label));
    sidebarEl.appendChild(a);
  }
}

function renderSidebarActive(navId) {
  if (!sidebarEl) return;
  for (const a of sidebarEl.querySelectorAll(".nav-item")) {
    a.classList.toggle("active", a.dataset.nav === navId);
  }
}

function renderTopbar() {
  const me = session.me;
  const topbar = document.getElementById("topbar");
  clear(topbar);
  const menuBtn = el("button", { class: "btn ghost small", "aria-label": "Toggle navigation" }, icon("menu", 18));
  menuBtn.addEventListener("click", toggleSidebar);
  const themeBtn = el("button", { class: "btn ghost small", "aria-label": "Toggle color theme" },
    icon(document.documentElement.dataset.theme === "light" ? "moon" : "sun", 16));
  themeBtn.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
    renderTopbar();
  });
  const initials = (me.display_name || me.email || "?").split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  topbar.appendChild(menuBtn);
  topbar.appendChild(el("span", { class: "title" }, "NHI Sentinel"));
  topbar.appendChild(el("span", { class: "tenant-chip", title: `tenant ${me.tenant_id}` },
    icon("shield", 13), me.tenant_name || me.tenant_id));
  topbar.appendChild(el("span", { class: "env-chip", title: "Synthetic demo environment (UX24)" }, "DEMO"));
  topbar.appendChild(el("span", { class: "spacer" }));
  // API24/UX12/VD10: global "Ask Sentinel" assistant toggle. The violet AI chip
  // is labelled per VD10 so it never implies generative agency.
  const askBtn = el("button", { class: "btn ai small", "aria-label": "Open the Ask Sentinel assistant panel" },
    el("span", { class: "chip ai", title: "AI - deterministic, citation-backed" }, "AI"),
    "Ask Sentinel");
  askBtn.addEventListener("click", openAssistantDrawer);
  topbar.appendChild(askBtn);
  topbar.appendChild(el("span", { class: "user-chip" },
    el("span", { class: "avatar", "aria-hidden": "true" }, initials),
    el("span", {}, el("div", {}, me.display_name || me.email), el("div", { class: "role" }, me.role))));
  topbar.appendChild(themeBtn);
  const logoutBtn = el("button", { class: "btn small" }, icon("logout", 14), "Log out");
  logoutBtn.addEventListener("click", async () => {
    try { await post("/v1/auth/logout", {}); } catch { /* session may already be gone */ }
    session.me = null;
    session.csrf = null;
    toast("Signed out.", "info");
    renderLogin();
  });
  topbar.appendChild(logoutBtn);
}

function toggleSidebar() {
  if (!sidebarEl) return;
  if (window.innerWidth <= 1024) {
    sidebarEl.classList.toggle("open");
  } else {
    const collapsed = sidebarEl.classList.toggle("collapsed");
    localStorage.setItem("nhi-sidebar", collapsed ? "collapsed" : "open");
  }
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("nhi-theme", theme);
}

/* ----------------------------------------------------------------- login --- */

const DEMO_USERS = [
  ["admin@demo.nhi", "tenant_admin"],
  ["analyst@demo.nhi", "analyst"],
  ["operator@demo.nhi", "operator"],
  ["approver1@demo.nhi", "approver"],
  ["approver2@demo.nhi", "approver"],
  ["reviewer@demo.nhi", "reviewer"],
  ["viewer@demo.nhi", "viewer"],
  ["auditor@demo.nhi", "auditor"],
];
const DEMO_PASSWORD = "demo-synthetic-only";

function renderLogin() {
  if (typeof currentTeardown === "function") { try { currentTeardown(); } catch {} currentTeardown = null; }
  document.getElementById("app-shell").hidden = true;
  const root = document.getElementById("login-root");
  root.hidden = false;
  clear(root);

  const email = el("input", { type: "email", autocomplete: "username", placeholder: "you@demo.nhi", required: true });
  const password = el("input", { type: "password", autocomplete: "current-password", placeholder: "password", required: true });
  const err = el("div", { class: "form-error hidden" });
  const submit = el("button", { class: "btn primary", type: "submit", style: "width:100%" },
    icon("shield"), "Sign in");

  const form = el("form", {},
    el("label", { class: "field" }, el("span", { class: "label" }, "Email"), email),
    el("label", { class: "field" }, el("span", { class: "label" }, "Password"), password),
    err, submit);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    submit.disabled = true;
    submit.textContent = "Signing in\u2026";
    try {
      const me = await post("/v1/auth/login", { email: email.value.trim(), password: password.value });
      session.me = me;
      session.csrf = me.csrf_token;
      root.hidden = true;
      document.getElementById("app-shell").hidden = false;
      renderSidebar();
      renderTopbar();
      toast(`Welcome, ${me.display_name} (${me.role}).`, "success");
      if (!location.hash || location.hash === "#/login") location.hash = "#/overview";
      navigate();
    } catch (ex) {
      err.textContent = ex instanceof Error && ex.code
        ? `[${ex.code}] ${ex.message}`
        : String(ex.message || ex);
      err.classList.remove("hidden");
    }
    submit.disabled = false;
    submit.replaceChildren(icon("shield"), "Sign in");
  });

  const card = el("div", { class: "card login-card" },
    el("div", { class: "brand" },
      icon("shield", 28),
      el("div", {},
        el("h1", { style: "font-size:22px;margin:0" }, "NHI Sentinel"),
        el("div", { class: "muted small" }, "Evidence-led non-human identity assessment"))),
    form,
    el("p", { class: "small muted", style: "margin-top:14px" },
      "Demo accounts all use the password ", el("code", {}, DEMO_PASSWORD), ". Pick a role:"),
    el("div", { class: "demo-users" },
      DEMO_USERS.map(([u, role]) => {
        const b = el("button", { type: "button", title: `sign in as ${role}` }, u.replace("@demo.nhi", ""), el("span", { class: "muted" }, ` \u00B7 ${role}`));
        b.addEventListener("click", () => { email.value = u; password.value = DEMO_PASSWORD; submit.focus(); });
        return b;
      })));

  root.appendChild(el("div", { class: "login-wrap" }, card));
  email.focus();
}

/* ------------------------------------------------------------------ boot --- */

async function boot() {
  setTheme(localStorage.getItem("nhi-theme") ||
    (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));

  onUnauthorized(() => {
    if (!session.me) return;
    session.me = null;
    session.csrf = null;
    toast("Session expired - sign in again.", "error", "SESSION_INVALID");
    renderLogin();
  });

  // Probe the session (cookie may still be valid from a previous visit).
  try {
    const me = await get("/v1/me");
    session.me = me;
    session.csrf = me.csrf_token;
  } catch {
    session.me = null;
    session.csrf = null;
  }

  if (!session.me) {
    renderLogin();
    return;
  }
  document.getElementById("app-shell").hidden = false;
  renderSidebar();
  renderTopbar();
  if (!location.hash) location.hash = "#/overview";
  navigate();
}

boot();
