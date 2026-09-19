/* views/runs.js - UI03 mission list: mission/scope/state/started/duration with
   distinct state chips for every run state. */
import {
  el, get, icon, runStateChip, fmtDateTime, fmtDuration, table, errorState,
  loadingState, emptyState,
} from "../core.js";

export async function viewRuns(container, params, query) {
  container.appendChild(loadingState("Loading runs\u2026"));
  let runs;
  try {
    runs = await get("/v1/runs");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewRuns(container)));
    return null;
  }
  container.replaceChildren();

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Runs"),
      el("p", {}, "Assessment missions with mode, state and duration. Select a run to open the swarm workspace.")));
  container.appendChild(head);

  if (!runs.length) {
    container.appendChild(emptyState({
      glyph: "\u25CE",
      title: "No runs yet",
      message: "No assessment has been launched for this tenant. Findings and scores appear after the first passive run completes.",
    }));
    return null;
  }

  const stateFilter = query.get("state") || "";
  const filterRow = el("div", { class: "facets" },
    el("span", { class: "label" }, "State:"),
    buildFacets(runs, stateFilter));
  container.appendChild(filterRow);

  const shown = stateFilter ? runs.filter((r) => r.state === stateFilter) : runs;

  const rows = shown.map((r) => {
    const tr = el("tr", { class: "clickable", tabindex: "0", role: "link",
      "aria-label": `Open run ${r.run_id}` },
      el("td", {}, el("span", { class: "mono" }, r.run_id)),
      el("td", {}, el("span", { class: "mono muted small" }, r.engagement_id)),
      el("td", {}, r.mode),
      el("td", {}, runStateChip(r.state)),
      el("td", {}, el("span", { class: "mono small" }, `epoch ${r.epoch}`)),
      el("td", {}, fmtDateTime(r.created_at)),
      el("td", {}, fmtDuration(r.created_at, r.finished_at)));
    const open = () => { location.hash = `#/runs/${r.run_id}`; };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    return tr;
  });

  container.appendChild(table(
    ["Mission", "Engagement", "Mode", "State", "Epoch", "Started", "Duration"],
    rows));

  if (!shown.length) {
    container.appendChild(emptyState({
      glyph: "\u2205", title: "No matches",
      message: `No runs with state "${stateFilter}".`,
    }));
  }
  return null;
}

function buildFacets(runs, current) {
  const states = [...new Set(runs.map((r) => r.state))];
  const wrap = el("div", { class: "facet-group" });
  const mk = (label, value) => {
    const b = el("button", { class: `facet${current === value ? " on" : ""}` }, label);
    b.addEventListener("click", () => {
      location.hash = value ? `#/runs?state=${value}` : "#/runs";
    });
    return b;
  };
  wrap.appendChild(mk("All", ""));
  for (const s of states) wrap.appendChild(mk(s, s));
  return wrap;
}
