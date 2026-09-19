/* views/exceptions.js - AT30/DC20 risk-acceptance queue: pending exceptions with
   finding link, justification, compensating controls, requester and expiry.
   Accept/Deny requires a reason and the approval:decide capability; the requester
   cannot decide their own exception - the server rejects with SELF_APPROVAL and
   the error envelope surfaces verbatim (EX07). */
import {
  el, get, post, icon, genericChip, fmtDateTime, countdown, canMutate,
  toast, toastError, formDialog, errorState, loadingState, emptyState,
  table, makeTimers, shortId,
} from "../core.js";

export async function viewExceptions(container) {
  const timers = makeTimers();
  container.appendChild(loadingState("Loading risk exceptions\u2026"));
  let exceptions;
  try {
    exceptions = await get("/v1/exceptions?status=pending");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewExceptions(container)));
    return null;
  }
  container.replaceChildren();

  const canDecide = canMutate("approval:decide");

  container.appendChild(el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Risk exceptions"),
      el("p", {}, "Risk acceptances requested by analysts. A separate approver must decide each request - the requester cannot accept their own exception (AT30/DC20). Expired exceptions reopen their finding for triage."),
      el("p", { class: "small muted", style: "margin-top:4px" },
        canDecide
          ? "You hold approval:decide - pending requests below can be accepted or denied with a recorded reason."
          : "Your role lacks approval:decide - the queue is read-only for you."))));

  if (!exceptions.length) {
    container.appendChild(emptyState({
      glyph: "\u2713",
      title: "No pending exceptions",
      message: "Nothing awaits a risk-acceptance decision. Analysts raise requests from a finding's detail drawer via \"Request risk exception\".",
      actions: el("a", { class: "btn primary", href: "#/findings" }, "Open findings"),
    }));
    return () => timers.clearAll();
  }

  const rows = exceptions.map((x) => exceptionRow(x, timers, canDecide));
  container.appendChild(table(
    ["Exception", "Finding", "Justification", "Compensating controls", "Requester", "Expires", "Decision"],
    rows));
  return () => timers.clearAll();
}

function exceptionRow(x, timers, canDecide) {
  const cd = el("span", { class: "small" });
  const tick = () => {
    const c = countdown(x.expires_at);
    cd.replaceChildren(c.expired
      ? genericChip("expired", "bad", "clock")
      : el("span", { class: "muted" }, c.text));
  };
  timers.every(1000, tick);

  const decisionCell = el("td", {});
  if (!canDecide) {
    decisionCell.appendChild(el("span", { class: "muted small" }, "-"));
  } else {
    const acceptBtn = el("button", { class: "btn small primary" }, icon("check", 13), "Accept");
    const denyBtn = el("button", { class: "btn small danger" }, icon("x", 13), "Deny");
    acceptBtn.addEventListener("click", () => decideDialog(x, "accept"));
    denyBtn.addEventListener("click", () => decideDialog(x, "deny"));
    decisionCell.appendChild(el("div", { class: "btn-row" }, acceptBtn, denyBtn));
  }

  return el("tr", {},
    el("td", {}, el("span", { class: "mono small", title: x.exception_id }, shortId(x.exception_id, 16))),
    el("td", {}, el("a", { class: "chip info", href: `#/findings?f=${encodeURIComponent(x.finding_id)}` },
      icon("findings", 12), "finding")),
    el("td", { class: "small", style: "max-width:260px" }, x.justification),
    el("td", { class: "small muted", style: "max-width:220px" }, x.compensating_controls || "-"),
    el("td", {}, el("span", { class: "mono small" }, x.requester_id)),
    el("td", {},
      el("div", { class: "small" }, fmtDateTime(x.expires_at)),
      cd),
    decisionCell);
}

function decideDialog(x, decision) {
  const isAccept = decision === "accept";
  formDialog({
    title: isAccept ? "Accept risk exception" : "Deny risk exception",
    message: isAccept
      ? `Accepting keeps finding ${x.finding_id} in workflow status "accepted" until ${fmtDateTime(x.expires_at)}, with ${shortId(x.exception_id, 16)} bound to it. The acceptance is audited with your reason.`
      : `Denying returns finding ${x.finding_id} to active triage; the requester is expected to remediate.`,
    fields: [
      { name: "reason", label: "Decision reason (required)", type: "textarea", required: true, min: 3 },
    ],
    submitLabel: isAccept ? "Record acceptance" : "Record denial",
    danger: !isAccept,
    note: el("div", { class: "reauth-note" },
      icon("alert", 15),
      el("span", {}, el("strong", {}, "Separation of duties: "),
        el("span", { class: "muted" },
          "the requester cannot decide their own exception. If you raised this request the server rejects the decision with SELF_APPROVAL."))),
    onSubmit: async (values) => {
      const out = await post(`/v1/exceptions/${encodeURIComponent(x.exception_id)}/decisions`, {
        decision, reason: values.reason,
      });
      toast(`Decision recorded: exception ${out.exception_id} is ${out.status}; finding workflow status: ${out.finding_workflow_status}.`,
        "success", "EXCEPTION_DECIDED", 9000);
      refreshAfterDecision();
      return true;
    },
  }).catch(toastError);
}

function refreshAfterDecision() {
  // Re-run the current route so the queue reflects the recorded decision.
  import("../app.js").then((m) => m.rerender()).catch(() => { location.hash = "#/exceptions"; location.reload(); });
}
