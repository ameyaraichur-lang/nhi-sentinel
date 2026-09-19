/* views/approvals.js - UI05 approval inbox: pending proposals with template,
   expected effects, rollback, action digest prefix, live expiry countdown,
   recorded approvers and "1 of 2 approvals" progress. Approve/deny requires a
   reason AND password re-auth; server error codes (SELF_APPROVAL,
   STALE_APPROVAL, DUPLICATE_ACTOR, PROPOSAL_EXPIRED) surface verbatim. */
import {
  el, get, post, icon, genericChip, fmtDateTime, countdown, canMutate,
  toast, toastError, formDialog, errorState, loadingState, emptyState, makeTimers,
} from "../core.js";

export async function viewApprovals(container) {
  const timers = makeTimers();
  container.appendChild(loadingState("Loading proposals\u2026"));
  let proposals;
  try {
    proposals = await get("/v1/proposals");
  } catch (err) {
    container.replaceChildren(errorState(err, () => viewApprovals(container)));
    return null;
  }
  container.replaceChildren();

  const head = el("div", { class: "page-head" },
    el("div", { class: "grow" },
      el("h1", {}, "Approval inbox"),
      el("p", {}, "Sensitive actions require two separate human approvals bound to the proposal digest, with re-authentication.")));
  container.appendChild(head);

  if (!proposals.length) {
    container.appendChild(emptyState({
      glyph: "\u2713",
      title: "No proposals",
      message: "There is nothing awaiting approval. Proposals appear here when the platform or an analyst requests a sensitive action.",
    }));
    return () => timers.clearAll();
  }

  const stack = el("div", { class: "stack" });
  for (const p of proposals) stack.appendChild(proposalCard(p, timers));
  container.appendChild(stack);
  return () => timers.clearAll();
}

function proposalCard(p, timers) {
  const canDecide = canMutate("approval:decide");
  const approvals = p.approvals || [];
  const approveCount = approvals.filter((a) => a.decision === "approve").length;
  const expired = new Date(p.expires_at).getTime() < Date.now();
  const done = p.status !== "pending";

  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "rowflex", style: "justify-content:space-between" },
    el("div", { style: "min-width:0" },
      el("h2", {}, icon("approvals"), p.title || p.template),
      el("div", { class: "rowflex", style: "margin-top:4px" },
        genericChip(`kind: ${p.kind}`, "ai"),
        genericChip(`template ${p.template} v${p.template_version}`, "neutral"),
        statusChip(p.status, expired)))));

  // Two-column: effects/rollback vs approvals state (side-by-side per UI05)
  const cols = el("div", { class: "card-grid grid-2", style: "margin-top:12px" });

  const left = el("div", {});
  left.appendChild(el("span", { class: "label" }, "Expected effects"));
  const eff = el("ul", { class: "small", style: "margin:0 0 10px;padding-left:18px" });
  for (const e of p.expected_effects || []) eff.appendChild(el("li", {}, e));
  left.appendChild(eff);
  left.appendChild(el("span", { class: "label" }, "Rollback"));
  left.appendChild(el("p", { class: "small", style: "margin-bottom:10px" }, p.rollback || "-"));
  left.appendChild(el("span", { class: "label" }, "Action digest (immutable revision binding)"));
  left.appendChild(el("div", { class: "mono small", style: "overflow-wrap:anywhere" }, p.action_digest));
  const pre = el("pre", { class: "codeblock" }, JSON.stringify(p.payload, null, 2));
  left.appendChild(el("details", {}, el("summary", { class: "small muted", style: "cursor:pointer" }, "Payload"), pre));
  cols.appendChild(left);

  const right = el("div", {});
  right.appendChild(el("span", { class: "label" }, "Approvals"));
  const progress = el("div", { class: "rowflex", style: "margin-bottom:8px" });
  for (let i = 0; i < p.required_approvals; i++) {
    progress.appendChild(el("span", { class: `chip ${i < approveCount ? "ok" : "neutral outline"}` },
      icon(i < approveCount ? "check" : "clock", 12),
      i < approveCount ? "approval recorded" : "approval pending"));
  }
  right.appendChild(progress);
  right.appendChild(el("p", { class: "small muted", style: "margin:0 0 10px" },
    `${approveCount} of ${p.required_approvals} approvals recorded. Two distinct humans are required; the proposer cannot approve (SC05).`));
  const recorded = el("div", { class: "stat-list" });
  if (!approvals.length) {
    recorded.appendChild(el("p", { class: "small muted", style: "margin:0" }, "No decisions recorded yet."));
  }
  for (const a of approvals) {
    recorded.appendChild(el("div", { class: "row" },
      el("span", { class: "mono small" }, a.actor_id),
      genericChip(a.decision, a.decision === "approve" ? "ok" : "bad", a.decision === "approve" ? "check" : "x"),
      el("span", { class: "muted small" }, `"${a.reason}"`),
      el("span", { class: "muted small mono" }, fmtDateTime(a.decided_at))));
  }
  right.appendChild(recorded);
  const cd = el("p", { class: "small", style: "margin:10px 0 0" });
  right.appendChild(cd);
  const tick = () => {
    const c = countdown(p.expires_at);
    cd.replaceChildren(
      c.expired && p.status === "pending"
        ? genericChip("EXPIRED - decisions disabled", "bad", "clock")
        : el("span", { class: c.expired ? "muted" : "" }, `Window ${p.expires_at ? "closes " : ""}${c.text}`));
  };
  timers.every(1000, tick);
  cols.appendChild(right);
  card.appendChild(cols);

  // Decision buttons
  if (p.status === "pending") {
    const row = el("div", { class: "btn-row", style: "margin-top:14px" });
    if (!canDecide) {
      row.appendChild(el("span", { class: "muted small" },
        "Your role lacks the approval:decide capability - decisions are made by approvers."));
    } else if (expired) {
      row.appendChild(el("span", { class: "muted small" },
        "Proposal window has expired; the server will reject further decisions (PROPOSAL_EXPIRED)."));
    } else {
      row.appendChild(decideBtn(p, "approve", card));
      row.appendChild(decideBtn(p, "deny", card));
    }
    card.appendChild(row);
  }
  return card;
}

function decideBtn(p, decision, card) {
  const isApprove = decision === "approve";
  const btn = el("button", { class: `btn ${isApprove ? "primary" : "danger"}` },
    icon(isApprove ? "check" : "x"),
    isApprove ? "Approve" : "Deny");
  btn.addEventListener("click", async () => {
    try {
      await formDialog({
        title: isApprove ? "Approve proposal" : "Deny proposal",
        message: `${isApprove ? "Approving" : "Denying"} "${p.title || p.template}". Your decision is bound to the current action digest.`,
        fields: [
          { name: "reason", label: "Decision reason (required)", type: "textarea", required: true, min: 3 },
          {
            name: "reauth_password", label: "Re-enter your password to authorize", type: "password",
            required: true, autocomplete: "current-password",
            hint: "Sensitive approvals require fresh re-authentication (SC05).",
          },
        ],
        submitLabel: isApprove ? "Record approval" : "Record denial",
        danger: !isApprove,
        note: reauthNote(),
        onSubmit: async (values) => {
          const out = await post("/v1/approvals", {
            proposal_id: p.proposal_id,
            proposal_digest: p.action_digest,
            decision,
            reason: values.reason,
            reauth_password: values.reauth_password,
          });
          toast(`Decision recorded. Proposal status: ${out.status}.`, "success", "APPROVAL_OK");
          refreshAfterDecision();
          return true;
        },
      });
    } catch (err) {
      // handled inline by the dialog; safety net:
      toastError(err);
    }
  });
  return btn;
}

function refreshAfterDecision() {
  // Re-run the current route so the proposal card reflects the recorded decision.
  import("../app.js").then((m) => m.rerender()).catch(() => { location.hash = "#/approvals"; location.reload(); });
}

function statusChip(status, expired) {
  if (status === "pending" && expired) return genericChip("expired", "bad", "clock");
  const map = {
    pending: ["warn", "clock", "pending"],
    approved: ["ok", "check", "approved"],
    denied: ["bad", "x", "denied"],
    expired: ["bad", "clock", "expired"],
    revoked: ["bad", "ban", "revoked"],
    redeemed: ["neutral", "check", "redeemed"],
  };
  const [cls, ic, label] = map[status] || ["neutral", "question", status];
  return genericChip(label, cls, ic);
}

function reauthNote() {
  return el("div", { class: "reauth-note" },
    icon("key", 15),
    el("span", {},
      el("strong", {}, "Re-enter your password to authorize this decision. "),
      el("span", { class: "muted" },
        "The server verifies the password again before recording the approval; a wrong password is rejected with REAUTH_FAILED.")));
}
