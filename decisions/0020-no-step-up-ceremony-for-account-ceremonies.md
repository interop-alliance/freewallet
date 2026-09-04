# 0020: The step-up ceremony is not how a transient session runs the account ceremonies

- Status: accepted
- Date: 2026-09-03
- Driving work: the browser wallet's design for running the
  account-management ceremonies from a credential-only transient
  session. Extracted at that design's approval, from its rejected
  alternatives.
- Affects: freewallet (`src/session/persistence.ts`'s
  `assertAccountCeremonyAllowed` and `StepUpRequiredError`,
  `src/session/enrolledContext.ts`, every Settings ceremony wrapper,
  `src/session/accountSettings.ts`'s
  `BrowserLocalSessionRequiredError`), `@interop/wallet-core` (the
  ceremony bodies whose account-log signer, roster store, and HTTP
  invoker become parameters).

## Context

Eleven Settings and Storage ceremonies refused on a transient session.
The refusal was one gate, `assertAccountCeremonyAllowed`, throwing
`StepUpRequiredError` on any in-memory session. The default session is
transient and the default account is credential-anchored, so on most
accounts those ceremonies were unreachable for the account's whole life.

One long-standing candidate for closing that gap was the step-up
ceremony. A transient session would self-enroll a loud in-memory client,
run the unchanged enrolled-client ceremony code inside that bracket, and
close with a ladder-signed retire entry. Its appeal was that it needed no
per-ceremony work at all.

The alternative is a ladder branch per ceremony. The transient session
already holds four authorities stamped at login, and three whole
ceremonies already run on them: the transient recovery, the last-client
transition, and account deletion.

## Decision

The step-up ceremony is not the mechanism by which a transient session
performs the account-management ceremonies. Do not reopen.

Each ceremony gains a ladder branch instead. The ladder rung signs the
account-log entry through the acting credential's bridge delegation. The
ladder VM signs the licensed roster append and any delegation the
ceremony mints. The annex VM invokes every HTTP request under the
generation delegation. The ceremony body takes its signer, roster store,
and invoker as parameters, so one body serves both branches.

`StepUpRequiredError` and the session-kind gate are deleted. No ceremony
refuses on the kind of session any more. One name survives and one is
added:

- `BrowserLocalSessionRequiredError` stays for the two ceremonies whose
  subject is this browser, which are update-key rotation and forgetting
  this browser.
- `ActingCredentialRemovalError` is new. Removing the acting passkey
  from its own transient session would strike the VM that session acts
  under, so the removal function raises it and Settings disables that
  row with copy pointing at a login with another credential.

## Rejected Alternatives

- **The step-up ceremony itself.** Five failures against the ladder
  branch. It writes three world-readable entries per ceremony where the
  ladder branch writes one. It puts a root-tier invoking key in tab
  memory. A run torn after its enroll entry leaves an orphan client that
  is authorization-live until someone removes it, and a client-less
  account has no actor to remove it. Every rotating ceremony inherits
  the recipient self-exclusion problem, since the ceremony's own
  in-memory client stands in the document the recipient resolver reads.
  And it cannot start without a live bridge delegation, which is the
  dependency `decisions/0013` records. Its one advantage, zero
  per-ceremony work, reduces to a signer parameter once the ceremony
  bodies take their signer as input, which they already do for the
  roster store and the invoker. `decisions/0014` rejected the same
  shape for one ceremony, as "a loud ephemeral enrolled client"; this
  record rejects it for the class.
- **A pre-pivot refusal pointing the user at a remembered session.** An
  earlier draft refused a passphrase change, a passkey removal, or a
  client disconnect when the strike would rot a sibling credential's
  unlock record, and told the user to run it from a remembered browser.
  That is the step-up ceremony under another name, reached from the
  other side. It makes the account's documented leaked-credential
  remedy conditional on the very enrollment the design exists to avoid,
  on exactly the accounts that are the default. It blocks nothing an
  attacker cannot route around, since a credential holder can
  self-enroll and run the enrolled branch. And it degrades with
  ordinary use, because every recovery code issued from a transient
  session would plant a permanent refusal in every later ceremony on
  that account. The dependency was removed instead. Every unlock record
  is now signed by its own credential, which is wallet-core's record of
  that rule, so a strike rots only the record the same ceremony
  deletes.

## Consequences

- Settings shows the same controls on both session kinds. The three
  strings telling a user who just typed their passphrase to log in with
  their passphrase are deleted.
- The CHAPI popup needs no code gate. Its pages are the two wallet
  request pages and nothing else, and no route inside a CHAPI-managed
  iframe reaches Settings or Storage, so deleting the error name leaves
  nothing there to refuse.
- Each ceremony body now carries a branch conditional in its stage
  order, and each ladder branch owes its own tear story. That is the
  per-ceremony cost the step-up ceremony would have avoided, and it is
  accepted.
- Downstream code may rely on the invariant that session kind is not an
  authorization input for these ceremonies. What a session may do
  follows from the keys it holds.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A re-proposal states what a user holding only their credential does
   when the refusal fires. That is the question both rejected shapes
   left unanswered. A proposal that does not answer it is not a
   reopening.
2. The ladder branch proves unable to express some ceremony's stage
   order, so that ceremony needs an invoking key the annex VM cannot
   stand in for. Then the answer is that ceremony's own design, not a
   revival of the bracket for the class.
