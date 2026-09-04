# 0013: The step-up ceremony is not the mender for a lapsed annex generation

- Status: accepted
- Date: 2026-08-28
- Driving work: the FW-356 design gate. Extracted at FW-356's approval,
  from that design's section 6, "Candidate B".
- Affects: freewallet (FW-208's step-up ceremony, the transient login's
  readiness stage), `@interop/wallet-core` (`clientAnnex/heal.ts`'s
  `ladder-vm-not-anchored` refusal and its doc comment).

## Context

A credential-only visit needs a generation delegation to invoke
anything, and that delegation has a one-year TTL. When it lapses, or
when the annex generation it names has been collected, something must
mint or renew it. On an account with enrolled clients the ladder VM was
struck at the first self-enrollment, so no credential-derived key in the
document could sign the replacement.

Two menders were on the table for that gap. Candidate A keys the ladder
VM's life to its credential, so the VM stands and signs the replacement
directly. Candidate B is FW-208's step-up ceremony: a loudly enrolled
in-memory client, bracketed by ladder-signed enroll and retire entries,
which would do the mend and then retire itself. B is attractive because
it leaves no standing delegation authority on the account, at a cost of
two permanent account-log entries per mend.

## Decision

The step-up ceremony is not the mender for a lapsed or collected annex
generation on an account with enrolled clients. Do not reopen.

The rejection is scoped to candidate B as the sole mender for that gap.
FW-208 is untouched in its main purpose: the twelve account-management
ceremonies it gates behind `StepUpRequiredError` each need an invoking
client, which a ladder VM structurally is not.

The primary reason is structural: candidate B presupposes candidate A.
A credential's only write path into the account log is the bridge
delegation carried in its unlock record, and both of the step-up
ceremony's entries go through it. There is no ladder-signed,
root-invoked, or annex-side alternative in either repo, and the server's
client-annex clause opens none -- it requires the proof verification
method to resolve as a ladder VM in the account document, which is
exactly what the self-enrollment strike removes. In the states B is
proposed to mend, that bridge is dead: it is minted under an enrolled
client's account key, the strike is account-wide while the login-time
refresh handles the login credential alone, a plain forget re-mints
nothing by design, and the one-year TTL expires on its own. So B needs a
standing ladder VM to have a live bridge to start from, and A is what
makes the VM stand. Remove the standing VM and B breaks again; keep it
and A has already closed the gap.

The secondary reason kept from the original pass: a phished credential
holder never needs the step-up ceremony, because they can already
self-enroll. Its loudness therefore constrains the honest user rather
than the attacker.

## Rejected Alternatives

- Candidate B as the sole mender, per the reasoning above.
- Candidate B as the mender for the subset of accounts that have
  enrolled a client, with candidate A left out. Same failure: those are
  precisely the accounts whose bridge the strike killed.

## Consequences

- wallet-core's `clientAnnex/heal.ts` doc comment, which names the
  step-up ceremony as the mender for an account with enrolled clients
  and no ladder VM, is false and is corrected. freewallet's
  ARCHITECTURE.md carried the same claim and was corrected 2026-08-28.
- The class B gap in the transient-refusal analysis belongs to FW-356,
  not to FW-208. FW-208's item records that the step-up ceremony
  depends on a live bridge delegation.
- A standing ladder VM per standing credential is the accepted cost.
  What bounds it is credential retirement, the server's client-annex
  clause, and FW-358's owner-visibility surface.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. FW-208 gains an entry into the account log that does not depend on a
   standing ladder VM. That is the premise the primary reason rests on,
   and nothing in either repo provides such a path today.
2. The server's client-annex chain clause is removed, or cannot be
   relied on across the hosts an account may move to, so that a standing
   `capabilityDelegation` key stops being bounded.
3. The annex log's record of a mend proves insufficient as an audit
   trail even with FW-358's surface built.

## Amendment (2026-09-03)

A clarifying amendment, from the browser wallet's design for running the
account-management ceremonies from a credential-only transient session,
approved 2026-09-03.

The Decision's premise holds as written. A ladder VM structurally is not
an invoking client, and nothing here changes that. What the record could
not yet say is that the ceremonies do not need the ladder VM to invoke.
On the ladder branch the invoker is the annex VM, acting under the
generation delegation the ladder VM signed. So the twelve
account-management ceremonies this record described as each needing an
invoking client now have one, without the step-up ceremony.

The Decision's closing sentence, that the step-up item is untouched in
its main purpose, is therefore superseded. That item was retired
2026-09-03, and its ceremony is rejected for the whole class rather than
for this record's one mender (`decisions/0020`). The scoped rejection
recorded here widens to that class and stands.
