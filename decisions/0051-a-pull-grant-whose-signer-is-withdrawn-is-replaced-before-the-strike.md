# 0051: A pull grant whose signer is being withdrawn is replaced before the strike

- Status: accepted
- Date: 2026-10-26
- Driving work: the design that lets every session kind, the transient
  default included, register a replica server and copy the account onto
  it. Extracted at that design's approval.
- Affects: freewallet (the dialogs of client revocation, the
  last-client transition, the passphrase change, and the passkey and
  backup-credential removals, `src/session/revocation.ts`,
  `src/session/forget.ts`, `src/session/credentialRotation.ts`; the
  lapsed-offer reading in `src/session/agentReconnect.ts`; the replica
  pass's withdrawn-signer row; the Storage page's lapsed state),
  was-teaching-server (the replicas route's delegated invocation and the
  in-place capability replacement the replacement rides), dcw (the
  lapsed-offer reading of a pull grant whose signer
  `revokeAccountClient` revoked).

## Context

A pull grant verifies only while its signer is listed in the account
document as resolved now. A client revocation or forget kills an
enrolled-signed grant. A passphrase change, a passkey or
backup-credential removal, or a recovery spend kills a ladder-signed
one. Decision 0043 keeps a grant signed by withdrawn authority out of
silent renewal, since a withdrawal may answer a compromise, and the
compromised party may be the one that registered a hostile replica.

After promotion, the replica server verifies every maintenance call
against its own copy of the account log, which advances only by pulls.
A ladder-signed pull stops the moment its VM is struck. If the copy then
predates the new credential's ladder VM, every maintenance call and
replica DELETE by the new VM is refused, forever, on a
credential-anchored account. The retired ladder VM keeps that reach on
the live replica from the frozen copy.

## Decision

Decision 0043 applies to replica servers as it does to agents. The pass
never re-mints a withdrawn signer's pull grant silently.

A client revocation, the last-client transition, and a credential
rotation list, in their dialogs, the replica servers whose pull grant
the withdrawn key signed, read off each grant's proof. This holds on
both account-ceremony context kinds. A remembered session's passphrase
change strikes a ladder VM that may have signed a replica's grant on an
earlier transient visit.

- Ticked, on a client revocation or the last-client transition: once
  the ceremony resolves, the acting authority re-mints the grant, and
  the replacement swaps it into the registration in place.
- Ticked, on a passphrase change or a passkey or backup-credential
  removal: the replacement runs before the strike. The new grant is
  signed by the VM that survives the ceremony. On a passphrase change
  that is the new credential's ladder VM, which the establishment entry
  has already published. On a removal it is the acting credential's
  own. The replacement call on the replica's replicas route is signed
  by the departing VM, which the replica's copy still lists. The
  ceremony then polls the replica's status, with a bounded wait, until
  the copy's log head includes the establishment entry, and strikes only
  after that. A replica that does not catch up inside the bound refuses
  the ceremony before its pivot, naming the replica server. The user may
  untick that server and re-run.
- Unticked: write `declined` on the entry first, pause the
  registration, drop the replica pointer, and revoke every recorded pull
  grant, whoever signed it. The copy stays as a snapshot. Only the
  user's explicit Re-start clears `declined`.

The ordinary forget and a recovery spend take no tick in their own
visit, nor do the dialog-less strike-or-swap callers and dcw's client
revocation. The lapsed-offer surface therefore reads withdrawn
authority generically, off each grant's proof, and does not key on
which ceremony withdrew it. Until that surface exists, the Storage page
offers the re-connect.

A recovery spend has no pre-strike window, since the pointer moves
atomically with the retirement. Its frozen copy on a credential-anchored
account is an accepted gap, under the invariant
`replica-pull-grants-are-current`, kind `none`, on the ladder shape.

## Rejected Alternatives

- **Re-mint a withdrawn signer's pull grant silently.** It would
  re-enable a replica a compromised client registered, the moment the
  owner revokes that client. Decision 0043's reasoning applies. Do not
  reopen.
- **Replace after the strike on the rotations.** The copy may predate
  the new ladder VM, when the establishment and the strike fall inside
  one pull interval or the loop is backing off. The replacement is then
  refused forever, and the retired VM keeps its reach.
- **State the frozen copy as an accepted consequence on every
  ceremony.** The rotations have a pre-strike window that removes it,
  as the generation delegation's pre-pivot renewal already does.

## Consequences

- An account ceremony now reaches a third-party server before its
  pivot. A slow or backing-off replica can hold a passphrase change
  until the user unticks it. The refusal keeps the ceremony re-runnable.
- After a recovery spend, a replica of a credential-anchored account
  cannot be maintained or deleted by the new credential, and the
  retired ladder VM keeps its maintenance and DELETE reach from the
  frozen copy. The server holding the frozen copy refuses a second
  registration of the same source Space, and refuses the new
  credential's DELETE, so the account can do nothing with that copy.
  The remedy is a registration at a different replica server. The
  frozen Space is removed by its server's operator, or unfrozen once a
  login against a replica can append to the copy's log directly. The
  wallet lists it as lost.
- Every restored pull grant is recorded as a fresh consent, with its
  own Grant activity.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A replica-side log append lets the new credential's ladder VM reach
   a frozen copy, which closes the recovery spend's gap.
2. The replica server can read the source's current account log when
   it verifies a maintenance call, so the copy's lag no longer decides
   what verifies and the pre-strike poll can go.
3. One of decision 0043's own revisit criteria holds.
