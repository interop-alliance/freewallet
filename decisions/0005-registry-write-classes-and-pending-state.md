# 0005: Registry write classes and the inferred pending state

- Status: accepted
- Date: 2026-08-23
- Driving work: the FW-292 design pass over the unlock-methods
  registry's write protocol
  (`_spec/designs/implemented/FW-292-unlock-registry-write-protocol.md`), run after
  the 2026-08-22 process review found five distinct tears in one week in
  the registry's interaction with the credential-rotation ceremony.
- Affects: freewallet (`src/session/unlockMethods.ts` and every ceremony
  that writes the registry), `@interop/wallet-core` (the helper
  extraction into `/unlock` inherits the contract; dcw inherits it only
  if it ever reverses its recorded no-registry decision).

## Context

The unlock-methods registry is one encrypted resource holding one entry
per unlock method, written by roughly fourteen sites across eight
modules under four authorities. Every write is a read-modify-write over
the whole record. The registry is an index: everything security-relevant
it records is verified elsewhere. A write that misnames a credential
(stamps one credential's fields on another's entry) still poisons every
consumer that keys on the entry, so the protocol's guards are about
naming, not authority.

## Decision

Registry writers split into two classes, and the split is
contract-binding on every current and future writer:

- An identity write may change which credential an entry names (create,
  the passphrase change's deferred entry write, the torn-retirement
  repair, the transient recovery's upsert). Only a ceremony or repair
  that has settled the direction against the account document may make
  one.
- A refresh write updates fields on the entry's existing credential. It
  must either derive its data from the entry itself, or carry the acting
  credential's `keyAgreementKeyMultibase` and write nothing on a
  mismatch.

For a ceremony that retires credential X while establishing or keeping
credential Y on the same entry, the retirement-reporting ordering holds:
X's standing configuration is read before anything durable happens (a
failed read refuses the ceremony); an entry naming a credential the
typed secret does not derive is refused as a pending retirement; the
entry is written last, after the retirement has reported, and it names
Y's configuration when the document edit landed, or X's restated
verbatim under Y's unlock Space when it did not. That restated state IS
the pending-retirement marker. It is inferred from fields that must be
correct anyway (entry names X, X is not the login credential, X still in
the document); no dedicated marker field exists.

## Rejected Alternatives

- An explicit pending-retirement marker field on the entry. Rejected as
  do-not-reopen: it is a new wire field needing sign-off, it duplicates
  state the inferred check derives from fields that must be correct
  anyway, and a marker can go stale independently of the fields it
  summarizes -- the failure mode the write protocol exists to close.
- Per-entry resources instead of one record. Finer write granularity
  would shrink the read-modify-write races. Rejected: the ceremonies
  need cross-entry atomicity (the recovery spend's replace-plus-drop;
  the change's single deferred write), and the single sealed envelope is
  the shipped shape.
- Making every registry write refusing (no best-effort class). Rejected:
  the registry is an index, and failing a login or a recovery over an
  index write inverts the dependency. Instead, every best-effort write
  names its detector, and refusal is reserved for writes whose absence
  strands authority.

## Consequences

- New writers must declare their class and carry the matching guard; a
  repoint (an `unlockSpaceId` change on the passphrase entry) is always
  an identity write, and the carry rule dropping standing fields across
  a Space change means a repoint must restate them explicitly or be a
  deliberate pending write.
- The pending state has exactly one mender (the torn-retirement repair
  at a passphrase login), so producers of the state may only run where
  that mender is reachable, and ceremonies that would destroy the
  mender's preconditions (the last-client transition) refuse on a
  pending entry.
- The races the classes leave between honest concurrent writers are
  bounded by fresh-base reads plus the CAS on the registry PUT (FW-299);
  against a tampering host the registry stays bounded as an index (an
  omitted entry loses an index row, not authority), a documented
  limitation.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A second pending-shaped state appears that the inferred check cannot
   distinguish from the retirement's (the marker-field rejection's
   stated criterion).
2. A ceremony appears whose correctness (not hygiene) depends on two
   entries updating independently under concurrent writers (the
   per-entry-resources rejection's stated criterion).
3. The registry stops being a pure index -- some consumer comes to treat
   an entry as a source of authority -- at which point the best-effort
   class and the replay bound both need re-deriving.

## Amendment (2026-08-28)

Revisit Criteria 3 was considered at FW-356's approval and is NOT met.

That design's first draft gave the unlock-methods registry a
`ladderVmKeyMultibase` field and let it decide which
`capabilityDelegation` key a credential retirement strikes from the
account document, which would have made an entry a source of authority.
The design's decision 9 replaced that approach rather than repairing it.
A retirement now attributes the ladder verification method from the
account log, by the signer of the entry that first published it,
anchored on the `updateKeyMultibase` the registry already records. The
log verifies that anchor, the strike is derived rather than trusted, and
an ambiguous attribution fails closed.

`ladderVmKeyMultibase` was retired before it was ever written, so no new
registry field ships and no consumer treats an entry as authority. The
registry remains a pure index, and this record's write classes,
best-effort class, and replay bound stand unchanged.

## Amendment (2026-09-03)

The browser wallet's design for running the account-management
ceremonies from a credential-only transient session, approved
2026-09-03, widens one Consequences bullet.

The actor rule is unchanged. It already reads "a ceremony or repair"
with no qualifier on the session's storage tier, and a ladder-branch
ceremony is such a ceremony.

The bullet saying that producers of the pending state may only run where
that mender is reachable is widened rather than dropped. The
ladder-branch passphrase change produces the pending state on a
client-less account, which may never see a remembered login. So the
torn-retirement repair, the bare-passkey rebuild, and the registry
backfill now run from a transient login too. They run on the same
ordered chain after navigation, invoking under the generation
delegation, with the acting credential's standing key-agreement key as
the unwrap key. The rule the bullet states holds; the set of places the
mender is reachable grew.

The tier guard that refused every registry write from a transient
session is retired with it. The write protocol's other guards do not
depend on the session tier. Every write is a compare-and-swap on the
ETag of a fresh read. A refresh write carries the acting credential's
key-agreement multibase and writes nothing on a mismatch. An identity
write is made only by a ceremony that has settled the direction against
the account document. `refreshTransientManageCapability`, the one
transient registry write outside a ceremony, keeps its narrow shape.

Revisit Criterion 1 was considered and is NOT met. No second
pending-shaped state appears; the ladder branch produces the same
inferred state the enrolled branch does, and the same repair detects it.

The write classes, the best-effort class, and the replay bound stand
unchanged.

## Amendment (2026-09-09)

Revisit Criterion 1 IS met, and this amendment resolves it.

A second pending-shaped state appeared. The enrolled branch of the standing
establishment writes the new credential's unlock record and roster wrap
before its document entry. A passphrase change torn between the two leaves
that record and wrap standing with nothing naming them: the registry still
names the old credential at the old unlock Space, and the document lists
only the old credential. The inferred check cannot distinguish that state
from an old passphrase logging in after a change that completed elsewhere,
nor from an abandoned torn passphrase after a later change succeeded. All
three read the same in the registry and the document. Establishing on
either of the other two readings would put a credential the account was
rotated off back into the document and retire the current passphrase, the
forbidden direction.

The decision:

- The pending-retirement marker stays inferred. Nothing here changes it,
  and the marker-field rejection stands for that state.
- An explicit establishment marker is added to the passphrase entry:
  `pendingEstablishment { unlockSpaceId, keyAgreementKeyMultibase }`, naming
  the credential being established.
- The carry rule is part of the field. `upsertPassphraseUnlockMethod`
  carries the marker forward only while a write keeps the entry on the same
  credential at the same unlock Space (a refresh, a backfill, a re-seal). An
  identity write naming another credential, and a repoint, drop it.
- One producer: the passphrase change's enrolled branch, an identity-class
  writer that has settled the direction against the account document. It
  stamps the marker onto the old credential's entry, restated at that
  credential's own unlock Space, before the establishment starts, and its
  final registry write drops the marker. The restatement comes from the
  fresh registry read the compare-and-swap wrapper hands over, and the write
  is skipped when that fresh entry names a credential other than the typed
  old passphrase. The stamp is a best-effort write; its detector is a retry
  of the same change, which re-runs it. An absent registry gets no marker,
  since that entry is the backfill's to write.
- The ladder branch stamps no marker. A transient session leaves nothing
  browser-local, so no later login could hold the new credential's
  client-key record and consume one. Its torn establishment is mended by a
  retry of the same change, and so is an add-a-passphrase run torn at the
  same point.
- One consumer: the torn-retirement repair's establish-first arm, at a
  passphrase login on the browser holding the new credential's client-key
  record. The arm fires only when the marker names the credential logging
  in, at that credential's own unlock Space, and the entry's own credential
  is still listed in the account document.

The original rejection's staleness concern is addressed rather than
waived. This marker can only go stale in the safe direction. A stale marker
names a credential whose sealed record either still matches the credential
logging in at its own unlock Space, in which case the mend is exactly the
abandoned change finishing, or does not exist, in which case the gate does
not match and nothing fires. The consumer's second gate covers the case
where the fields the marker summarizes moved under it: an entry whose own
credential a later ceremony retired (a recovery spend whose registry write
tore, say) is no longer a state the marked passphrase may be established
into, and the arm refuses there rather than reinstating an abandoned
passphrase over the account's current one. Any identity write drops the
marker, so a completed change leaves none behind, and the login-time
backfill carries the refresh write's identity guard so that it neither
repoints such an entry nor drops the marker. The registry stays an index:
the mend re-derives the ladder seed, the standing configuration, and the
retirement direction from the sealed record and the account document, and
the marker decides only whether to look.

The write classes, the best-effort class, and the replay bound stand
unchanged.
