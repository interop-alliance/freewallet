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
