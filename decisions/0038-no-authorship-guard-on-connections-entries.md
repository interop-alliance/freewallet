# 0038: No authorship guard on `connections` entries

- Status: accepted
- Date: 2026-10-01
- Driving work: the question FW-612's design left open, of what the
  storage host can do to a `connections` entry, tracked by FW-620.
- Affects: freewallet (the directory's reader rules; the replica pass's
  restate and renewal; the host-bound prose in ARCHITECTURE.md and
  `docs/architecture/app-connect.md`). No wire contract, and no change to
  any shared package's API.

## Context

Each `connections` entry is an EDV envelope, sealed to the public key the
collection's `encryption` descriptor publishes for the current epoch. The
host cannot read an entry. It can write one, though, at any resource id it
has observed. It cannot compute the id a given party's DID derives to,
since that id is an HMAC under the blinded-index key. Nothing authenticates
an entry's body. The question was whether to guard against a host-written
(planted) or rolled-back entry.

Three reader rules already bound a planted entry:

- Every reader drops a grant whose `zcap.controller` is not the entry's
  `id`, and one whose target lies outside this Space. On a
  `replica-server` entry, the Spaces its `replicas` items record as
  `fromSpace` count as this Space, so the auxiliary Space's pull grant
  stays visible until it is revoked.
- A disconnect deletes an app key only when the key's own seed derives the
  entry's `id` (`appKeySeedBindsSubject`).
- The admitted-recipient resolver fails closed, so nothing rotates, when
  the directory is absent or refused, or holds an entry it cannot decrypt.

Under those rules a plant can only put a party's own genuine capabilities
back at that party's own id. The host holds every capability a party ever
invoked, since an invocation carries the full capability. Serving an older
version of the same Resource, a rollback, does the same thing.

Two guards were weighed. One signs each entry, as the unlock-methods
registry record is signed: an eddsa-jcs-2022 proof by the Ed25519 key the
user key derives. The other pins each entry's ETag in an in-memory store
for the visit.

## Decision

No authorship guard. An entry carries no signature, and no reader pins its
ETag. The three reader rules above are the bound, and they stay as they
are.

wallet-core's
`decisions/0027-directory-codec-reads-leniently-and-writes-strictly.md`
already lists both guards as deferred. Its revisit criterion, "an
authorship proof the host cannot forge, verified before decrypt", stays the
hook for reopening this record.

## Rejected Alternatives

- **Sign each entry.** It stops a plant. It does not stop a rollback,
  because the rolled-back body carries the wallet's own valid signature.
  The unlock-methods registry accepts the same replay limit, and
  `decisions/0012-no-durable-continuity-pins.md` leaves cross-session
  continuity to the log layer. What signing alone adds is refusing
  host-authored content: `name`, `label`, the advisory `writers` list,
  `lastSeen`, and a `retired` flip. A rollback or a withheld entry already
  has the flip's effect. The cost is a new wallet-core signer for a plain
  object, and a `proof` member with an entry `version` bump, a permanent
  layout in wallet-core's wire constants. Every entry would be re-signed at
  each user key rotation, as the registry re-seal does, and dcw's writer
  would sign too. Verifying before decrypt would also need the proof
  outside the EDV envelope. That is a new stored layout, since the Resource
  body today is the bare envelope.
- **Pin each entry's ETag for the visit.** Weaker than signing. The ETag is
  host-asserted, so a plant met on first sight passes. The pin dies with
  the tab. The local adapter's RxDB revisions are not ETags.
- **Both.** The pin catches a rollback only after this visit has seen a
  later version. A rollback served at the visit's first read still passes.
  The pair leaves the same bound as signing alone, at both costs.

## Consequences

- The host can roll an entry back, or plant a party's genuine capabilities
  at its own id. A departed party can reappear as a listing row with its
  genuine, already-revoked grants. A re-disconnect then POSTs those
  already-revoked capabilities again, harmlessly.
- The host can rename a listing row through `name` or `label`, and flip a
  registered writer's advisory liveness. Neither is an input to any
  authorization decision.
- A rollback can drop a grant a later consent added, so the next rotation
  of that collection leaves its party out of the fresh epoch. Withholding
  the entry has the same effect.
- No rolled-back entry re-admits a party whose rotation landed. A rotation
  wraps the fresh epoch only to the current epoch's recipients, minus the
  retiring ones, and only to those the directory admits.
- A planted grant cannot steer a revocation at another party, since a grant
  whose `zcap.controller` is not the entry's `id` is dropped.
- The history rows carried the same class of residue: a revoked party's
  genuine old grant still vouching for it at a rotation (FW-573). That was
  closed by ordering grants against Revoke records, not by signing.
- Renewal of agent grants (record 0043 and the cleartext audiences
  design) ends the harmlessness of a replayed entry. A replayed or
  restored pre-revoke agent entry is unretired, carries genuine grants
  and a live channel, and the renewal pass re-mints those grants to the
  revoked agent. The residue is bounded: it covers only genuine grants
  whose signing authority is still listed and whose `expires` has not
  passed when the entry comes back. A grant a withdrawn authority signed
  is outside silent renewal, a lapsed grant returns only by the owner's
  tick, and the renewal's own rules close a torn revoke, a revoke racing
  a renewal, and grants a later-revoked client planted. The pairwise
  seed, the one member a plant could use to speak as the wallet, carries
  its own HMAC tag under the blinded-index key, so a planted seed is
  refused and a replayed seed is the genuine one.
- Replica servers carry the same residue (the replica registration
  design, 2026-10-26). The replica pass turns `replica-server` entry
  content into wallet-signed annex pointers and minted pull grants. A
  planted entry carries no wallet-signed grant, so no restate selects
  it, and the pass finishes a torn registration only from a rung-signed
  annex pointer plus an entry whose grant proof verifies. A planted
  entry therefore stays in the not-set-up state. The residue is a
  rollback. A host that serves a pre-Stop or pre-Delete body whose grant
  proof verifies can resume a stopped replica, or re-create a deleted
  one, through the pass's renewal, until the user stops it again. Stop
  revoked the rolled-back grant at the source, so a restated pointer
  admits nothing for it, but the renewal mints a fresh one. The pass
  does not ask the source whether a grant is revoked, since no such
  read exists. The Storage page shows the resumed replica. A withheld
  entry makes a legitimate pointer look orphaned, and the pass drops
  it, which stops that pull until the user re-starts it.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A reader comes to trust entry content the three rules do not bound. For
   example, a `contact` kind or an audiences producer that acts on `name`
   or `label`. Met 2026-10-05 by agent-grant renewal; answered with the
   bounded residue and the seed tag above, not with a signature, since
   signing would still not stop a replay of a genuine entry. Met
   again 2026-10-26 by the replica pass's restate and renewal; answered
   with the bounded rollback residue above, for the same reason.
2. The log layer gains witnessing, or the Resource Log Profile gives a
   plain Resource a verifiable version. Rollback then becomes detectable,
   and signing would close the plant half as well.

A drop in the cost of signing is not a reason to reopen. Signing would
still buy only authorship of the free-text members, which criterion 1
covers.

## Changelog

- 2026-10-05: Revisit criterion 1 was met by the renewal of agent
  grants. The record was refined rather than reversed: no signature is
  added, the seed gains a keyed tag, and the Consequences state the
  bounded replay residue renewal leaves.
- 2026-10-26: Revisit criterion 1 was met again, by the replica pass's
  restate and renewal of `replica-server` entries. Refined, not
  reversed: no signature is added, the reader rule's Space check covers
  a replica-server entry's recorded source Spaces, and the Consequences
  state the rollback residue a replica carries.
