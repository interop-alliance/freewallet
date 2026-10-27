# 0045: The replica pointer lives in the annex document

- Status: accepted
- Date: 2026-10-26
- Driving work: the design that lets every session kind, the transient
  default included, register a replica server and copy the account onto
  it. Extracted at that design's approval.
- Affects: freewallet (the replica registration ceremony, whose pivot
  writes the pointer; the replica pass, which restates and reconciles
  it; the restate sites in the transient readiness stage
  `src/session/transientLogin.ts`, the transient recovery spend
  `src/session/recovery.ts`, and the remembered login's annex GC sweep),
  wallet-core (`/clientAnnex`: the pointer's builder and reader, the
  restate in every installing path in `gc.ts`, `heal.ts`, `log.ts`, and
  `recoveryLadderAnchored.ts`, and the `log.ts` header's account of
  which entry installs which service entries), app-connect-spec
  (decision 0001: the pointer's entry type on the annex document, and
  the restate rule beside the generation delegation's install rule),
  was-teaching-server (the ladder clause's replica-pull predicate reads
  the pointer), portable-web-spaces-spec (the replication decision 0013
  amendment, and the `ReplicaServer` term in the pws context).

## Context

A credential-anchored account copies itself to a replica server through
a pull delegation its ladder VM signs. Under decision 0002 that exercise
of credential-derived authority must rest on a record in a hash-chained
log. Something has to name each replica server before any delegation
names it, and the source server has to be able to check that record on
every pull.

Two documents could carry the record. The account document is
world-readable and its log is permanent. The annex document is the
client-annex did:webvh the account document's `DelegatedClients` entry
points at. Its Space is capability-gated, so its readers are the
account's own sessions, its storage host, and, once copied, the replica
servers. Its log is garbage-collected: a GC swap mints a fresh
generation from a bare genesis and collects the old one. The source
server already reaches the pointed annex DID through the
`DelegatedClients` entry when it checks a ladder-signed delegation.

## Decision

Each replica server is named by one service entry in the pointed annex
document. Its `type` is `https://w3id.org/pws#ReplicaServer`, its
`serviceEndpoint` is the bare `serverDid`, and its id's fragment is
`#replica-<multihash>`. The `<multihash>` is the SHA-256 multihash of
the `serverDid` string, base64url with no padding. So the id is the
same on every restate, and a reader may match an entry by id or by
endpoint. Its shape follows app-connect-spec decision 0001.

A standing credential's annex rung writes the pointer. The ladder kind
appends as the acting credential's rung, through the sibling
delegation. The enrolled kind appends as the login credential's rung,
from the `ladderSeed` a remembered login stamps on the profile, through
the controller-tier store. A remembered session whose login credential
is not standing holds no rung, and the registration refuses before it
writes anything. The pointer lands before any delegation names the
server, and it is the registration ceremony's pivot.

The pointer is restated at every fresh generation. Genesis stays bare.
Every path that mints a fresh generation installs that generation's
delegation in one entry, either the GC swap's install stage or the
entry publishing the generation's first transient method. That
installing entry also carries every replica pointer the restate
predicate selects. The predicate selects a `replicas` item that has no
`stoppedAt`, sits on an entry that is not `declined`, and carries a
recorded pull grant whose proof verifies as this account's. An item
with no recorded grant is not restated, so the ceremony's inert first
write publishes nothing, and a planted entry is not restated.

The connections directory is the source of record for the restate.

- The remembered GC swap reads the directory. The superseded annex
  document's pointers serve only as a cross-check there, so a pointer
  with no entry is not carried forward.
- A ladder-kind fresh mint runs before the user key is read, so the
  directory is out of reach. On its uncommitted-rung arm, which already
  reads the superseded generation's log for the rung restate, the
  install entry carries that document's replica pointers forward. On
  its dead-generation and Space-gone arms there is nothing to read.
  There the replica pass restates in a post-assembly stage of the same
  visit.
- In every case the replica pass then reconciles the pointed annex
  document against the directory. It drops a pointer with no verified
  entry, and restates an entry the predicate selects that has no
  pointer.

A swap whose directory read fails restates nothing and proceeds. The
swap is not blocked on the directory.

## Rejected Alternatives

- **The pointer in the account document.** It is permanent and
  world-readable, and the replica server could read it during
  registration. Rejected on 2026-10-24: "Broadcasting to the world at
  large which other servers a space is replicated to is unacceptable."
  Do not reopen.
- **The restate in the genesis.** The pointer names the `serverDid`,
  not the SCID, so unlike the generation delegation it could ride the
  genesis. That would break the bare-genesis convention every annex
  reader relies on, for no gain. The installing entry lands before the
  account re-point either way.
- **The post-assembly restate alone on a ladder-kind fresh mint.** The
  directory stays the only source, at the cost of a pointer-less window
  of seconds on every common mint, during which the source server
  refuses every ladder-signed pull. The carry-forward closes that window
  on the uncommitted-rung arm. Its cost is that a pointer with no entry
  survives one carry-forward, until the same visit's pass drops it.

## Consequences

- The record is gated, not public. An outside observer of the DID
  cannot see which servers hold a copy.
- The record is mortal. A collected generation takes its entries with
  it, and the GenerationCollect digest keeps only counts and times. A
  hostile pointer the owner never saw is gone after the next swap,
  together with the evidence that it existed.
- The restate is a new duty on every generation-minting path, and a
  missed one is a new residue class. A swap that misses it stops every
  ladder-signed pull to that server until the replica pass restates.
  That is seconds on a full login. A generation minted in a CHAPI popup,
  where the pass does not run, stays pointer-less until the next full
  login. An enrolled-signed pull is not gated and does not stop. The
  duty is the invariant `pointed-annex-names-every-replica-server`,
  converged by the replica pass on both login chains, which a
  credential-only visit fires.
- The source server's check costs one did:webvh resolution of the annex
  log out of its own storage. The verified-document cache revalidates on
  the log's ETag and re-verifies from genesis whenever the log moved.
  On a credential-anchored account the pointed generation grows by one
  entry per transient visit, so the first pull after each visit
  re-verifies a growing log.
- The pointer is consistent with portable-web-spaces-spec decision
  0013's rejection of a service entry as the registration locator. The
  server makes no request to the endpoint the pointer names. It reads
  the pointer as a fact of a verified log, to gate a delegation it is
  already verifying.
- wallet-core's `clientAnnex/log.ts` convention changes. The installing
  entry carries the generation delegation and the replica pointers, and
  genesis carries neither.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The annex log gains a durable record of its service entries across
   generations, so a fresh generation inherits the pointers without a
   restate.
2. The transient readiness stage gains the directory before its install
   entry, so the carry-forward from the superseded annex document can
   be dropped.

If revisited, the account document stays rejected as the pointer's
home. A replacement home must keep the replica-server set out of a
world-readable document.
