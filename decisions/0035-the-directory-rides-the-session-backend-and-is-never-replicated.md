# 0035: The directory rides the session backend and is never replicated

- Status: accepted
- Date: 2026-10-01
- Driving work: the design of the `connections` directory, which had to
  pick a storage path for a mutable collection every session kind reads
  and writes. Extracted at that design's approval.
- Affects: freewallet (`src/stores/storageManager.ts`'s directory store
  seam and its two adapters, `src/stores/browserStore.ts`'s collection
  set, `src/app.config.ts`'s collection sets, the local descriptor mint
  `localOnlyDescriptors`, `src/stores/syncController.ts`, the replica
  registration ceremony, which leaves the directory in the copy); dcw
  (the same seam).

## Context

Every synced standard collection is replicated to a local RxDB replica
and merged on conflict. The directory's entries are mutable and carry
grants, so a replica merge has to decide which grants survive when two
sides diverge: a union resurrects a grant one side revoked, and
last-write-wins drops a grant one side added. Revocation also has to
read current server state, not a replica that may lag.

A guest session and a no-WAS deployment have no Space, yet App Connect
still mints an app key there, and the user needs a surface that lists
and removes it.

## Decision

The directory is never replicated to a local replica. It is outside the
synced collection set, and the sync controller never touches it.

Server-to-server replication is a different axis. A replica server's
copy of the account Space includes the `connections` collection as
ciphertext, since the copy is whole (0050), and a login against the
replica would need it there. That copy raises no merge question. The
replica server applies the source's changes one way, and the wallet
neither reads nor writes the copy while the source stands. The
directory keeps one writer and one grant index, on the source Space
(0034).

It rides the session's storage backend through one store seam with two
adapters. On a session with a Space it is read and written remote-direct:
listings read the documents feed with ETags, a write re-GETs only its own
entry, and every write is a read-modify-write under `ifMatch` or a create
under `ifNoneMatch`. On a guest or no-WAS session it is a local RxDB
collection on the generic synced-doc schema, the only copy, and the
consent-time write and every listing run there unchanged. Such a
session's entries are `app` entries with empty `grants`.

The local descriptor mint installs the blinded-index key beside epoch[0],
as the remote mint does, so the keyed id derivation holds on every
session kind.

The admitted-recipient resolver fails closed when the directory
collection is absent, a listing fails, or an entry cannot be decrypted;
it never reads an absent or withheld directory as empty.

## Rejected Alternatives

- **Replicate the directory with a conflict handler.** The merge dilemma
  above; direct reads under `ifMatch` have neither problem.
- **A guest Applications page listing app-key rows from the key
  collection.** A second listing source and a carve-out in the
  acceptance criteria, for a session that has the same storage pattern
  as every other collection.
- **No guest listing.** A guest-minted app key would have no surface
  that shows or removes it short of wiping the profile.

## Consequences

- Listings on a session with a Space need the network. A transient
  session already does for everything; a remembered session's
  Applications page goes remote for this one read.
- `BrowserStore` gains one RxDB collection that is never replicated and
  that only the local adapter reads or writes.
- Reading a withheld directory as empty would evict every co-admitted
  party at the next rotation, so a withheld directory stops rotations
  instead.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A merge rule for per-entry `grants` is defined that neither
   resurrects a revoked grant nor drops an added one, for example a
   per-grant tombstone the revocation writes.
2. Offline revocation becomes a requirement, which needs a local copy
   and the merge rule above.
3. Server-to-server replication becomes two-way, so a replica server's
   copy of the directory can be written and merged back into the
   source.

## Changelog

- 2026-10-26: Scoped the rule to the wallet's own local replica, and
  stated that a replica server's server-to-server copy of the directory
  is a different axis the rule does not forbid. Added revisit criterion
  3 for two-way replication. The rule for the local replica is
  unchanged.
