# 0021: The RxDB replication driver lives in its own package

- Status: accepted
- Date: 2026-09-05
- Driving work: the extraction design for the WAS replication driver for
  RxDB, approved 2026-09-05. Extracted at that design's approval, from its
  placement decision and its rejected alternatives.
- Affects: freewallet (`src/lib/sync/`, deleted; `src/stores/syncController.ts`,
  reduced to a session binding; `src/stores/contactsConflictHandler.ts`;
  `src/stores/browserStore.ts`'s schema import;
  `StorageManager.localCollection()`; `tests/conformance/crossReplica.test.ts`),
  `@interop/was-sync` (new), `@interop/was-react` (`src/sync/` deleted, its
  `storage/` modules reduced to bindings, the root barrel narrowed),
  `@interop/was-client` (a peer of the new package), byoe-ecosystem's
  dependency layer map.

## Context

The WAS replication driver for RxDB exists twice. Freewallet has a copy
under `src/lib/sync/`; was-react has a more developed one under
`src/sync/`. They were forked from one origin and have drifted. The
was-react copy grew four modules freewallet lacks, the two `pushWrites.ts`
copies differ by about 420 lines, and was-react carries a last-write-wins
rule that disagrees with social-core's `remotePayloadWins` on a pair where
only one `updatedAt` parses.

Neither consumer may depend on the other. Freewallet is a wallet;
was-react is an app framework carrying React, MUI, and Zustand peers. So
there is no canonical copy for the other to import, and no amount of
upstreaming produces one. A shared package is the only home one driver can
have. That is the structural argument the `@interop/vh-resource-log`
extraction already made.

A second constraint is packaging. was-react re-exports the whole driver
from its root barrel and declares `rxdb` as a non-optional peer, so a BYOE
app that only reads shared collections still installs RxDB. Freewallet has
the mirror-image constraint: its auth store imports the sync controller
statically, so the controller must not drag `rxdb` into the eager bundle
chunk.

## Decision

The driver lives in `@interop/was-sync`, a new package built from
was-react's copy with freewallet's behavioral deltas ported into it before
the move. Freewallet and was-react both consume it. Neither keeps a copy.

The package has three entry points, and the split is part of the contract:

- The root entry is free of RxDB, in its module graph and in its emitted
  declarations. It carries the shared types, the synced-doc schema, the
  conflict-handler factory, the last-write-wins stamp accessors, and the
  `writerId` mint.
- `./rxdb` carries the RxDB replication wiring and the controller core.
  Freewallet's session binding imports it dynamically inside `start`, which
  is what keeps RxDB out of the eager chunk. was-react's replica-less
  reader path resolves without it.
- `./testing` carries the in-memory server fake, the port literals, and the
  memory schedule and online source the controller tests need. Each
  consumer writes a lint restriction keeping it out of production globs.

`rxdb` and `@interop/was-client` are peer dependencies of the package;
`rxdb` is marked optional, since only `./rxdb` needs it. was-client is a
peer rather than a dependency so the consumer's single range decides which
copy resolves.

The package holds no key material and no logging opinion. The conflict
handler takes an injected resolver, the controller core takes an injected
port and an injected log port, and the collection set, the ciphers, and the
session gates stay app-side.

## Rejected Alternatives

- **A `./sync` subpath in was-react, with `rxdb` as an optional peer.**
  This is the declined fallback rather than a do-not-reopen rejection. It
  answers the packaging constraint at near-zero cost, and it is what this
  work falls back to if the package is declined. It cannot be the primary,
  because freewallet must not depend on was-react. Under it the
  duplication stays, and so does the last-write-wins divergence. Choosing
  it later is a decision record of its own.

  It is also a complement rather than only an alternative. The package's
  RxDB-free root removes the driver from a replica-less app's module
  graph, but was-react's root barrel still value-exports `LocalStore`,
  which value-imports `rxdb/plugins/core`. A missing package is a
  resolution failure rather than something a bundler can drop. So a
  replica-less install without `rxdb` needs a was-react entry-point split
  too, which is a separate was-react item filed at this approval.
- **Put the driver in wallet-core.** It would put an `rxdb` peer on a
  wallet library that dcw installs, and dcw has no RxDB anywhere.
  wallet-core's `sync` subpath runs on React Native with zero internal
  imports; a peer dependency on a browser storage engine inverts that.
  Do not reopen.
- **Put the driver in was-client.** was-client's scope is transport and
  the wire contract, held free of crypto by an import-graph test, and the
  ecosystem map keeps replica policy out of it. The driver is replica
  policy: checkpoint rules, write routing, conflict handling, the benign
  412 delete retry. wallet-core's `decisions/0009` rejected the same move
  for the engine on the same ground. Do not reopen.
- **Upstream the deltas and import one canonical copy.** That shape works
  when one side may depend on the other. Here neither may, so short of a
  third package there is nothing to upstream to. Do not reopen, for the
  same structural reason as the two above.

## Consequences

- Freewallet gains a dependency on `@interop/was-sync` and deletes
  `src/lib/sync/`. Its sync controller becomes a session binding: the
  guest, no-WAS, and replica gate, the port built from `session.storage`,
  the status callback, the browser online source, and the dynamic import
  of `@interop/was-sync/rxdb`. `StorageManager.localCollection()` goes
  behind the port, since it is the one facade member whose return type
  names RxDB.
- The cross-replica conformance harness re-points at the package, so it
  pins a published implementation against the engine rather than an
  app-internal module.
- The merged synced-doc schema is the union of the two copies, shipped at
  `version: 0` with no migration strategy. The union turned out to be
  freewallet's copy verbatim (only `createdBy` differed), so freewallet's
  replicas keep their stored schema hash and open unchanged; a freewallet
  test pins that. was-react's copy did change, so every remembered browser
  of an app on it needs one forget-and-log-in-again after the upgrade. That
  is the greenfield stance rather than an oversight, and the CHANGELOG
  entries say so. Transient sessions are untouched.
- The `writerId` mint moves into the package, parameterized by key prefix
  and over an injected storage port. Freewallet's localStorage key stays
  exactly `freewallet:writerId`, and the persistence strategy keeps
  deciding which storage tier answers.
- No Parties-table row lands in the WAS spec for the package. The driver
  speaks no WAS HTTP itself: every request goes through was-client's sync
  port, so by the table's admission rule the package is a downstream
  consumer like the wallets. was-client stays the one named speaker of the
  `changes` profile. byoe-ecosystem's layer map gains the package's node
  and its edges instead.
- The costs accepted: one more package to version and publish, a release
  train across five repos, and a lockfile audit after each step for one
  resolved copy each of the package, was-client, wallet-core, and `rxdb`.
  Two RxDB copies in one tree is the sharp case, since it breaks late and
  quietly, when a tab is hidden.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Freewallet retires its RxDB driver for the shared engine. Then there is
   one replica algorithm left, and the package's contents belong wherever
   that algorithm lives.
2. was-react and freewallet stop being independent, so one may depend on
   the other. That removes the structural reason the package exists, and
   the declined fallback above becomes available on its merits.
3. The engine moves out of wallet-core. The RxDB-free root entry was left
   free for it deliberately, and the package's name and layout are worth
   re-examining at that point rather than before.
