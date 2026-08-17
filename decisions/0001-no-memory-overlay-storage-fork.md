# 0001: No memory-overlay storage fork for session persistence

- Status: accepted
- Date: 2026-08-17
- Driving work: the default public-computer login posture (a login
  persists nothing locally unless the user opts into remembering the
  browser). Its first implementation shipped as a read-through
  in-memory overlay over IndexedDB and was reverted the next day; this
  record is the rejection that revert enacted.
- Affects: freewallet only (the `freewallet-session` layer, the RxDB
  replica, the descriptor and meta caches, and every ceremony that
  persists key material).

## Context

Freewallet's local persistence is invariant-dense. Ceremonies persist
key material before publishing log entries, the forget and
account-deletion remedies promise complete removal of local traces,
and continuity pins must only move forward. All of these assume that a
write to local storage is durable. The public-computer posture needs
the opposite default: a non-remembered login must leave nothing on
disk, while reads still see whatever durable state the browser already
holds (pins keep protecting, a remembered browser stays enrolled).

## Decision

The local persistence layer keeps a single code path, and a write's
durability must be visible at the write site. Expressing ephemerality
by interposing a second storage backend -- a read-through in-memory
IDBFactory (or equivalent transparent factory) that silently redirects
writes away from durable state -- is rejected and must not be
re-proposed in that shape.

## Rejected Alternatives

The overlay itself, implemented and reverted (freewallet commit
fec4c9c, dropped from the branch; the revert is the driving event).
It forked every persistence path into two invariant regimes, durable
and overlay, without any write site knowing which regime it was in.
The branch review found the fork's interaction bugs across unrelated
surfaces: a durable log publication whose staged key material died
with the tab, forget and account-deletion runs that missed durable
state or deleted only in memory, a cache lifecycle split into two
disconnected instances, and a first-contact read that durably created
the database the posture promised not to create. Each bug was the same
defect instantiated at another write site, and every future write site
would have inherited the hazard.

## Consequences

- The posture goal stands and still needs a design: the redo must
  express ephemerality in the data or the session lifecycle (for
  example, a persistence handle whose type states its durability), so
  that durable-publish ceremonies can refuse or demand durability
  explicitly.
- Until that design lands, the wallet keeps the prior behavior:
  logging in remembers the browser.
- The reverted implementation remains in git history for reference;
  its review findings are carried as design inputs for the redo.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The persistence layer has been narrowed to a single seam where
   every write site receives a typed persistence handle, so a second
   backend could no longer be silent -- at that point an overlay is
   just an implementation of the typed seam, and the objection
   dissolves.
2. The web platform ships a native ephemeral-storage mode for
   IndexedDB (bucket-scoped or session-scoped storage) that replaces
   the hand-rolled factory with a browser-enforced one.

If revisited, prefer an explicit, typed seam over a transparent
interposed factory: the defect class was silence, not memory-backing.
