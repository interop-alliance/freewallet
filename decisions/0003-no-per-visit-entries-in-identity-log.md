# 0003: No per-visit entries in the identity log

- Status: accepted
- Date: 2026-08-19
- Driving work: the public-computer posture redesign for the browser
  wallet (default persist-nothing login; per-visit transient clients).
  The transient client class needed a membership venue, and the obvious
  one -- the account's own did:webvh document, with expiring
  verification methods -- was analyzed and rejected.
- Affects: freewallet and every other wallet publishing the account's
  did:webvh log; `@interop/wallet-core` (the companion log machinery
  that exists because of this rejection); the companion profile's spec
  text.

## Context

The account's stable identity is a did:webvh whose hash-chained log is
world-readable. The method's shape sets the costs: every log entry
carries the full document state (update entries clone the whole prior
document), the log is append-only with no compaction, resolution is a
full-log walk (hash chain, prerotation, per-entry signatures), and
every entry's versionTime is public and permanent. A transient login
from a public terminal happens per visit, not per membership change.

## Decision

Per-visit facts do not belong in the identity log. Transient client
membership is recorded in a disposable companion did:webvh, referenced
by one typed pointer in the account document. The companion is
garbage-collected by wholesale replacement: a fresh DID (new SCID,
empty log), a pointer update in the account document, deletion of the
old log. The account log gains one small pointer-update entry per GC
cycle instead of two entries per visit.

## Rejected Alternatives

- Expiring verification methods in the account document, one per
  visit. Three compounding costs. Size: pruning a lapsed VM edits the
  current document, but the entries recording its add and its prune
  stay forever, each a full document snapshot -- at roughly 2 entries
  per visit plus an amortized prune share, 3-5 KB per entry, a daily
  public-terminal user accretes on the order of 2-4 MB per year,
  permanently, and un-pruned VMs inflate every other entry published
  while they stand. Latency: per-visit entries convert a log designed
  for low-frequency membership change into an access log, with
  thousands of signature checks before any login, ceremony read,
  popup, or server-side authorization proceeds. Privacy: versionTime
  per entry is world-readable and permanent, so the identity log
  becomes a public record of when and how often the user logged in
  from public terminals.
- The sidecar as a roster-style verified resource log rather than a
  second did:webvh. Same anchoring idea, but it requires the server to
  grow a new verifier class for authorization inputs, and its
  rolling-window retention fights the chain-head pin -- a rolling
  window is exactly what that pin refuses, so it needs new
  scoped-freshness continuity semantics invented for it.

## Consequences

- A second did:webvh lifecycle exists (companion genesis, generation
  GC, deletion), with its own ceremonies and failure modes.
- Consequences residue: the account log still gains one permanent,
  versionTime-stamped pointer-update entry per GC cycle, a coarse but
  permanent public proxy for transient-use frequency -- bounded by the
  fixed quarterly GC cadence, deliberately not usage-driven.
- GC deletes the owner's only per-entry audit record of the collected
  window's visits; the GC ceremony writes an owner-side digest before
  the delete, and detection of a past compromise ends at the digest's
  granularity.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. did:webvh gains native compaction or checkpointing as a spec
   feature, so per-visit entries stop being permanent and stop
   inflating verification.
2. The identity log ceases to be world-readable, removing the privacy
   cost (the size and latency costs would still need answers).

If revisited, per-visit membership must not silently degrade
resolution latency for every consumer of the account document.
