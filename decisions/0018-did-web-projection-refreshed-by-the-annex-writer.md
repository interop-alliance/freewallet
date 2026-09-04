# 0018: The did:web projection is refreshed by the annex writer, not by the bridge

- Status: accepted
- Date: 2026-09-03
- Driving work: closing the stale `id/did.json` that a ladder-signed
  account-log entry leaves behind on a credential-anchored account. Found
  while retiring the wallet's standalone did:web mint, which made the
  projection the wallet's whole did:web story (`decisions/0017`).
- Affects: freewallet (`src/session/transientLogin.ts`,
  `src/session/forget.ts`), `@interop/wallet-core` `/webvh`
  (`ensureDidWebProjection`, `putDidWebProjection`) and `/clientAnnex`
  (`ladderSignedAccountEntry`'s `beforePublish`, `forgetEnrolledClient`,
  `forgetLastEnrolledClient`), the WAS deployment's `id` collection.

## Context

`id/did.json` is the did:web projection of the account log: the resolved
`did.jsonl` document with its ids rewritten. It is a derived cache of a
source of truth, and it is written by whoever holds a writer for the
account Space's `id` collection.

A ladder-signed entry holds no such writer. Every entry a standing unlock
credential publishes goes through wallet-core's `publishEntryPinned`,
which writes `did.jsonl` and nothing else, because the bridge delegation
carried in the unlock record is a PUT on exactly that resource.
`concludeWithPublishedLog`, the projection republish, ran on the
enrolled-client paths and the adopt branch alone.

So on a credential-anchored account the projection went stale and stayed
stale. After the last-client transition the forgotten client's
`authentication` verification method kept standing in `did.json`. After a
transient recovery the retired credential's `keyAgreement` entry did. Every
did:web verifier accepted keys the account had revoked, with no writer left
to correct the document. WAS authorization was never affected: the server
resolves a Space's controller by reading and verifying `did.jsonl` out of
its own storage, and reads `did.json` nowhere.

One authority already covers the resource. The generation delegation a
transient visit invokes under targets the account Space's items subtree,
and the server's client-annex clause admits it under its first predicate.
`id/did.json` is inside that subtree.

## Decision

Two writers keep the projection fresh, and neither widens any authority.

The removal ceremonies write it ahead of the entry that ends their
authority. `forgetEnrolledClient` and `forgetLastEnrolledClient` PUT the
post-removal projection through the still-standing enrolled client's own
root-authority `id` store, immediately before the ladder-signed removal
entry publishes (wallet-core's `beforePublish` seam on
`ladderSignedAccountEntry`). Freewallet supplies that store as
`clientLogStore`, required at both call sites. The idempotent
already-forgotten path writes no projection: the removal entry landed on an
earlier run, so that client's authority is already gone and its store can
only be refused.

Every transient visit is the standing mender. The transient composition
runs `ensureDidWebProjection` after the per-visit key is enrolled, since an
invocation under the generation delegation needs the visit's verification
method in the annex document first. It is aimed at the account Space's `id`
collection over a `delegatedWebvhLogStore`, signing as the annex
verification method. The ensure compares the served document against the
one it re-derives and writes only on a difference, so a healthy account
costs one GET and no write. The `id` collection is world-readable, so that
read is unauthenticated and only the republish invokes the delegation.

Two rules keep that write from undoing a concurrent writer's. The visit's
document was resolved at the start of the composition, so a difference alone
does not say which side is stale. On a difference the ensure calls the
caller's `refresh`, which re-resolves the account log under the visit's own
chain-head pins, re-derives, and re-compares; the write runs only when the
refreshed derivation still differs. And the PUT is a compare-and-swap on the
ETag of the read it was based on (`If-None-Match: *` when the projection was
absent), so a projection written in between stands and the ensure returns
the outcome `conflict` instead of throwing. The
ensure is best-effort and not awaited, and it runs for the CHAPI popup's
transient session too. A visit whose account mend published is the one
exception: it skips the ensure, because the document it holds may sit behind
the head that mend advanced to.

No server change, no spec change, and no new wire artifact: the resource
id, the content type, and the document shape are the ones the publish tails
already write.

## Rejected Alternatives

- Widening the bridge delegation to cover `did.json`. The server's
  client-annex clause admits a bridge-shaped target only as the account's
  own history log resource with PUT, so this needs a server predicate
  change and an amendment to app-connect-spec `decisions/0003`, plus a
  re-mint of every standing credential's bridge before any of it takes
  effect. It also buys a credential the ability to write a resource that is
  not a log, where every exercise of bridge authority today is itself a log
  append.
- Projecting `did.json` server-side from the log at read time. It puts a
  did:web special case inside a generic WAS resource route, so the server
  would have to know which resource in which collection is derived from
  which other one.
- Accepting the gap with a recorded bound. The projection is the wallet's
  whole did:web story after `decisions/0017`, and a stale document that
  publishes a revoked key is a revocation bypass rather than lag. A bound
  no writer can ever close is not a bound worth recording.

## Consequences

- A removal run torn between its projection PUT and its removal entry, or
  one whose entry loses its compare-and-swap and retries, leaves `did.json`
  omitting a client the log still lists. That is the fail-closed direction
  for a did:web verifier, and the re-run re-PUTs the projection.
- A window remains between the ensure's read of the served projection and
  its PUT. Another client publishing an inventory-removing entry and its
  correct projection in that window wins: the re-compare after `refresh`
  finds nothing to write, or the compare-and-swap refuses the write and the
  visit reports `conflict`. Either way the newer projection stands and the
  next visit is the mender.
- A window remains between a ladder-signed entry and the next visit that
  runs the ensure. A transient recovery's add-and-retire entry is the sharp
  case: the retired credential's `keyAgreement` entry stands in the
  projection until someone visits. A self-enrollment's add entry leaves the
  other direction, a projection under-listing a client the log has, which
  is fail-closed and was left open deliberately.
- The mender is a credential-only visit, so it fires on the default session
  type and on an account that never remembers a browser. The residue is a
  mended tear rather than an open gap
  (`decisions/0010-remembered-login-is-not-a-mender-trigger.md`).
- Every transient visit pays one extra GET against the `id` collection, a
  second GET of the account log only when the served projection differs, and
  a PUT only when it still differs after that.
- The projection still carries no signature and no chain. A host can freeze
  it or serve a different body per verifier with nothing to check it
  against. This decision does not touch that bound, and did:webvh
  resolution is the answer to it.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A WAS deployment serves the did:web projection from the log itself, at
   which point both writers become redundant and the freshness ensure is
   dead weight.
2. The projection gains its own integrity story, a signature or a witness
   over the derived document, which would change what a stale copy costs
   and where it may be written.
3. The server's client-annex clause changes what a bridge-shaped target may
   be. Widening the bridge to `did.json` is do-not-reopen while that clause
   stands as it does today.
