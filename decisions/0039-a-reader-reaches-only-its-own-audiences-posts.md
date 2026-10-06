# 0039: A reader reaches only its own audience's posts

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences for social software,
  where a user's posts are readable by a set of people and each post
  carries its own access level. Extracted at that design's approval.
- Affects: freewallet (the audience collection layout and the grants it
  delegates), wallet-core (`/audiences`), was-react (the member-side
  reader), app-connect-spec (the agent connect section), and the deferred
  gate note.

## Context

A collection read zcap is collection-level. The server serves every
Resource in the collection to any holder: GET and HEAD, `/meta`, the
listing, the `changes` feed, and the `blinded-index` query. Nothing is
filtered per caller. With every post of a user in one collection, a
friends-only reader sees that every post exists, when it was written,
how often it changed, its size, and its `createdBy`. In the key layer
the body stays sealed to another audience's epoch. In the cleartext
layer, the body is readable, so a collection read grant is a read of
every post regardless of audience.

## Decision

No design ships in which a reader's grant reaches a post outside the
reader's audience. The cleartext layer meets the rule by partitioning:
one plaintext collection per audience, membership a GET and HEAD zcap on
that collection's container (`delegateAudienceGrant` in wallet-core's
`/audiences`). A later layer may meet it by a server-side gate instead.
Either way, the rule is the invariant, and accepting the leak is not a
step on the way to it.

## Rejected Alternatives

- **One collection, every member reads every post (accepting the
  leak).** Rejected as never the end state, and rejected again as an
  interim: once apps and readers are built against one shared
  collection, moving to either partitioning or a gate is a data
  migration under live subscribers, and the readers built meanwhile
  have read posts they were not meant to. Do not re-propose this as a
  first build.
- **Accepting the metadata leak alone, with bodies sealed per audience.**
  The key layer's variant. It still tells every member how often and
  how much the owner writes to audiences they are not in, and it does
  not exist in the cleartext layer, where there is no sealed body.

## Consequences

- A post that changes audience moves between collections under
  partitioning. Apps keep a stable post id of their own and merge one
  feed per audience (record 0040 states the partitioning and the
  deferred gate).
- The rule holds for the agent's grants as well as the owner's: an
  agent holds one grant per audience collection and re-delegates per
  audience, never a Space-wide read.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The WAS spec defines a per-caller filter on a collection read under
   its authorization profile, so one collection can serve different
   subsets to different valid holders. That satisfies the rule by other
   means and is the gate pivot, not a reopening of the leak.

The rule itself is not reopened by scale or convenience arguments; those
were the arguments for the leak.
