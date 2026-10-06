# 0044: A party's pending messages queue on its connection entry

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences. The review found that
  a renewal whose push to the agent failed was never retried before the
  renewed grant itself fell due, about eleven months on, while the
  agent's old grant lapsed and its subscribers were cut. Extracted at
  that design's approval.
- Affects: freewallet (the renewal pass, the drain of each entry's
  outbox, retirement), wallet-core (`recordRenewedGrants`,
  `settleOutboxItem`, the entry codec's `outbox` member), dcw (the same
  pass), and the message kind a later seed rotation adds.

## Context

A renewal mints a fresh zcap, records it on the agent's entry, and must
hand it to the agent by posting an envelope into the agent's inbox. The
record and the push are two writes to two servers. Nothing durable told
a pushed renewal from an unpushed one, so a failed push was lost until
the renewed record's own expiry made it due again. The renewed record
also replaces the one the agent still holds, so the loss is invisible to
every invariant that reads grant records alone.

A fix has to make the push's pending state durable in the same write
that records the renewal, or the two can disagree after a tear. The
entry is written by compare-and-swap, so a member on it is atomic with
the grant record. A separate Resource is not.

## Decision

An agent's connection entry carries `outbox`, a list of pending
messages to that party. Each item is `{ message, createdAt }`: the
envelope verbatim, the exact body the drain will POST, and the queueing
time in ISO 8601 UTC. An item names no channel. `recordRenewedGrants`
writes the renewed grant records and the pending envelope in one
compare-and-swap, so the queue item is atomic with the renewal's pivot.

After recording, the pass drains every entry's outbox. Each message is
POSTed through the live `inbox` record with the latest `expires`,
selected at push time. An item is removed on success, kept on a network
error or a 5xx, and discarded once every zcap it carries is past
`expires`. A same-scope renewal replaces the pending envelope of that
scope, and removes the superseded zcap from an older envelope carrying
several scopes. A 401 or 403 drops the channel record, and the items
wait for the next invitation. Retirement empties `outbox` with
`grantsReceived`. The agent adopts by zcap id, so a repeat after a torn
removal is harmless.

The list is general to any message kind. A seed-rotation message rides
it the same way.

## Rejected Alternatives

- **A derived re-push rule**, sending a renewed record again at every
  pass while its superseded predecessor still stands. No wire field,
  but it ties delivery to another record's lifetime, re-pushes for the
  predecessor's whole remaining life, and serves renewals alone; a
  rotation message would need its own mechanism.
- **A `pushedAt` member on the renewed grant record.** Marks delivery
  per grant, so it cannot carry another message kind, and it is a
  second write per push.
- **A global `outbox` collection.** A second Resource is not atomic with
  the entry. Making its row the pivot moves the pivot, needs an
  HMAC-keyed row id, and needs per-party sweeps.
- **A `channel` member on the item**, as the inbox record's zcap id or
  a copy of its zcap. A stale reference needs the drain-time fallback
  anyway, and a stale copy is invoked after the held record changed.
- **A flat item**, the envelope with `createdAt` added and sent
  verbatim. Queue bookkeeping travels to the agent, and later queue
  members have no namespace of their own.

## Consequences

- A failed push is retried at every pass until it succeeds or every
  zcap it carries has expired, with no second mechanism.
- Superseded grant records stay on the entry until their own expiry,
  since a replaced body would strand a still-live zcap past every
  revoke. A superseded record whose chain is dead is pruned sooner,
  once the item carrying its successor is removed on success.
- The entry grows by one pending envelope per unpushed scope, bounded
  by the number of scopes the agent holds.
- `recordRenewedGrants` refuses a retired entry and leaves `retired`
  untouched, unlike `recordGrants`, which a fresh consent runs.
- Any future message to a party is queued the same way, so the entry
  is the one place a wallet's outbound state lives.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A message kind arrives that must be delivered before the entry it
   belongs to can be written, or to a party that has no entry.
2. The entry's size bound is reached by outbox items in practice, which
   would argue for a per-party queue Resource with the entry as its
   index.
