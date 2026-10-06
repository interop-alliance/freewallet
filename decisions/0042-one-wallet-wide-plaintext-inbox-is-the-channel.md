# 0042: One wallet-wide plaintext inbox is the channel a party reaches the wallet by

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences, which needs a way for
  a subscription agent and the wallet to deliver capabilities to each
  other when neither can reach the other except through storage.
  Extracted at that design's approval.
- Affects: freewallet (the `inbox` provision-roster collection, the
  login-time drain, the `#inbox` target class on the interaction-URL
  page, the renewal push), wallet-core (the envelope codec on `/space`,
  the `grantsReceived` channel record), app-connect-spec (the `#inbox`
  descriptor type and the envelope), was-teaching-server and the WAS
  spec (`createdBy` on every Resource, WASS-58's exact target), the
  agent (its own Space with an inbox).

## Context

Renewal is a delivery problem in both directions. The wallet mints a
renewed grant for the agent and has to hand it over. The agent holds a
capability on its own inbox and has to hand that to the wallet. Neither
side has a standing endpoint the other can call: the wallet is a browser
tab, and a direct call to the agent's URL would be a second contract
with its own reachability and CORS. Both sides do have WAS Spaces, and a
WAS server authenticates every writer and records the invoking DID as
`createdBy` on the Resource it creates.

DIDComm needs per-connection mediation because it has no
server-authenticated writer. WAS has one, so the minimum here is
smaller.

## Decision

The owner's Space carries one `inbox` collection, display name "Inbox",
plaintext, `grantable: false`, in the provision roster, never replicated.
A party reaches the wallet by holding a POST zcap whose
`invocationTarget` is the inbox container URL with no `*` marker, so it
covers the container alone: the holder can create a Resource and can
neither list, read, overwrite, nor delete, and reaches no query
endpoint. The grant is issued only through the `#inbox` descriptor type
in an interaction-URL connection request, never through App Connect in
this build, and a plain URL string naming the inbox is refused under the
never-grantable rule.

A message is the envelope `{ type: 'Grant', actor, object: { zcaps } }`,
`application/json`, with no context member. The wallet attributes a
message by the server-recorded `createdBy` and refuses one whose `actor`
differs. The zcaps it carries authenticate themselves. The message is
not signed. The wallet drains its inbox at login and deletes every
message it read, refused or not.

The agent runs the mirror: its own Space with an inbox, and it hands the
wallet a POST zcap on it by posting that zcap into the wallet's inbox as
its invitation. From then on the wallet pushes renewed grants into the
agent's inbox through the entry's `outbox` (record 0044), and the agent
pushes into the wallet's. An inbox the wallet cannot trust, one that is
public, carries an `encryption` descriptor, or carries a `generator`
stamp, is refused and counts as absent.

## Rejected Alternatives

- **Per-connection inboxes.** Flooding is bounded by the Space quota
  either way, and the server authenticates the writer, so one inbox per
  party buys isolation nothing needs. Not planned; it may be reopened
  (see Revisit Criteria), unlike the rest of this list.
- **Direct HTTP to the agent's URL as the channel.** A second contract,
  agent reachability, and a browser's CORS to an arbitrary host, for
  what the WAS channel already carries. The renewal push is itself a
  request to the agent's host, but it rides the WAS capability the
  agent delegated, which is the one contract.
- **A mailbox Resource in the owner's Space**, in three variants.
  Inside the audience collection: every subscriber reads it and every
  feed carries a non-post. A well-known Resource in the agent's own
  collection: unreadable after the passphrase-change cut, which is
  exactly when it is needed. A wallet-wide outbox with Resource-depth
  grants: three new artifacts for one use.
- **A signed Verifiable Presentation as the envelope.** A presentation
  with no credential, and a canonicalization plus a signature per
  message, to prove what `createdBy` already proves.
- **Message signing in general.** The server-recorded invoker is the
  authentication. A body-level signature would duplicate it and give a
  host nothing it cannot already forge by other means.
- **Reading the inbox through a replica.** The inbox is transient mail
  with no sync engine; a replica would re-read every refusal.

## Consequences

- A connection request on a server that does not promise `createdBy` is
  refused, since the drain could attribute nothing. The spec must make
  `createdBy` required for this use or advertise it.
- The inbox grant is the one write grant a requester may hold on a
  wallet collection, and it takes the share lifetime, as this channel's
  exception to the write-bearing rule.
- No backfill: an older account with no inbox, a transient-only account
  that deleted it, and an adopted untrusted inbox are declared open gaps
  (record 0036 as amended).
- A POST-only holder learns nothing from the inbox. A reader of it would
  learn the owner's connections, which is why it is never grantable for
  reads.
- The owner's remedy against a flooding agent is deleting the inbox's
  contents and revoking the agent; a per-collection quota is a later
  item.
- The key layer must keep this rule: an inbox carrying an `encryption`
  descriptor is untrusted to every wallet built now.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A deployment shows one party flooding the shared inbox to the point
   that the Space quota, the per-pass byte cap, and the per-sender
   budget do not keep another party's invitation readable. Per-connection
   inboxes are then the candidate.
2. The WAS spec drops or makes optional the `createdBy` the drain
   attributes by, in which case message signing returns as the
   alternative.
3. A message kind arrives that must be read by a party other than the
   wallet, which the never-readable rule forecloses.
