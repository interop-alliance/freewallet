# 0052: The App Connect holder is the pairwise connection did:key

- Status: accepted
- Date: 2026-10-31
- Driving work: giving a connected app a stable wallet identity for the
  connection, now that every connection entry can carry a pairwise seed every
  client of the account derives the same did:key from. Supersedes rule 2 of
  0016; the connection request's holder (0016's 2026-10-05 refinement) was the
  precedent.
- Affects: freewallet (`src/lib/walletRequest/appConnect.ts`'s holder
  override, `respond.ts`'s seed resolver, the consent's entry write, the
  ceremonies that withdraw signing authority); dcw (the same override); app-
  connect-spec (`decisions/0004` and the response presentation's holder
  text); was-react (the holder forms an app may see); wallet-core
  (`decisions/0032`, the seed on an `app` entry and its rotation).

## Context

0016 pinned the App Connect response's holder and its DIDAuth proof key to the
client did:key: the enrolled client's on a remembered session, the visit key's
bare did:key on a transient one. On a transient session, the default, that
holder is unlinkable across visits, so it binds nothing. An app sees a fresh
wallet identity every time the same account connects, and the app-key
credential's subject DID is the only thing that ties the visits together.

The cleartext audiences build gave every agent's connection entry a pairwise
`seed`, written once at consent, from which the wallet derives one did:key
toward that party. A connection request's presentation already holds and
signs as that key. The same seed can sit on an app's entry, and the same
resolver already does the work: a stored seed is taken once its tag verifies,
an absent one is minted with its tag, and a seed whose tag fails refuses the
consent, since the host is misbehaving.

A stable key is only as good as its custody. A client the owner revokes may
hold a copy of every seed it read, and would keep presenting as the wallet to
every connected app. wallet-core's 0032 is the rotation that closes that.

## Decision

1. Every App Connect response names the pairwise did:key toward the app as
   `holder`, and its DIDAuth proof's `verificationMethod` is that key's, on
   every session kind. The key is derived from the app entry's `seed` by
   `connectionDidKey`, and the response is signed by it. `processAppConnect`
   passes this as the holder override; the app's `acceptedMethods` is still
   unread.
2. The seed is resolved by the same resolver a connection request uses, before
   anything is delegated, and rides the consent's entry write, as the agent's
   does. An app entry carrying no seed (one written before this rule) gets one
   at its next consent, and the app sees the holder change once. A seed whose
   tag fails refuses the consent.
3. Retiring an app entry keeps its seed, as retiring an agent entry does. A
   disconnected app that reconnects is answered with the same key.
4. The seed rotates under wallet-core's 0032, in the ceremonies that withdraw
   signing authority: client revocation, the forget ceremony, the last-client
   transition, a passphrase change, a passkey or backup-credential removal,
   and a recovery spend. An app has no channel, so its entry promotes with no
   message, and the app learns the new holder at its next connect.

0016's rules 1 and 3, the DIDAuth dispatch outside App Connect and the
did:webvh signer rule, are unchanged.

## Rejected Alternatives

- **Keeping the client did:key** (0016 rule 2). A transient visit's holder
  binds nothing, and an app that wants one wallet identity per connection has
  only the app-key subject to go by.
- **Steering the holder by the app's `acceptedMethods`.** 0016 rejected it,
  and the reason stands: an app sending `webvh` would move every connecting
  app onto the account identifier and its whole document history.
- **The account did:webvh or its did:web projection.** app-connect-spec's
  0004 rejected it, and it discloses the document to every app.
- **Clearing the seed on an app's disconnect**, so a reconnect presents a
  fresh holder. A kind-specific branch in retirement that buys nothing: the
  returning-app match reuses the same app-key credential, whose subject DID
  the app already holds, so the app recognizes the account across the
  reconnect anyway.
- **Clearing the seed on retirement for every kind.** Reopens wallet-core's
  0028, and a returning agent would need a fresh channel on every reconnect.

## Consequences

- An app gets one stable wallet identity per connection, the same from a
  remembered session, a transient session, and the mobile wallet.
- The holder is still a bare did:key, so the app-side loader resolves it with
  no new case, and app-connect-spec 0004's resolvability argument holds.
- 0004's "fresh, unlinkable holder per visit" consequence no longer holds. The
  holder is stable per connection and changes only at a rotation.
- A revoked client holds the seeds it read until the rotation runs, and the
  rotation runs inside the ceremony that revokes it.
- The spec's response presentation text, which today says the holder is the
  wallet account's own DID, is rewritten to say the pairwise did:key.
- An app that binds state to the holder DID re-binds at the connect after a
  rotation. was-react's holder note says so.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Account did:webvh identities become usable across hosts, so an app could
   be given the account DID with the document disclosure weighed afresh.
2. A verifier in the ecosystem enforces holder semantics that require the
   holder to be a document member of the granting account.
