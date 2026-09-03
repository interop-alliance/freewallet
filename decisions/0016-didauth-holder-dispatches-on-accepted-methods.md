# 0016: The DIDAuth holder dispatches on `acceptedMethods`; App Connect is pinned to the client did:key

- Status: accepted
- Date: 2026-09-03
- Driving work: the FW-344 design gate (retiring the wallet's standalone
  did:web mint, so the holder form stops being a function of what was
  provisioned). Extracted at that design's approval.
- Affects: freewallet (`src/lib/walletRequest/composeVP.ts`,
  `processRequest.ts`, `appConnect.ts`, the CHAPI get and store pages),
  `@interop/wallet-core` `/request` (the `didAuthMethodSupported`
  predicate), the App Connect response presentation (app-connect-spec
  `decisions/0004`), was-react (the holder forms an app may see).

## Context

The wallet used to pick a DIDAuth holder from its own provisioning
state: a KMS-held key with a did:web holder whenever one had been
minted, a did:key otherwise. The request's own `DIDAuthentication`
query carries `acceptedMethods`, and the shared classifier treated it as
a refusal gate -- any constraint omitting `key` was refused -- so a
verifier asking for `web` was blocked by a wallet that would have
presented did:web to a verifier that asked for nothing.

App Connect reached the same signer. On a remembered session against a
KMS deployment its response VP already held as did:web, which
contradicted both wallets' architecture docs and app-connect-spec
`decisions/0004`. A unit fixture with no keystore hid the drift.

Three DID forms are available on a promoted account: the account
`did:webvh`, its did:web projection (the same document with ids
rewritten), and the client's own `did:key`. The first two hand a
verifier a permanent account identifier from which the world-readable
log is fetchable; the third hands over nothing and is unlinkable across
visits.

## Decision

Three rules, one dispatch.

1. Outside App Connect, the holder is a function of the request and of
   what the session can present, in order: `webvh`, then `web` (the
   projection id), then `key`. An absent, empty, or malformed
   `acceptedMethods` takes the did:web projection when it is
   presentable, and did:key otherwise. Presentability is settled against
   the account document resolved from the verified log, read as a cache:
   no fetch, no throw, false when the memo is cold. A stored key map is
   not evidence, because it is written on paths that never edit the
   document.
2. App Connect does not dispatch. `processAppConnect` passes an explicit
   holder override, pinning the response VP's holder and its DIDAuth
   proof verification method to the client did:key -- the enrolled
   client's on a remembered session, the visit key's bare did:key on a
   transient one. An app's `acceptedMethods` does not steer it. This
   makes the code match app-connect-spec `decisions/0004`, which it
   currently does not.
3. A remembered session signs a `did:webvh` holder with the enrolled
   client's own account authentication key, which the document already
   lists. The KMS-held key signs only where no client key exists, and on
   the did:web arm.

The refusal for a constrained request the wallet cannot answer is split
by what each position can know. Pre-login, the widened gate refuses only
methods no session on this deployment could ever present, judged by
deployment capability (a configured KMS makes `web` and `webvh`
possible). Post-login, a routed session that can present none of the
listed methods gets the block screen -- the same component in the same
position as today's pre-login block, with its own copy -- rendered in
place of the consent panel. That is a hard constraint on the
implementation: the post-login refusal replaces the consent panel and
adds no step, screen, or click to the flow.

The dispatch itself never throws. Two of its callers have no refusal
surface: the CHAPI store page renders a raw error message, and the
external-request delivery path resolves a signer it never uses.

## Rejected Alternatives

- Steering the App Connect holder by the app's `acceptedMethods`. It is
  a contract change rather than a wallet-local one: app-connect-spec
  `decisions/0004` rejected the account DID as holder outright, so the
  record would need amending in substance, and an app sending `webvh`
  would move every connecting app onto a permanent account identifier
  that discloses the whole document and its history.
- Keeping the KMS key as the signer for the did:webvh arm. The KMS
  facet is, by default, on the storage host itself. That key attesting
  the account's chain-verified identity means a host or KMS compromise
  mints DIDAuth over any challenge and domain with no client action,
  and a careful verifier accepts it.
- Dropping the gate and answering did:key whenever a listed method is
  unpresentable. It hands the verifier a form it did not accept, and
  the substitution is invisible.
- Moving the whole gate after login. It shows a login form for a request
  the wallet will refuse, and the post-login refusal then reads as an
  extra step rather than as the consent panel's replacement.

## Consequences

- On a promoted account the unconstrained default discloses by default:
  either account form lets the verifier fetch every enrolled client key,
  every standing ladder VM, the credential commitments and
  `keyAgreement` entries, the recovery codes' keys, and the ceremony
  timestamps, plus the whole history behind them. A did:key holder
  discloses none of that.
- The holder form is not stable across a session's lifetime. A
  mid-session ceremony that extends the account log empties the verified
  log memo, and the dispatch falls to did:key until something re-primes
  it. An offline visit does the same.
- A refusal that depends on whether this browser is remembered is a
  browser-state signal a verifier can probe, and it nudges users toward
  remembering a browser to satisfy verifiers.
- The widened predicate takes a second argument naming the presentable
  methods, defaulted to "did:key only", so every existing consumer keeps
  today's semantics and the change is additive.
- App Connect's holder now matches the spec record by construction
  rather than by a fixture's accident, so the app-side parse is
  unchanged.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. `webvh` appears in requests the wallet actually receives, or verifier
   stacks resolve did:webvh commonly enough that the unconstrained
   default should move off the projection.
2. The projection's staleness is closed. A stale `did.json` is a
   revocation bypass rather than lag, and while it stands the did:web
   arm answers with a document that may list a forgotten client.
3. app-connect-spec amends `decisions/0004` to make the App Connect
   holder negotiable, at which point rule 2 becomes a wallet policy
   rather than a contract obligation.
