# Hosted did:webvh DID log

Every WAS account publishes a
[`did:webvh`](https://identity.foundation/didwebvh/) DID: a hash-chained,
self-certifying history log stored as one world-readable Resource in the
user's Wallet Attached Storage (WAS) Space. Hosting it needs no server
changes. A [`did:web`](https://w3c-ccg.github.io/did-method-web/) DID comes
free with it, as the log's own projection.

## The log

`did.jsonl` is a [JSON Lines](https://jsonlines.org/) file: one JSON object
per line, each a full DID-document snapshot plus a proof. The first entry's
hash is the DID's **SCID** (self-certifying identifier), and every later
entry hashes itself with the previous entry's version id mixed in, giving a
tamper-evident hash chain. Anyone can fetch the log and verify the whole
chain and every entry's signature offline. The DID is self-certifying, and
needs no registry and no trusted resolver.

## Resolution

The DID's path segments name the `id` collection that holds the log, so
resolution is a plain unauthenticated `GET`:

```
DID:            did:webvh:<scid>:<host>:space:<spaceId>:id
resolves to:    https://<host>/space/<spaceId>/id/did.jsonl
```

A dev host with a port is percent-encoded into the host segment
(`did:webvh:<scid>:localhost%3A8080:space:...`).

## did:web is the log's projection

Beside the log the wallet publishes `did.json`, the **did:web projection**
of the same document: every id with the `did:webvh:<scid>:` prefix rewritten
to `did:web:`, plus an `alsoKnownAs` cross-link so a resolver of one id can
find the other.

```
DID:            did:web:<host>:space:<spaceId>:id
resolves to:    https://<host>/space/<spaceId>/id/did.json
```

The wallet assembles no did:web document of its own. The projection is the
only writer of `did.json`, so did:web resolution and did:webvh resolution of
one account cannot disagree. The projection is the whole document with its
ids rewritten, so a verifier handed either form sees every key the account
publishes.

Its verification methods carry the `Multikey` type the did:webvh data model
uses (same key material and multibase as the 2020 suites, different `type`
and `@context`). `Ed25519Signature2020` and `eddsa-rdfc-2022` proofs verify
against `Multikey` methods.

## What the document publishes

The document is the account's roster of keys:

- one Ed25519 verification method per connected wallet client, under
  `authentication`, `assertionMethod`, `capabilityInvocation` and
  `capabilityDelegation`, plus its X25519 twin under `keyAgreement`;
- a verification method for each standing unlock credential's update-key
  ladder, which is what lets a passphrase or a passkey extend the log with
  no connected client in hand;
- one key held in the user's WebKMS keystore, under `authentication`, which
  the wallet invokes at the key server to sign DIDAuth.

No server-held key is ever a wrap recipient or an update key, so the KMS
holds that one key and nothing else.

## The update key and prerotation

The log's write authority is a **dedicated Ed25519 update key**, and it is
client-held. Each connected client has its own, derived from a seed inside
that browser's wrapped client-key record; a standing unlock credential
derives its rungs from a random ladder seed inside its unlock record. The
key server never holds one, so the storage host cannot extend the log. That
is what makes the log the one artifact the host stores but cannot forge.

From the very first entry the log commits to a **prerotation** hash of a
staged key, so there is no unprotected-rotation window.

## Rotating an update key

Rotation is a user-triggered action on the Settings page, and it rotates
only this browser's own key. It needs a session on a browser the account
remembers, since the fresh seeds are persisted into that browser's
client-key record before the log entry publishes. The entry reveals the
staged key to sign its own activation, makes it this client's active update
key, and commits a fresh staged key as the new prerotation hash.

## Which DID a verifier sees

When a relying party asks for DID Authentication (over CHAPI or "Login with
Wallet"), its request may list the DID methods it accepts. The wallet
answers with the first form it can present, in the order `webvh`, `web`,
`key`. A request that lists nothing gets the did:web projection id when the
account can present it, since did:webvh resolution is still uncommon in
verifier stacks.

Presenting either account form means handing the verifier an identifier from
which the whole document and its history are fetchable. A `did:key` holder
hands over nothing beyond one key, and it is what guests, deployments with
no key server, and not-yet-published accounts present. App Connect always
answers with this browser's own wallet client `did:key`, whatever the app
asks for.

A request that accepts only methods this wallet cannot present is refused
before any credential is shared, rather than answered with a form the
verifier did not accept.

## Storage layout

The `id` collection holds `did.jsonl` and its `did.json` projection.
Public-read is a collection-level policy, so both are world-readable with no
per-resource grant. The collection is not wallet-synced: it has no local
replica and no background replication.

Key material stays out of it. The private, capability-gated `key-map`
collection holds `keys.json`, which records the account's own DID and the
one KMS binding as `{ vmId, kmsKeyId }`. It records no update keys, because
update keys never reach the server.
