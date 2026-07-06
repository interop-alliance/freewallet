# Hosted did:web DID

Every full login provisions and publishes a multi-key
[`did:web`](https://w3c-ccg.github.io/did-method-web/) DID in the user's
Wallet Attached Storage (WAS) Space. Its verification methods are backed by
keys held in the user's WebKMS keystore -- the passphrase-derived `did:key`
remains the keystore controller and never leaves the browser.

## Resolution

The DID's path segments name the `id` collection that holds its document, so
resolution is a plain unauthenticated `GET` (no server changes required):

```
DID:            did:web:<host>:space:<spaceId>:id
resolves to:    https://<host>/space/<spaceId>/id/did.json
```

A dev host with a port is percent-encoded per the did:web method
(`did:web:localhost%3A8080:space:...`).

## The DID document

A minimal multi-key document assembled from three KMS-held keys:

- **`authentication`** and **`assertionMethod`** -- `Ed25519VerificationKey2020`
- **`keyAgreement`** -- `X25519KeyAgreementKey2020`

Each verification-method id fragment is the key's multibase fingerprint
(`#z6Mk...` / `#z6LS...`), so it is self-describing and rotation naturally
mints a new fragment.

```jsonc
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ],
  "id": "did:web:<host>:space:<spaceId>:id",
  "verificationMethod": [ /* auth + assertion (Ed25519), keyAgreement (X25519) */ ],
  "authentication": ["...#z6Mk..."],
  "assertionMethod": ["...#z6Mk..."],
  "keyAgreement": ["...#z6LS..."]
}
```

## DIDAuth

When a relying party asks for DID Authentication (over CHAPI or "Login with
Wallet"), the wallet presents this `did:web` DID as the holder and signs the
presentation with the KMS-held `authentication` key. In a refresh-restored
session the browser session key invokes the persisted keystore `sign`
capability, so DIDAuth completes without a passphrase re-prompt. Guests,
deployments without a KMS, and not-yet-provisioned sessions fall back to
root-key `did:key` DIDAuth.

## Storage layout

The DID lives in a dedicated `id` collection alongside a non-public
`keys.json` (the verification-method-to-KMS-key map, and the recovery anchor).
Only `did.json` carries a resource-level `PublicCanRead` policy; the key map
is readable only with the Space's own capability. The `id` collection is not
wallet-synced -- it has no local replica and no background replication.

# Hosted did:webvh DID log

Every full login also publishes a
[`did:webvh`](https://identity.foundation/didwebvh/) DID -- a hash-chained,
self-certifying history log stored right next to `did.json` in the same `id`
collection. Like `did.json`, the log is one more world-readable WAS Resource,
so hosting it needs no server changes. Publishing it out of the box makes
freewallet a demo platform for the did:webvh method; deployments that want
did:web only can opt out with `VITE_ENABLE_DID_WEBVH=false`.

## The log

`did.jsonl` is a [JSON Lines](https://jsonlines.org/) file: one JSON object per
line, each a full DID-document snapshot plus a proof. The first entry's hash is
the DID's **SCID** (self-certifying identifier), and every later entry hashes
itself with the previous entry's version id folded in -- a tamper-evident hash
chain. Anyone can fetch the log and verify the whole chain and every entry's
signature offline; the DID is self-certifying, needing no registry or trusted
resolver.

## Resolution

The DID's path segments name the `id` collection that holds the log, so
resolution is again a plain unauthenticated `GET`:

```
DID:            did:webvh:<scid>:<host>:space:<spaceId>:id
resolves to:    https://<host>/space/<spaceId>/id/did.jsonl
```

A dev host with a port is percent-encoded into the host segment
(`did:webvh:<scid>:localhost%3A8080:space:...`).

## did.json is now the log's projection

From this point on the log is the single source of truth, and `did.json` is its
**did:web projection**: the same document with the `did:webvh:<scid>:` id prefix
rewritten to `did:web:`, plus an `alsoKnownAs` cross-link so a resolver of one
id can find the other. Two consequences:

- The `did.json` verification methods change type from the 2020 suites to
  **`Multikey`** (same key material and multibase, new `type` and `@context`) --
  the type the did:webvh data model uses. `Ed25519Signature2020` /
  `eddsa-rdfc-2022` proofs still verify against `Multikey` methods.
- The three verification methods are the **same three KMS-held keys** as the
  did:web document (reusing them sidesteps the SCID's chicken-and-egg: a KMS key
  alias is fixed at generate time, but the SCID does not exist until the first
  log entry is hashed).

## The update key and prerotation

The log's write authority is a **dedicated Ed25519 update key**, held in the
user's WebKMS keystore and separate from both the document verification methods
and the root `did:key`. From the very first entry the log commits to a
**prerotation** hash of a pregenerated staged key, so there is never an
unprotected-rotation window. Because the update key lives only in the
root-controlled keystore, a stolen browser session key can sign DIDAuth but can
never extend the log.

## Rotating the update key

Rotation is a user-triggered action on the Settings page (a full/passphrase
session is required, since extending the append-only log needs the root
capability). It reveals the staged key to sign its own activation, makes it the
sole active update key, and commits a freshly generated staged key as the new
prerotation hash -- appending one verifying entry to the public log. `keys.json`
records both keys' KMS ids throughout, so an interrupted ceremony is always
recoverable.

## Verifiers still see did:web

For now the wallet keeps presenting the **did:web** holder for CHAPI DIDAuth and
"Login with Wallet": almost no verifier stack resolves did:webvh yet, and the
`alsoKnownAs` cross-link lets a relying party correlate the two ids meanwhile.
The signer machinery is holder-agnostic, so switching the presented holder to
did:webvh later is a small, isolated change.

## Storage layout

The log joins `did.json` and `keys.json` in the same non-synced `id`
collection. `did.jsonl` is stored and served as `text/jsonl` with the same
resource-level `PublicCanRead` policy as `did.json`; `keys.json` gains a
non-public `webvh` block recording the active update key, the staged
(prerotation) key, and any retired keys -- the anchor that keeps the log from
ever being frozen by a lost KMS key id.
