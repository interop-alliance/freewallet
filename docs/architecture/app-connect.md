<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# App Connect (one-popup app login)

**App Connect** lets a BYOE web app (built on `@interop/was-react`) connect
in a single CHAPI `get`, which returns an app-key credential plus delegated
storage capabilities in one signed presentation. The request VPR carries a
`DIDAuthentication` query plus one `AppConnectQuery`:

- `app: { name, appUrl }` -- the consent screen's display name, and the
  application's canonical URL, which scopes the app-key identity within the
  requesting origin. The `appUrl` must parse as an absolute URL, carry no
  fragment, and be same-origin with the attested requesting origin; a
  violation makes the query malformed. Everything downstream stores and
  compares the parsed URL's serialization, so forms differing only in a
  default port, encoding case, or dot-segments name one application.
- `capabilityQuery: [...]` -- the usual capability descriptors minus
  `controller` (the wallet fills it) and `reason` (the consent screen
  supersedes per-grant reasons).

Mixing an `AppConnectQuery` with `QueryByExample` or standalone capability
queries is rejected at classification time (the shared
`appConnectRequestOf`) rather than degrading into a partial generic flow.

The wire contract is normative in the **App Connect companion spec**
(<https://github.com/interop-alliance/app-connect-spec>; local checkout
`../app-connect-spec`). The app-key module is
`@interop/wallet-request`'s `appKey.ts`, shared with DCW: wire
constants, match and mint paths, and the store-time refusal policy.
Freewallet's half is consent UI, credential storage, and delegation
machinery.

The key design move: **the wallet mints the app-key seed**, a client secret
that must not transit a server. It exists only in the wallet and the app,
over the browser-direct CHAPI channel. On first run the wallet generates 32
random bytes and derives the did:key via `CapabilityAgent.fromSeed({ seed,
keyName: 'app-key' })`; the `keyName` string must match was-react's
derivation exactly. It self-issues the credential (issuer == subject ==
seed-derived DID, seed base64url-no-pad in `credentialSubject.seed`) and
saves it to the `app-connections` collection under the same consent. No
second popup.

Every app key has the same shape: the fixed two-entry `type` array
`["VerifiableCredential", "AppKeyCredential"]`, and an inline `@context` of
one static object mapping `appUrl`, `seed`, and `origin` to their
`https://w3id.org/byoe#` IRIs. Which application a credential belongs to is
the `credentialSubject.appUrl` claim rather than a type.

On a returning visit a stored credential matches on three equalities: the
`AppKeyCredential` marker type, `credentialSubject.appUrl` against the
request's serialized `appUrl`, and `credentialSubject.origin` against the
CHAPI requesting origin. A phishing origin can neither recover another
origin's key nor be handed one, and two applications sharing an origin stay
apart by their `appUrl`s. was-react's `parseSeedCredential` repeats the
origin check app-side.

A match also requires the subject DID to re-derive from the seed the
credential carries (`appKeySeedBindsSubject`), failing closed on an absent,
non-base64url, or wrong-length seed. Without it a planted credential could
win the match and its DID would become the delegation `controller`. The
check proves internal consistency rather than provenance, so the store-time
refusal below is what keeps plants out. Candidates rank on the instant each
self-stated `issuanceDate` denotes rather than on its text, and an absent or
unparseable date sorts last.

**App keys live in their own collection.** `app-connections` is synced,
EDV-encrypted and content-addressed like the credential replica, but
structurally separate. The credential-wide surfaces are scoped to
`private-credentials`, so they cannot reach a seed and need no filtering
code. The collection is not shareable (`shareable: false` on its roster
spec), and a capability descriptor or URL naming it is unsatisfiable rather
than merely read-only. A whole-Space read grant covers its ciphertext, but
the grantee is not an epoch recipient and decrypts nothing. An idempotent
login-time sweep deletes app-key rows stranded in `private-credentials` and
retracts app-key public copies left with no private row behind them; the
affected app reconnects as a first run.

Match and consent-preview candidates come from
`StorageManager.listAppKeys()`, so ordinary credentials stay out of the
match. It reports what the scan skipped: rows whose key epoch is unknown
after the one descriptor refresh, rows in a known epoch this session holds
no wrap for, and envelopes that will not decrypt at all. A scan that found
nothing but skipped such rows refuses to mint, since a fresh mint would
orphan the app's prior identity. Undecryptable rows are purgeable from the
Applications page; the other two kinds stay unpurged.

Which bucket a row lands in is decided by the error's NAME rather than by
`instanceof`, through `isUnknownEpochError` and `isKeyUnwrapError`
(`@interop/was-client/sync`, the latter also on `/edv`). The cipher is an
injected seam, so a second resolved copy of `@interop/was-client` throws a
class the store did not import, and a missed `KeyUnwrapError` would put real
data in the purgeable bucket. The push handler classifies its `412` the same
way (`isSyncConflictError`).

**Externally arriving app keys are refused at store time, unconditionally.**
The marker type `AppKeyCredential`
(`https://w3id.org/byoe#AppKeyCredential`, one stable IRI for every app)
makes "presents as an app key" a term check rather than a shape heuristic.
It is a self-declaration a plant can copy, and a plant binds just as well,
so binding cannot license storage. `StorageManager.addCredential` is the one
door for externally supplied credentials (the CHAPI store popup, the URL /
QR / manual-paste import, the credentials half of a space import). It
refuses every marked credential, binding or not (`assertStorableAppKey`,
`AppKeyRefusedError`). The mint path has its own door,
`StorageManager.addMintedAppKey` (called only by `processAppConnect`,
writing into `app-connections`), which asserts the mint invariants.

Two ingest paths sit outside that door: the background sync pull, and the
space half of an import. The pull replicates the account's own remote
collections, writable only by the account's enrolled wallet clients
(`app-connections` is never grantable, and `private-credentials` is
protected, so RP and share grants on it are read-only). The import writes
opaque resources into the user's own Space server-side. For both, the
match-time binding is the backstop.

The wallet delegates to the subject DID of the credential it just matched or
minted, so the request names no controller DID. That is what makes the flow
single-round. Delegation reuses `resolveGrants` / `processZcaps` verbatim.
Requested actions are normalized against the closed WAS action vocabulary and
intersected with the limitation for the target's class: read-only for a
whole Space, a protected collection, and a share, the full vocabulary for
public collections and app-provisioned private collections. The consent
screen shows exactly what `resolveGrants` resolved. A grant left with no
permitted action is unsatisfiable rather than delegated empty. A whole-Space
read resolves the same on every session kind. A transient session's
generation delegation targets the Space's canonical container URL, the
string a whole-Space target resolves to. What bounds the grant is the
wallet-side GET/HEAD limitation. The server adds one thing on top of it,
that writing the Space Metadata object is controller-only. Resolution
consults a snapshot of the existing collections' state, kept current as the
delegation loop provisions, so duplicate names in one request resolve
against what the request itself created.

The response VP embeds the credential, the `zcap` array, and a
wallet-provided `appConnect: { firstRun }` member (a JSON-literal term in
the VP `@context`), all before signing so the DIDAuth proof covers them
(`processAppConnect` in `src/lib/walletRequest/appConnect.ts`).
`WalletGetPage` renders an app-centric consent panel in place of the three
generic sections, and approval records an app-connect Login activity.

The response VP does not take the holder dispatch above.
`processAppConnect` passes an explicit holder override, so the holder and
the DIDAuth proof's verification method stay the client did:key. That is the
enrolled client's key on a remembered session, and the visit key's bare
did:key on a transient one. An app's own `acceptedMethods` does not steer it
(`decisions/0016-didauth-holder-dispatches-on-accepted-methods.md`).

**App-provisioned collection encryption (day-one policy).** A private
(non-public) collection provisioned by an App Connect `capabilityQuery` is
declared EDV-encrypted. Its key-epoch roster holds the user's vault KAK as
recipient zero alongside the app's identity KAK, the X25519 (Montgomery)
twin of the `did:key` being delegated to, derived with the same
`x25519RecipientFromDidKey` a share uses. One recipient-derivation rule
covers app and person alike, and the app seed stays out of the grant path.

Provisioning is idempotent. The collection is created bare, and epoch[0]
wrapped to the owner lands as its governing log's genesis, create-if-absent
(`ensureIndexedFirstEpoch` from `@interop/wallet-core/keys`, which adopts an
existing roster rather than overwriting it). A first connect or a reconnect
after revoke then escrows the app into every epoch (`addRecipient(app)`, one
signed append); an app already present is a no-op. Epoch[0] is minted
together with the collection's blinded-index HMAC key, wrapped to the same
roster, so the app can declare searchable attributes and query the
collection. That key is installed at provisioning, so a collection
provisioned before blind-index support stays unindexable.

The wallet's own writes carry the same blinded `indexed` entries a
Collection-handle write does. Each encrypted collection's doc cipher
installs the persisted index schema from the `custom` member of the
collection's Metadata object, an opaque encrypted envelope the cipher
decrypts. The schema is cached beside the encryption descriptors and
refetched on the same unknown-epoch refresh.
The wallet ensures the collection exists without writing a descriptor of its
own, so an established epoch roster is never dropped.

Public (`https://w3id.org/byoe#public-collection`) grants stay plaintext and
world-readable; only private app collections are encrypted. A public grant
can only ever CREATE its collection, and one naming an existing non-public
collection is unsatisfiable, so no consent approval can turn an established
collection world-readable. An idempotent re-grant on an already-public
collection delegates without re-provisioning, and any target naming one is
classed public-collection and skips provisioning, whether it arrives as a
`#public-collection` descriptor, a `#private-collection` descriptor, or a
plain URL string. The user is always a recipient of an encrypted collection
in their own Space, and any future exception needs its own explicit consent
surface.

Because the user is recipient zero, the wallet decrypts these collections in
the storage browser as an ordinary recipient with its vault KAK,
descriptor-driven from the collection's governing log. Revoking a connected
app rotates the epoch off the app's key for each such collection
(`removeRecipient`, which rotates then revokes the pull-axis grants
indivisibly), so a revoked app cannot decrypt future writes. Ciphertext it
already fetched stays readable to it. The blinded-index key is not rotated
on revoke (see "Client revocation and the epoch cascade" in client-revocation.md), so the revoked
app keeps the ability to compute blinded terms while the query endpoint
stays behind the revoked pull grant.

A grant minted in a transient session ends at its own expiry or when its
annex generation is collected, whichever comes first. Revocation is
available for the whole window in which the grant is usable, and generation
collection runs from the remembered-login chain alone, so on an account that
never remembers a browser it never runs. The consent screen shows the
shortened bound, the earlier of the grant's own `expires` and the generation
delegation's, rather than the configured TTL.

Two security properties of App Connect:

- **Challenge/domain**: was-react verifies the DIDAuth challenge and domain
  app-side.
- **Per-user app identity**: an app key is minted from 32 fresh random bytes
  inside the connecting user's own wallet, so the app's DID, and the X25519
  recipient key derived from it, is scoped to the **(user, origin,
  `appUrl`)** triple. The same app connected by two users gets two unrelated
  DIDs, so there is no cross-user linkability. "Encrypted to the app's key"
  throughout this document therefore means _that user's_ instance of the
  app.

  This holds on the App Connect path, where the wallet mints the key and
  fills `controller` itself. A standalone `AuthorizationCapabilityQuery`
  names its own `controller`, so an app taking that route could supply one
  static DID for every user. The wallet cannot detect this, so it is an
  ecosystem expectation of app authors rather than an enforced invariant:
  **a grantee DID SHOULD NOT be shared across users.** Either way the
  recipient key derives from the named controller, so a request cannot pair
  controller DID A with recipient key B.

## Sharing a wallet collection (`https://w3id.org/byoe#shared-wallet-collection`)

**Sharing** lets a grantee read and decrypt one of the wallet's own
encrypted collections. It is asked for with a distinct invocation-target
descriptor, `{ type: 'https://w3id.org/byoe#shared-wallet-collection', name
}`, in either channel (a standalone `AuthorizationCapabilityQuery`, or an
`AppConnectQuery.capabilityQuery`). A distinct `type` rather than a flag is
load-bearing: an unknown `type` already resolves to unsatisfiable, so a
wallet predating the feature refuses visibly instead of degrading to a
ciphertext-only read.

**The two axes stay fused.** Pull (a read-only Collection zcap) and read (an
epoch-key recipient entry, one signed append on the collection's governing
log) are granted together, by one call to `StorageManager.shareCollection`,
which returns the delegated zcap alongside the refreshed descriptor so it
rides back in the response VP's `zcap` array. A share grant therefore
bypasses the ordinary delegation loop in `processZcaps`; no code path grants
one axis without the other.

**The recipient key is derived, not transmitted.** `name` must be one of the
shareable standard collections: every `WALLET_STANDARD_COLLECTIONS` entry
whose roster spec carries `shareable: true`, so today `private-credentials`,
`wallet-activity`, `contacts`, and `contacts-history`. `app-connections` is
encrypted but never shareable, its rows carrying app seeds. The grantee's
X25519 key is derived from the `did:key` the request already names as
`controller` (`x25519RecipientFromDidKey` from `@interop/was-client/edv`),
so a request can never pair controller DID A with recipient key B. A
controller with no Ed25519 twin (a did:web, an X25519 did:key) makes the
grant unsatisfiable.

**Consent states the limitations before approval.** The share row on the
consent screen is visually distinct from every other grant and says three
things: the grant is read and decrypt; it covers the collection's contents
from the moment of approval, not only future writes; and removing access
later stops future reads but cannot take back what has already been read.
The second holds because every encrypted collection carries epoch[0] from
provisioning (wrapped to the user key, recipient zero), so a share is always
an `addRecipient` escrowing the grantee into every existing epoch, with no
rotation and no envelope outside an epoch the grantee now holds. An
epoch-less descriptor is refused fail-closed rather than seeded lazily at
share time, since it can only mean an unprovisioned or torn collection.

Removal is the shares dialog behind a collection row's "Shared" chip in the
Storage collection list (`unshareCollection`), not expiry: the share TTL
(`SHARE_ZCAP_TTL_MS`) is long, because expiry would end the pull axis while
leaving the grantee in the key roster. A share also escrows the grantee into
the collection's blinded-index HMAC key when the descriptor carries one;
removal drops that wrap but never rotates the key (see "Client revocation
and the epoch cascade" for why, and what a removed grantee keeps).

**The grantee's half lives in `@interop/was-react`.** An app declares the
wallet-owned collections it wants in `WasAppConfig.sharedCollections`, which
adds the descriptors to its App Connect request. On approval a
`SharedCollectionReader` reads the Collection Metadata object through the
delegated read zcap, builds the epoch-aware cipher from it, and decrypts the
envelopes locally with the X25519 twin of its own controller DID, the key
the wallet derived, so both sides land on the same `kid` with nothing on the
wire. That is the same recipient identity an app-provisioned collection
admits the app with. The `encryption` member it reads is the server's
derivation of the governing log head, and the delegated read zcap covers
that log, so a grantee can verify the descriptor's history for itself.
