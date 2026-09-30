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
than merely read-only. So are `key-map` and `unlock-methods`. `key-map`'s
user key roster carries a passphrase-derived key beside a wrap of the user
key, so a read of it would be an offline guessing oracle, and
`unlock-methods` is the account's credential registry. An idempotent
login-time sweep deletes app-key credentials stranded in
`private-credentials` and retracts app-key public copies left with no private
credential behind them; the
affected app reconnects as a first run.

Match and consent-preview candidates come from
`StorageManager.listAppKeys()`, so ordinary credentials stay out of the
match. It reports what the scan skipped: Resources whose key epoch is
unknown after the one descriptor refresh, Resources in a known epoch this
session holds no wrap for, and envelopes that will not decrypt at all. A
scan that found nothing but skipped such Resources refuses to mint, since a
fresh mint would orphan the app's prior identity. Undecryptable Resources are purgeable from
the Applications page; the other two kinds stay unpurged.

Which bucket a Resource lands in is decided by the error's NAME rather than by
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
entry point for externally supplied credentials (the CHAPI store popup, the
URL / QR / manual-paste import, the credentials half of a space import). It
refuses every marked credential, binding or not (`assertStorableAppKey`,
`AppKeyRefusedError`). The mint path has its own store method,
`StorageManager.addMintedAppKey` (called only by `processAppConnect`,
writing into `app-connections`), which asserts the mint invariants.

Two ingest paths sit outside that entry point: the background sync pull, and
the space half of an import. The pull replicates the account's own remote
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
protected collection and a share, the full vocabulary for public
collections and app-provisioned private collections. The consent screen
shows exactly what `resolveGrants` resolved. A grant left with no permitted
action is unsatisfiable rather than delegated empty. No grant reaches the
whole Space. The `https://w3id.org/byoe#space` type is reserved, and a
string target naming the Space itself is unsatisfiable, as the App Connect
spec requires. A string target never provisions either. It resolves only
onto a collection that already exists, so a grantee cannot create one
through its first write. Resolution
consults a snapshot of the existing collections' state, kept current as the
delegation loop provisions, so duplicate names in one request resolve
against what the request itself created. A string target is the exception.
It sees only the collections that stood before the request, as the consent
preview does, so approval never grants a row the preview refused.

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

**Provisioned collection encryption (day-one policy).** A private
(non-public) collection a grant provisions is declared EDV-encrypted,
whichever path the request took: an App Connect `capabilityQuery` or the
interaction-URL request page. Those are the only two paths that grant
capabilities at all. The Applications page lists each one's grantees and can
revoke them: an App Connect grant under its app's row, keyed by the app key,
and an interaction-URL grant under its agent's row, keyed by the grantee
`controller`. A plain CHAPI `get` carrying a standalone
`AuthorizationCapabilityQuery` would have no row to land on, so the get
popup refuses it before consent (`standaloneZcapRequest` in
`precheckGetRequest`, see "CHAPI integration"). A provisioned
collection's key-epoch roster holds the user's vault KAK as recipient zero alongside
the grantee's identity KAK, the X25519 (Montgomery) twin of the `did:key`
being delegated to, derived with the same `x25519RecipientFromDidKey` a
share uses (`StorageManager.provisionEncryptedCollection`). One
recipient-derivation rule covers app, agent, and person alike, and the app
seed stays out of the grant path. A controller that is not an Ed25519
did:key has no twin to derive, so resolution classes its private-collection
grant unsatisfiable and the consent screen shows it as one that cannot be
fulfilled.

Provisioning is idempotent. The collection is created bare, and epoch[0]
wrapped to the owner lands as its governing log's genesis, create-if-absent
(`ensureIndexedFirstEpoch` from `@interop/wallet-core/keys`, which adopts an
existing roster rather than overwriting it). A first grant or a re-grant
after revoke then escrows the grantee into every epoch (`addRecipient`, one
signed append); a grantee already present is a no-op. Epoch[0] is minted
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
world-readable; only provisioned private collections are encrypted. A public grant
can only ever CREATE its collection, and one naming an existing non-public
collection is unsatisfiable, so no consent approval can turn an established
collection world-readable. An idempotent re-grant on an already-public
collection delegates without re-provisioning, and any target naming one is
classed public-collection and skips provisioning, whether it arrives as a
`#public-collection` descriptor, a `#private-collection` descriptor, or a
string target. The user is always a recipient of an encrypted collection
in their own Space, and any future exception needs its own explicit consent
surface.

Two applications may name the same private collection, since a request
names it by `name` alone. The second is admitted exactly as a reconnecting
app is: the idempotent provisioning escrows its key-agreement key into every
key epoch the collection has, so it reads what the first app stored. That is
the decided policy, and the consent row is what keeps it from being
silent. `resolveInvocationTarget` reports, on a target naming a private
collection that already stands, an `existing` reading of its creator: the
requester's own did:key (`this-app`), a key the same application held
earlier (`this-application`, the site reconnecting after a disconnect), a
different application (`other`), or nothing stamped (`unattributed`, a
collection an interaction-URL grant provisioned). The signal is the
`generator` object stamped at creation (`{ id, origin, url, name }`: the
app's did:key, its attested origin, its canonical app URL, and its display
name), read off each named collection's own Collection Metadata object.
The lean Space listing grant resolution consults does not carry it. A collection entry
in the resolution snapshot therefore carries an optional `attribution`, and
while it is absent the resolver reports no `existing` reading, so the row
shows no note. The consent page resolves once over the listing, so the
screen renders at once. A second pass then reads the named private
collections' metadata in parallel, sets each `attribution`, and resolves
again (`attributeExistingCollections` in
`src/lib/walletRequest/attributeExistingCollections.ts`). Both consent pages
drive the two passes through one hook, `useAttributedGrants` in
`src/hooks/useAttributedGrants.ts`. It shows the first pass, runs the second
behind it, and drops a superseded pass's late result. A second pass that
fails outright is logged, and the rows settle over the first resolution. A
metadata read that fails, or a collection the store cannot see, gets an
empty attribution and reads `unattributed`. The second pass also joins the
creating app (`creatorApp: { name, appUrl }`) onto `generator.id` from the
wallet's own records (`lookupCollectionCreators` in
`src/lib/connectedApps.ts`). The app key answers while the creator is
connected. Once it is not, the App Connect Login activities that recorded
grants to its DID answer, since a disconnect deletes the app key. The
storage browser's "Created by" line reads the same join, so a creator is
named the same way on both. The CHAPI get popup has already listed
`app-connections` for its app-key match, and hands that listing to the
second pass rather than listing the collection again. The
same-application test compares app URLs rather than origins, because the
wallet tells apps apart by `appUrl` and two may share one origin. The
creator's app URL is the collection's own `generator.url` when it carries
one, so a matching URL reads `this-application` and a different URL on the
same origin reads `other`, whatever the wallet's records say. Only a
collection stamped without `generator.url` falls back to the app URL the
join recovers. An App Connect requester whose creator app URL is known from
neither reads `other`, the cautious side. An interaction-URL agent carries no
app URL, so it reads `other` unless the collection is its own (`this-app`).
The reading carries the creator's display name (`creatorName`): the stamped
`generator.name`, else the name the join recovers. The row names the creator
by it, or by `generator.origin` otherwise. A public collection carries no roster and reports no
reading. The same metadata read says whether the collection carries an
`encryption` descriptor. A string target admits the grantee to no roster,
so on an encrypted collection the row gets the ciphertext note once the
second pass lands.

Because the user is recipient zero, the wallet decrypts these collections in
the storage browser as an ordinary recipient with its vault KAK,
descriptor-driven from the collection's governing log. Revoking a connected
app rotates the epoch off the app's key for each such collection
(`removeRecipient`, which rotates then revokes the pull-axis grants
indivisibly), so a revoked app cannot decrypt future writes. The pull
revokes each grant under the grant stage's per-grant policy, so a refusal
it cannot explain fails that collection. The retiring
entry is the app's own, derived from its subject DID the way provisioning
wrote it, so another app admitted to the same collection keeps its access.
Ciphertext it already fetched stays readable to it. Revoking a connected
agent runs the same rotation over the collections its recorded grants
target (see "The interaction-URL request page" in external-request.md).

Which collections that rotation covers is the union of two sources. The
first is the Space's collection listing: every collection whose Collection
Metadata names the app's subject DID as its `generator.id`, the attribution
stamped at provisioning. The second is the collections the app's recorded
grants target, expired grants included, which reaches a collection the app
was admitted to but did not create. A grant expires on its own; a recipient
entry does not, so the listing is what keeps the rotation working for an app
whose grants all lapsed before the user disconnected it. The unexpired
grants still supply the capabilities the rotation revokes on its pull axis.

The recorded grants are written before any grantee is escrowed. Approval
signs every delegation first, which is local and needs no target to exist.
When some grant shares or provisions a collection, the Login activity is
then persisted with the signed grants and the connect's `firstRun`. Only
after that is each share escrowed and each collection provisioned
(`beforeProvision` in `processZcaps`, wired in
`composeAndDeliverResponse`). This matters for an existing private
collection, whose `generator.id` still names its first creator: the recorded
grants are the only source that names it for the second app. A failed
persist fails the request with nothing escrowed. A share or provisioning
step that fails after the persist fails the request too, and the Login is
removed again, since nothing was delivered. If that removal fails, the
Login stays, naming a grant whose collection may not list the app.
Revocation tolerates that: it
skips a collection whose current key epoch does not list the grantee, and a
collection that was never created reads as having no epochs. A request with
nothing to provision persists its Login after compose, as before. Either way
one request writes one Login.

A collection the rotation could not re-key, or a collection listing that
could not be read, keeps the disconnect incomplete: the app-key row stays
listed, no Revoke activity is recorded, and the page reports the failure so
the user can retry. The remaining grants are still revoked first. The retry
converges, since each stage detects its own completion. The login-time sweep
of stranded app keys runs the same sequence (`revokeAppAuthority`). The blinded-index key is not rotated
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
  fills `controller` itself. A standalone `AuthorizationCapabilityQuery` on
  the interaction-URL page names its own `controller`, so an agent could
  supply one static DID for every user. The wallet cannot detect this, so it
  is an ecosystem expectation of agent authors rather than an enforced
  invariant: **a grantee DID SHOULD NOT be shared across users.** Either way
  the
  recipient key derives from the named controller, so a request cannot pair
  controller DID A with recipient key B.

## Sharing a wallet collection (`https://w3id.org/byoe#shared-wallet-collection`)

**Sharing** lets a grantee read and decrypt one of the wallet's own
encrypted collections. It is asked for with a distinct invocation-target
descriptor, `{ type: 'https://w3id.org/byoe#shared-wallet-collection', name
}`, in an `AppConnectQuery.capabilityQuery`. The interaction-URL page bars
the share class, and a plain CHAPI `get` grants nothing. A distinct `type` rather than a flag is
load-bearing: an unknown `type` already resolves to unsatisfiable, so a
wallet predating the feature refuses visibly instead of degrading to a
ciphertext-only read.

**The two axes stay fused.** Pull (a read-only Collection zcap) and read (an
epoch-key recipient entry, one signed append on the collection's governing
log) are granted together. `StorageManager.delegateShareGrant` signs the
zcap with the request's other grants, and it rides back in the response
VP's `zcap` array. Once the Login records it,
`StorageManager.shareCollection` escrows the reader and records the share.
It refuses a zcap that is not read-only on that collection, so no code path
grants one axis without the other.

**The recipient key is derived, not transmitted.** `name` must be one of the
shareable standard collections: every `WALLET_STANDARD_COLLECTIONS` entry
whose roster spec carries `shareable: true`, so today `private-credentials`,
`contacts`, and `contacts-history`. `app-connections` is encrypted but never
shareable, its Resources carrying app seeds. Neither is `wallet-activity`. Its
Login and collection-share activities carry each delegated capability verbatim,
proof and capability chain included, so one reader of it would learn every
connected app and agent, with its targets, verbs, and expiry, and would hold
the capability documents themselves. The flag gates new shares only. A
reader escrowed into `wallet-activity` before it was narrowed stays in that
collection's key-epoch roster. The shares listing reads every encrypted
standard collection rather than only the shareable ones, so such a reader
still shows on the collection's "Shared" chip and is removed there. The grantee's
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
