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
saves it to the `app-keys` collection under the same consent. No
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

**App keys live in their own collection.** `app-keys` is synced,
EDV-encrypted and content-addressed like the credential replica, but
structurally separate. The credential-wide surfaces are scoped to
`private-credentials`, so they cannot reach a seed and need no filtering
code. The collection is not shareable (`shareable: false` on its roster
spec), and a capability descriptor or URL naming it is unsatisfiable rather
than merely read-only. So are `key-map` and `unlock-methods`. `key-map`'s
user key roster carries a passphrase-derived key beside a wrap of the user
key, so a read of it would be an offline guessing oracle, and
`unlock-methods` is the account's credential registry. The refusal reads the
roster rather than a list kept here: each of the three declares
`grantable: false` on its roster spec, so a new roster entry is never
grantable only by its own declaration. An app-key credential stranded in
`private-credentials` from before the dedicated app-key collection existed
stays where it is, and so does any public copy of one. Such a key predates the
`connections` directory and has no entry there, so deleting it would
revoke none of the app's grants. The login-time sweep that deleted these
keys is retired for that reason. A stranded key keeps both of
`private-credentials`' exits open onto its seed, the public link and the
share. Nothing tracks that residue: the mender registry declares no
invariant for it, and the Applications page does not list such a key.

Match and consent-preview candidates come from
`StorageManager.listAppKeys()`, so ordinary credentials stay out of the
match. It reports what the scan skipped: Resources whose key epoch is
unknown after the one descriptor refresh, Resources in a known epoch this
session holds no wrap for, and envelopes that will not decrypt at all. A
scan that found nothing but skipped such Resources refuses to mint, since a
fresh mint would orphan the app's prior identity. Undecryptable Resources are purgeable from
the Applications page; the other two kinds stay unpurged.

Which bucket a Resource lands in is decided by the error's NAME rather than by
`instanceof`, through `isIntegrityError`, `isUnknownEpochError`, and
`isKeyUnwrapError` (`@interop/pws-client/sync`, the latter two also on
`/edv`). The integrity check is asked first, and it also catches a key epoch
entry that names this wallet but fails its key-wrap check, which pws-client
raises as `IntegrityError` on the first decrypt under that epoch. The cipher is an
injected seam, so a second resolved copy of `@interop/pws-client` throws a
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
writing into `app-keys`), which asserts the mint invariants.

Two ingest paths sit outside that entry point: the background sync pull, and
the space half of an import. The pull replicates the account's own remote
collections, writable only by the account's enrolled wallet clients
(`app-keys` is never grantable, and `private-credentials` is
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
generic sections. Approval writes the app's `connections` entry and then an
App Connect `Grant` activity (see "The consent record" below). A plain
"Login with Wallet" that grants nothing records a `Login` activity instead.

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
revoke them: an App Connect grant under its app's row, and an
interaction-URL grant under its agent's row. Each row is one `connections`
entry, keyed by the grantee DID. A plain CHAPI `get` carrying a standalone
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

Two requesters (each an app, service, or agent) may name the same private
collection, since a request names it by `name` alone. The second is admitted
exactly as a reconnecting requester is: the idempotent provisioning escrows
its key-agreement key into every key epoch the collection has, so it reads
what the first requester stored. That is
the decided policy, and the consent row is what keeps it from being
silent. `resolveInvocationTarget` reports, on a target naming a private
collection that already stands, an `existing` reading of its creator: the
requester's own did:key (`this-app`), a key the same application held
earlier (`this-application`, the site reconnecting after a disconnect), a
different requester (`other`), or nothing stamped (`unattributed`). The
signal is the `generator` object stamped at creation, read off each named
collection's own Collection Metadata object. Its `id` is always the
creating requester's DID. App Connect stamps
`{ id, origin, url, name }`: the app's did:key, its attested origin, its
canonical app URL, and its display name. An interaction-URL grant comes
from an agent, one kind of requester, and stamps a collection it creates
with `{ id, name }`: the agent's did:key, and its
self-declared `agent.name` when the request carries one.
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
creating app (`creatorApp: { name, appUrl }`) onto an app stamp's
`generator.id` from the `connections` directory (`lookupCollectionCreators`
in `src/lib/connectedApps.ts`). It reads the directory once and matches each
stamp in memory to the `kind: 'app'` entry whose `id` is that DID, so the
host sees no read at the id a DID derives to. A disconnected creator still
answers, since retirement keeps an entry's names. A failed directory read
leaves every creator unresolved. The storage browser's "Created for" line
reads the same join, so a creator is named the same way on both. The
reading decides on `generator` alone. The server-observed `createdBy` names
the wallet's invoking DID on a collection the wallet provisioned for an
app, so it says nothing about the requester here. The storage browser shows
it as a separate line (see "Two creator signals" below). The
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
by it, or by `generator.origin` otherwise. A stamp with no `origin` names an
agent. The join skips it, and an unnamed one is named by its shortened
`generator.id`. A public collection carries no roster and reports no
reading. The same metadata read says whether the collection carries an
`encryption` descriptor. A string target admits the grantee to no roster,
so on an encrypted collection the row gets the ciphertext note once the
second pass lands.

**Two creator signals.** The `generator` stamp is controller-asserted, and
nothing verifies it. It only labels the consent row and the storage
browser's listings, and grants nothing. A collection that already stands
keeps its stamp, so a second requester admitted to it does not rename the
creator. The content migration stamps an app collection it creates too,
copying the bundle's value as it stands (see "Content migration" in
session-persistence.md). The Storage page's listing and the collection
contents page name an app stamp's creator through `lookupCollectionCreators`
(`useCollectionCreators`), as the consent row does. A retired entry still
answers. Only an app the Applications page lists carries the entry resource
id the caption links with. A creator no entry names is shown by its
`generator.origin`.

A collection and a Resource carry a second creator signal, `createdBy`. The
server records it on the first write as the DID whose capability invocation
created the object. It is server-observed, read-only, and optional. Neither
signal is verified identity. Under delegated provisioning the two differ by
design, since the wallet creates an app's collection and `createdBy` names
the wallet's invoking DID. The collection contents page shows the two as
separate labeled lines, the stamp as "created for" and `createdBy` as what
the server observed. The Resource page shows a Resource's `createdBy` the
same way, since a Resource has no `generator` of its own. It reads the
Resource's metadata beside the body and hands that read to its Metadata
card, so expanding the card costs no second GET. Elsewhere the Metadata card
fetches only when the user expands it.

`resolveCreatedBy` (`src/lib/collectionAttribution.ts`) names a `createdBy`
DID, driven by `useCreatorAttribution`. A DID the wallet itself invokes as
reads as "this wallet" (`walletOwnDids` in `src/session/clients.ts`). That
set is the account DID, every wallet client and ladder VM the verified
account log ever listed, and the client-annex DID a transient session's own
writes record. An app, an agent, or a share recipient is named from its
connection entry by `lookupCreatedByParty` (`src/lib/connectedApps.ts`),
over the same listing read `lookupCollectionCreators` uses. A `createdBy`
the wallet invokes as reads the directory only when an app stamp needs
naming. Any other DID is shown shortened, and an absent one as "not
recorded". The Storage page's listing shows `generator` alone. It carries
`createdBy` off the Collection Metadata object it already reads, and
fetches nothing more for it.

Because the user is recipient zero, the wallet decrypts these collections in
the storage browser as an ordinary recipient with its vault KAK,
descriptor-driven from the collection's governing log.

**The consent record.** Every grant the wallet delegates is recorded on the
grantee's `connections` entry, in `grants`, before the grantee is escrowed
into any key epoch and before any presentation leaves the wallet
(`decisions/0034-the-directory-is-the-grant-index.md`). Approval signs every
delegation first, which is local and needs no target to exist. Then the
app's entry is written (`recordGrants`, through `beforeProvision` in
`composeAndDeliverResponse`). It is created as `kind: 'app'`, or merged into
by zcap id, with the app's `name`, its attested `origin`, its canonical app
URL as `url`, and the `app-keys` Resource holding its key as
`appKey`. A share grant is marked `grantKind: 'share'`, and every other
grant `'grant'`. The App Connect `Grant` activity follows, as audit trail.
Only then is each share escrowed and each collection provisioned. Every App
Connect writes its entry before the VP is composed, a zero-grant connect
included, on every session kind. A guest's lands in its local directory.
An interaction-URL connection request also writes the agent's pairwise
`seed` and its `seedTag` in the same write, on whichever path records. An
entry already carrying a different seed refuses the write, and the request
fails closed (see "The connection request" in external-request.md).

A failed entry write fails the request closed, with nothing escrowed and
nothing delivered. So does an entry of another kind at the app's id, which
wallet-core refuses with `ConnectionKindMismatchError`. A share or
provisioning step that fails after the write fails the request too. Nothing
was delivered, so the consent is rolled back. Each of the request's grants
whose escrow did not land is removed (`removeGrants`, by zcap id). A grant
whose escrow landed stays listed. Its grantee holds the decryption
material, and the user needs a row to revoke it from. An escrow counts as
landed when the governing-log append's response was lost but a re-read
finds the grantee on the current epoch.

When no grant escrowed, the Grant is removed too. The consent cleared the
entry's `retired` and set its `appKey`, so an entry that was absent or
retired before the consent is retired again (`retireConnection`). A
pairwise seed the consent wrote stays, since nothing outside the wallet saw
its did:key, and the next consent reuses it. The state
before the consent is read at the app's id just ahead of the write. A
disconnected app whose reconnect failed is therefore not listed as
connected. An entry the consent created is retired rather than deleted. It
keeps the app's names, and a later consent un-retires it. An entry that was
live before stays live. When some grant escrowed, the entry stays live, and
the Grant stays as the audit trail for the escrowed grants. It also names
the undelivered ones.

If the rollback fails, the undelivered grants stay listed, and revoking
them POSTs revocations for capabilities no requester holds. A failed
delivery to an exchange (`exchangeFailed`) keeps the record, since the
composed response is offered for manual delivery.

Recording before escrow matters most for an existing private collection,
whose `generator.id` still names its first creator. The entry's grants are
the only source that names that collection for the second app.

This sequence is the request consent ceremony (`request-consent`), and
`composeAndDeliverResponse` is its one entry point, for the CHAPI popup and
the interaction-URL page alike. Its pivot is the first escrow into a key
epoch. Before it, every write is the record a failure rolls back. Past it,
the grantee holds decryption material, so the escrowed grants stay recorded
and the run can only go forward. A tab closed between the record and the
escrow leaves recorded grants the requester never received. A tab closed
past the escrow leaves a recorded grantee that may never get its zcap. Both
are listed rows, and the user's own revoke from that row converges them.
The ceremony event channel carries its stages: `record-entry`,
`record-activity`, `escrow` (the pivot), and `deliver` (the exchange POST).
The outcome is `clean`, or `refused` for an unavailable Space or an
unreadable app-key scan, or `failed`, with the failure's `reason` as
detail.

**The Applications listing** (`listApplicationsView` in
`src/session/applications.ts`) reads the directory once and filters in
memory. An app row is an unretired `kind: 'app'` entry holding an `appKey`
or any grant. Its display name is the user's `label`, then the app's
`name`, then its origin, then its shortened DID. Rows sort by `lastSeen`,
which only a consent moves. The page still lists `app-keys` for its
health: the undecryptable and no-epoch-key warnings and the purge button
read that scan. A row opens `/applications/:resourceId`, keyed by the
entry's resource id. That page shows one card per grant scope (grantee,
target, and actions), live and expired, newest first, and dates "Connected"
from `firstSeen`. A card shows the scope's latest record, and the records a
renewal or a later consent superseded collapse under it. The listing's
lapse date and grant count read the latest record per scope too
(`newestFirst` in `src/lib/connectedApps.ts`), so a renewal is neither
counted twice nor dated by the record it replaced. An app that
connected before the directory existed has no entry. It is not listed, and
its grants end at their own expiry
(`decisions/0036-no-backfill-for-the-directory.md`).

**Disconnecting an app** (`revokeAppAccess` in `src/lib/connectedApps.ts`)
reads the app's entry and runs its stages in order. The confirmation dialog
first names the wallet collections the app holds a share of
(`sharedCollectionIds`, the `grantKind: 'share'` grants' collections), so
the user is told no less than the Storage page's shares dialog would tell
them.

1. The rotation. Each candidate collection's key epoch rotates off the
   app's key (`removeRecipient`, which rotates and then revokes the
   pull-axis grants indivisibly), so a revoked app cannot decrypt future
   writes. The retiring recipient is the app's own, derived from its DID the
   way provisioning wrote it, so another party admitted to the same
   collection keeps its access. Ciphertext the app already fetched stays
   readable to it.
2. The grant POSTs (`revokeConnectionGrants`), each under the grant stage's
   per-grant policy. A grant the rotation's pull already confirmed revoked
   is counted without a second POST.
3. The server-side app-key delete (`StorageManager.deleteAppKeyResource`).
   The Resource the entry's `appKey` names is read, and deleted only when
   its credential binds the entry's DID: its subject is that DID, and
   `appKeySeedBindsSubject` holds. Every other `app-keys` Resource
   carrying the same credential goes with it. A 404 or a dangling `appKey`
   reads as already deleted. A Resource that does not bind the DID is left
   alone, since it is some other app's seed. On a session with a Space the
   delete goes to the server whatever the session kind, so a disconnect
   before a remembered session's pull cannot leave the key there for a
   reconnect to match.
4. The retirement (`retireConnection`), and then the Revoke row, as audit
   trail.

The rotation's candidates are the union of two sources. The first is every
collection the entry's grants target, expired grants included, protected
share targets among them. That reaches a collection the app was admitted to
and did not create. The second is every unprotected collection whose
Collection Metadata, in the Space listing, names the app's DID as
`generator.id`. A grant expires on its own, and a recipient entry does not,
so the listing keeps the rotation working for an app whose grants all
lapsed. Only a candidate whose current epoch still lists the app is rotated.
The unexpired grants supply the capabilities the pull revokes.

A stage that does not land throws before the retirement, so the row stays
listed and the user can retry. A collection the rotation could not re-key
is such a failure, and so is a collection listing that could not be read.
The remaining grants are still revoked first. The retry converges, since
each stage detects its own completion. A collection whose current epoch no
longer lists the app is skipped, a re-POSTed grant answered
`AlreadyRevokedError` counts as revoked, and a key already deleted reads as
absent. The retirement passes the ids of the grants the run handled. When a
concurrent consent has merged another grant onto the entry since, the
retirement throws and the row stays listed. A Revoke row that fails after
the retirement leaves no audit row. The blinded-index key is not rotated on
revoke (see "Client revocation and the epoch cascade" in
client-revocation.md), so the revoked app keeps the ability to compute
blinded terms while the query endpoint stays behind the revoked pull grant.
Revoking a connected agent runs the same stages with no app key to delete,
behind one first write that empties the entry's channel (see "The agent
connection" below).

The disconnect, the agent revoke, and the unshare below are one ceremony,
grant revocation (`grant-revocation`), with three entry points:
`revokeApplication` and `revokeAgent` in `src/session/applications.ts`, and
`removeCollectionShare` in `src/session/shares.ts`. Its pivot is the first
epoch rotation, or the first grant POST when nothing rotates. Neither can
be undone. A torn run leaves the row listed, and the user's own re-run from
that row converges it. The rotate-then-revoke tail the client revocation
and the forget run on a wallet client's entry (`retireConnectionParty`) is
shared, and emits nothing of its own. The event channel carries the stages
`rotate-recipients`, `revoke-grants`, `delete-app-key` (an app only),
`retire-entry`, `remove-grants` (an unshare only), and `record-activity`,
each once its write lands. The outcome is `clean` for a run that completed,
`refused` for an app with no entry (`ConnectionEntryMissingError`), and
`failed` otherwise. Its detail carries counts only, and a zero `withdrawn`
and `rotated` there mean the access had already ended.

**The `connections` directory.** The directory holds one connection entry
per party the wallet has dealt with: an app, an agent, or a wallet client,
with `contact` reserved. Each entry sits at a resource id keyed by an HMAC
of the party's DID under the collection's blinded-index key, so the host
cannot probe for a guessed DID. An entry carries the party's names, every
grant the wallet delegated to it, an app's `appKey`, and a wallet client's
registered writers. An agent's entry also carries the pairwise `seed` and
its `seedTag`, the channel capabilities in `grantsReceived`, the queued
messages in `outbox`, and the `declined` marker (see "The agent
connection" below). Its grants are the revocation index, and the
`wallet-activity` rows are audit trail that nothing deciding about a party
reads (`decisions/0034-the-directory-is-the-grant-index.md`). The
directory rides the session's backend through one store seam
(`src/stores/connectionsStore.ts`), and is never replicated (see
"Replica-less, capability-bound storage" in session-persistence.md). Every
write is a read-modify-write
under `ifMatch` or a create under `ifNoneMatch`, and a lost race surfaces
as pws-client's `PreconditionFailedError`. A write re-reads only its own
entry. A page reads the directory once, and every lookup by DID matches in
memory, so the host sees no GET at the id a DID derives to.

Every directory operation fails closed while the collection is refused as
the directory (`#directoryAccess` in `StorageManager`). There are five
refusals. `absent` is a collection with no epoch-bearing descriptor.
`stranded` is one whose key epochs do not name this session's vault KAK.
`no-blinded-index-key` is one whose descriptor declares no blinded-index
key, so no resource id can be derived. `foreign-recipient` is one whose
current epoch lists a recipient outside the account's user key
generations. `generator` is one whose Collection Metadata object carries a
`generator` stamp. The last two mark a collection a requester was
provisioned with, which some requester could already read. The directory is
never grantable and never shareable.

Every rule over the encrypted collections reads one roster-wide set,
`ENCRYPTED_WALLET_COLLECTION_IDS` in `src/app.config.ts`, which holds the
directory beside the synced ones. Its readers are the descriptor
acquisition, the local descriptor mint, the stranded report, the user key
cascade's base set, the credential-anchored mend, and the shares listing.

An entry is retired when its relationship ends: an app disconnect, an agent
revoke, a wallet-client disconnect, or a forget. Retirement stamps
`retired`, empties `grants`, `grantsReceived`, and `outbox`, and drops
`appKey`. It keeps the names, the pairwise `seed` and its tag, and
`declined`, so a departed party still resolves. It follows the revocation that handled those
grants, and refuses when the entry has since gained a grant that revocation
did not handle. A later consent from the same party un-retires the entry.

**Which recipients a rotation keeps.** A rotation wraps the fresh epoch only
to recipients the wallet admitted, through the admitted-recipient resolver
in `StorageManager`. These are the owner, the account's user key
generations, and the recipient kid of every grant on every unretired
`connections` entry that targets the collection. Expired grants count, since
a recipient entry outlives its grant. No protected-collection filter
applies, so a share reader of `private-credentials` is kept. Any other
roster entry receives no wrap. Every reader of the directory drops a grant
whose `zcap.controller` is not the entry's `id`, and one whose target lies
outside this Space, so a planted entry cannot steer the set at another
party's capabilities. Nothing authenticates an entry's body, so a host can
roll an entry back, or plant a party's genuine capabilities at its own id.
What that steers is listed in
`decisions/0038-no-authorship-guard-on-connections-entries.md`. A body
sitting at another id than its own derives to is ignored. The resolver fails closed, so nothing rotates, when the
directory is absent or refused, when its listing fails, or when it holds an
entry it cannot decrypt, a body it cannot parse at its own id, or an entry
from a newer build. Reading such a directory as empty would evict every
co-admitted party
(`decisions/0035-the-directory-rides-the-session-backend-and-is-never-replicated.md`).

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

## The agent connection

A subscription agent connects through an interaction-URL connection request
(see "The connection request" in external-request.md). The consent gives it
GET and HEAD on audience collections, and POST on the account's `inbox`.
The wallet keeps a pairwise did:key toward it, derived from the `seed` on
its connection entry. Two things keep the agent's grants alive with no
further prompt: a channel the agent opens back to the wallet, and a renewal
the wallet runs at login. The decisions are
`decisions/0041-the-agents-grant-is-an-ordinary-delegated-grant-with-no-standing-anchor.md`,
`decisions/0042-one-wallet-wide-plaintext-inbox-is-the-channel.md`,
`decisions/0043-a-grant-signed-by-withdrawn-authority-is-renewed-only-on-the-owners-tick.md`,
and `decisions/0044-a-partys-pending-messages-queue-on-its-connection-entry.md`.

**The channel capability.** Once connected, the agent delegates POST on its
own inbox to the wallet's pairwise did:key. It posts that capability into
the owner's `inbox` as a `Grant` envelope: `actor` is the agent's did:key,
and `object.zcaps` carries the capability (`inboxGrantMessage` and
`parseInboxGrantMessage` in `@interop/wallet-core/space`). The wallet
stores it on the agent's entry in `grantsReceived`, under `grantKind:
'inbox'` (`recordReceivedGrants`). A record is kept only when its
`controller` is the entry's pairwise did:key and its target lies outside
this Space. The wallet treats a channel record as lapsed at the earlier of
its `expires` and its `receivedAt` plus `SHARE_ZCAP_TTL_MS`. That limit
governs the wallet's own use alone. A copy someone else holds is bounded
only by the agent issuing no longer capability. The wallet does not verify
a received capability's delegation chain, since the agent's server checks
it at invocation.

**The inbox pass** (`src/session/inboxPass.ts`, logger `fw:inbox`) runs
behind each login chain's mender block and settles `session.inboxPass`
(see "Session & auth flow" in session-and-auth.md). It also runs on the
Settings page once a ceremony that replaces the generation delegation
resolves. Passes on one session never overlap. A CHAPI popup, a guest, and
a session with no Space run none. Each pass has three steps, in order.

1. The drain. The pass refuses an `inbox` it does not trust (public,
   carrying an `encryption` descriptor, or carrying a `generator` stamp)
   and counts it as absent. It walks the listing page by page until the
   listing is empty or the pass has read its byte cap
   (`INBOX_DRAIN_BYTE_CAP`), and each sender has a byte budget per pass of
   its own (`INBOX_SENDER_BYTE_BUDGET`). It reads each message's metadata
   before its body, and refuses a message with no `createdBy`, a content
   type other than `application/json`, or a size over
   `INBOX_MESSAGE_MAX_BYTES`. The sender is the server-recorded
   `createdBy`, matched in memory against the directory listing the pass
   read, with one re-read per pass for a sender it does not find. It must
   be an unretired agent entry carrying a seed whose tag verifies, and the
   envelope's `actor` must equal `createdBy`. A capability that targets this
   Space is ignored and logged, since the wallet accepts no renewed grant
   from an agent. Every message is deleted once acted on or refused, and a
   delete that finds it gone counts as done. A re-run stores the same
   capability, so the drain is idempotent.
2. The renewal. It reads the listing as the drain left it, so a channel the
   drain just stored is seen. A candidate is an unretired agent entry
   carrying a seed and a live channel. Of its grants, only the latest
   record per scope is read, where a scope is the grantee, the target, and
   the actions. Only a grant inside the renewal scope is renewed: GET and
   HEAD on a collection, or POST on `inbox`, recorded by a consent that also
   recorded an inbox grant. Any other grant lapses at its own TTL. A grant
   is renewed when it is due and its proof verifies as this account's
   against the current document (`renewalSignerCheck` on `StorageManager`,
   over wallet-core's `verifyRecordedGrantProof`). A grant delegated under
   the Space root is verified by its own proof. A grant a transient session
   minted embeds its generation delegation, and both links are verified:
   the generation delegation against the account document, and the leaf
   against the annex document of that generation, which the signer check's
   `annexDocument` resolver reads (`currentAccountSignerCheck`) under the
   session's authority and the log's chain-head pin. Any generation of the
   account's auxiliary Space resolves, so a grant under a superseded
   generation stays renewable while its log stands. A grant whose
   generation was collected resolves no document and is refused
   (`leaf-generation-collected`), so it lapses into a re-consent. The leaf
   check is what stops a host from planting a leaf of its own under the
   genuine, host-held generation delegation. A document that cannot be
   read renews nothing, and a generation log that cannot be read grades
   the pass `partial`. A grant is due when its
   `expires` falls inside the agent renewal window
   (`AGENT_GRANT_RENEWAL_WINDOW_MS`), or when it is chained under a
   generation delegation other than the pointed one while that delegation's
   signer is still listed (`agentGrantDue`). The pointed delegation is read
   from the generation log's head, not from memory. A grant already past
   its `expires` is not due. Renewals are minted under consent's parent
   rule (`delegateRenewalGrants`). A stale generation delegation is renewed
   first, and when it cannot be, nothing is minted.
3. The outbox push. Each entry's pending envelopes are POSTed through its
   live channel, invoking that capability as the pairwise did:key, in
   parallel up to `INBOX_PUSH_PARALLELISM` and under one time budget per
   pass. A delivered item is removed. A network failure or a 5xx keeps it
   for the next pass. A 401, 403, or 404 stops the pushes to that entry for
   the pass, since a WAS host answers every capability denial with one of
   them. The refused channel record is then dropped from the entry
   (`dropReceivedGrant`), and the queued envelopes stay on the `outbox`.
   The next pass pushes nothing to an entry with no channel. It lists the
   entry's waiting items as `no-channel` push failures, and they do not
   grade the pass `partial`. The agent's next invitation stores the
   replacement channel whatever its `expires`, since the dropped record is
   gone, and the pass after that pushes the queue.

   A refusal that was not the agent's doing drops the channel too: an agent
   server whose clock skew answers 401, or a 404 during its redeploy. Only
   the agent's next invitation brings the channel back. Until then the
   renewals queue undelivered, and at worst the agent's grants lapse at
   their own `expires` and the agent invites again. That cost is accepted.
   A 401, 403, or 404 from the agent's own host is that host's answer about
   the capability. Keeping the record would cost one wasted request per pass
   for the channel's whole life, and a `partial` grade on every pass that
   would hide a real one.

The renewal's pivot is `recordRenewedGrants`. Inside one compare-and-swap
it re-reads the entry, refuses a retired one, and checks that a live
channel still stands and that the record it renews is still the latest of
its scope. It then appends the renewed records and queues their envelope on
the entry's `outbox` in the same write. A check that fails discards the
minted grant unrecorded. So a renewal whose push fails still reaches the
agent at a later pass. The renewed record keeps the original `grantedAt`.
The record it supersedes stays on the entry, so a revoke still reaches it,
and is pruned once past its `expires` plus the revocation clock skew
(`pruneSupersededGrants`). One Grant activity is written per renewed entry
per pass, so History shows every renewal. A listing, read, write, or push
failure grades the pass `partial`, which does not spend an encounter's
once-per-session budget. An entry waiting on a channel is not such a
failure. An absent or untrusted inbox grades it `refused`.
Each push is a direct browser request to the agent's host. So every
connected agent learns the owner's IP address, user agent, and login
cadence, and its server must serve cross-origin requests on its inbox.

**Withdrawn authority and the owner's tick.** A grant whose parent was
replaced while the parent's signer still stands is renewed silently, as
long as the superseded generation's log still stands. The annex GC's
quarterly swap and the in-place generation renewal leave such grants, and
so does a client revocation's generation swap for a grant under a
delegation a remaining key signed. Once the GC collects the superseded
generation, the leaf check can no longer verify the grant, and it lapses
into a re-consent at its own expiry. A grant whose signing authority
was withdrawn fails the proof check and is never renewed silently. A
genuine grant and one a stolen client planted look the same, so only the
owner can tell them apart. Withdrawal is a client revocation, a forget, the
departing client of the last-client transition, or a ladder VM struck by a
passphrase change, a passkey or backup-credential removal, or a recovery
spend.

Before such a ceremony runs, its dialog lists the connected agents holding
a grant the withdrawn key or ladder VM signed
(`agentsSignedByWithdrawnAuthority` in `src/session/agentReconnect.ts`,
rendered by `src/components/AgentReconnectList.tsx`). A root-anchored grant
names its signer in its own proof, and an annex-anchored grant names its
minter in its embedded parent's proof. A client ceremony names the client's
signing key. A credential retirement names the credential's ladder VM,
read the way the strike reads it: the ladder inventory attributed over the
verified account log from the registry entry's recorded anchor, and the
claim held against the current document (`retiredCredentialWithdrawnKeys`
in `src/session/credentialRotation.ts`). The entry's recorded proof key
ids are not used, since a remembered login's standing-delegation refresh
re-mints the bridge pair under the enrolled client's key. Each agent is
ticked by default (`useAgentReconnect` in `src/hooks/useAgentReconnect.ts`),
and the dialog's confirm button waits until the list has been read. Once
the ceremony succeeds, each unticked agent's entry gets the `declined`
marker, and `reconnectAgents` restores the ticked agents. A ceremony that
fails writes no marker. The restore re-mints each ticked agent's renewable
grants (`renewableAgentGrants` in `src/session/inboxPass.ts`, the one
selection the renewal and the lapsed-agent offer also read) under the
session's current authority, with the share TTL limited by the parent. It records them through `recordGrants` as a fresh consent,
with the envelope queued on the entry's `outbox`, and writes one Grant
activity per agent. It reads no proof check, since the owner's tick is the
consent. The record leaves a retired entry as stored (`unlessRetired`), so
a revoke that landed since the listing is not undone, and that agent reads
`not-found`. Then the Settings inbox pass runs
(`renewAgentGrantsAfterCeremony`), which pushes the queued envelopes and
renews the rest in place. A pass still in flight is waited out and the
pass runs again, since the one in flight read the directory before the
restore wrote. The dialog's notice names any agent it could not restore.
An unticked agent's grants stay dead, and its row stays listed for
revocation.

Two ceremonies cannot restore in their own visit. The ordinary forget lists
the agents with no tick and says their access ends, since the browser is
leaving. The last-client transition ends the session, so it marks its
unticked agents declined and restores none. Those markers are written once
the transition's up-front refusals have passed and before its first write
(`beforeFirstWrite` on `forgetThisBrowser`), under this client's authority,
which the transition then takes away. A recovery spend runs outside
Settings and shows no list. `lapsedAgentOffers` reads the agents such a
ceremony, a failed restore, or a lapse left with no live grant, for a later
visit to offer back with one tick. No page renders those offers yet.

A declined agent shows a Declined chip on the Applications listing. Its
detail page offers Restore beside Revoke. Restore runs the same re-mint as
a fresh consent, which clears the marker, and so does a new connection
request the owner approves. Retirement keeps the marker.

**The subscriber cut.** An agent re-delegates a child of each audience
grant to its subscribers, so every ceremony above cuts every subscriber
child of the affected grants at once, and so does the annex GC's swap. The
wallet's own order adds no delay. The renewal or the restore runs in the
same login or visit. The outage is the agent's inbox-read cadence, plus its
re-issue of each child, plus each subscriber's next fetch.

**Revoking an agent** (`revokeAgentAccess` in `src/lib/connectedApps.ts`)
runs the disconnect's stages with no app key to delete, behind one first
write. That write empties the entry's `grantsReceived` and `outbox` in its
own compare-and-swap (`StorageManager.clearConnectionChannel`), before any
POST. No pass renews or pushes to an entry with no channel, so a torn
revoke is not undone by the next login's renewal. Every grant on the entry
is then POSTed, the inbox grant and any superseded renewal included. The
audience collections and `inbox` are plaintext, so the rotation stage finds
no recipient list on them and skips them. Retirement keeps the seed, and
nothing is sent to the agent. The agent learns from its refused
invocations, and its subscribers' children die with its grants. A later
consent from the same agent un-retires the entry and reuses the seed, and
the agent posts a fresh invitation. One residue is left to the re-run. A
torn revoke whose inbox-grant POST failed leaves the agent able to post a
fresh invitation, which the drain stores. A renewal pass before the re-run
may then re-mint grants the first run revoked. The row stays listed, and
the user's re-run POSTs those too.

What the pairwise key does not give is unlinkability. Every grant the agent
receives names the owner's Space URL as its target, so a returning owner
under a new key is recognizable. A lost directory loses every seed with
it. Renewals to those agents then stop, the Applications page lists none
of them, and the owner is not told. A reconnect mints a new seed. The
epoch cascade does not reach a seed either. A party whose authority the
account withdrew keeps every seed and channel capability it read, and can
post into an agent's inbox as the wallet until that capability expires.
No seed rotation is built, and the mender registry declares the residue as
an open gap (invariant `no-withdrawn-party-holds-a-live-pairwise-channel`).

The authorization profile's subtree marker (`*` appended to a target) is
not shipped yet. Every grant target is the bare container URL for now, the
inbox grant's included, and the current server reads a bare container URL
as covering the container's subtree. So the inbox grant is not yet the
exact target it is meant to be. Once the marker ships, an audience grant
takes it and the inbox grant stays bare. A renewal keeps whatever target
form the consent recorded.

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
VP's `zcap` array. Once the reader's `connections` entry records it, marked
`grantKind: 'share'`, `StorageManager.shareCollection` escrows the reader
and writes a `CollectionShare` activity as audit trail. It refuses a zcap
that is not read-only on that collection, so no code path grants one axis
without the other.

**The recipient key is derived, not transmitted.** `name` must be one of the
shareable standard collections: every `WALLET_STANDARD_COLLECTIONS` entry
whose roster spec carries `shareable: true`, so today `private-credentials`,
`contacts`, and `contacts-history`. `app-keys` is encrypted but never
shareable, its Resources carrying app seeds. Neither is `wallet-activity`. Its
Grant and collection-share activities carry each delegated capability verbatim,
proof and capability chain included, so one reader of it would learn every
connected app and agent, with its targets, verbs, and expiry, and would hold
the capability documents themselves. The `connections` directory carries the
same documents and is never grantable at all. The flag gates new shares
only. A
reader escrowed into `wallet-activity` before it was narrowed stays in that
collection's key-epoch roster. The shares listing reads every encrypted
standard collection rather than only the shareable ones, so such a reader
still shows on the collection's "Shared" chip and is removed there. The grantee's
X25519 key is derived from the `did:key` the request already names as
`controller` (`x25519RecipientFromDidKey` from `@interop/pws-client/edv`),
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
removal drops that wrap but does not rotate the key (see "Client revocation
and the epoch cascade" for why, and what a removed grantee keeps).

The dialog lists each collection's current-epoch readers, read from the
roster on its own, so a directory that cannot be read leaves the readers
listed unnamed. Beside them it lists a reader whose entry still holds an
unexpired share grant on the collection. That is the state a torn unshare
leaves, and listing it keeps the removal retryable. A reader is named from
the entry whose DID derives its kid, by `label`, then `name`, with its
origin and the expiry of its latest share grant. An unshare reads the
directory once. It rotates the epoch off the reader's kid, under the same
admitted-recipient resolver a revocation uses, and POSTs the share grants
the reader's entry holds on that collection. Then it removes those grants
from the entry (`removeGrants`) and writes a `CollectionUnshare` activity.
The entry is not retired, since the party may hold other grants. The
unshare runs as the grant revocation ceremony (see "Disconnecting an app").
Its pivot is the epoch rotation. A run torn after it leaves the reader
listed through its share grant, and a retry runs the pull alone. A run torn
after `removeGrants` leaves no audit row. Sharing itself has no ceremony of
its own: the escrow is one stage of the request consent.

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
