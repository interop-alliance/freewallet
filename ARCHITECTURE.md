# Architecture

How Freewallet is structured -- the layer map, session and auth flow, storage
model, CHAPI and App Connect flows, the domain model, and the ZCap
authorization structure. For contribution conventions see
[CONTRIBUTING.md](CONTRIBUTING.md); for agent-facing rules (tech stack, env
vars) see [AGENTS.md](AGENTS.md).

## Layer map

```
src/pages/          Route-level React components (one file per page)
  auth/             Login, Signup, GuestLogin, Logout
  chapi/            CHAPI popup pages (WalletGetPage, WalletStorePage)
  dashboard/        Authenticated dashboard pages
src/components/     Shared React components
  credentialDetails/  Credential detail sub-components
  storage/          Storage browser sub-components
src/lib/            Pure business logic (no React)
  appKey.ts         App Connect app-key credential (match + mint)
  didKeyRecipient.ts  A grantee's X25519 recipient key, derived from its
                    did:key controller (the share flow)
  kms.ts            WebKMS keystore provisioning (ensureKeystore)
  sessionKey.ts     freewallet-session IndexedDB caches (keyring, unlock
                    methods, passkey-safety notices)
  viewMappers/      Transform raw credential data into display-ready values
  walletRequest/    VPR classification + response assembly for CHAPI requests
src/lib/sync/       Collection-agnostic WAS replication adapter (RxDB-based)
src/stores/         Global state
  authStore.ts      Zustand store — holds the live Session object
  storageManager.ts StorageManager facade (local-first routing)
  browserStore.ts   BrowserStore — the local RxDB active replica
  wasRemoteStore.ts WASRemoteStore — the remote WAS backend
  edvDocCipher.ts   Per-collection EDV document cipher (encrypt/decrypt seam)
  syncController.ts Background replication lifecycle (start/stop/reSync)
  toastStore.ts     Transient success/info messages (`showToast`), rendered as a
                    Snackbar by DashboardLayout. Global, not page-local state:
                    an action often redirects (delete returns to the dashboard)
                    before a local message could render.
src/session/        Session bootstrap (initSession.ts)
src/types/          Shared TypeScript interfaces
src/i18n/           i18next config + locale JSON files
src/styles/         MUI sx-object style constants (co-located by feature)
src/app.config.ts   Environment variable exports + app-wide constants
```

## Session & auth flow

There is no external identity provider. A user's identity is derived entirely
from their passphrase:

```
passphrase (string | Uint8Array)
  → CapabilityAgent.fromSecret()   → keyAgent  (holds an Ed25519 key pair)
                                      keyAgent.id === a did:key DID
  → ZcapClient(invocationSigner)   → zcapClient (signs HTTP requests with ZCap)
  → { user: { id: did:key }, profile: { keyAgent, zcapClient } }
  → StorageManager.initStorageClients()
  → Session { user, profile, storage, isGuest }
```

The `Session` object is stored in the Zustand `authStore`; it is **in-memory
only** (the passphrase is never persisted), so reloading the browser logs the
user out and they must log in again. Guest sessions use a random 32-byte
secret and never touch the WAS server or the KMS.

All four session entry points (login, signup, both CHAPI popup pages) funnel
through `initSessionFromSecret`. When a KMS is configured (`KMS_SERVER_URL`),
it also provisions a **WebKMS keystore** for the controller (`ensureKeystore`
in `src/lib/kms.ts`: list-by-controller, create on miss -- one keystore per
controller by convention), binding a `KeystoreAgent` as
`profile.keystoreAgent`. Operational keys can live server-side in that
keystore, while the passphrase-derived `keyAgent` stays strictly client-side
as the **keystore controller**. Provisioning failure is non-fatal (logged;
the settings page shows the state).

## Session persistence

Sessions are **in-memory only**. A fresh passphrase login builds the whole
`Session` -- the root `keyAgent`, the passphrase-derived vault KAK, and the
`zcapClient` that signs every WAS request with the root key. Nothing about
the session is written to disk, so there is no refresh-survival: reloading
the browser drops the session and the user logs in again. The vault is
therefore always unlocked while a session exists (the KAK is present) and
simply gone once it ends; there is no "locked vault" state.

## Storage model (local-first)

The local `BrowserStore` (RxDB over Dexie/IndexedDB) is always the **active
replica**: every credential, public-link, and history read/write targets it,
online or offline, guest or not. One local database per user holds all three
standard collections (`private-credentials`, `public-credentials`,
`wallet-activity`) on the generic synced-doc schema
(`{ id, updatedAt, version, data }`, see `src/lib/sync/syncedDocSchema.ts`).

The encrypted collections (`private-credentials`, `wallet-activity`) store
**EDV envelopes**, not plaintext -- encrypted-at-rest locally and opaque to
the server. A per-collection document cipher (`src/stores/edvDocCipher.ts`,
built from the session's passphrase-derived X25519 key) encrypts at write
time and decrypts at read time; the row id is content-derived (a hash of the
JWE ciphertext), so it is identical on every replica. Page-facing identity
stays the credential `cid` / activity `id`, recovered by decrypting at read
time; because JWE encryption is nondeterministic, dedupe keys on that content
identity, not the row id. `public-credentials` is plaintext for good (it is
public data) and keyed directly by `cid`.

When `VITE_WAS_SERVER_URL` is set (and the session is not a guest), a remote
WAS Space is attached as a **sync target**: the `SyncController`
(`src/stores/syncController.ts`) replicates all three local collections to
their remote WAS Collection counterparts in the background via the
collection-agnostic adapter in `src/lib/sync/`, which ships stored bodies
(plaintext or envelope) verbatim and never touches keys. Each replication
(and `WASRemoteStore` request) is signed with the session's root key.

`WASRemoteStore` no longer serves credential reads/writes; it keeps the Space
lifecycle (create/exists/wipe), the storage-browser read-through
(`/storage/**` pages work directly over remote collections), export/import,
and quotas.

`StorageManager` is the facade; pages and components always talk to it, never
directly to a backend class.

A user's remote Space is identified by `spaceId = base64url(SHA-256(did:key))`.
Collections created on first login: `private-credentials`, `public-credentials`,
`wallet-activity`.

## CHAPI integration

CHAPI (Credential Handler API) lets a website trigger a credential
request/store via a browser pop-up without the site ever seeing the user's
wallet passphrase.

Flow:

1. On login, `registerWallet()` (`src/lib/registerWallet.ts`) calls
   `installHandler()` via the credential-handler-polyfill, registering
   `/wallet/get` and `/wallet/store` as this wallet's handler URLs with the
   CHAPI mediator (`authn.io`).
2. When a third-party site calls `navigator.credentials.get/store()`, the
   browser opens `/wallet/get` or `/wallet/store` **in a CHAPI-managed popup
   iframe** — outside the normal app shell and `ProtectedRoute`.
3. The popup page calls `receiveCredentialEvent()` to intercept the CHAPI
   event, shows a minimal login form, initialises a full `Session` in-popup,
   then calls `chapiEvent.respondWith(...)` to return the result to the site.

The CHAPI pages (`src/pages/chapi/`) are deliberately not wrapped in
`ProtectedRoute` and do not use the main app layout.

**Remote-direct popup storage.** The popup runs in a third-party iframe, so
its own IndexedDB is a partitioned bucket that no `SyncController` ever
drives: a credential stored there would be stranded and a credential list
would always come back empty. Every synced-collection read/write in
`StorageManager` goes through one `SyncedCollectionStore` backend chosen once
at construction (`src/stores/remoteDirectStore.ts`): the local `BrowserStore`
in the normal case, or a `RemoteDirectStore` for the popup (selected via
`remoteDirect`, threaded from `loginWithPassphrase({ remoteDirectStorage:
true })` in both popup pages). The remote-direct backend serves credential,
history, and public-link reads/writes straight over the remote WAS collections
(`WASRemoteStore.listSyncedResources` / `getSyncedResource` /
`putSyncedResource` / `deleteSyncedResource`), encrypting/decrypting with the
same per-collection ciphers the local store uses -- so the envelope, id, and
key-epoch logic lives once. A write reproduces verbatim what background
replication would have pushed (the raw EDV envelope under its content-derived
envelope-hash id, created with `If-None-Match: *`, stamped with the same
`WAS-Key-Epoch`), so the main app's replication pulls it cleanly. An
unknown-epoch read (a rekey by another client) drives the same one-time marker
refresh the local backend uses, so a fresh-epoch credential is never dropped.
Contacts are not reachable in a popup, so the remote-direct backend rejects
them rather than touching the empty partitioned store. The backend is selected
only when a remote store is configured; a guest or no-WAS session always uses
the local `BrowserStore`. Reads gate on `StorageManager.ready()` -- the local
collections being open, or nothing at all in remote-direct mode.

## App Connect (one-popup app login)

**App Connect** lets a BYOE web app (built on `@interop/was-react`) connect
to the wallet in a **single CHAPI `get`**: the app gets back an app-key
credential plus delegated storage capabilities in one signed presentation.
The request VPR carries a `DIDAuthentication` query plus one
`AppConnectQuery`:

- `app: { name, credentialType, vocabBase }` -- the display name for the
  consent screen and the pair that parameterizes the app-key credential;
- `capabilityQuery: [...]` -- the usual capability descriptors _minus_
  `controller` (the wallet fills it) and `reason` (the App Connect consent
  screen supersedes per-grant reasons).

An `AppConnectQuery` is one mental model per popup: mixing it with
`QueryByExample` or standalone capability queries is rejected at
classification time (`classify.ts`), and wallets that predate it fail closed
(the app surfaces an "update Freewallet" error) rather than degrading into a
partial generic flow.

The key design move: **the wallet mints the app-key seed**
(`src/lib/appKey.ts`). The seed is a client secret that must never transit
a server,
so on first run the wallet generates 32 random bytes, derives the did:key
via `CapabilityAgent.fromSeed({ seed, keyName: 'app-key' })` (the `keyName`
string is load-bearing -- it must match was-react's derivation exactly),
self-issues the credential (issuer == subject == seed-derived DID, seed
base64url-no-pad in `credentialSubject.seed`), and saves it to its own
credential store under the same consent -- no second popup. On a returning
visit the stored credential is matched by the `AppKeyCredential` marker type
AND `credentialType` AND `credentialSubject.origin === ` the CHAPI requesting
origin, so a phishing origin can neither recover nor be handed another
origin's key (the app-side origin check in was-react's `parseSeedCredential`
stays as defense in depth).

A match additionally requires that the credential's subject DID **re-derive
from the seed the credential itself carries** (`appKeySeedBindsSubject`).
Self-issuance is a weak signal -- anyone can self-issue, and candidates are
ranked on an `issuanceDate` the credential itself states -- so without this a
credential planted through the store popup or a manual import would win the
match and its DID would become the `controller` the wallet delegates to. The
check is local and deterministic (the seed is right there; re-derive with the
same `CapabilityAgent.fromSeed` call that minted it) and fails closed on an
absent, non-base64url, or wrong-length seed.

**The same binding is enforced at store time, so a foreign app key never
lands.** Every minted app key carries the marker type `AppKeyCredential`
(`urn:was:AppKeyCredential` -- one stable IRI for every app, defined in the
inline `@context`, never interpolated from `vocabBase`), which turns "presents
as an app key" into a term check rather than a shape heuristic. Be clear about
what the marker is: the `type` array of a planted credential is
attacker-controlled like everything else in it, so the marker is a
**self-declaration, not evidence** -- it makes the refusal rule precise, and
the seed-to-subject binding remains the only thing that authenticates.
`StorageManager.addCredential` -- the one door every externally supplied
credential goes through (the CHAPI store popup, the URL / QR / manual-paste
import, the credentials half of a space import) -- refuses a marked credential
that does not bind (`assertStorableAppKey`, `AppKeyRefusedError`). Refusing
beats storing-and-ignoring on two counts: future consumers of an app-key match
do not each have to remember to re-check the binding, and the wallet does not
present the user with a credential it will never act on. The marker is
_required_ at match time rather than merely tolerated, so a credential can
only reach the delegation path by carrying it -- which is exactly what the
store-time refusal screens. The wallet's own mint path stores through the same
door and passes, since a freshly minted key binds by construction. The space
half of an import is not screened: it writes opaque resources into the user's
own Space server-side, and the credentials it carries surface through
`addCredential` like any other import.

The claim terms are shared, not per-app: `seed` and `origin` map to
`urn:was:seed` / `urn:was:origin`, since they mean the same thing in every app.
`vocabBase` namespaces only the app's own type term. The JSON keys are
unchanged.

Because the wallet delegates to the subject DID of the credential it just
matched or minted, the request never needs to name a controller DID --
which is what makes the flow single-round. Delegation reuses
`resolveGrants` / `processZcaps` verbatim (descriptor resolution,
provisioning, the per-target-class action ceilings, TTLs,
protected-collection rules). The response VP embeds the credential, the `zcap` array, and a
wallet-provided `appConnect: { firstRun }` member (a JSON-literal term in
the VP `@context`), all before signing so the DIDAuth proof covers them
(`processAppConnect` in `src/lib/walletRequest/appConnect.ts`).
`WalletGetPage` renders a dedicated app-centric consent panel ("Connect
{app}?") in place of the three generic sections; approval also records an
app-connect Login activity.

**App-provisioned collection encryption (day-one policy).** When an App
Connect `capabilityQuery` provisions a **private** (non-public) collection, the
wallet does not leave it plaintext: it declares the collection EDV-encrypted
and sets up a multi-recipient key-epoch roster in which **the user's vault KAK
is always a recipient (recipient zero)** alongside the app's **identity KAK**
-- the X25519 (Montgomery) twin of the `did:key` the wallet is delegating to,
derived with the same `x25519RecipientFromDidKey` a share uses. There is one
recipient-derivation rule in the system, for an app and a person alike, and the
app seed never enters the grant path: the wallet derives the app's recipient
key from a public identifier it already has. The app derives the private half
from its own controller key, so the app and the wallet -- holding the vault KAK
-- both read the collection, while the WAS server only ever stores ciphertext.
Provisioning is idempotent: no epochs yet ->
`initRecipients([owner, app])`; a reconnect after revoke -> `addRecipient(app)`;
already present -> no-op. The wallet ensures the collection exists without
clobbering an existing `encryption` marker, so an established epoch roster is
never dropped. Public (`urn:was:public-collection`) grants stay plaintext and
world-readable as before; only private app collections are encrypted. The
policy is that **the user is always a recipient of an encrypted collection in
their own Space** -- any future exception (an app collection the user is
deliberately not a recipient of) must be an explicit, separate consent surface,
never a silent default.

Because the user is recipient zero, the wallet decrypts these collections in
the storage browser as an ordinary recipient with its vault KAK, marker-driven
from the fetched Collection Description (no seed at read time). Revoking a
connected app rotates the epoch off the app's key for each such collection
(`removeRecipient`, which rotates then revokes the pull-axis grants
indivisibly), so a revoked app cannot decrypt future writes -- the honest
ceiling being that ciphertext it already fetched stays readable to it.

## Sharing a wallet collection (`urn:was:shared-collection`)

The collections above are ones an app created. **Sharing** is the other
direction: letting a grantee read and _decrypt_ one of the wallet's own
encrypted collections. It is asked for with a distinct invocation-target
descriptor -- `{ type: 'urn:was:shared-collection', name }` -- in either
channel (a standalone `AuthorizationCapabilityQuery`, or an
`AppConnectQuery.capabilityQuery`). A distinct descriptor type rather than a
flag on the existing shape is load-bearing: an unknown `type` already resolves
to unsatisfiable, so a wallet that predates the feature refuses visibly instead
of silently degrading to a ciphertext-only read.

**The two axes stay fused.** _Pull_ (a read-only Collection zcap) and _read_
(an epoch-key recipient entry) are granted together, by one call to
`StorageManager.shareCollection`, which returns the delegated zcap alongside
the refreshed marker so it rides back in the response VP's `zcap` array. A
share grant therefore leaves the ordinary delegation loop in `processZcaps`
entirely; there is no code path that grants one axis without the other.

**The recipient key is derived, not transmitted.** `name` must be one of the
encrypted standard collections -- every `WALLET_STANDARD_COLLECTIONS` entry
carrying an `encryption` marker, so today `private-credentials`,
`wallet-activity`, `contacts`, and `contacts-history` -- since sharing is
meaningless where no epoch roster exists. The grantee's X25519 key is derived
from the `did:key` the request
already names as `controller` (`x25519RecipientFromDidKey` in
`src/lib/didKeyRecipient.ts`, the same Ed25519-to-Montgomery conversion the
wallet applies to its own vault KAK). An explicit key field would let a request
pair controller DID A with recipient key B; deriving makes that substitution
impossible by construction. A controller with no Ed25519 twin (a did:web, an
X25519 did:key) makes the grant unsatisfiable.

**Consent states the ceiling before approval.** The share row on the consent
screen is visually distinct from every other grant and says three things: the
grant is read _and_ decrypt; it covers the collection's contents from the
moment of approval, not only future writes; and removing access later stops
future reads but cannot take back what has already been read. The second line
is hedged for a reason: on a collection's FIRST share the epoch roster is
created lazily (`initRecipients`), and resources written before it are
single-recipient envelopes sealed to the owner's vault KAK alone. Nothing
re-encrypts them, so the new reader can fetch but not decrypt those -- the
owner keeps reading them through the permanent pre-epoch tolerance path. Removal is the Settings "Shared collections"
panel (`unshareCollection`), not expiry -- the share TTL
(`SHARE_ZCAP_TTL_MS`) is deliberately long, because expiry would end the pull
axis while leaving the grantee in the key roster.

**The grantee's half lives in `@interop/was-react`.** An app declares the
wallet-owned collections it wants in `WasAppConfig.sharedCollections`, which
adds the `urn:was:shared-collection` descriptors to its App Connect request; on
approval a `SharedCollectionReader` fetches the Collection Description through
the delegated read zcap, builds the epoch-aware cipher from the marker, and
decrypts the raw envelopes locally. The key it decrypts with is the app's
IDENTITY key-agreement key -- the X25519 twin of its own controller DID, which
is exactly what `x25519RecipientFromDidKey` derived wallet-side, so the two
sides land on the same `kid` without anything travelling on the wire. It is the
same key an app-provisioned collection admits the app with: one recipient
identity per app, whoever owns the collection.

Security notes:

- **Seed confidentiality**: the seed exists only in the wallet and the app
  (browser-direct CHAPI channel); no server ever sees it.
- **Origin binding**: enforced twice -- wallet-side at match/mint time
  (against the CHAPI requesting origin) and app-side in was-react's
  `parseSeedCredential`.
- **Grant scope**: unchanged from the generic capability-query model; the
  requested actions are normalized against the closed WAS action vocabulary
  and intersected with the ceiling for the target's class (whole Space,
  protected collection, and share read-only; public collection add-only; an
  app-provisioned private collection the full vocabulary), and the consent
  screen shows exactly what `resolveGrants` resolved. A grant left with no
  permitted action is unsatisfiable, never delegated empty.
- **Challenge/domain**: unchanged DIDAuth verification app-side in
  was-react.
- **Per-user app identity**: an app key is minted from 32 fresh random bytes
  inside the connecting user's own wallet and stored in that user's own
  credential store, so the app's DID -- and therefore the X25519 recipient
  key derived from it -- is scoped to the **(user, origin, credentialType)**
  triple. The same app connected by two users gets two unrelated DIDs. This
  is deliberately independent randomness per user rather than a derivation
  over (app, user): there is no cross-user linkability between an app's
  DIDs, and compromising one user's app key reveals nothing about another's,
  where a shared-root KDF would break every user at once. "Encrypted to the
  app's key" throughout this document therefore means _that user's_ instance
  of the app, never a key the app reuses across its users.

  The expectation this states is on the App Connect path, where the wallet
  mints the key and fills `controller` itself. A standalone
  `AuthorizationCapabilityQuery` names its own `controller`, so an app taking
  that route could supply one static DID for every user, and each user's
  collection would then wrap its (still distinct) epoch secret to one
  app-held key. The wallet cannot detect this -- it only ever sees one user's
  view -- so it is an ecosystem expectation of app authors, not an enforced
  invariant: **a grantee DID SHOULD NOT be shared across users.** What the
  wallet does guarantee either way is that the recipient key is derived from
  the named controller, so a request can never pair controller DID A with
  recipient key B.

## Route map

| Path                                     | Component                | Notes                                |
| ---------------------------------------- | ------------------------ | ------------------------------------ |
| `/`                                      | `LandingPage`            | Public landing / wallet registration |
| `/login`                                 | `LoginPage`              | Passphrase login                     |
| `/signup`                                | `SignupPage`             | New account creation                 |
| `/guest-login`                           | `GuestLoginPage`         | Ephemeral guest session              |
| `/logout`                                | `LogoutPage`             | Clears session                       |
| `/wallet/get`                            | `WalletGetPage`          | CHAPI popup — share a VC             |
| `/wallet/store`                          | `WalletStorePage`        | CHAPI popup — accept a VC            |
| `/dashboard`                             | `DashboardPage`          | VC list (protected)                  |
| `/credential/:cid`                       | `CredentialDetailPage`   | VC detail + verify (protected)       |
| `/add-credential`                        | `AddCredentialPage`      | Manual VC import (protected)         |
| `/accept-credentials`                    | `AcceptCredentialsPage`  | URL / QR import flow (protected)     |
| `/contacts`                              | `ContactsPage`           | Contact list (protected, stub data)  |
| `/contacts/:contactId`                   | `ContactDetailPage`      | Contact detail (protected)           |
| `/storage`                               | `StoragePage`            | WAS collection browser (protected)   |
| `/storage/collections/:id`               | `CollectionContentsPage` | Collection resources (protected)     |
| `/storage/collections/:id/resources/:id` | `CollectionResourcePage` | Resource viewer (protected)          |
| `/history`                               | `HistoryPage`            | Wallet activity log (protected)      |
| `/settings`                              | `SettingsPage`           | Account settings (protected)         |
| `/docs/:fileName`                        | `DocsPage`               | Renders `public/docs/*.md`           |

## Glossary

Containment hierarchy (remote mode): **Space ⊃ Collection ⊃ Resource**.

- **VC (Verifiable Credential)** — a W3C-standard JSON-LD document asserting
  claims about a subject, signed by an issuer.
- **VP (Verifiable Presentation)** — a wrapper around one or more VCs, used
  when sharing credentials with a verifier.
- **DID (Decentralised Identifier)** — a W3C-standard identifier. Freewallet
  uses only `did:key` DIDs, derived deterministically from an Ed25519 key pair.
- **did:key** — a DID method where the identifier encodes the public key
  directly. No blockchain or registry needed. Freewallet derives each user's
  DID from their passphrase via `CapabilityAgent.fromSecret()`.
- **CID (Content-addressed Identifier)** — a base64url-encoded SHA-256 hash of
  the canonicalized credential JSON (`cidFrom()` in `src/lib/cidFrom.ts`).
  Used as the primary key for stored credentials.
- **ZCap (Authorization Capability)** — the authorization model used to sign
  HTTP requests to the WAS server. Clients sign requests with their Ed25519
  key; the server verifies the signature against the Space controller's DID.
  See the WAS server AGENTS.md for details.
- **CHAPI (Credential Handler API)** — a browser standard that lets websites
  delegate credential operations to a registered wallet via a popup. The
  mediator is `authn.io`.
- **App Connect** — the one-popup app login: a CHAPI `get` whose VPR carries
  an `AppConnectQuery`, answered with an app-key credential (matched by
  origin and seed-to-subject binding, or minted wallet-side on first run)
  plus capabilities delegated to
  its subject DID, in a single signed presentation. See "App Connect" under
  Architecture.
- **App key** — a self-issued credential holding a 32-byte seed in
  `credentialSubject.seed`, bound to a requesting origin in
  `credentialSubject.origin`; issuer and subject are the seed-derived
  did:key (`CapabilityAgent.fromSeed`, `keyName: 'app-key'`). It is how a
  BYOE app keeps its identity/encryption root in the user's wallet
  (`src/lib/appKey.ts`). Every app key carries the marker type
  `AppKeyCredential` (`urn:was:AppKeyCredential`); one carrying the marker
  without binding its subject DID to its own seed is refused at store time.
- **Client / `clientId`** — the keyed, custodied, revocable identity of an
  (app, user) pair: a keypair that can be a zcap grantee, a delegation
  `controller`, or an entry in a collection's key-epoch roster. For a BYOE app
  it is the **app key**'s subject DID above, scoped to
  `(user, origin, credentialType)` and stable across browsers because the
  wallet custodies the seed and re-issues it on a browser-attested origin
  match — a client-only SPA holds no durable secret of its own, so its
  identity is stable by custody, with the origin as the anchor. Deliberately
  not called a "device": one machine hosts many clients (browser profiles,
  several apps, several accounts), and a client is not tied to hardware.
  "App session" is informal prose for one live session of a client; nothing
  named `appSessionId` is persisted.
- **`writerId`** — an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision. Its only jobs are history
  attribution and breaking last-write-wins ties; it is minted locally
  (`src/lib/deviceId.ts`, a `localStorage` key), dies with a wallet reset, and
  is deliberately not derived from any secret — so it is never an identity and
  must not be treated as one. Distinct from a `clientId` in lifetime and in
  trust: it can vanish and be re-minted with nothing carried over. Also not a
  `replicaId`: it is minted per browser profile while the local database is
  per user, so it is not 1:1 with a replica. Still spelled `deviceId` in code
  and in the `@interop/social-core` contact payloads pending the cross-repo
  rename.
- **Share** — granting a third party read AND decrypt access to one of the
  wallet's own encrypted collections, asked for with a
  `urn:was:shared-collection` invocation-target descriptor. One
  `shareCollection` call grants both axes: a read-only Collection zcap and an
  entry in the collection's key-epoch roster. Removed from Settings >
  Shared collections, never by expiry. See "Sharing a wallet collection".
- **WAS (Wallet Attached Storage)** — an HTTP protocol for storing arbitrary
  resources in user-owned Spaces. Requests are authorized via ZCap.
  See [the spec](https://w3c-ccg.github.io/wallet-attached-storage-spec/).
- **Space** — a storage area on the WAS server, identified by
  `spaceId = base64url(SHA-256(controller DID))`. Owned by one controller.
- **Collection** — a named grouping of Resources within a Space.
  Standard collections: `private-credentials`, `public-credentials`,
  `wallet-activity`.
- **Resource** — an individual stored item (JSON or binary) within a
  Collection.
- **Controller** — the `did:key` DID that owns a Space. Its Ed25519 key signs
  all ZCap-authorized requests.
- **CapabilityAgent** — from `@interop/webkms-client`. Wraps the Ed25519
  key pair derived from the passphrase and exposes `getSigner()`.
- **ZcapClient** — from `@interop/ezcap`. Wraps the session's root-key signer
  and adds ZCap headers to HTTP requests.
- **WebKMS / keystore** — the key management server (`KMS_SERVER_URL`,
  by default the WAS server's `/kms` facet). Holds a per-controller
  **keystore** in which operational keys can live server-side; the
  passphrase-derived `keyAgent` remains the keystore's controller,
  client-side only. Accessed via `KmsClient`/`KeystoreAgent` from
  `@interop/webkms-client`; provisioned at login by `src/lib/kms.ts`.
- **Vault KAK** — the X25519 key-agreement key that encrypts/decrypts the
  EDV envelopes, unwrapped at login from the keyring with the
  passphrase-derived unlock key (for pre-keyring accounts and guests it IS
  the passphrase/secret-derived key). Never replicated in unwrapped form
  and never held by the KMS; it is present for the life of every session.
- **Session** — the in-memory object (`src/types/auth.ts`) holding the logged-in
  user, their `ControllerProfile` (keyAgent + zcapClient), and their
  `StorageManager` instance.
- **StorageManager** — the facade class in `src/stores/storageManager.ts`.
  Routes all wallet reads/writes to the local `BrowserStore` (the active
  replica) and exposes the optional `WASRemoteStore` for background
  replication and remote-only features (storage browser, export/import,
  quotas).
- **BrowserStore** — the always-on local active replica, using RxDB /
  IndexedDB (Dexie). Holds every standard wallet collection on the generic
  synced-doc schema.
- **WASRemoteStore** — remote storage client. Speaks the WAS protocol via
  `ZcapClient`. Handles the Space lifecycle, the storage-browser
  read-through over arbitrary collections and resources, export/import, and
  quotas; wallet data reaches it via background replication, not direct calls.
- **SyncController** — the lifecycle around background replication
  (`src/stores/syncController.ts`): starts per-collection
  `replicateRxCollection` state machines on login, cancels on logout,
  re-syncs on reconnect. Uses the collection-agnostic adapter in
  `src/lib/sync/`.
- **DCC Known Registries** — a public JSON registry of trusted issuer DIDs
  fetched from GitHub (`KNOWN_REGISTRIES_URL` in `app.config.ts`) and used
  during credential verification.

## ZCap Structure

A zcap answers "**who** can do **what**, **with** which resource, **given** what
restrictions": `controller` (who, a DID) / `allowedAction` (what, e.g. HTTP
verbs) / `invocationTarget` (with, a URL) / caveats like `expires` (given). A
delegated zcap also carries `parentCapability` and a `proof` with a
`capabilityChain`; a root zcap carries none of those.

**Root vs delegated invocation** (the `Capability-Invocation` header):

- Root: `zcap id="urn:zcap:root:<url-encoded target>"` — just the id.
- Delegated: `zcap capability="<base64url(gzip(json))>",action="GET"` — the full
  capability and its `proof.capabilityChain`, embedded and compressed.

**Signing:** requests are signed with Cavage HTTP Signatures Draft 12 (not yet
RFC 9421). The `Authorization` header signs `(key-id) (created) (expires)
(request-target) host capability-invocation`, plus `content-type digest` when
there's a body. The `Digest` header is a multihash (`mh=`, sha256). See the
[zCap Developer Guide](https://github.com/interop-alliance/zcap-developer-guide).
