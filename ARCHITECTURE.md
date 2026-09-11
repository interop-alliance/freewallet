# Architecture

The map of Freewallet: layer map, the session, identity, and persistence
overviews, the storage model, the route map, the ceremony inventory, where
shared logic lives, the domain glossary, and ZCap structure. Each area's
full account lives in a topic doc under `docs/architecture/` (see "Topic
docs"). For contribution conventions see [CONTRIBUTING.md](CONTRIBUTING.md);
for agent-facing rules (tech stack, env vars) see [AGENTS.md](AGENTS.md).

## Layer map

```
src/pages/          Route-level React components (one file per page)
  auth/             Login, Signup, Lobby, Recover, GuestLogin, Logout
  chapi/            CHAPI popup pages (WalletGetPage, WalletStorePage)
  external/         Requests arriving without CHAPI (ExternalRequestPage,
                    the interaction-URL door)
  dashboard/        Authenticated dashboard pages
src/components/     Shared React components
  credentialDetails/, storage/, resume/   Feature sub-components
src/hooks/          Shared React hooks (verification, credential delete,
                    PRF retry prompt, clipboard, search, the Storage page's
                    one-read shares and apps listings)
src/context/        Theme and info-box React context
src/lib/            Pure business logic (no React)
  kms.ts            WebKMS keystore provisioning (ensureKeystore) and the
                    one KMS-held key the account document publishes
                    (ensureKmsAuthentication)
  didWeb.ts         The did:web projection id of a promoted account
  resolveWalletInput.ts  The one door for free-form text (paste box, QR),
                    over the shared wallet-input classifier
  sessionKey.ts     freewallet-session IndexedDB state (keyring cache,
                    client-key records, unlock methods, passkey-safety
                    notices)
  registryManager.ts     The known-issuer registries client used during
                    credential verification
  storageAccess.ts  Storage Access API handle for the CHAPI popup
  corsProxy.ts      The one CORS-proxy path (`VITE_CORS_PROXY_URL`): the
                    pasted-URL credential fetch, the `oidf` issuer-registry
                    lookups, and the retry behind a blocked direct registry
                    fetch
  writerId.ts, prefsStorage.ts, log.ts   The writerId binding over the
                    package's mint, the global UI prefs seam, the
                    @interop/logger wiring
  connectedApps.ts  Connected-app and agent listings for the Applications page
  viewMappers/      Transform raw credential data into display-ready values
  walletRequest/    VPR classification + response assembly for CHAPI requests
    respond.ts      Compose, persist the Login activity, then deliver (the
                    CHAPI `get` approval sequence)
    externalRequest.ts  The interaction-URL entry point's pure half: the
                    deep-link parser, exchange opening, and pre-consent
                    refusal matrix
src/stores/         Global state
  authStore.ts      Zustand store -- holds the live Session object
  storageManager.ts StorageManager facade (local-first routing)
  browserStore.ts   BrowserStore -- the local RxDB active replica
  remoteDirectStore.ts   The replica-less backend (transient and popup sessions)
  wasRemoteStore.ts WASRemoteStore -- the remote WAS backend
  syncController.ts Background replication lifecycle (restart/stop/reSync)
  setupStore.ts     The one in-flight signup ceremony's step feed and
                    outcome, read by the lobby page (in-memory only)
  toastStore.ts     Transient success/info messages (`showToast`), rendered
                    by DashboardLayout as a Snackbar. Global rather than
                    page-local, since an action often redirects before a
                    local message could render.
src/session/        Session bootstrap and the account ceremonies -- the
                    ordered sequences pages drive but do not own (React
                    components keep rendering and confirmation callbacks
                    only). Grouped by role:
  Login             transientLogin.ts (the default login's routing and
                    composition), initSession.ts, keyring.ts,
                    verifiedLog.ts, loginErrorKey.ts
  Signup            credentialAnchoredGenesis.ts and standingUnlock.ts
                    (the default signup, every WAS deployment),
                    signup.ts, provisionNewWallet.ts
  Persistence       persistence.ts -- the typed strategy both the default
                    and the remembered path ride
  Settings          accountSettings.ts, credentialRotation.ts,
                    unlockMethods.ts, clients.ts, shares.ts, applications.ts
  Ceremonies        recovery.ts, revocation.ts, forget.ts, wipe.ts,
                    ceremonies.ts
  Repairs / sweeps  registryPasses.ts (the passes both chains share),
                    pendingEnrollment.ts, pendingRetirement.ts,
                    registryReseal.ts, userKeySweep.ts, userKeyAdoption.ts,
                    userKeyCascade.ts, standingDelegationRefresh.ts,
                    pointerHeal.ts, appKeySweep.ts, clientAnnexGc.ts,
                    credentialCoverage.ts
  Menders           menders/ -- the mender registry: the invariant table,
                    the two chains' registration lists, the runner that
                    executes one, and the gap allowlist
  Shared parts      rosterStore.ts, collectionLogStore.ts, annexReach.ts,
                    recordEnvelope.ts,
                    accountCeremonyContext.ts, completeAppLogin.ts (the
                    page-level post-login sequence), completePopupLogin.ts,
                    walletLoginActivity.ts
src/types/          Shared TypeScript interfaces
src/i18n/           i18next config + locale JSON files
src/styles/, src/themes/   MUI sx-object style constants and theme config
src/fixtures/       Seed data (default contacts, welcome credential)
src/app.config.ts   Environment variable exports + app-wide constants
```

## Topic docs

The topic docs under `docs/architecture/` carry the mechanism in full. Open
the one covering the area before changing it.

- [Session & auth flow](docs/architecture/session-and-auth.md) -- before
  changing login, the unlock record, the login-time registry repairs, or the
  unlock-credential rotation ceremony.
- [The did:webvh identity (per-client keys, promoted
  controller)](docs/architecture/did-webvh-identity.md) -- before changing
  the account log, update keys, the did:web projection, log continuity, or
  account deletion and the shared wipe.
- [Account genesis
  (`@interop/wallet-core/genesis`)](docs/architecture/account-genesis.md) --
  before changing signup, the credential-anchored establishment, or the
  KMS stage.
- [Session persistence](docs/architecture/session-persistence.md) -- before
  changing the persistence strategy, the transient login, or the
  account-ceremony context.
- [The user key wrap-set roster
  (`key-map/user-key.jsonl`)](docs/architecture/keys-and-descriptor-logs.md)
  -- before changing the user key, a key epoch, or a collection's
  `encryption` descriptor.
- [The client enrollment ceremony
  (`@interop/wallet-core/enrollment`)](docs/architecture/client-enrollment.md)
  -- before changing the connect code or the rendezvous onboarding
  transport.
- [Recovery codes
  (`@interop/wallet-core/recovery`)](docs/architecture/recovery-codes.md) --
  before changing code issuance, a spend, or revocation.
- [Client revocation and the epoch
  cascade](docs/architecture/client-revocation.md) -- before changing
  disconnect, the epoch cascade, or the Connected wallets panel.
- [CHAPI integration](docs/architecture/chapi.md) -- before changing a popup
  page, the DIDAuth holder, or remote-direct popup storage.
- [App Connect (one-popup app login)](docs/architecture/app-connect.md) --
  before changing the app-key credential, grant resolution, or sharing a
  wallet collection.
- [The interaction-URL request page
  (`/external/request`)](docs/architecture/external-request.md) -- before
  changing that page or its pre-consent refusal matrix.

## Session & auth flow

There is no external identity provider, and nothing about the account
derives from the passphrase. The passphrase (or a passkey PRF output)
derives only an unlock identity (`src/session/keyring.ts`), which locates
the account's unlock record in its own minimal unlock Space. That record
carries none of the account's content keys.

One post-KDF question decides the rest (`routeUnlockLogin` in
`src/session/transientLogin.ts`). Does this browser hold a client-key record
for this credential? A browser holding none takes the transient
composition, the default. A browser holding one proceeds as the enrolled
client that record names. A no-WAS deployment always proceeds on the
browser-local tier.

```
unlock secret (passphrase | passkey PRF output)
  -> deriveUnlockSeed(KDF) -> unlock identity -> unlock Space
       -> unlock record { controller, pointer, bridge delegation,
                          ladder seed (standing layout only) }
  -> routeUnlockLogin: this browser holds a client-key record?

     no (the default) -> transient composition
       per-visit key minted in tab memory, enrolled into the client annex
       generation; user key unwrapped from the standing roster wrap
       -> signs as <clientAnnexDid>#<vm> under the generation delegation
       -> in-memory persistence strategy, replica-less storage

     yes, or rememberBrowser: true -> enrolled client
       unwrap the local client-key record
         -> { clientSeed, userKey, webvhUpdateKeys }
       -> agentsFromSeed -> keyAgent; ZcapClient -> zcapClient
       -> browser-local persistence strategy, local replica

  -> Session { user, profile { keyAgent, zcapClient, userKey },
               storage, persistence, isGuest }
```

Navigation to the dashboard waits on `session.storageReady` alone. The
login-time repairs, sweeps, and registry writes run after navigation, as one
mender block: the registrations listed for this chain, in registration
order, run by the mender runner. The runner holds the try, warn, and skip
discipline once, so a failed registration is logged and the block carries
on; only the block's seed, storage provisioning, aborts it. Two promises
settle it. `session.registryReady` settles when the registry-writing
registrations have reported, and never rejects, so a Settings-entered
ceremony that writes the unlock-methods registry awaits it at its own entry
rather than racing them. It does not wait on the keystore promotion: the
pointer heal fires that and the block's tail reports it, so no
`registryReady` awaiter sits behind a KMS round trip. `session.mends`
settles when the whole block has run -- the app-key sweep, the annex GC,
and the keystore report included -- and behind any report the composition
fired beside the block (the did:web projection mend). It carries this
login's mend report: one entry per invariant a mender reported, the routing
entries first.

The unlock-methods registry record is signed as well as sealed: an
eddsa-jcs-2022 proof by the Ed25519 key the account's user key derives,
verified before the record is decrypted. It bounds authorship, since no host
holds that key. It does not bound replay of a body the account itself signed
under a superseded key generation the roster still escrows, which is an open
item.

The `Session` object lives in the Zustand `authStore` and is in-memory only,
so reloading the browser logs the user out. Record authenticity, the replay
bound, the rotation ceremony, and each registry repair are in ["Session &
auth flow"](docs/architecture/session-and-auth.md).

## Identity, keys, and logs

The account's stable id is a `did:webvh` whose hash-chained log lives as
`did.jsonl` in the world-readable `id` collection. Its document is the
enrolled-client roster. Each enrolled client contributes an Ed25519
verification method under `authentication`, `assertionMethod`,
`capabilityInvocation`, and `capabilityDelegation`, plus its X25519 twin
under `keyAgreement`. `updateKeys` carries one update key per enrolled
client, derived from seeds inside that client's wrapped client-key record,
so the server cannot extend the log. Authorization follows the
current-key-set rule (Glossary): one document edit pulls a client's whole
authority.

A standing unlock credential carries a ladder in place of a client key:
update keys derived from a random ladder seed, each rung committed ahead of
use, with a ladder VM published under `assertionMethod` and
`capabilityDelegation`. Every WAS signup produces a credential-anchored
account, whose document publishes that ladder VM and no enrolled client.

The user key is recipient zero of every encrypted collection. Its one remote
home is the log-governed roster `key-map/user-key.jsonl`, whose current key
epoch IS the current user key, wrapped once to each enrolled client's
key-agreement key and once to each standing credential's. Each encrypted
collection's `encryption` descriptor is governed by a resource log of its
own, at the collection's `meta/log` sub-resource. Reads resolve to the
verified head, and writes are signed appends whose proofs must come from
keys the account document lists under `assertionMethod` at the anchored
version.

Every log read is checked against a chain-head pin held in memory for the
visit, so continuity is checked within a session rather than across
sessions.

The account log, the did:web projection, and account deletion are in ["The
did:webvh identity (per-client keys, promoted
controller)"](docs/architecture/did-webvh-identity.md). The roster and the
descriptor logs are in ["The user key wrap-set roster
(`key-map/user-key.jsonl`)"](docs/architecture/keys-and-descriptor-logs.md)
and its ["Per-collection descriptor
logs"](docs/architecture/keys-and-descriptor-logs.md) section. Signup is in
["Account genesis
(`@interop/wallet-core/genesis`)"](docs/architecture/account-genesis.md).
The credential and client halves are in ["Recovery codes
(`@interop/wallet-core/recovery`)"](docs/architecture/recovery-codes.md),
["The client enrollment ceremony
(`@interop/wallet-core/enrollment`)"](docs/architecture/client-enrollment.md),
and ["Client revocation and the epoch
cascade"](docs/architecture/client-revocation.md).

## Session persistence

The storage tier a session may write to is decided once at login, by the
typed persistence strategy at `session.persistence`. The variant IS the
type, so a write site consults no flag. The unlock-methods registry cache,
the passkey-safety notice, the descriptor and meta caches, and the
`writerId` mint ride it. Both continuity pin stores ride it in memory
whichever variant it is.

The in-memory variant is the default, carried by every transient login. Its
whole reach is the pre-session in-memory store family, and it dies with the
tab. It also carries the visit's client-annex identity: the annex DID every
WAS request signs under, and the generation delegation every request rides,
surfaced to the storage layer as `profile.invocationCapability`. It
constructs no `BrowserStore`, serving every synced-collection operation
remote-direct.

The browser-local variant is the opt-in one, carried by a login on a browser
holding a client-key record and by a guest session: the
`freewallet-session` database, the localStorage caches, the persistent
`writerId`, and the local replica the sync controller replicates.

An account-management ceremony binds to one of two kinds of account-ceremony
context, resolved once from the live session. A remembered session resolves
the enrolled kind: this client's update keys and key agent sign, and every
request invokes the root capability. A transient session on a standing
unlock credential resolves the ladder kind: a ladder rung signs through the
record's bridge delegation, the ladder VM appends the roster, and the annex
VM invokes under the generation delegation. The detail is in ["Session
persistence"](docs/architecture/session-persistence.md).

## Ceremonies

A ceremony is an ordered sequence of writes across the account's systems
(the account log, the roster, the unlock records, collection epochs) and
this browser's local state. Three orderings carry its invariants:
persist-before-publish, document-edit-first, and
decryption-material-before-authorization. Every stage detects its own
completion from durable state, so a re-run converges. Every ceremony has a
pivot, the first durable write past which backward recovery is impossible,
and every write either precedes it inertly or is re-derivable from the pivot
entry plus durable state. Every tear point either has a mender a
credential-only visit can fire, or is listed below as an open gap. The
design gate in AGENTS.md governs this set, and the shared stage orders are
canonical in wallet-core's ARCHITECTURE.md. The inventory table below is the
list.

## CHAPI, App Connect, and external requests

CHAPI lets a website trigger a credential request or store through a browser
popup without the site seeing the wallet's passphrase. `registerWallet()`
registers `/wallet/get` and `/wallet/store` with the mediator (`authn.io`)
at login, and the popup pages under `src/pages/chapi/` sit outside
`ProtectedRoute` and the main app layout. The popup makes no routing choice
of its own. It runs the same post-KDF routing every login runs, with the
Storage Access API handle threaded in as the record probe's `idb` factory,
so a denied or unsupported handle finds no record and routes transient. The
store popup refuses a DID-Auth request whose `domain` is absent or does not
match the requesting origin before its login form renders.

App Connect is a CHAPI `get` whose VPR carries one `AppConnectQuery`,
answered in one signed presentation with an app-key credential plus
capabilities delegated to that credential's subject DID. The wallet mints
the app-key seed, a client secret that exists only in the wallet and the
app, and matches a returning app on the marker type, the `appUrl`, the
requesting origin, and the seed-to-subject binding. App keys live in the
dedicated `app-connections` collection, and `StorageManager.addCredential`
refuses every externally supplied credential carrying the marker type.

A request can also arrive with no popup and no attested origin, through the
interaction-URL page `/external/request`. That entry point is stricter than
the popup, the only requester signals being the grantee DID and
request-supplied text: every refusal is decided before consent renders, and
only public-collection and private-collection targets are granted from a
link.

Sharing is the other direction, granting a third party read and decrypt
access to one of the wallet's own encrypted collections through a
`https://w3id.org/byoe#shared-wallet-collection` descriptor. One
`shareCollection` call grants both axes together, the read-only Collection
zcap and the epoch-key recipient entry.

The three flows are in ["CHAPI integration"](docs/architecture/chapi.md),
["App Connect (one-popup app login)"](docs/architecture/app-connect.md), and
["The interaction-URL request page
(`/external/request`)"](docs/architecture/external-request.md). Sharing is
that second doc's "Sharing a wallet collection
(`https://w3id.org/byoe#shared-wallet-collection`)" section.

## Storage model (local-first)

Every credential, public-link, and history read/write goes through one
`SyncedCollectionStore` backend, chosen once at session construction by the
session's storage tier (see "Replica-less, capability-bound storage" in docs/architecture/session-persistence.md under
"Session persistence" in docs/architecture/session-persistence.md). A session with a local replica (a remembered login,
a guest, a no-WAS session) serves them from the local `BrowserStore` (RxDB
over Dexie/IndexedDB), online or offline. A transient session is
replica-less and serves them remote-direct over the remote WAS collections;
so does a remembered CHAPI popup, which constructs a `BrowserStore` and
routes past it (see "Remote-direct popup storage" in docs/architecture/chapi.md). One local database per
user holds every standard collection (`private-credentials`,
`public-credentials`, `wallet-activity`, `contacts`, `contacts-history`,
`app-connections`) on the generic synced-doc schema (`{ id, updatedAt,
version, data }`, `syncedDocSchema` from `@interop/was-sync`). RxDB hashes
that schema and refuses a replica whose stored hash differs, so its shape is
browser-local stored state rather than a code detail.

The encrypted collections, all of the above except `public-credentials`,
store **EDV envelopes**: encrypted at rest locally and opaque to the server.
A per-collection document cipher (`createEdvDocCipher` from
`@interop/was-client/edv`, built from the session's vault KAK) encrypts at
write time and decrypts at read time. The row id is a hash of the JWE
ciphertext, so it is identical on every replica. Page-facing identity stays
the credential `cid` or activity `id`, recovered by decrypting at read time.
JWE encryption is nondeterministic, so dedupe keys on that content identity
rather than on the row id. `public-credentials` is plaintext and keyed
directly by `cid`. Each encrypted collection's key epochs come from the
verified head of its own governing log rather than from a Description member
the host serves (see "Per-collection descriptor logs" in docs/architecture/keys-and-descriptor-logs.md).

When `VITE_WAS_SERVER_URL` is set and the session is not a guest, a remote
WAS Space is attached as a **sync target**. `SessionSyncController` in
`src/stores/syncController.ts` replicates every synced local collection to
its remote WAS Collection counterpart in the background, over
`@interop/was-sync`'s collection-agnostic driver, which ships stored bodies
verbatim and touches no keys. That module is the session binding around the
package's controller core. It owns the gate: a guest, a deployment with no
WAS server, and a replica-less session each replicate nothing. It also owns
the port the core reads the Space and the local collections through, and
where status and diagnostics go. Every replication, and every
`WASRemoteStore` request, is signed with the session's root key.

`WASRemoteStore` does not serve credential reads and writes. It keeps the
Space lifecycle (create/exists/wipe), the storage-browser read-through
(`/storage/**` pages work directly over remote collections), export/import,
and quotas. `StorageManager` is the facade; pages and components always talk
to it rather than to a backend class.

Deleting a credential retracts its world-readable public copy before
removing the private credential (`StorageManager.deleteCredential`), since
once the private credential is gone nothing is left to retract with.
Retraction of a live public copy is blocking, and one that cannot be
retracted refuses the delete (`PublicCopyRetractionError`). The interactive
delete decides on the local replica, so a credential with no local public
copy deletes normally offline. The unattended app-key sweep has retraction
consult the remote `public-credentials` collection too, the local replica
being unable to prove a remote copy absent; an unreachable remote then
refuses the delete. The delete dialog's "keep public copy" choice skips
retraction entirely.

The world-readable share link a public copy gets
(`WASRemoteStore.publicCredentialUrl`) is built with was-client's paths
helpers, which join onto the storage server's base path, so on a sub-path
deployment (a server URL like `https://host/was`) the link addresses exactly
the resource replication wrote, with per-segment encoding.

A collection provisioned for a connected application carries its attribution
on the Collection Description: `generator`, the app's did:key, and
`generatorOrigin`, the Web origin that DID was bound to. Both are stamped
when App Connect provisioning creates the collection, and a collection that
already stands keeps its attribution, so a second app admitted to it does not
rename the creator. The storage browser reads them through
`attributeCollectionsToApps` (`src/lib/collectionAttribution.ts`), which
names a collection's app by matching `generator` against the connected apps'
subject DIDs.

A user's remote Space is identified by an independent random `spaceId`
minted at signup and carried in the account pointer; unlock Spaces keep
`spaceId = base64url(SHA-256(unlock did:key))` as a discovery convention.
The six standard collections above are created on first login.

## Route map

Every row from `/dashboard` through `/settings` is protected;
`/docs/:fileName` and the catch-all are not. `DocsPage` renders
`public/docs/*.md`.

| Path                                                       | Component                |
| ---------------------------------------------------------- | ------------------------ |
| `/`                                                        | `LandingPage`            |
| `/login`                                                   | `LoginPage`              |
| `/signup`                                                  | `SignupPage`             |
| `/lobby`                                                   | `LobbyPage`              |
| `/recover`                                                 | `RecoverPage`            |
| `/guest-login`                                             | `GuestLoginPage`         |
| `/logout`                                                  | `LogoutPage`             |
| `/wallet/get`                                              | `WalletGetPage`          |
| `/wallet/store`                                            | `WalletStorePage`        |
| `/external/request`                                        | `ExternalRequestPage`    |
| `/dashboard`                                               | `DashboardPage`          |
| `/credential/:cid`                                         | `CredentialDetailPage`   |
| `/credential/:cid/issuer`                                  | `IssuerDetailPage`       |
| `/add-credential`                                          | `AddCredentialPage`      |
| `/accept-credentials`                                      | `AcceptCredentialsPage`  |
| `/contacts`                                                | `ContactsPage`           |
| `/contacts/new`                                            | `ContactFormPage`        |
| `/contacts/:contactId`                                     | `ContactDetailPage`      |
| `/contacts/:contactId/edit`                                | `ContactFormPage`        |
| `/contacts/:contactId/history`                             | `ContactHistoryPage`     |
| `/applications`                                            | `ApplicationsPage`       |
| `/applications/:cid`                                       | `ApplicationDetailPage`  |
| `/storage`                                                 | `StoragePage`            |
| `/storage/collections/:collectionId`                       | `CollectionContentsPage` |
| `/storage/collections/:collectionId/resources/:resourceId` | `CollectionResourcePage` |
| `/history`                                                 | `HistoryPage`            |
| `/settings`                                                | `SettingsPage`           |
| `/docs/:fileName`                                          | `DocsPage`               |
| `*`                                                        | `NotFoundPage`           |

## Ceremony inventory

The account ceremonies in one place: the set AGENTS.md's design gate
governs. The shared stage orders are canonical in wallet-core's
ARCHITECTURE.md ("Ceremonies and cascades"); this table lists the
freewallet-side wrappers and the app-only ceremonies. The mender column
names how a torn run gets finished (see Tear mending in the Glossary): a
trigger a credential-only visit can fire, or a remembered-login sweep on a
ceremony only a remembered session runs. A residue left to that chain on an
account that may never run one is an open gap instead, listed below. Every
mender is also declared as an invariant in the mender registry
(`src/session/menders/invariants.ts`), keyed by the predicate it makes true.
The declarations are data and the registrations are code
(`src/session/menders/registrations.ts`): the runner executes one chain's
list in order and reports each entry into `session.mends`, and a routing or
ceremony-tail entry reports from its own call site instead.

| Ceremony                                  | Entry point                                                     | Module                                                                      | Shared half                 | Mender                                                                                                                                                          | Topic doc               |
| ----------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| Credential-anchored genesis               | every WAS signup, remembered or not (the default)               | `src/session/credentialAnchoredGenesis.ts`                                  | `/clientAnnex`              | re-run; the transient login's heal branch                                                                                                                       | `account-genesis.md`    |
| Recovery spend (remembered and transient) | `/recover`                                                      | `src/session/recovery.ts`                                                   | `/recovery`, `/clientAnnex` | remembered: pending record pre-pivot + spend resume; transient: re-run, open gaps (below)                                                                       | `recovery-codes.md`     |
| Self-enrollment at login                  | remembered login on a fresh browser                             | `src/session/initSession.ts` + `src/session/pendingEnrollment.ts`           | `/clientAnnex`              | pending record pre-pivot; the next remembered login's resume                                                                                                    | `session-and-auth.md`   |
| Client enrollment (two-party)             | Settings > Connected wallets, any session type                  | `src/lib/enrollment.ts` (UI in `src/components/EnrolledClientsSection.tsx`) | `/enrollment`               | re-run with the same connect code; the escrow-direction convergence of any later ladder-branch ceremony                                                         | `client-enrollment.md`  |
| Client revocation + epoch cascade         | Settings > Connected wallets, any session type                  | `src/session/revocation.ts`                                                 | `/clients`                  | re-run; the cascade-completion sweep; on the ladder branch, the retire-direction convergence of any later ladder-branch ceremony (open gap below)               | `client-revocation.md`  |
| Recovery-code issuance                    | Settings > Recovery codes, any session type                     | `src/session/recovery.ts`                                                   | `/recovery`                 | re-run with the same code (every stage detects its own completion); a tear after the document entry has no mender                                               | `recovery-codes.md`     |
| Recovery-code revocation                  | Settings > Recovery codes, any session type                     | `src/session/recovery.ts`                                                   | `/recovery`                 | re-run; the cascade-completion sweep                                                                                                                            | `recovery-codes.md`     |
| Unlock-credential rotation                | Settings (passphrase change, passkey removal), any session type | `src/session/credentialRotation.ts`                                         | `/unlock`                   | torn-retirement repair at the next passphrase login, transient or remembered, with its marker-gated establish-first arm; remembered-login sweep; re-seal repair | `session-and-auth.md`   |
| Forget ceremony                           | Settings > Connected wallets, own row, browser-local only       | `src/session/forget.ts`                                                     | `/clientAnnex`              | re-run (wipe last); forgotten-browser detector at the next remembered login                                                                                     | `did-webvh-identity.md` |
| Last-client transition                    | same row, `lastClient` confirm, browser-local only              | `src/session/forget.ts`                                                     | `/clientAnnex`              | re-run                                                                                                                                                          | `did-webvh-identity.md` |
| Update-key rotation                       | Settings, browser-local only                                    | `src/session/accountSettings.ts`                                            | `/webvh`                    | re-run (persist-before-publish)                                                                                                                                 | `did-webvh-identity.md` |
| Account genesis (plain)                   | a no-WAS deployment's signup only; healed at every login        | `src/session/signup.ts`                                                     | `/genesis`                  | re-run (every stage an ensure)                                                                                                                                  | `account-genesis.md`    |
| Account deletion                          | Settings, any session type                                      | `src/session/accountSettings.ts` + `wipe.ts`                                | app-side phase order        | re-run; an in-run retry for the acting credential's own unlock Space; otherwise the next login with that credential offering to remove it (not yet built)       | `did-webvh-identity.md` |
| Shared wipe (executor, not user-facing)   | consumed by the deletion-shaped ceremonies                      | `src/session/wipe.ts`                                                       | app-side                    | re-probe verification; the `unverified` report                                                                                                                  | `did-webvh-identity.md` |

A WAS signup's remembered and passkey flavors continue into the
self-enrollment row, and the credential-anchored genesis heal branch also
mends a remembered signup torn before its self-enrollment.

This list is mirrored by the mender registry's declared gap allowlist
(`src/session/menders/gaps.ts`). Each bullet below names its invariant id,
and a unit test holds the two id sets equal. The allowlist kinds each row
independently of the class its bullet sits in. A `none` gap is a residue no
registration reports on any trigger. An `unreachable` gap is one a
registration reports, on triggers no credential-only visit on the affected
account shape can fire.

The open gaps come in three classes. First, a stated residue with no mender
built:

- The transient recovery's roster-append repair, on a client-less account
  (invariant `recovery-spend-is-completed`).
- A user-key rotation torn mid-fan-out on a client-less account (invariant
  `collection-epochs-name-the-current-user-key`).
- A recovery-code issuance torn after its document entry leaves a saved code
  that locates no account, plus a document `keyAgreement` entry and a roster
  wrap nothing names (invariant
  `every-document-key-agreement-entry-has-a-locatable-credential`). The
  login sweep rotates the orphan wrap away, but the registry-driven health
  check cannot see the code, so the retire-and-reissue mender is unbuilt.
- A sibling unlock Space an account deletion could not remove, whose
  credential is never used again (invariant
  `no-unlock-space-outlives-its-credential`). That credential's own next use
  is the only mender, and an unspent recovery code is the sharp case.
- On a KMS deployment, a keystore orphaned by an account deletion that ran
  before the keystore-deletion route lands (invariant
  `no-keystore-outlives-its-account`). A server-side reaper is not a wallet
  mender.
- A signup whose KMS stage failed or timed out publishes a document with no
  `authentication` relation, and nothing adds one (invariant
  `account-document-publishes-an-authentication-key`). The failure is
  collected rather than thrown, so the account pointer binds and no
  establishment re-run fires the stage again, leaving a remembered login
  this account may never see as the only other trigger. The account presents
  did:key and refuses a `web` or `webvh` request; closing it means a
  ladder-signed entry adding the verification method after the fact.
- A ladder-branch disconnect of the account's last enrolled client, torn
  after its removal entry, leaves the roster wrapping the current key to the
  removed client (invariant `roster-wraps-exactly-the-document-key-set`).
  The row is gone from the listing and that account runs no
  remembered-login sweep, so the only mender is the retire-direction
  convergence of a later ladder-branch ceremony, which the user may never
  run.
- The retired credentials' unlock Spaces on a recovery spend torn between
  the landed registry drop and the deletes (invariant
  `no-unlock-space-outlives-its-credential`). The entries are gone, so
  nothing names the Spaces again. The residue is inert, and is the class the
  registry-driven account-deletion walk already leaves behind.
- An establishment torn between the record re-bind and the registry
  re-entry leaves the unlock-methods registry naming no establishing
  credential (invariant `registry-records-the-establishing-credential`). The
  re-entry arm's trigger is a marker held in the crashed tab's memory, so
  the next visit does not fire it.
- A pending passphrase entry written by a refusal after establishment stays
  in the registry (invariant
  `registry-passphrase-entry-names-the-standing-credential`). The seedless
  torn-retirement repair cannot clear it (wallet-core's `decisions/0015`).

Second, a residue whose only mender is a remembered login:

- The collection descriptor logs behind a forget ceremony's removal entry
  (invariant `governed-log-heads-anchor-past-the-membership-change`).
  Both forget grades run their collection fan-out before the entry, so every
  append anchors at a version that still lists the forgotten client's key,
  and that key can keep appending there until a still-listed key appends
  past the removal. An ordinary forget leaves that to the next remembered
  login's sweep. The last-client transition leaves an account nothing seals,
  since the departing client's authority ends at its own entry and the
  transient login runs no collection seal.
- The annex generation GC, which runs from the remembered-login chain only
  (invariant `no-annex-generation-outlives-its-pointer`). On a client-less
  account the pointed generation's log grows by one entry per transient
  visit with nothing collecting it, and every visit resolves that log from
  genesis. A `gen-` collection orphaned by a crashed first visit waits for
  the same sweep, and an account-log pointer entry left by one is
  append-only. The constraint is authority: the swap re-points the account
  log, the collect fan-out is controller-tier, and a ladder VM can sign
  neither.
- An auxiliary Space stranded between its mint and its pointer entry by a
  crashed first visit (invariant `no-auxiliary-space-stands-unnamed`). No
  account-log pointer entry names it, and nothing deletes it.
- A credential-anchored signup whose pointer backfill failed leaves the
  unlock record pointing at the signup-time did:key (invariant
  `account-pointer-names-the-account-did`). The heal that converges it is
  registered on the remembered-login block alone, which a client-less
  account never runs.
- An establishment torn between the record re-bind and the promotion leaves
  the KMS keystore's controller on the ladder's bare did:key, outside the
  current-key-set rule (invariant `keystore-controller-is-the-account-did`).
  The promotion that converges it is fired by the same remembered-login
  pointer heal and reported from that block's tail. A mender could run from
  a transient visit instead, the keystore ensure not depending on the
  Space.
- Stranded app keys after a last-client transition (invariant
  `app-keys-live-only-in-app-connections`). The sweep that clears them runs
  from the remembered-login chain alone.
- A signup torn before its standard collections are provisioned, on an
  account that runs no remembered login (invariant
  `standard-collections-are-provisioned`). Whether the transient heal
  re-provisions them is the tracking item's first question.
- A forgotten or disconnected browser whose local wipe tore, on an account
  with no remembered login left to run the detector (invariant
  `this-browser-is-still-an-enrolled-client`). Whether this is a gap at all
  is the tracking item's first question, since a login on the browser
  holding the residue routes remembered and fires the detector.

Third, a detector that is not a mender: a declaration carrying a detector and
no registration, by design, so the derivation kinds it `none` and the row
tracks the decision rather than a build:

- The acting credential's document listing (invariant
  `document-lists-the-acting-credential`). The detector refuses the transient
  login with `credential-not-standing`; the ceremony that tore converges it
  on its own re-run.
- The saved recovery codes' health (invariant
  `saved-recovery-codes-locate-their-account`). The detector nudges the user
  rather than refusing; the user's own reissue is the mender.

One bound is not an open gap. An account that runs the last-client
transition with several standing credentials lands client-less carrying one
standing ladder VM per credential, since the transition strikes only the
departing client's inventory. Each stays a live delegation signer until its
credential is retired. The credential ceremonies run on the ladder kind, so
a transient login with any one standing credential retires the others
through the passphrase change and the passkey removal. Removing the
credential the visit itself entered on refuses
(`ActingCredentialRemovalError`), so retiring a VM takes a login on a
different credential.

## What lives elsewhere (do not reimplement here)

Every `@interop/*` package is in-house, checked out beside this repo (e.g.
`../wallet-core`). A change needed in one is an in-house change: export it
from the owning package and import it, rather than copying or re-deriving it
app-side. The shared wallet layer's map is
[`../wallet-core/ARCHITECTURE.md`](../wallet-core/ARCHITECTURE.md): module
layers and dependency direction, the key hierarchy, the ceremonies and
cascades, and the permanent wire-level constants.

- **`@interop/wallet-core`** -- the correctness-critical logic shared with
  the DCW mobile wallet, imported by subpath. The set this app uses:
  - the root entry (the ceremony-id vocabulary, and the stage-notifier and
    logger seams)
  - `/webvh` (the did:webvh log, the document halves of the ceremonies)
  - `/clientAnnex` (the ladder, the annex log and its GC, the
    ladder-anchored ceremonies: credential-anchored genesis, self-enrollment,
    transient recovery, and the recorded-grant revocation
    `revokeRecordedGrant` with its refusal reading). The verify-side halves
    stay in the base subpaths.
  - `/keys` (the user key, its wrap-set roster, the per-collection
    descriptor log store, the client-key record codec, client labels)
  - `/keyring` (the unlock layer), `/unlock` (standing unlock credentials,
    the credential rotation and retirement sequence)
  - `/genesis` (the account-genesis key mint and ceremony)
  - `/enrollment`, `/recovery`
  - `/clients` (listing, disconnect policy, the revocation cascade
    orchestrator, the login-time roster policy)
  - `/descriptors` (the log-governed descriptor source and the collection
    descriptor log's pin slot), `/identity`
  - `/space` (collection layout, activity builders, `was-link`)
  - `/resourceLog` (the did:webvh controller adapter
    `webvhResourceLogController` and the ceremony-tail license)
  - `/menders` (the mender registry's structure: the declaration and
    registration types, the vocabularies and the closed invariant-id census,
    the readers, the runner that executes one chain trigger's registrations
    under one try, warn, and skip discipline, and the derived-set helpers
    the audit tests read)
  - `/sync` (contacts head-conflict resolution,
    `resolveContactHeadConflict`, over social-core's comparison; the change
    engine beside it is the mobile wallet's).
  - `/testing` (test fixtures only, lint-restricted to test files: the
    recorded-grant builder and the account signer check the revocation
    tests on both sides of the package boundary assert against)
- **`@interop/wallet-request`** -- the request pipeline shared with DCW:
  wallet-input classification, VPR parsing, QueryByExample matching,
  cryptosuite negotiation, VP composition, the App Connect app-key
  credential, the VC-API and ephemeral-exchange clients, and the
  `WalletOnboardingQuery` vocabulary. `src/lib/walletRequest/` is the
  App Connect-aware layer over it. The classifier does not know the
  account conventions it routes: `lib/resolveWalletInput.ts` hands it
  wallet-core's `isWasLinkPayload` and `isConnectCode` as injected
  recognizers. The package has its own logger seam, wired beside
  wallet-core's in `lib/log.ts`.
- **`@interop/was-sync`** (+ `/rxdb`, `/testing`) -- the WAS replication
  driver for RxDB, shared with `@interop/was-react`: the synced-document
  schema, the opaque-body helpers, the conflict-handler seam, and the
  writer-id mint on the root entry; the changes-feed pull handler, the
  conditional-write push handler, the `replicateRxCollection` wiring, and the
  controller core on `/rxdb`; test fixtures on `/testing`, which an eslint
  rule keeps out of production code. Freewallet keeps the three bindings
  around it: the session binding in `stores/syncController.ts` (the gate, the
  port, the status store, the browser reachability source), the contacts
  decision closure in `stores/contactsConflictHandler.ts`, and the writer-id
  key prefix and storage in `lib/writerId.ts`. The driver runs no
  unknown-epoch refresh of its own, so the closure reads was-client's
  self-refreshing cipher (`stores/refreshingCollectionCipher.ts`). A conflict
  side sealed under an epoch another client rotated to is re-read once before
  it counts as undecryptable.
- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic
  client side: chain verification, the chain-head pin port
  (`ResourceLogPinStore`, `ResourceLogHeadPin`, `memoryResourceLogPinStore`)
  with its host-free slot keys, and the continuity and integrity refusal
  classes. Freewallet imports the pin port directly and matches the refusals
  by `err.name` rather than by class, since a duplicate package copy would
  break `instanceof`. The did:webvh controller adapter stays on
  `@interop/wallet-core/resourceLog`.
- **`@interop/was-client`** (+ `/edv`, `/sync`, `/paths`, `/log`) -- the WAS HTTP
  client, the sync wire contract the RxDB driver speaks, its error classes
  and the `err.name` predicates that classify them (`isUnknownEpochError`,
  `isSyncConflictError`, `isSyncAuthError`), the EDV envelope cipher and
  key-epoch construction (`createEdvDocCipher`, `x25519RecipientFromDidKey`),
  the descriptor-store seam, and on `/log` the generic resource-log store
  (`resourceLogStore`) the per-collection descriptor logs ride.
- **`@interop/social-core`** -- the contacts collection specs and the
  `remotePayloadWins` last-write-wins comparison itself.
- **`@interop/vc-display`** -- credential display mapping.
- **`@interop/capability-agent`** -- `CapabilityAgent`;
  **`@interop/webkms-client`** -- `KmsClient` / `KeystoreAgent`;
  **`@interop/ezcap`** -- `ZcapClient`.
- **`@interop/data-integrity-core`** -- loose VC/VP shape guards and the VPR
  type vocabulary.
- **`@interop/did-method-webvh`** -- the webvh log primitives (normally
  reached through `wallet-core/webvh`).
- **`@interop/verifier-core`** -- credential verification.

## Glossary

This is the repo's ubiquitous language: one canonical term per concept, used
the same way in code, tests, docs, and conversation. Where an entry ends
with `Avoid:`, that list names the synonyms this repo does not use. The
convention is canonical in isomorphic-lib-template's ARCHITECTURE.md,
Glossary section.

Containment hierarchy (remote mode): **Space > Collection > Resource**.

- **VC (Verifiable Credential)** -- a W3C-standard JSON-LD document
  asserting claims about a subject, signed by an issuer.
- **VP (Verifiable Presentation)** -- a wrapper around one or more VCs, used
  when sharing credentials with a verifier.
- **DID (Decentralised Identifier)** -- a W3C-standard identifier. An
  account's stable id is a `did:webvh`; clients, apps, and agents are
  identified by `did:key`.
- **did:key** -- a DID method where the identifier encodes the public key
  directly. A wallet client's did:key derives from its randomly minted
  32-byte client seed (`agentsFromSeed`) rather than from the passphrase.
- **CID (Content-addressed Identifier)** -- a base64url-encoded SHA-256 hash
  of the canonicalized credential JSON (`cidFrom()` from
  `@interop/was-client/sync`), the primary key for stored credentials.
- **ZCap (Authorization Capability)** -- the authorization model for HTTP
  requests to the WAS server. Clients sign with their Ed25519 key, and the
  server verifies against the Space controller's DID.
- **CHAPI (Credential Handler API)** -- a browser standard that lets
  websites delegate credential operations to a registered wallet via a
  popup. The mediator is `authn.io`.
- **App Connect** -- the one-popup app login: a CHAPI `get` whose VPR
  carries an `AppConnectQuery`, answered in one signed presentation with an
  app-key credential plus capabilities delegated to its subject DID.
- **App key** -- a self-issued credential holding a 32-byte seed in
  `credentialSubject.seed`, bound to a requesting origin
  (`credentialSubject.origin`) and the application's canonical URL
  (`credentialSubject.appUrl`), issued to and by the seed-derived did:key
  (`CapabilityAgent.fromSeed`, `keyName: 'app-key'`). It carries the type
  `AppKeyCredential` (`https://w3id.org/byoe#AppKeyCredential`) and lives in
  the `app-connections` collection.
- **Client / `clientId`** -- the keyed, custodied, revocable identity of an
  (app, user) pair: a keypair that can be a zcap grantee, a delegation
  `controller`, or an entry in a collection's key-epoch roster. It is a
  cache rather than the account's durable state, so state reconstructible
  from a client alone is a defect. Avoid: device, device id, durable client.
- **Agent** -- a connected app that mints its own did:key and asks for
  scoped, expiring, revocable grants through a standalone
  `AuthorizationCapabilityQuery`, naming itself as `controller`. It holds
  neither the user key nor the unlock credential and is not a wallet client.
  Avoid: transient client (the annex inventory), agent client, bot.
- **`writerId`** -- an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision, used to attribute history
  and break last-write-wins ties. It is minted per browser profile in
  `src/lib/writerId.ts` under the `localStorage` key `freewallet:writerId`,
  derives from no secret, and is not an identity. Avoid: replicaId, device
  id, session id.
- **Share** -- granting a third party read AND decrypt access to one of the
  wallet's own encrypted collections, asked for with a
  `https://w3id.org/byoe#shared-wallet-collection` invocation-target
  descriptor. One `shareCollection` call grants both axes. See "Sharing a
  wallet collection".
- **WAS (Wallet Attached Storage)** -- an HTTP protocol for storing
  arbitrary resources in user-owned Spaces, authorized via ZCap. See [the
  spec](https://w3c-ccg.github.io/wallet-attached-storage-spec/).
- **Space** -- a storage area on the WAS server, owned by one controller.
  The account Space's id is an independent random identifier carried in the
  account pointer; unlock Spaces are addressed by `spaceId =
base64url(SHA-256(unlock did:key))` (a discovery convention).
- **Collection** -- a named grouping of Resources within a Space. Standard
  collections: `private-credentials`, `public-credentials`,
  `wallet-activity`, `contacts`, `contacts-history`, `app-connections`.
- **Resource** -- an individual stored item (JSON or binary) within a
  Collection.
- **Controller** -- the DID that owns a Space: the account's `did:webvh`
  once promoted, and a `did:key` before promotion and on an unlock Space.
- **Current-key-set rule** -- the server's authorization policy for a Space
  whose controller is a did:webvh: an invocation or delegation verifies iff
  its verification method is listed in the account document as resolved NOW,
  which the server settles by reading and fully verifying `did.jsonl` out of
  its own storage. Revoking a client is therefore one document edit.
  Log-entry and roster proofs anchor at a version instead, so history never
  rots. The annex is governed the same way, against its own document: an
  enrolled client's invocation or delegation link settles against the account
  document, a transient VM's against the current annex document. See "The
  did:webvh identity".
- **Standing unlock credential** -- an unlock method (passphrase or passkey)
  whose unlock record, beside locating the account, carries a wrap of the
  user key in the roster and latent self-enrollment authority: a bridge
  delegation, the `delegatedClients` sibling delegation, and a random ladder
  seed. Its entropy bounds everything server-held that it alone decrypts.
- **Bridge delegation** -- the pre-minted zcap carried inside an unlock or
  recovery record beside the account pointer: a PUT-on-`did.jsonl`
  capability, plus annex-log access where that applies. All it can do is
  extend the world-readable log, which keeps credential use loud.
- **Unlock-local state** -- the browser-local artifacts one unlock method
  leaves on a browser, keyed by its unlock Space id: today the keyring cache
  and the wrapped client-key record. `deleteUnlockLocalState` in
  `src/lib/sessionKey.ts` is the one deleter. Avoid: unlock trio, local
  trio, unlock artifacts, credential residue.
- **Ladder (update-key ladder)** -- the chain of did:webvh update keys
  derived from a standing credential's random ladder seed, each rung
  committed ahead of use as a hash in `nextKeyHashes` and revealed in an
  entry signed by the current rung. The **ladder VM** derived from it
  publishes under `assertionMethod` and `capabilityDelegation` with no
  invocation relation, and is struck when its credential retires.
- **Roster** -- three related uses: the **enrolled-client roster** is the
  did:webvh document itself, the **user key wrap-set roster**
  (`key-map/user-key.jsonl`) is the log-governed record whose current epoch
  IS the current user key, and a **key-epoch roster** is the per-collection
  recipient set on an encrypted collection's `encryption` descriptor. All
  three deliver key material rather than authority.
- **Inventory** -- a credential's or client's set of durable entries in the
  account document, the annex log, or the ladder: its `keyAgreement` entry
  or commitment, its ladder VMs, its committed rung hashes, its annex rung
  hashes. An entry is inventory-changing iff the set differs from the
  previous version's. Avoid: posture, footprint.
- **Loudness** -- the design property that any exercise of
  credential-derived authority must first extend a hash-chained log (the
  account log, or the annex log) before it can read or grant anything, so a
  takeover is detected and remediated rather than prevented. The two logs
  grade differently: the account log is world-readable and append-only, so
  a record there is public and permanent; the annex log is capability-gated
  and garbage-collected, so a record there is mortal. A mechanism
  "fails loudness" when it lets a credential exercise authority with no
  logged record at all; account deletion is a stated exception, since
  destroying the account Space destroys the log such a record would live in
  (`decisions/0002`'s 2026-09-01 amendment).
- **Continuity pin** -- remembered evidence of what this client last saw,
  checked against what the host now serves: a log's verified chain head
  (`persistence.logPins`) or the user key roster's current epoch
  (`persistence.epochPins`). It catches the attack in which every signature
  verifies, and every pin store is in-memory
  (`decisions/0012-no-durable-continuity-pins.md`). See "Log continuity
  within a session". Avoid: continuity prior.
- **Ceremony** -- an ordered sequence of writes across the account's systems
  and this browser's local state, ordered by persist-before-publish,
  document-edit-first, and decryption-material-before-authorization. Each
  has a **pivot**, the first durable write past which backward recovery is
  impossible, and every write either precedes it inertly or is re-derivable
  from it plus durable state (wallet-core's
  `decisions/0010-post-pivot-derivability-rule.md`). Avoid: flow, workflow,
  wizard.
- **Invariant** -- the mender registry's unit: a predicate over the
  account's server-held state, and for a few entries over this browser's
  local state, that must hold between ceremonies. A ceremony may violate it
  while it runs. Once no ceremony is running, a violation is a torn state,
  and converging it is mending. Each declaration names one authority
  (`none`, `account`, `enrolled`, or `ladder`) and the triggers that check
  the predicate today (`remembered-login-chain`, `transient-login-chain`,
  `login-routing`, `ceremony-tail`). A session holds `none` always, plus
  `account` and the resolved kind whenever an account-ceremony context
  resolves, and an entry is satisfied when the held set contains its
  authority. The id names the predicate rather than the code, so moving a
  converger between modules renames nothing. Avoid: mender id, check, rule.
- **Mender registry** -- the invariant declaration table plus the
  per-trigger registration lists. `@interop/wallet-core/menders` carries the
  structure and the readers; `src/session/menders/` carries freewallet's
  table. Declarations are data and registrations are code. The registry
  describes the ceremonies from the outside and executes no stage order.
  Registration order within a list is execution order, and there is no
  dependency graph. Its gap allowlist declares the residues nothing
  converges today, in two kinds: `none`, where no registration reports the
  invariant at all, and `unreachable`, where one reports it on triggers a
  credential-only visit cannot fire. Avoid: saga, state machine, mender
  table.
- **Tear mending** -- the umbrella for how a torn ceremony (one interrupted
  mid-run) gets finished, by a converging re-run, a standing sweep, or a
  repair. A mender counts only if a credential-only visit can fire it, so a
  residue whose one trigger is the remembered-login chain is an open gap
  (`decisions/0010-remembered-login-is-not-a-mender-trigger.md`). The open
  gaps are declared in the mender registry's gap allowlist, in the two kinds
  `none` and `unreachable`. Avoid: tear closure.
- **Repair** -- the mender of last resort: code waiting at the one entry
  point where the authority a torn state needs reassembles, detecting that
  state from stored state alone and finishing the ceremony. Always qualified
  by its torn state ("the torn-retirement repair"). Avoid: completer,
  finisher, fixup.
- **Client annex** (`clientAnnex`) -- the transient session's counterpart of
  an enrolled client: a did:webvh whose log lives in a capability-gated
  auxiliary Space beside the account Space, recording per-visit verification
  methods in GC'd **generations** ("the annex" in prose). It never appears
  in the account document, and transient keys invoke and delegate as
  `<clientAnnexDid>#<vm>` under `capabilityInvocation` and
  `capabilityDelegation` alone.
- **Generation delegation** -- the one Space-scoped zcap per annex
  generation, delegated to the annex DID by the enrolled client that mints
  the generation, or by the ladder VM on a credential-anchored account. Its
  `invocationTarget` is the Space's items subtree, so a whole-Space target
  under it is unsatisfiable and every grant's `expires` is limited to its
  own.
- **CapabilityAgent** -- from `@interop/capability-agent`. Wraps the Ed25519
  key pair derived from the passphrase and exposes `getSigner()`.
- **ZcapClient** -- from `@interop/ezcap`. Wraps the session's root-key
  signer and adds ZCap headers to HTTP requests.
- **WebKMS / keystore** -- the key management server (`KMS_SERVER_URL`, by
  default the WAS server's `/kms` facet), holding a per-controller
  **keystore** in which operational keys live server-side while the
  controlling key stays client-side. One key is minted there today, the
  `authentication` key the account document publishes, recorded in
  `key-map/keys.json` as `{ vmId, kmsKeyId }`.
- **Vault KAK** -- the X25519 key-agreement key that encrypts and decrypts
  the EDV envelopes: the user key's key-agreement key. It is never
  replicated in unwrapped form and never held by the KMS. Avoid: PUK.
- **Session** -- the in-memory object (`src/types/auth.ts`) holding the
  logged-in user, their `ControllerProfile` (keyAgent + zcapClient), their
  `StorageManager` instance, and the persistence strategy at
  `session.persistence`. The strategy sits beside `storage` rather than on
  the profile: it is session-lifetime scaffolding, and the profile is the
  identity bundle alone.
- **Durable** -- persisted server-side, on the WAS host: the account log,
  the user key roster, the unlock records, the Collection Descriptions and
  their key epochs. It survives a cleared browser, an evicted origin, and a
  lost machine, and the word names this tier alone
  (`decisions/0011-durable-names-server-storage-only.md`). Avoid: durable
  session, durable client, durable login, durable pin.
- **Browser-local** -- persisted in this browser's IndexedDB or
  localStorage: the client-key record, the keyring cache, the Space-to-DID
  mapping, the descriptor and meta caches, the `writerId`, and the replica
  database. It survives a reload but not an eviction, and it is a cache
  rather than the only home of anything the account needs. Avoid: durable
  local state, disk, persistent storage.
- **In-memory** -- held in tab memory and gone when the tab closes: a
  transient session's whole store family, every session's continuity pin
  stores and unlocked key material, and the prefs overlay.
- **Session persistence** -- the axis deciding which storage tier a session
  may write to, fixed once at login by the typed persistence strategy. Its
  two variants are browser-local and in-memory; this is not the remembered /
  transient axis, since a guest session is browser-local and is not
  remembered. Avoid: durability, posture, mode.
- **Persistence strategy** -- the typed object at `session.persistence`
  through which every tier-sensitive write travels. The variant IS the type,
  so a write site never branches: an in-memory strategy has no member
  reaching the session database
  (`decisions/0001-no-memory-overlay-storage-fork.md`). Avoid: persistence
  handle, durability handle ("handle" in this repo is the Storage Access
  API's).
- **Transient session** -- the default session, taken on a WAS deployment by
  a login on a browser holding no client-key record for the credential typed
  and given no explicit `rememberBrowser`. It mints a per-visit key in tab
  memory, enrolls it into the client annex generation, unwraps the user key
  from the credential's standing roster wrap, and runs on the in-memory tier
  with no local replica. Avoid: ephemeral session, temporary session, and
  any name for a physical setting.
- **Credential-anchored account** -- an account whose authority is anchored
  in a standing unlock credential's ladder rather than in an enrolled
  client. Its document publishes that ladder VM and no enrolled client, so
  its log state is **ladder-anchored** and every visit is a transient
  session unless someone opts into remembering a browser. Avoid:
  client-less signup, transitional account.
- **Remembered browser** -- a browser holding a client-key record for an
  unlock credential, so a login on it proceeds as (or self-enrolls into) an
  enrolled client. Remembering is a deliberate opt-in (`rememberBrowser`),
  undone by the forget ceremony, and lost with a cleared profile. A login on
  one is a **remembered login**, its session a **remembered session**.
  Avoid: durable browser, durable login, trusted browser, persistent
  login.
- **Enrolled client** -- a wallet client published in the account document,
  keyed on `capabilityInvocation`, holding a client-key record, a wrap in
  the user key roster, and its own did:webvh update key. Contrast the
  **transient client**, a per-visit key recorded in a client annex
  generation; both are caches. Avoid: durable client, permanent client.
- **Account-ceremony context** -- the authorities an account-management
  ceremony binds to, resolved once from the live session
  (`accountCeremonyContext`). The **enrolled kind** signs entries with this
  client's did:webvh update keys, appends the roster with its key agent, and
  root-invokes; the **ladder kind** signs with a rung of the credential's
  ladder through the record's bridge delegation, appends with the ladder VM,
  and invokes as the per-visit annex VM under the generation delegation. A
  guest, a no-WAS session, and a transient session whose record carries no
  standing members resolve to neither, so no account-management ceremony
  runs. Update-key rotation and the forget ceremony ignore both kinds, since
  their subject is this browser itself.
- **StorageManager** -- the facade class in `src/stores/storageManager.ts`,
  routing all wallet reads and writes to the session's
  `SyncedCollectionStore` backend and exposing the optional `WASRemoteStore`
  for remote-only features.
- **BrowserStore** -- the local active replica of a session that has one,
  over RxDB / IndexedDB (Dexie), holding every standard wallet collection on
  the generic synced-doc schema. A transient session constructs none.
- **WASRemoteStore** -- remote storage client, speaking the WAS protocol via
  `ZcapClient`. Handles the Space lifecycle, the storage-browser
  read-through over arbitrary collections and resources, export/import, and
  quotas.
- **SyncController** -- the lifecycle around background replication: one
  `replicateRxCollection` state machine per synced collection, started on
  login and cancelled on logout. The core is `@interop/was-sync`'s and its
  `stop()` is terminal, so the binding in `src/stores/syncController.ts`
  constructs a fresh core per session.
- **DCC Known Registries** -- a public JSON registry of trusted issuer DIDs
  fetched from GitHub (`KNOWN_REGISTRIES_URL` in `app.config.ts`) and used
  during credential verification.

## ZCap Structure

A zcap answers "**who** can do **what**, **with** which resource, **given**
what restrictions": `controller` (who, a DID) / `allowedAction` (what, e.g.
HTTP verbs) / `invocationTarget` (with, a URL) / caveats like `expires`
(given). A delegated zcap also carries `parentCapability` and a `proof` with
a `capabilityChain`; a root zcap carries none of those.

**Root vs delegated invocation** (the `Capability-Invocation` header):

- Root: `zcap id="urn:zcap:root:<url-encoded target>"` -- just the id.
- Delegated: `zcap capability="<base64url(gzip(json))>",action="GET"` -- the
  full capability and its `proof.capabilityChain`, embedded and compressed.

**Signing:** requests are signed with Cavage HTTP Signatures Draft 12 (not
yet RFC 9421). The `Authorization` header signs `(key-id) (created)
(expires) (request-target) host capability-invocation`, plus `content-type
digest` when there's a body. The `Digest` header is a multihash (`mh=`,
sha256). See the [zCap Developer
Guide](https://github.com/interop-alliance/zcap-developer-guide).
