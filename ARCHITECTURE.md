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
                    the interaction-URL entry point)
  dashboard/        Authenticated dashboard pages
src/components/     Shared React components
  credentialDetails/, storage/, resume/   Feature sub-components
  AgentReconnectList.tsx  The agent list a ceremony's dialog shows, and
                    the notice its reconnect leaves
  RemoveSignInDataButton.tsx  The dead-pointer prompt's accept, shared by
                    the login, recover, and interaction-URL pages
src/hooks/          Shared React hooks
  useAgentReconnect.ts  A ceremony dialog's agent ticks, and the decline
                    and restore once the ceremony succeeds
  useDeadPointerRemoval.ts  The dead-pointer removal offer a login
                    surface holds, and the removal run on its accept
src/context/        Theme and info-box React context
src/lib/            Pure business logic (no React)
  kms.ts            WebKMS keystore provisioning (ensureKeystore), the
                    keystore controller promotion, and the one KMS-held key
                    the account document publishes (ensureKmsAuthentication)
  didWeb.ts         The did:web projection id of a promoted account
  resolveWalletInput.ts  The one entry point for free-form text (paste box,
                    QR), over the shared wallet-input classifier
  sessionKey.ts     freewallet-session IndexedDB state (keyring cache,
                    client-key records, writer first-seen records, the
                    Space-to-DID mapping, the unlock-methods registry cache,
                    passkey-safety notices)
  registryManager.ts     The known-issuer registries client used during
                    credential verification
  storageAccess.ts  Storage Access API handle for the CHAPI popup
  corsProxy.ts      The one CORS-proxy path (`VITE_CORS_PROXY_URL`)
  verify.ts         The credential verification adapter over
                    @interop/verifier-core
  passkey.ts        The WebAuthn registration and assertion ceremonies and
                    their PRF output
  registerWallet.ts CHAPI handler registration with the mediator
  wasService.ts     The one WAS service discovery every WasClient reuses
  decryptFailure.ts The classifier sorting a failed envelope decrypt into
                    its handling bucket
  collectionAttribution.ts  A collection's and a Resource's creator lines
                    (`generator` and `createdBy`)
  enrollment.ts     The app-side halves of the client enrollment ceremony
  writerId.ts, prefsStorage.ts, log.ts   The writerId binding over the
                    package's mint, the global UI prefs seam, the
                    @interop/logger wiring
  connectedApps.ts  Connected-app and agent listings for the Applications
                    page, read from the `connections` directory, and the
                    app and agent revocations
  viewMappers/      Transform raw credential data into display-ready values
  walletRequest/    VPR classification + response assembly for CHAPI requests
    getRequest.ts   The CHAPI get popup's pre-consent refusal matrix,
                    the attested requesting origin included
    respond.ts      The consent record, escrow, and delivery sequence shared
                    by the CHAPI get popup and the interaction-URL page
    externalRequest.ts  The interaction-URL entry point's pure half: the
                    deep-link parser, exchange opening, and pre-consent
                    refusal matrix
    externalRequestPath.ts  The deep-link route and query-parameter
                    contract, dependency free so e2e specs can import it
    connectionRequest.ts  The connection request's `#inbox` descriptor and
                    the test that tells a connection request apart,
                    dependency free
    storeRequest.ts The store popup's pre-login DID-Auth check
    appConnect.ts   App Connect processing: the app-key credential found or
                    minted, and the capabilities delegated to it
    processZcaps.ts Grant resolution onto the user's Space, the requester's
                    delegations, and requester collection provisioning
    attributeExistingCollections.ts  The consent screen's second grant
                    pass, naming whose collection a request targets
src/stores/         Global state
  authStore.ts      Zustand store -- holds the live Session object
  storageManager.ts StorageManager facade over the session's backend
  connectionsStore.ts   The `connections` directory's store seam: the
                    remote-direct adapter on a session with a Space, the
                    local one on a guest or no-WAS session
  browserStore.ts   BrowserStore -- the local RxDB active replica
  remoteDirectStore.ts   The replica-less backend (transient and popup sessions)
  wasRemoteStore.ts WASRemoteStore -- the remote WAS backend
  syncController.ts Background replication lifecycle (restart/stop/reSync)
  syncStatusStore.ts     Per-collection replication status (in-memory only)
  contactsConflictHandler.ts  The contacts collection's conflict decision
                    closure
  refreshingCollectionCipher.ts  The contacts cipher that re-reads the
                    descriptor on an unknown-epoch decrypt
  sessionTeardown.ts     The one teardown order for a session not entered
                    again (disposal, replication stop, replica release)
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
                    verifiedLog.ts, loginErrorKey.ts, deadAccountPointer.ts
                    (the dead-pointer refusal and the sign-in data removal
                    it offers), retireUnlockIdentity.ts (the one unlock
                    identity retirement)
  Signup            credentialAnchoredGenesis.ts and standingUnlock.ts
                    (the default signup, every WAS deployment),
                    signup.ts, provisionNewWallet.ts, standingEstablishment.ts
                    (the entry-first establishment a passkey add and a
                    backup credential share)
  Persistence       persistence.ts -- the typed strategy both the default
                    and the remembered path ride
  Settings          accountSettings.ts, credentialRotation.ts,
                    unlockMethods.ts, backupCredential.ts, clients.ts,
                    shares.ts, applications.ts, agentReconnect.ts (the
                    agents a ceremony cuts off, the decline marker, and
                    the restore)
  Ceremonies        recovery.ts, revocation.ts, forget.ts, wipe.ts,
                    backupExport.ts, contentMigration.ts
  Repairs / sweeps  registryPasses.ts (the passes both chains share),
                    pendingEnrollment.ts, pendingRetirement.ts,
                    registryReseal.ts, userKeySweep.ts, userKeyAdoption.ts,
                    userKeyCascade.ts, standingDelegationRefresh.ts,
                    pointerHeal.ts, clientAnnexGc.ts,
                    credentialCoverage.ts, connectionWriters.ts (the
                    writer registration and the writer sweep),
                    inboxPass.ts (the inbox drain, the agent grant
                    renewal, and the outbox push)
  Menders           menders/ -- the mender registry: the invariant table,
                    the two chains' registration lists, the runner that
                    executes one, the gap allowlist, and the encounter
                    runner and its session bindings (encounter.ts,
                    encounterSites.ts), and the ceremony-tail report
                    consumer (ceremonyTail.ts)
  Shared parts      rosterStore.ts, collectionLogStore.ts, annexReach.ts,
                    recordEnvelope.ts, sessionLifecycle.ts (the disposal
                    signal and the encounter gate),
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
  changing the persistence strategy, the transient login, the
  account-ceremony context, the backup export, or content migration.
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
browser-local tier. The explicit `rememberBrowser: true` entry self-enrolls
a browser holding no record. No login form offers it yet, so on a WAS
deployment a production browser becomes remembered only as the enrollee of
a two-party client enrollment.

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

     yes -> enrolled client
       (rememberBrowser: true with no record self-enrolls one first)
       unwrap the local client-key record
         -> { clientSeed, userKey, webvhUpdateKeys }
       -> agentsFromSeed -> keyAgent; ZcapClient -> zcapClient
       -> browser-local persistence strategy, local replica

  -> Session { user, profile { keyAgent, zcapClient, userKey },
               storage, persistence, isGuest }
```

Navigation to the dashboard waits on `session.storageReady` alone. The
login-time repairs, sweeps, and registry writes then run as one mender
block per chain, in registration order. The registry admits only the
registrations whose authority the session holds. `session.registryReady`
settles when the block's registry-writing registrations have reported, and
a Settings ceremony that writes the unlock-methods registry awaits it.
`session.mends` settles when the whole block has run, and carries the
login's mend report. `session.inboxPass` settles when the inbox pass
behind the block has run, outside both. None of the three rejects. The
`Session` object lives in the Zustand `authStore`, in memory only, so a
reload logs the user out.

The chain lists, the block's seed, the signed unlock-methods registry
record, record authenticity, the replay bound, the rotation ceremony, and
each registry repair are in ["Session & auth
flow"](docs/architecture/session-and-auth.md).

## Identity, keys, and logs

The account's stable id is a `did:webvh` whose hash-chained log lives as
`did.jsonl` in the world-readable `id` collection. Its document is the
enrolled-client roster: each enrolled client contributes its signing and
key-agreement methods and one client-held update key, so the server cannot
extend the log. Authorization follows the current-key-set rule (Glossary).
A standing unlock credential carries a ladder in place of a client key.
Every WAS signup produces a credential-anchored account, whose document
publishes a ladder VM and no enrolled client.

The user key is recipient zero of every encrypted collection. Its one remote
home is the log-governed roster `key-map/user-key.jsonl`, wrapped once to
each enrolled client and each standing credential. Each encrypted
collection's `encryption` descriptor is governed by a resource log of its
own. Every log read is checked against a chain-head pin held in memory for
the visit.

The account log, the roster, the descriptor logs, signup, and the credential
and client ceremonies each have a topic doc (see "Topic docs" above).

## Session persistence

The storage tier a session may write to is decided once at login, by the
typed persistence strategy at `session.persistence`. The variant IS the
type, so a write site consults no flag. The in-memory variant is the
default, carried by every transient login. It dies with the tab, carries the
visit's client-annex identity (surfaced as `profile.invocationCapability`),
and constructs no `BrowserStore`. The browser-local variant is the opt-in
one, carried by a remembered login and by a guest session. It holds the
`freewallet-session` database, the localStorage caches, the per-profile
`writerId`, and the local replica. Both variants hold every continuity pin
store in memory.

An account-management ceremony binds to one of two account-ceremony context
kinds, resolved once from the live session: the enrolled kind on a
remembered session, and the ladder kind on a transient session with a
standing unlock credential (see "Account-ceremony context" in the Glossary).
The detail is in ["Session
persistence"](docs/architecture/session-persistence.md).

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
match the requesting origin before its login form renders. The get popup
refuses, before its own login form renders, a request whose attested origin
does not parse, so the consent screen always names a requester. It also
refuses a standalone capability query outside an `AppConnectQuery`: a plain
CHAPI `get` delegates no capabilities. Only App Connect and the
interaction-URL page grant storage access, and the Applications page lists
and revokes both kinds of grantee.

App Connect is a CHAPI `get` whose VPR carries one `AppConnectQuery`,
answered in one signed presentation with an app-key credential plus
capabilities delegated to that credential's subject DID. The wallet mints
the app-key seed, a client secret that exists only in the wallet and the
app, and matches a returning app on the marker type, the `appUrl`, the
requesting origin, and the seed-to-subject binding. App keys live in the
dedicated `app-keys` collection, and `StorageManager.addCredential`
refuses every externally supplied credential carrying the marker type.

A request can also arrive with no popup and no attested origin, through the
interaction-URL page `/external/request`. That entry point is stricter than
the popup, the only requester signals being the grantee DID and
request-supplied text: every refusal is decided before consent renders, and
only public-collection and private-collection targets are granted from a
link. A plain URL target naming an existing encrypted collection whose
current key epoch does not list the agent is refused too, since that grant
would read only ciphertext. So is a request whose grantee `controller` is
the did:key of a wallet client the verified account document lists or ever
listed (`enrolledClient`,
`decisions/0037-an-interaction-url-may-not-name-an-enrolled-client.md`).
The popup still delegates a ciphertext-only grant, with a note on its
consent row.

An agent connects through a connection request: an interaction-URL request
whose grants include the `https://w3id.org/byoe#inbox` descriptor. It asks
for reads on audience collections, named by container URL, and for POST on
the account's `inbox`. It must carry a VPR-root `challenge` and a proof by
the did:key it names as `controller`. So the wallet mints no key toward a
party that never asked. The wallet answers with a presentation held and
signed by a pairwise did:key, derived from a seed kept on the agent's
connection entry. The agent then posts a channel capability into the
`inbox`, and the login-time inbox pass stores it. While the connection
stands, the pass renews the agent's grants in the same scope with no
prompt, and pushes the renewals through that channel. The consent rows
state both facts. The request and its refusals are in "The interaction-URL
request page" (external-request.md), and the channel, the renewal, and the
revoke are in "The agent connection" (app-connect.md).

Both paths record a consent the same way (`composeAndDeliverResponse` in
`src/lib/walletRequest/respond.ts`). Once the delegations are signed, the
party's `connections` entry is written with the grants. That entry is the
revocation index. The Grant activity is written after it, as audit trail.
Both precede any escrow into a key epoch and any delivery. A failed entry
write fails the request closed, and a failure after it rolls the consent
back (`decisions/0034-the-directory-is-the-grant-index.md`).

A share is the other direction: a third party gets read and decrypt access
to one of the wallet's own encrypted collections, recorded on its
connection entry as `grantKind: 'share'` (see "Sharing a wallet
collection" in docs/architecture/app-connect.md).

The three flows are in ["CHAPI integration"](docs/architecture/chapi.md),
["App Connect (one-popup app login)"](docs/architecture/app-connect.md), and
["The interaction-URL request page
(`/external/request`)"](docs/architecture/external-request.md).

## Storage model (local-first)

Every credential, contact, public-link, and history read and write goes through
one `SyncedCollectionStore` backend, chosen once at session construction by the
session's storage tier. A session with a local replica (a remembered login, a
guest, a no-WAS session) serves them from the local `BrowserStore` (RxDB over
Dexie/IndexedDB), online or offline. A transient session and a remembered CHAPI
popup serve them remote-direct over the remote WAS collections (see
"Replica-less, capability-bound storage" in
docs/architecture/session-persistence.md, and "Remote-direct popup storage" in
docs/architecture/chapi.md). One local database per user holds every standard
collection (`private-credentials`, `public-credentials`, `wallet-activity`,
`contacts`, `contacts-history`, `app-keys`) on the generic synced-doc
schema (`syncedDocSchema` from `@interop/was-sync`). Its shape is
`{ id, updatedAt, data }` plus optional members the server assigns or
reports: the rest of the write stamp (`updatedAtCounter`, `originId`), the
nested `meta` stamp and the `custom` body, `createdBy`, `epoch`, the
`etag` and `metaEtag` validators, and the `writerId` label the latest
revision was declared under. A local write carries only `id`,
`updatedAt`, `data`, and an optional `epoch`, and the write's ack or the
feed's echo fills in the rest. RxDB hashes that schema and refuses a replica
whose stored hash differs, so its shape is browser-local stored state rather
than a code detail. `BrowserStore` forgets a replica RxDB refuses on its
schema hash. It removes the whole database, the replication checkpoint
included, and the next replication re-pulls it from the Space. Writes not yet
pushed are lost. A guest or no-WAS session has no Space to re-pull from, so
its replica is lost whole. No member of a resource replica is an order key,
so a listing that needs an order sorts on a timestamp in the decrypted
payload.

The encrypted collections, all of the above except `public-credentials`, store
**EDV envelopes**: encrypted at rest locally and opaque to the server. A
per-collection document cipher (`createEdvDocCipher` from
`@interop/was-client/edv`, built from the session's vault KAK) encrypts at write
time and decrypts at read time. The resource id is a hash of the JWE ciphertext,
so it is identical on every replica. The exception is `contacts`, whose head
Resources keep a stable random id and are rewritten in place. Every decrypt
names the id the body was read under, and a body sealed for some other resource
is refused rather than opened, so a host cannot answer one resource with
another's envelope. Such a Resource is counted in its own bucket, apart from the
purgeable one: producing it takes no keys, so a host that could have it
collected as garbage could have the wallet destroy recoverable data. The
dashboard reports it and offers no removal. A body that is not an envelope at
all, served from an encrypted collection, is refused the same way: nothing
authenticates it, so it is skipped, counted in a third non-purged bucket, and
reported with no removal. The only plaintext passthrough left is a collection
built with no cipher. Page-facing identity stays the
credential `cid` or activity `id`, recovered by decrypting at read time. JWE
encryption is nondeterministic, so dedupe keys on that content identity rather
than on the resource id. `public-credentials` is plaintext and keyed directly by
`cid`. Each encrypted collection's key epochs come from the verified head of its
own governing log rather than from a metadata member the host serves (see
"Per-collection descriptor logs" in
docs/architecture/keys-and-descriptor-logs.md).

The `connections` directory holds one encrypted connection entry per party the
wallet has dealt with (an app, an agent, or a wallet client), at a resource id
keyed by an HMAC of the party's DID. The entries' grants are the revocation
index. The `wallet-activity` rows are audit trail, which the History page reads
and nothing deciding about a party does
(`decisions/0034-the-directory-is-the-grant-index.md`). The directory is never
replicated. It is read and written remote-direct on a session with a Space, and
is a local RxDB collection on a guest or a no-WAS session
(`decisions/0035-the-directory-rides-the-session-backend-and-is-never-replicated.md`).
It is never grantable, and nothing authenticates an entry's body, so reader
rules bound what a host can steer
(`decisions/0038-no-authorship-guard-on-connections-entries.md`). An entry is
retired, keeping its names, when its party's relationship ends. The binding
refusals, the read and write rules, and retirement are in "The `connections`
directory" in docs/architecture/app-connect.md.

The `inbox` collection is the channel a connected agent reaches the wallet
by (`decisions/0042-one-wallet-wide-plaintext-inbox-is-the-channel.md`). It
is plaintext, not public, and outside every ordinary target class. An agent
holds POST on it and nothing more, so it can post a message and cannot
list or read one. The wallet reads and deletes its mail remote-direct under
the session's own capability, with no local replica. It refuses an `inbox`
that is public, carries an `encryption` descriptor, or carries a
`generator` stamp. Each marks a collection some requester created under
that name, and a refused inbox counts as absent. A guest or no-WAS session
has no inbox. The inbox pass that reads it is in "The agent connection" in
docs/architecture/app-connect.md.

When `VITE_WAS_SERVER_URL` (the server's Spaces Repository URL; the base URL is
its parent) is set, and the session holds a local replica and is not a guest, a
remote WAS Space is attached as a **sync target**. `SessionSyncController` in
`src/stores/syncController.ts` replicates every synced local collection to its
remote WAS Collection counterpart in the background, over `@interop/was-sync`'s
collection-agnostic driver, which ships stored bodies verbatim and touches no
keys. That module is the session binding around the package's controller core,
and owns that gate. It also owns the port the core reads the Space and the local
collections through, where status and diagnostics go, and the `writerId` every
push declares (the session persistence's per-profile label). Replication signs
with the session's root key. A transient session's `WASRemoteStore` requests
invoke under its generation delegation (`profile.invocationCapability`).

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
copy deletes normally offline. The delete dialog's "keep public copy"
choice skips retraction entirely.

The world-readable share link a public copy gets
(`WASRemoteStore.publicCredentialUrl`) is built by wallet-core/space's
`publicCredentialUrl`, over was-client's path helpers, which join onto the
storage server's base path, so on a sub-path deployment (a server URL like
`https://host/was`) the link addresses exactly the resource replication wrote,
with per-segment encoding.

A collection provisioned for a requester carries a `generator` stamp on its
Collection Metadata object. Its `id` is the requester's DID, an
origin-bound app's stamp adds `origin` and `url`, and `name` is optional.
The stamp is controller-asserted, only labels the consent row and the
listings, and grants nothing. A collection and a Resource also carry
`createdBy`, the DID the server observed creating it, which is optional.
Neither signal is verified identity. Both are named against one in-memory
read of the directory (`lookupCollectionCreators`, `lookupCreatedByParty`,
`resolveCreatedBy`), and a DID the wallet itself invokes as reads as "this
wallet" (see "Two creator signals" in docs/architecture/app-connect.md).

Content migration brings another account's backup bundle into this one,
through `StorageManager`'s import methods, which skip a Resource the account
already holds by its content identity. Every session kind may run it, and it
contacts no server of the old account. App collections are re-provisioned
remote-direct under their archived `generator`, need remote storage and a
promoted account, and are merged by the same skip-existing rule. The walk
and its refusals are in "Content migration" and "Content migration's app
collections" in docs/architecture/session-persistence.md.

The backup export goes the other way. It establishes a backup credential,
then streams the account Space, the client-annex Space, and every unlock
Space into one tar through `@interop/wallet-backup`'s `exportBundle`. A
pre-flight refuses before anything is minted. The credential's secret is
packed sealed under an export passphrase or in the clear, and the file's
bound is the weaker of that passphrase and the wallet passphrase. A restore
login on the credential is not built yet. The stage order is in "The backup
export's stage order" in docs/architecture/session-persistence.md.

Signup provisions the six standard collections, the `connections`
directory, and the `inbox`, and a remembered login re-walks that roster.
That re-walk is the only thing that adds an `inbox` to an older account.
Nothing backfills the directory on an older account
(`decisions/0036-no-backfill-for-the-directory.md`).

## Route map

Every row from `/dashboard` through `/settings` is protected;
`/docs/:fileName` and the catch-all are not. `DocsPage` renders
`public/docs/*.md`. `ApplicationDetailPage` is keyed by the party's
`connections` entry resource id, and opens an app or an agent.

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
| `/applications/:resourceId`                                | `ApplicationDetailPage`  |
| `/storage`                                                 | `StoragePage`            |
| `/storage/collections/:collectionId`                       | `CollectionContentsPage` |
| `/storage/collections/:collectionId/resources/:resourceId` | `CollectionResourcePage` |
| `/history`                                                 | `HistoryPage`            |
| `/settings`                                                | `SettingsPage`           |
| `/docs/:fileName`                                          | `DocsPage`               |
| `*`                                                        | `NotFoundPage`           |

## Ceremony inventory

A ceremony is an ordered sequence of writes across the account's systems
(the account log, the roster, the unlock records, collection epochs) and
this browser's local state. Three orderings carry its invariants:
persist-before-publish, document-edit-first, and
decryption-material-before-authorization. Every stage detects its own
completion from durable state, so a re-run converges. Every ceremony has a
pivot, the first durable write past which backward recovery is impossible,
and every write either precedes it inertly or is re-derivable from the pivot
entry plus durable state. AGENTS.md's design gate governs this set. The
shared stage orders are canonical in wallet-core's ARCHITECTURE.md
("Ceremonies and cascades"), and every ceremony below is named by an id in
wallet-core's `CEREMONY_IDS`.

The table lists the freewallet-side wrappers and the ceremonies implemented
app-side. The mender column names how a torn run gets finished (see Tear
mending in the Glossary): a trigger a credential-only visit can fire, or a
remembered-login sweep on a ceremony only a remembered session runs. A
residue left to that chain on an account that may never run one is an open
gap instead, listed after the table.

Every mender is declared as an invariant in the mender registry
(`src/session/menders/invariants.ts`), and the registrations that run them
live in `src/session/menders/registrations.ts`. The runner executes one
login chain's list in order and reports into `session.mends`. Behind the
block, the inbox pass (the drain of the account's `inbox`, then the renewal
of the connected agents' grants, `src/session/inboxPass.ts`) runs as each
chain's tail and reports into `session.inboxPass` alone, since it reaches
other parties' servers. A routing or ceremony-tail entry reports from its
own call site, through a report-only site that names the invariants it
grades. Two tail sites exist, the client revocation's and the
unlock-credential rotation's; a ceremony's own roster rotation and
collection cascade report no entry and back no trigger. Five encounter
registrations run mid-visit through the
encounter runner, where a session meets the evidence: a collection
recorded as stranded, a stale registry seal at the Settings mount, the
`connections` writer sweep at the page-level directory listing read
(`readDirectoryListing`), and the inbox pass twice. One is the Settings
page after a ceremony that replaces the generation delegation. The other is
the Notifications page open (`openInboxNotifications`), which no page calls
yet. Five more encounter sites report from their own call sites, since each
caller needs a return value or a refusal back. Encounter entries go to the page that
asked, not to `session.mends`. Every ceremony but update-key rotation, and
every mend entry, also emits on the ceremony event channel (wallet-core's
`ceremonyEvents` and `menderEvent`), which the debug-logs skill documents.

| Ceremony                                              | Entry point                                                                                                                                                               | Module                                                                      | Shared half                 | Mender                                                                                                                                                                                                                                                                                                                            | Topic doc                |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| Credential-anchored genesis                           | every WAS signup, remembered or not (the default)                                                                                                                         | `src/session/credentialAnchoredGenesis.ts`                                  | `/clientAnnex`              | re-run; the transient login's heal branch                                                                                                                                                                                                                                                                                         | `account-genesis.md`     |
| Recovery spend (remembered and transient)             | `/recover`                                                                                                                                                                | `src/session/recovery.ts`                                                   | `/recovery`, `/clientAnnex` | remembered: pending record pre-pivot + spend resume; transient: re-run, the next login's collection fan-out, open gaps (below)                                                                                                                                                                                                    | `recovery-codes.md`      |
| Self-enrollment at login                              | `rememberBrowser: true` on a browser holding no record (no login form offers it yet)                                                                                      | `src/session/initSession.ts` + `src/session/pendingEnrollment.ts`           | `/clientAnnex`              | pending record pre-pivot; the next remembered login's resume                                                                                                                                                                                                                                                                      | `session-and-auth.md`    |
| Client enrollment (two-party)                         | Settings > Connected wallets, any session type                                                                                                                            | `src/lib/enrollment.ts` (UI in `src/components/EnrolledClientsSection.tsx`) | `/enrollment`               | re-run with the same connect code; the escrow-direction convergence of any later ladder-branch ceremony                                                                                                                                                                                                                           | `client-enrollment.md`   |
| Client revocation + epoch cascade                     | Settings > Connected wallets, any session type; the dialog ticks the agents to keep                                                                                       | `src/session/revocation.ts`                                                 | `/clients`                  | re-run; the cascade-completion sweep; the transient login's collection fan-out; on the ladder branch, the retire-direction convergence of any later ladder-branch ceremony (open gap below)                                                                                                                                       | `client-revocation.md`   |
| Recovery-code issuance                                | Settings > Recovery codes, any session type                                                                                                                               | `src/session/recovery.ts`                                                   | `/recovery`                 | re-run with the same code (every stage detects its own completion); a tear after the document entry has no mender                                                                                                                                                                                                                 | `recovery-codes.md`      |
| Recovery-code revocation                              | Settings > Recovery codes, any session type                                                                                                                               | `src/session/recovery.ts`                                                   | `/recovery`                 | re-run; the cascade-completion sweep; the transient login's collection fan-out                                                                                                                                                                                                                                                    | `recovery-codes.md`      |
| Unlock-credential rotation                            | Settings (passphrase change or add, passkey add or removal, backup-credential removal), any session type; a change or removal dialog ticks the agents to keep             | `src/session/credentialRotation.ts`                                         | `/unlock`                   | torn-retirement repair at the next passphrase login, transient or remembered, with its marker-gated establish-first arm; remembered-login sweep; the transient login's collection fan-out; re-seal repair                                                                                                                         | `session-and-auth.md`    |
| Forget ceremony                                       | Settings > Connected wallets, own row, browser-local only; ends the agent grants this client signed                                                                       | `src/session/forget.ts`                                                     | `/clientAnnex`              | re-run (wipe last); forgotten-browser detector at the next remembered login                                                                                                                                                                                                                                                       | `did-webvh-identity.md`  |
| Last-client transition                                | same row, `lastClient` confirm, browser-local only; the dialog marks unticked agents declined                                                                             | `src/session/forget.ts`                                                     | `/clientAnnex`              | re-run                                                                                                                                                                                                                                                                                                                            | `did-webvh-identity.md`  |
| Update-key rotation                                   | Settings, browser-local only                                                                                                                                              | `src/session/accountSettings.ts`                                            | `/webvh`                    | re-run (persist-before-publish)                                                                                                                                                                                                                                                                                                   | `did-webvh-identity.md`  |
| Account genesis (plain)                               | every remembered login's storage provisioning on a WAS deployment, as a heal (a no-WAS signup mints keys only)                                                            | `src/stores/storageManager.ts` + `src/session/signup.ts`                    | `/genesis`                  | re-run (every stage an ensure)                                                                                                                                                                                                                                                                                                    | `account-genesis.md`     |
| Account deletion                                      | Settings, any session type                                                                                                                                                | `src/session/accountSettings.ts` + `wipe.ts`                                | app-side phase order        | re-run; an in-run retry for the acting credential's own unlock Space; otherwise the dead-pointer prompt at the next login or recovery spend with that credential, which offers to remove its sign-in data                                                                                                                         | `did-webvh-identity.md`  |
| Shared wipe (executor, not user-facing)               | consumed by the deletion-shaped ceremonies                                                                                                                                | `src/session/wipe.ts`                                                       | app-side                    | re-probe verification; the `unverified` report                                                                                                                                                                                                                                                                                    | `did-webvh-identity.md`  |
| Content migration                                     | Storage page, beside Export Space, every session kind including guest                                                                                                     | `src/session/contentMigration.ts`                                           | `@interop/wallet-backup`    | re-run (skip existing by content identity; the import activity replaced put-then-delete-others; an app collection's own torn create, empty and carrying the archived `generator`, finished)                                                                                                                                       | `session-persistence.md` |
| Backup export                                         | Storage page, the export action, any session with remote storage                                                                                                          | `src/session/backupExport.ts`                                               | `@interop/wallet-backup`    | re-run; the pre-flight refuses before the pivot; a tear inside the establishment leaves the entry-first row, whose Remove under Settings > Backup credentials converges whatever it reached (strike, roster rotation, Space delete, entry drop); a tear after it leaves an ordinary labeled backup credential the user can remove | `session-persistence.md` |
| Request consent (App Connect, interaction URL, share) | CHAPI get popup and `/external/request`, approval of a request; an agent restore (a dialog's tick, Restore on the Applications detail page); a grant needs a remote Space | `src/lib/walletRequest/respond.ts` + `src/session/agentReconnect.ts`        | app-side                    | a failure before the first escrow rolls the record back; past it, the recorded grants stay listed, and the user's own revoke from that row converges them                                                                                                                                                                         | `app-connect.md`         |
| Grant revocation (app, agent, unshare)                | Applications page (disconnect, revoke), Storage page shares dialog (unshare); an unshare needs a remote Space                                                             | `src/lib/connectedApps.ts` + `src/session/shares.ts`                        | app-side                    | the user's own re-run from the row a torn run leaves listed; an agent revoke's first write empties the channel, so no renewal undoes a torn one                                                                                                                                                                                   | `app-connect.md`         |

A WAS signup's remembered and passkey flavors continue into the
self-enrollment row, and the credential-anchored genesis heal branch also
mends a remembered signup torn before its self-enrollment.

A client revocation and a forget each retire the client's `connections`
entry, best-effort. What a tear around that retirement leaves is in "Client
revocation and the epoch cascade" (client-revocation.md).

The inbox pass is not a ceremony. It runs behind each login chain's block
(`REMEMBERED_INBOX_TAIL`, `TRANSIENT_INBOX_TAIL`) and reports into
`session.inboxPass` alone. Its renewal's pivot is `recordRenewedGrants`,
which records the renewed grants and queues their envelope on the entry's
`outbox` in one compare-and-swap. A push that fails waits on the outbox for
the next pass. A ceremony that withdraws signing authority cuts every
subscriber child of the agent grants that authority signed, all at once.
These are a client revocation, a forget, the last-client transition, a
passphrase change, a passkey or backup-credential removal, and a recovery
spend. The
ceremony dialogs and the restore are in "The agent connection" in
app-connect.md
(`decisions/0043-a-grant-signed-by-withdrawn-authority-is-renewed-only-on-the-owners-tick.md`).

The open gaps below mirror the gap allowlist (`src/session/menders/gaps.ts`).
Each bullet names its invariant id, and a unit test holds the bullet ids
equal to the allowlist ids. The allowlist kinds each torn state, not each
invariant, and independently of the class its bullet sits in. A `none` gap
is a torn state nothing converges on any trigger, even where a registration
reports the same invariant for other torn states. An `unreachable` gap is
one a registration converges, on triggers no credential-only visit on the
affected account shape can fire.

The open gaps come in three classes. First, a stated residue with no mender
built:

- The transient recovery's roster-append repair, on a credential-anchored
  account (invariant `recovery-spend-is-completed`).
- A recovery-code issuance torn after its document entry leaves a saved code
  that locates no account (invariant
  `every-document-key-agreement-entry-has-a-locatable-credential`). The
  remembered login's sweep rotates the orphan wrap away, but no
  retire-and-reissue mender exists.
- A sibling unlock Space an account deletion could not remove, whose
  credential is never used again (invariant
  `no-unlock-space-outlives-its-credential`). The dead-pointer prompt at a
  login or a recovery spend on that credential is the mender, so only the
  credential never used again leaves the Space standing.
- A keystore orphaned by an account deletion on a KMS deployment (invariant
  `no-keystore-outlives-its-account`). A server-side reaper is not a wallet
  mender.
- A signup whose KMS stage failed publishes a document with no
  `authentication` relation (invariant
  `account-document-publishes-an-authentication-key`). No re-run fires the
  stage again, and a remembered login's genesis heal adds no method either.
- The retired credentials' unlock Spaces on a recovery spend torn between
  the registry drop and the deletes (invariant
  `no-unlock-space-outlives-its-credential`). Nothing names them again, and
  the residue is inert.
- The retired credentials' registry entries and unlock Spaces on a
  transient recovery spend whose registry write and its one retry both
  failed (invariant `no-unlock-space-outlives-its-credential`). No pending
  carrier is left to resume the drop.
- An establishment torn between the record re-bind and the registry
  re-entry (invariant `registry-records-the-establishing-credential`). The
  re-entry arm's trigger is a marker in the crashed tab's memory.
- A pending passphrase entry written by a refusal after establishment
  (invariant `registry-passphrase-entry-names-the-standing-credential`),
  which the seedless torn-retirement repair cannot clear.
- A party holding a live grant the wallet delegated with no `connections`
  entry, because a re-created directory lost it or it predates the
  directory (invariant
  `every-grantee-of-the-wallet-has-a-connection-entry`). Nothing backfills
  the directory, and its grants end only at their own expiry. A subscriber
  holding a child of an agent's grant has no entry by design. The owner
  reaches it through the agent's entry.
- A party whose authority the account withdrew (a revoked client, a
  retired credential, a struck annex generation) keeps every pairwise seed
  and channel capability it read from the directory (invariant
  `no-withdrawn-party-holds-a-live-pairwise-channel`). The epoch cascade
  does not reach the seed. Such a party can post into an agent's inbox as
  the wallet until that capability expires, and no seed rotation is built.
- An auxiliary Space stranded between its mint and its pointer entry by a
  crashed first visit (invariant `no-auxiliary-space-stands-unnamed`).
  Nothing names it, and nothing deletes it.
- An account that adopted an untrusted `inbox`, one that is public, carries
  an `encryption` descriptor, or carries a `generator` stamp (invariant
  `standard-collections-are-provisioned`). The drain refuses it, and the
  provision re-walk's presence check reads it as present, so no trigger on
  either account shape replaces it.

Second, a residue whose only mender is a remembered login:

- A ladder-branch disconnect of the last enrolled client, torn after its
  removal entry, leaves the roster wrapping the current key to that client
  (invariant `roster-wraps-exactly-the-document-key-set`). Otherwise only
  the retire-direction convergence of a later ladder-branch ceremony mends
  it.
- The user key roster log behind an ordinary forget ceremony's removal
  entry (invariant `roster-log-head-anchors-past-the-membership-change`).
  The forgotten client's key can keep appending there until a still-listed
  key appends past the removal.
- The annex generation GC (invariant
  `no-annex-generation-outlives-its-pointer`). On an account with no
  enrolled client the pointed generation's log grows by one entry per
  transient visit, and every visit resolves it from genesis. A `gen-`
  collection a crashed first visit orphaned waits for the same sweep. A
  ladder VM can sign neither the swap nor the collect fan-out.
- A credential-anchored signup whose pointer backfill failed, leaving the
  unlock record on the signup-time did:key (invariant
  `account-pointer-names-the-account-did`).
- An establishment torn between the record re-bind and the promotion,
  leaving the KMS keystore's controller on the ladder's bare did:key
  (invariant `keystore-controller-is-the-account-did`).
- A signup torn before its standard collections are provisioned (invariant
  `standard-collections-are-provisioned`). The one converger needs a
  browser-local session. The same holds for the `inbox` collection: an
  account created before `inbox` joined the provision roster, and an
  account whose user deleted it.
- A forgotten or disconnected browser whose local wipe tore, on an account
  with no remembered login left to run the detector (invariant
  `this-browser-is-still-an-enrolled-client`).

Third, a detector that is not a mender, by design:

- The acting credential's document listing (invariant
  `document-lists-the-acting-credential`). The detector refuses the
  transient login with `credential-not-standing`, and the torn ceremony's
  re-run converges it.
- The saved recovery codes' health (invariant
  `saved-recovery-codes-locate-their-account`). The detector nudges the
  user, whose own reissue is the mender.

One bound is not an open gap. An account that runs the last-client
transition with several standing credentials lands ladder-anchored, carrying
one standing ladder VM per credential, since the transition strikes only the
departing client's inventory. Each stays a live delegation signer until its
credential is retired. The credential ceremonies run on the ladder kind, so
a transient login with any one standing credential retires the others
through the passphrase change and the passkey or backup-credential removal.
Removing the credential a transient visit entered on refuses
(`ActingCredentialRemovalError`), so removing that one takes a login on a
different credential. A passphrase change does retire the acting
passphrase's own ladder VM, replacing it with the new passphrase's.

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
  - `/webvh` (the did:webvh log, the update-key ladder's rung and ladder VM
    derivation and attribution, the document halves of the ceremonies)
  - `/clientAnnex` (signing as the ladder VM, the annex log and its GC, the
    ladder-anchored ceremonies: credential-anchored genesis, self-enrollment,
    transient recovery, and the recorded-grant revocation
    `revokeRecordedGrant` with its refusal reading). The verify-side halves
    stay in the base subpaths.
  - `/keys` (the user key, its wrap-set roster, the per-collection
    descriptor log store, the client-key record codec)
  - `/connections` (the `connections` directory: the entry codec, the
    keyed resource id, the store seam and its WAS adapter, the upsert
    helpers, and the grant index)
  - `/keyring` (the unlock layer), `/unlock` (standing unlock credentials,
    the ladder seed mint, the credential rotation and retirement sequence)
  - `/genesis` (the account-genesis key mint and ceremony)
  - `/enrollment`, `/recovery`
  - `/clients` (listing, disconnect policy, the revocation cascade
    orchestrator, the login-time roster policy)
  - `/descriptors` (the log-governed descriptor source and the collection
    descriptor log's pin slot)
  - `/space` (collection layout, activity builders, `was-link`)
  - `/resourceLog` (the did:webvh controller adapter
    `webvhResourceLogController` and the ceremony-tail license)
  - `/menders` (the mender registry's structure: the declaration and
    registration types, the vocabularies and the closed invariant-id census,
    the readers, the runner that executes one chain trigger's registrations
    under one try, warn, and skip discipline, the derived-set helpers the
    audit tests read, and `errorNameOf`)
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
  rule keeps out of production code. Freewallet keeps three bindings around
  it: the session binding in `stores/syncController.ts`, the contacts
  conflict closure in `stores/contactsConflictHandler.ts` (over the
  self-refreshing cipher in `stores/refreshingCollectionCipher.ts`), and the
  writer-id key prefix and storage in `lib/writerId.ts`. Each module's header
  states its behavior.
- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic
  client side: chain verification, the chain-head pin port
  (`ResourceLogPinStore`, `ResourceLogHeadPin`, `memoryResourceLogPinStore`)
  with its host-free slot keys, and the continuity and integrity refusal
  classes. Freewallet imports the pin port directly and matches the refusals
  by `err.name` rather than by class, since a duplicate package copy would
  break `instanceof`. The did:webvh controller adapter stays on
  `@interop/wallet-core/resourceLog`.
- **`@interop/was-client`** (+ `/edv`, `/sync`, `/paths`, `/log`, `/identity`)
  -- the WAS HTTP client, the sync wire contract the RxDB driver speaks, its
  error classes and the `err.name` predicates that classify them
  (`isUnknownEpochError`), the EDV envelope cipher and key-epoch construction
  (`createEdvDocCipher`, `x25519RecipientFromDidKey`), the descriptor-store
  seam, on `/log` the generic resource-log store (`resourceLogStore`) the
  per-collection descriptor logs ride, and on `/identity` the seed-to-agents
  derivation (`agentsFromSeed`).
- **`@interop/social-core`** -- the contact data model (`ContactData`, the
  head and revision payloads and their upgraders, `CONTACTS_COLLECTION`),
  and the last-write-wins comparison wallet-core's `/sync` applies.
- **`@interop/wallet-backup`** -- the backup bundle: `exportBundle` for the
  backup export, and `migrateBundle` with its sink contract for content
  migration.
- **`@interop/space-archive`** -- the Space archive reader
  (`readSpaceArchive`). The backup export reads the account Space's archive
  with it, to check the account log against the visit's pinned head.
- **`@interop/logger`** -- the logger seam `src/lib/log.ts` wires every
  `fw:*` namespace and each package's `setLogger` through.
- **`@interop/storage-core`** -- the storage quota and backend-state types.
- **`@interop/vc-display`** -- credential display mapping.
- **`@interop/capability-agent`** -- `CapabilityAgent`;
  **`@interop/webkms-client`** -- `KmsClient` / `KeystoreAgent`;
  **`@interop/ezcap`** -- `ZcapClient`.
- **`@interop/data-integrity-core`** -- loose VC/VP shape guards and the VPR
  type vocabulary.
- **`@interop/did-method-webvh`** -- the webvh log primitives (normally
  reached through `wallet-core/webvh`).
- **`@interop/verifier-core`** -- credential verification.
- Primitives imported directly: `@interop/vc` and
  `@interop/ed25519-signature` (the login credential), and
  `@interop/http-client` (the CORS proxy). Tests also import
  `@interop/x25519-key-agreement-key` and
  `@interop/ed25519-verification-key`.

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
  app-key credential plus capabilities delegated to its subject DID. Its
  requester is an origin-bound app, attested by the CHAPI mediator.
- **App key** -- a self-issued credential holding a 32-byte seed in
  `credentialSubject.seed`, bound to a requesting origin
  (`credentialSubject.origin`) and the application's canonical URL
  (`credentialSubject.appUrl`), issued to and by the seed-derived did:key
  (`CapabilityAgent.fromSeed`, `keyName: 'app-key'`). It carries the type
  `AppKeyCredential` (`https://w3id.org/byoe#AppKeyCredential`) and lives in
  the `app-keys` collection. The app's connection entry names that
  Resource as `appKey`.
- **Client / `clientId`** -- the keyed, custodied, revocable identity of an
  (app, user) pair: a keypair that can be a zcap grantee, a delegation
  `controller`, or an entry in a collection's key-epoch roster. It is a
  cache rather than the account's durable state, so state reconstructible
  from a client alone is a defect. Avoid: device, device id, durable client.
- **Requester** -- the party that sends an App Connect or interaction-URL
  request and receives the grants: an app, service, or agent. A collection
  provisioned for it records it as the `generator` on the Collection
  Metadata object, with its DID as `generator.id`. Its grants are recorded
  at consent on its connection entry, of kind `app` or `agent`. Text about
  the App Connect exchange itself (the app-key credential, the attested
  origin, `appUrl`) still says "app". Avoid: requesting app, calling app,
  client app.
- **Agent** -- a requester that mints its own did:key and asks for scoped,
  expiring, revocable grants through a standalone
  `AuthorizationCapabilityQuery`, naming itself as `controller`. It holds no
  app key, no user key, and no unlock credential, and is not a wallet
  client. Its connection entry is of kind `agent`, at the DID it names. An
  interaction URL may not name a wallet client's did:key as that
  controller. Avoid: transient client (the annex inventory), agent client,
  bot.
- **Audience** -- a plaintext collection in the owner's Space whose
  Resources are posts, readable by a set of people. Membership is a GET and
  HEAD grant on the collection, and removal is that grant's revocation. A
  public audience is a collection under `PublicCanRead`. Nothing on the
  wire marks a collection as an audience, and the wallet has no surface
  that creates one yet. A connection request names each audience by its
  container URL. Avoid: group, circle, feed.
- **Subscription agent** -- an agent that holds read grants on the owner's
  audiences and re-delegates a child of each grant to the subscribers it
  serves. It connects through a connection request (see "CHAPI, App
  Connect, and external requests"). Revoking the agent cuts every
  subscriber at once. The owner never sees a subscriber's capability, and
  the agent revokes its subscribers itself. A subscriber has no connection
  entry. Avoid: relay, proxy, subscriber agent.
- **`writerId`** -- an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision, used to attribute history
  and break last-write-wins ties. It is minted per browser profile by
  `@interop/was-sync`, bound in `src/lib/writerId.ts` under the
  `localStorage` key `freewallet:writerId`. It derives from no secret and is
  not an identity. Which sessions declare it on the wire is in "Session
  persistence". One met in a second session under the same account may
  become a registered writer. Avoid: replicaId, device id, session id.
- **Registered writer** -- a `writerId` that earned a member in the
  `writers` list of its wallet client's connection entry, holding a platform
  label and its liveness state. A remembered session registers its own on
  its second session and touches it at most once a day. The writer sweep,
  run at the page listing read (`readDirectoryListing`), marks a member
  inactive past its inactivity window. It is advisory display data and no
  input to any authorization decision. Avoid: known writer, trusted writer.
- **Share** -- granting a third party read AND decrypt access to one of the
  wallet's own encrypted collections, asked for with a
  `https://w3id.org/byoe#shared-wallet-collection` invocation-target
  descriptor. A share grants both axes together, and its grant is recorded
  on the reader's connection entry with `grantKind: 'share'`. See "Sharing
  a wallet collection" in docs/architecture/app-connect.md.
- **Connections directory** -- the `connections` collection: one encrypted
  connection entry per party the wallet has dealt with, written by the
  wallet alone and never replicated. Its entries' grants are the revocation
  index. See "Storage model (local-first)". Avoid: party registry,
  connections log, client labels.
- **Inbox** -- the `inbox` collection: one plaintext, wallet-wide
  collection of incoming messages in the owner's Space, through which a
  connected agent delivers capabilities to the wallet. An agent holds POST on its container and
  nothing more. The inbox pass drains it at login and deletes every
  message. See "Storage model (local-first)". Avoid: mailbox, message
  queue, notifications collection.
- **Connection entry** -- one party's record in the connections directory,
  at a resource id keyed by an HMAC of its DID under the collection's
  blinded-index key. It carries `kind`, the party's DID as `id`, `name` and
  `label`, an app's `origin`, `url`, and `appKey`, `firstSeen` and
  `lastSeen`, the party's `grants`, and a wallet client's `writers`. An
  agent's entry also carries `seed` and `seedTag` (the pairwise seed and
  its HMAC tag), `grantsReceived` (the channel capabilities the agent
  delegated to the wallet), `outbox` (the messages queued for the agent),
  and `declined` (the owner's decline of keeping it connected). Avoid:
  connection record, party row.
- **Pairwise did:key** -- the did:key the wallet holds toward one agent,
  derived from the `seed` on that agent's connection entry
  (`connectionDidKey`). It is not a Client. It is not the keypair of an
  (app, user) pair, it appears in no roster, and it signs nothing in the
  owner's Space. It is not an Agent either: the agent is the other party,
  and this is the wallet's own key toward it. It is durable, since its seed
  is server-held on the entry. It is a grantee on the agent's server, and
  it is not revocable until a seed rotation is built. It gives continuity,
  one key per edge, and no unlinkability, since every grant the agent
  receives names the owner's Space. Avoid: connection key, edge key.
- **Name and label** -- the two display strings on a connection entry. `name` is
  the party's own or suggested name: an app's `app.name`, an agent's
  self-declared `agent.name`, or a wallet client's platform label or the name
  its approver was offered. A consent refreshes an app's or an agent's. `label`
  is the user's own, and no consent writes it. A display reads `label` first.
  Both are held to one rule, 1 to 64 code points once control and bidi
  characters are stripped, and a name outside it is not stored. Avoid: nickname,
  alias.
- **Retirement** -- ending a party's relationship on its connection entry,
  which keeps the entry and its names. It follows the revocation that
  handled the entry's grants, and refuses when the entry has since gained a
  grant that revocation did not handle. It also empties `grantsReceived`
  and `outbox`, and keeps the pairwise `seed`, so the same agent's later
  consent reuses it. What it changes, and what retires an entry, are in
  "Storage model (local-first)". Avoid: removal, tombstone.
- **WAS (Wallet Attached Storage)** -- an HTTP protocol for storing
  arbitrary resources in user-owned Spaces, authorized via ZCap. See [the
  spec](https://w3c-ccg.github.io/wallet-attached-storage-spec/).
- **Space** -- a storage area on the WAS server, owned by one controller.
  The account Space's id is an independent random identifier carried in the
  account pointer; unlock Spaces are addressed by `spaceId =
base64url(SHA-256(unlock did:key))` (a discovery convention).
- **Collection** -- a named grouping of Resources within a Space. Standard
  collections: `private-credentials`, `public-credentials`,
  `wallet-activity`, `contacts`, `contacts-history`, `app-keys`. The
  `connections` directory and the `inbox` sit in the same provision roster,
  outside the synced set.
- **Resource** -- an individual stored item (JSON or binary) within a
  Collection.
- **Collection Metadata object** -- a Collection's configuration together
  with its user-writable `custom` member, served as one object at the
  Collection's `meta` path under one `metaVersion` validator. It carries the
  `encryption` descriptor the server derives from the governing log head. A
  Space carries the same shape at its own `meta` path, the **Space Metadata
  object**, which is where the Space's `controller` is written and read.
  Avoid: Collection Description, Space Description, the Description.
- **Container URL** -- the URL of a Space or a Collection, written with a
  trailing slash (`/space/{spaceId}/`, `/space/{spaceId}/{collectionId}/`).
  The slash-less form only redirects. A Resource URL carries no trailing
  slash. Both are built through was-client's path builders rather than by
  string concatenation. Avoid: collection URL prefix, space base URL.
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
  document, a transient VM's against the current annex document. See
  docs/architecture/did-webvh-identity.md.
- **Standing unlock credential** -- an unlock method (passphrase or passkey)
  whose unlock record, beside locating the account, carries a wrap of the
  user key in the roster and latent self-enrollment authority: a bridge
  delegation, the `delegatedClients` sibling delegation, and a random ladder
  seed. Its entropy bounds everything server-held that it alone decrypts.
- **Backup credential** -- a standing unlock credential a backup export
  establishes from 32 random bytes and packs into the bundle
  (`backup-credential.json`), with nothing retired and no key rotated. No
  login form accepts one yet, and neither the Settings last-method refusal
  nor the passkey-safety notice counts one (`isLoginEntry`). Its registry
  kind is `backup-credential`, and Settings > Backup credentials lists and
  removes it. Contrast the recovery code, which a spend retires. Avoid:
  backup code, packed code, export code.
- **Bridge delegation** -- the pre-minted zcap carried inside an unlock or
  recovery record beside the account pointer: a PUT-on-`did.jsonl`
  capability, plus annex-log access where that applies. All it can do is
  extend the world-readable log, which keeps credential use loud.
- **Unlock-local state** -- the browser-local artifacts one unlock method
  leaves on a browser, keyed by its unlock Space id: today the keyring cache,
  the wrapped client-key record, and the writer first-seen record a
  remembered session's writer registration reads. `deleteUnlockLocalState` in
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
  within a session" in docs/architecture/did-webvh-identity.md. Avoid:
  continuity prior.
- **Content migration** -- bringing a backup bundle's content into a
  DIFFERENT account, through `StorageManager`'s import methods, which skip
  a Resource the account already holds by its content identity. Contrast the
  restore, which puts a bundle back into the account it came from, and the
  move, which carries an account's identity across. Only content travels: no
  DID, no grant, no share, no public link.
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
  `login-routing`, `ceremony-tail`, `encounter`). An `encounter` site runs
  inside a live session, at the read or write that meets the evidence, and
  names the session kinds that reach it. A session holds `none` always, plus
  `account` and its kind whenever its key material carries one: an enrolled
  client's keys, or a standing ladder seed (`sessionAuthorityKind`). An entry
  is satisfied when the held set contains its authority. The id names the
  predicate rather than the code, so moving a converger between modules
  renames nothing. Avoid: mender id, check, rule.
- **Mender registry** -- the invariant declaration table plus the
  per-trigger registration lists. `@interop/wallet-core/menders` carries the
  structure and the readers; `src/session/menders/` carries freewallet's
  table. Declarations are data and registrations are code. The registry
  describes the ceremonies from the outside and executes no stage order.
  Registration order within a list is execution order, and there is no
  dependency graph. An encounter registration is run by the encounter
  runner (`src/session/menders/encounter.ts`): an authority check, a wait on
  the session's encounter gate, one run per session and registration at a
  time, and a once-per-session budget on a failed or refused run. A
  `ceremony-tail` trigger is site-backed, as `encounter` is: the registry
  refuses a declaration listing either with no site behind it, and the
  derived sets count a tail site only under the authority its invariants
  declare. A `login-routing` declaration stands with no site, since its
  detector refuses from inside the login itself. Its gap allowlist
  declares the residues nothing converges today (see "Ceremony
  inventory"). Avoid: saga, state machine, mender table.
- **Tear mending** -- the umbrella for how a torn ceremony (one interrupted
  mid-run) gets finished, by a converging re-run, a standing sweep, or a
  repair. A mender counts only if a credential-only visit can fire it, so a
  residue whose one trigger is the remembered-login chain is an open gap
  (`decisions/0010-remembered-login-is-not-a-mender-trigger.md`). The open
  gaps are declared in the mender registry's gap allowlist. Avoid: tear
  closure.
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
  `invocationTarget` is the Space's canonical container URL, so every
  collection-scoped grant chains under it, and every grant's `expires` is
  limited to its own.
- **CapabilityAgent** -- from `@interop/capability-agent`. Wraps an Ed25519
  key pair derived from a 32-byte seed and exposes `getSigner()`. The seed is
  a client seed, the unlock KDF output, or an app-key seed.
- **ZcapClient** -- from `@interop/ezcap`. Wraps the session's signer and
  adds ZCap headers to HTTP requests. The signer is an enrolled client's key,
  or on a transient session the per-visit annex VM.
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
  the user key roster, the unlock records, the Collection Metadata objects
  and their key epochs. It survives a cleared browser, an evicted origin, and a
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
  and given no explicit `rememberBrowser`. It signs with a per-visit annex
  key and runs on the in-memory tier with no local replica (see "Session &
  auth flow"). Avoid: ephemeral session, temporary session, and
  any name for a physical setting.
- **Credential-anchored account** -- an account whose authority is anchored
  in a standing unlock credential's ladder rather than in an enrolled
  client. Its document publishes that ladder VM and no enrolled client, so
  its log state is **ladder-anchored** and every visit is a transient
  session unless someone opts into remembering a browser. Avoid:
  client-less, client-less signup, transitional account.
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
- **Resource replica** -- the local replica's copy of one remote Resource:
  one synced document (`{ id, updatedAt, data }` plus the server's write
  stamp and validators) in a `BrowserStore` collection. Its `id` is the Resource's id, and `data` holds
  the stored body verbatim, an EDV envelope on an encrypted collection.
  Replication keeps it in step with the Resource in both directions. A
  replica-less session holds none and reads the Resource directly. Avoid:
  row, local row, doc.
- **WASRemoteStore** -- remote storage client, speaking the WAS protocol via
  `ZcapClient`. Handles the Space lifecycle, the storage-browser
  read-through over arbitrary collections and resources, export/import, and
  quotas.
- **SyncController** -- the lifecycle around background replication: one
  `replicateRxCollection` state machine per synced collection, started on
  login and cancelled on logout. The core is `@interop/was-sync`'s and its
  `stop()` is terminal, so the binding in `src/stores/syncController.ts`
  constructs a fresh core per session.
- **Known issuer registries** -- the issuer registries credential
  verification consults through `src/lib/registryManager.ts`, over
  `@digitalcredentials/issuer-registry-client`. The list is fetched from
  `KNOWN_REGISTRIES_URL` in `app.config.ts`. It names `dcc-legacy` list files
  and `oidf` OpenID Federation trust anchors. `KnownDidRegistries` is the
  fallback list when that fetch fails.

## ZCap Structure

A zcap answers "**who** can do **what**, **with** which resource, **given**
what restrictions": `controller` (who, a DID) / `allowedAction` (what, e.g.
HTTP verbs) / `invocationTarget` (with, a URL) / caveats like `expires`
(given). A delegated zcap also carries `parentCapability` and a `proof` with
a `capabilityChain`; a root zcap carries none of those.

**Root vs delegated invocation** (the `Capability-Invocation` header):

- Root: `zcap id="urn:zcap:root:<url-encoded target>",action="GET"` -- the
  id plus the action. `ZcapClient` defaults the action to the HTTP method.
- Delegated: `zcap capability="<base64url(gzip(json))>",action="GET"` -- the
  full capability and its `proof.capabilityChain`, embedded and compressed.

**Signing:** requests are signed with Cavage HTTP Signatures Draft 12 (not
yet RFC 9421). The `Authorization` header signs `(key-id) (created)
(expires) (request-target) host capability-invocation`, plus `content-type
digest` when there's a body. The `Digest` header is a multihash (`mh=`,
sha256). See the [zCap Developer
Guide](https://github.com/interop-alliance/zcap-developer-guide).
