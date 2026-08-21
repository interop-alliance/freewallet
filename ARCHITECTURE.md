# Architecture

How Freewallet is structured -- the layer map, session and auth flow, storage
model, CHAPI and App Connect flows, the domain model, where shared logic
lives, and the ZCap authorization structure. For contribution conventions see
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
  kms.ts            WebKMS keystore provisioning (ensureKeystore)
  resolveWalletInput.ts  The one door for free-form text (paste box, QR),
                    over the shared wallet-input classifier
  sessionKey.ts     freewallet-session IndexedDB caches (keyring, unlock
                    methods, pins, passkey-safety notices)
  corsProxy.ts      The one CORS-proxy path (`VITE_CORS_PROXY_URL`), used by
                    the pasted-URL credential fetch and the registries fetch
  viewMappers/      Transform raw credential data into display-ready values
  walletRequest/    VPR classification + response assembly for CHAPI requests
    respond.ts      Compose, persist the Login activity, then deliver (the
                    CHAPI `get` approval sequence)
src/lib/sync/       Collection-agnostic WAS replication adapter (RxDB-based)
src/stores/         Global state
  authStore.ts      Zustand store — holds the live Session object
  storageManager.ts StorageManager facade (local-first routing)
  browserStore.ts   BrowserStore — the local RxDB active replica
  wasRemoteStore.ts WASRemoteStore — the remote WAS backend
  syncController.ts Background replication lifecycle (start/stop/reSync)
  toastStore.ts     Transient success/info messages (`showToast`), rendered as a
                    Snackbar by DashboardLayout. Global, not page-local state:
                    an action often redirects (delete returns to the dashboard)
                    before a local message could render.
src/session/        Session bootstrap (initSession.ts) and the account
                    ceremonies -- the ordered sequences the pages drive but do
                    not own (React components keep rendering and confirmation
                    callbacks only)
  signup.ts         The two new-account provisioning sequences
  accountSettings.ts  The Settings ceremonies (passphrase, passkeys, update-key
                    rotation, account deletion's phase order)
  clients.ts        Enrolled-client listing + disconnect (a session-shaped
                    adapter over the shared clients surface)
  recovery.ts       Recovery-code issuance, spend, revocation
  shares.ts         Shared-collection listing + removal
  applications.ts   Connected-app listing + revocation
src/types/          Shared TypeScript interfaces
src/i18n/           i18next config + locale JSON files
src/styles/         MUI sx-object style constants (co-located by feature)
src/app.config.ts   Environment variable exports + app-wide constants
```

## Session & auth flow

There is no external identity provider, and nothing about the account is
derivable from the passphrase. Each wallet client (a browser profile) mints a
random 32-byte **client seed** locally on first run -- the Ed25519 pair
behind its did:key plus the X25519 twin -- and the private halves never leave
the client. The passphrase (or a passkey PRF output) derives only an **unlock
identity** (the keyring v2 seam in `src/session/keyring.ts`), which does two
jobs at login: it fetches the **unlock record** from its own minimal unlock
Space -- carrying the encrypted account pointer `{ did, spaceId, host }`, the
controller, and the email, plus (in the standing layout below) the sealed
bridge delegation and update-key ladder seed, never the account's content
keys -- and it unwraps the local **client-key record** in the
`freewallet-session` IndexedDB, which holds this client's seed, a cached
copy of the user key, and this client's did:webvh update-key seeds:

```
unlock secret (passphrase | passkey PRF output)
  → deriveUnlockSeed(KDF), expanded twice:
      unlock identity              → unlock Space → unlock record
                                      { controller, email, pointer,
                                        bridge delegation, ladder seed }
      standing client identity     → { client seed, binding MAC key }
  → unwrap local client-key record → { clientSeed, userKey, webvhUpdateKeys }
    (or, on a fresh browser: self-enroll through the record's bridge, then
     persist the freshly minted key set as this record)
  → agentsFromSeed(clientSeed)     → keyAgent  (keyAgent.id === a did:key DID)
  → ZcapClient(invocationSigner)   → zcapClient (signs HTTP requests with ZCap)
  → { user: { id: did:key }, profile: { keyAgent, zcapClient, userKey } }
  → StorageManager.initStorageClients()
  → Session { user, profile, storage, isGuest }
```

When the account pointer names a did:webvh (every promoted account -- see
"The did:webvh identity" below), the session's `zcapClient` signs with the
same client Ed25519 key under its verification-method id in the did:webvh
document (`<did:webvh>#<multibase>`) instead of the did:key form, since the
data Space's controller is the did:webvh and, under the current-key-set
rule, only a keyId the resolved document lists can authorize anything.
`user.id` stays the client did:key (it is also the App Connect response VP's
holder, which must remain resolvable by app-side loaders).

Every unlock method is a **standing credential** (the recovery-code posture
minus spend-on-use): beside locating the account, it holds a wrap in the
user-key roster (escrowed into every epoch, kept alive by rotation fan-out)
and latent self-enrollment authority -- its record carries a pre-minted
PUT-on-`did.jsonl` bridge delegation and a random update-key ladder seed
(`@interop/wallet-core/unlock`; the bind-time establishment is
`src/session/standingUnlock.ts`, run at signup and at every
add/change-method ceremony). A fresh browser holding nothing but the
credential can therefore **self-enroll** at login as an ordinary full
client, with no second browser involved -- reachable today through the
programmatic `rememberBrowser: true` entry, since the DEFAULT login on a
non-remembered browser is the transient posture (see "Session persistence"
below); the login-form choice is a planned follow-up. The self-enrollment:
two loud entries extend the
world-readable hash-chained log through the bridge (a reveal-and-commit
entry signed by the ladder's current rung, then an add entry publishing the
freshly minted client), and only then is the user key unwrapped from the
credential's standing wrap. On a ladder-anchored account the enrollment's
add entry removes the ladder VM, so a still-unexpired bridge delegation
(and `delegatedClients` sibling) it signed stops verifying under the
current-key-set rule; the same login's refresh block catches that -- its
predicate covers signer rot beside expiry (the delegation's proof key gone
from the memoized verified account document,
`delegationKeyInDocument`) -- re-signs both members with the enrolled
client's account key, and reseals the record, so no window is left where
the fresh-terminal entry path is bricked. A durable login also self-heals
a rotted embedded generation delegation the same way
(`ensureGenerationDelegationCurrent` with the account-document axis,
signed by the login credential's ladder seed carried in-memory on
`profile.ladderSeed`). Detection replaces the old enrollment gate:
takeover with a phished credential is visible in the log and remediable,
not prevented by requiring another browser. The document carries a
passphrase-derived `keyAgreement` key only as a hash commitment
(`MultikeyCommitment`; the roster's recipient resolver verifies the
roster-carried key against it) -- publishing the key verbatim would turn
the server-gated guessing oracle into a world-readable offline one -- while
a passkey's PRF-derived key, being high-entropy, publishes verbatim. The
connect-another-wallet ceremony (see "The client enrollment ceremony"
below) survives as the path for records without standing authority (a
pre-promotion or no-WAS bind) and as the future opt-in step-up approval
policy; the storage-partitioned CHAPI popup deliberately never
self-enrolls (a durable client per popup visit would litter the log) and
stays a degraded state.

The unlock record is **signed** by the unlock identity's own Ed25519 key,
and its proof is verified before the record is decrypted. That is what closes
host forgery: the record's JWE is sealed to the unlock KAK, whose public half
is derivable from the unlock did:key the server stores as the unlock Space's
controller, so a malicious host can seal a record of its own that decrypts
perfectly. The signing key derives from the typed secret, so it never reaches
the host, and a client that has only ever typed the secret already holds the
verification prior -- there is no bootstrap window. A record whose proof does
not verify is refused (`KeyringRecordForgedError`). A standing record's
account core (controller, pointer, ladder seed) is additionally
authenticated by a MAC under a credential-derived key the host never holds
-- the same construction as the recovery record's, verified before the
pointer is trusted -- which is what closes the redirect a re-mint-signed
record would otherwise reopen (a cascade re-mint signs with an enrolled
client's account key, settled against the account document at login). The
unlock Space's
request paths (the unlock record fetch and rewrite, and the management
delegation's `invocationTarget`) are built by was-client's paths helpers on
both the delegation and the invocation side, so the bytes the server's
`allowedTarget` check compares cannot drift -- load-bearing on a sub-path
deployment, and doubly so since the unlock record carries the recovery
bridge (a broken target would break login itself, not just a bind).

A signature cannot catch a REPLAY, though: a record the account has since
moved off stays authentic forever. So each client keeps a **freshness pin**
(plaintext local state, per unlock credential): the newest signed `createdAt`
it has accepted. A record older than the pin is refused as a rollback
(`KeyringRecordRolledBackError`); an equal or newer one is accepted and
advances the pin, which only ever moves forward -- the pin write itself is a
transactional forward-only compare-and-set, so no write site can move it
backward. The stamps are wall-clock, made safe against clock skew by a floor:
every record write site stamps `max(now, fetched record's createdAt + 1ms,
local pin + 1ms)`, so a rebind after a fast-clock client's bind still
supersedes it and cannot wedge other clients into the rollback refusal.
Nothing compares pointers: a
record naming an account this client has never seen is followed wherever it
points, as long as it is validly signed and not stale -- a rebind, a host
migration, and a fresh account bound under a reused passphrase are all
legitimate, and all produce a newer signed record.

What the whole construction is bounded by, standing: server-held material
the unlock credential alone decrypts -- the record, and the credential's
standing wrap of the user key in the roster -- is only as strong as that
credential's entropy. Against a malicious storage host running an offline
KDF grind, zcap scoping, TTLs, and revocation are worth nothing; the
credential's entropy is the entire bound, so the custodian of the unlock
credential must not be the storage host, and a wallet's security is tiered
on and limited by its weakest standing unlock method. Logging in from a
public terminal is a core supported case -- nothing need persist locally to
reach the account -- which is exactly why the record must stay server-held
and self-authenticating rather than depending on local state. Client
revocation does not bound an attacker who holds the credential itself (they
re-derive and self-enroll again); credential rotation is that remedy.

**The unlock-credential rotation ceremony** is that remedy made real:
changing a passphrase and removing a passkey both retire the old
credential's standing rather than merely rebinding the unlock record. The
shared sequence is wallet-core's `retireUnlockCredential`
(`@interop/wallet-core/unlock`), wrapped session-side by
`rotateOffUnlockCredential` (`src/session/credentialRotation.ts`): the
credential's document posture leaves first (its `keyAgreement` entry --
commitment or verbatim -- and its ladder's whole standing footprint, resolved
from the log itself rather than from the registry's recorded bind-time rung,
in one log entry), then the credential's companion posture (between the
document edit and the roster tail, wallet-core's `retireCompanionPosture`
closure): a strike entry on the companion log drops the retired
credential's revealed rung and standing hash when a distinct surviving
credential's committed rung can sign it, and otherwise -- a self-strike, or
no committed survivor -- the whole generation is swapped onto a surviving
credential's ladder (`swapCompanionGeneration`), the old generation left to
orphan discovery. A passphrase change signs with the NEW credential's
ladder seed (`survivingLadderSeed`); the stage is best-effort and reports
itself on the outcome's `companion` member. Then the same
roster-and-cascade tail the client revocation runs --
the user key rotates off the credential's wrap (pairing-free convergence
onto the post-edit document) and every encrypted collection re-epochs onto
the fresh key. The callers then tear down the registry entry and the old
unlock Space under the pre-rotation vault keys and adopt the rotated key in
place (`adoptRotatedUserKey`: registry re-seal, profile vault keys, storage
ciphers), the `revokeRecoveryCode` ordering. The document-removal-first
order is load-bearing: a run torn anywhere after it leaves the roster
keying a recipient the document no longer backs, exactly what the
login-time sweep detects and finishes. The honest limitation is the
cascade's: ciphertext the credential's holder already fetched stays
readable, and Settings says so -- the ceremony is the documented "I think
my passphrase leaked" remedy there.

The `Session` object is stored in the Zustand
`authStore`; it is **in-memory only** (the passphrase is never persisted), so
reloading the browser logs the user out and they must log in again. Guest
sessions use a random 32-byte seed directly and never touch the WAS server or
the KMS.

All four session entry points (login, signup, both CHAPI popup pages) funnel
through `initSessionFromSeed`. When a KMS is configured (`KMS_SERVER_URL`),
it also provisions a **WebKMS keystore** for the controller (`ensureKeystore`
in `src/lib/kms.ts`: list-by-controller, create on miss -- one keystore per
controller by convention), binding a `KeystoreAgent` as
`profile.keystoreAgent`. Operational keys can live server-side in that
keystore, while the controlling key stays strictly client-side: the keystore
is created under the first client's did:key and its controller is promoted
to the account's did:webvh alongside the Space's (the same
`promoteKeystoreController` sequence, non-fatal). No server-held key is ever
an update key or an encryption-roster recipient. Provisioning failure is
non-fatal (logged; the settings page shows the state).

## The did:webvh identity (per-client keys, promoted controller)

The account's stable id is a `did:webvh` whose hash-chained log lives as
`did.jsonl` in the world-readable `id` collection
(`@interop/wallet-core/webvh`).
Its document is the enrolled-client roster: each enrolled wallet client
contributes its Ed25519 verification method (published under
`authentication`, `assertionMethod`, `capabilityInvocation`, AND
`capabilityDelegation`) and its X25519 twin under `keyAgreement` -- ids are
`<did:webvh>#<multibase>`. The signing method carries
`controller: <did:webvh>`; the key-agreement method carries
`controller: did:key:<the client's signing multibase>`, a marker that says
which client the key belongs to. Every reader pairs a client with its
key-agreement key by that marker -- the client listing, the revocation
removal, and the roster's recipient resolver alike -- so nothing re-derives
a twin to find it. One KMS-held VM
(`authentication`) remains as a server-side convenience; the KMS-held
`keyAgreement` VM is deliberately NOT in the document -- the `keyAgreement`
relation is the source of record for user-key wrap recipients, and no
server-held key may ever be a wrap target -- and no KMS assertion key is
minted: the App Connect Resource Log Profile authorizes log appends by
`assertionMethod` membership, so that relation lists client signing keys
only.

**Update keys are client-held.** `updateKeys` carries one update key per
enrolled client (apps never), derived from 32-byte seeds that live in the
wrapped client-key record beside the client seed and the user key -- so the
server cannot extend the log, which is what makes it the one
self-certifying artifact the server hosts. Prerotation stays on with a
**carry-over commitment convention**: `nextKeyHashes` commits each client's
staged key AND each active key's own hash, because the resolver re-checks
every entry's re-stated `updateKeys` against the previous entry's
commitments -- without the active-key hashes no non-rotating entry (an
enrollment commit, a future document edit) could ever resolve. Rotation is
per-client self-rotation (`rotateWebvhUpdateKey`: persist the rolled seeds
into the client-key record BEFORE the log entry publishes, then finalize),
and it preserves every other client's update key while swapping only its
own. `keys.json`'s webvh block narrows to `{ did }` -- key roles no longer
live server-side.

**Conditional publish.** Every ceremony publishes `did.jsonl` as a
compare-and-swap on the ETag of the read its entry was built on, so two
clients extending the log concurrently never silently erase each other's
entries; a lost race surfaces as wallet-core's typed `WebvhLogConflictError`
and the ceremony re-runs itself on the new head (`withLogConflictRetry`).
The shared `wasWebvhIdStore` carries the ETag and preconditions for every
enrolled-client ceremony; the recovery continuation's delegated store
(`delegatedLogStore` in `src/session/recovery.ts`) does the same over its
public log fetch and delegated PUT. The `did.json` projection PUT stays
unconditional -- it runs only behind a won log CAS, and the log is the
source of truth.

**The account-log chain-head pin.** Resolving the world-readable log is
one-shot verification: a valid PREFIX of the real log carries the same
genesis, so the same SCID and DID, and a ceremony built on it would
republish erased enrollments and undone revocations as durable state. So
every `verifyAccountLog` read carries a durable chain-head pin
(`sessionLogPinStore` in the session database -- the keyed pin store shared
with the roster log, beside the keyring-freshness pin and the roster-epoch
pin):
a served log that is a rollback, a fork, or an SCID/method switch against
the pinned head is refused (wallet-core's `ResourceLogContinuityError` --
the same seam and refusal class as the roster log's pin), established at
first contact (trust-on-first-use) and advanced only by a log verifying
past it, never regressed. The pin rides the verified-log memo
(`src/session/verifiedLog.ts`), the bare-parts roster store's controller
resolution, the recovery flows' direct reads, and the enrollment
completion's first contact; the login page renders the refusal
(`auth.errors.accountLogContinuity`). A `rollback` is the one reason that
may be nothing worse than replication lag -- nothing rolled back is
adopted, and a caller with a cached document view may carry on with what it
has. Ceremony-path `did.jsonl` reads additionally check the resolved DID
against the account pointer (`expectedDid` on the revocation cascade and
the recovery ceremonies). The two log-publishing ceremonies on this repo's
own paths carry both checks too: the login-time provisioning
(`ensureDidWebvh`) and the settings-page update-key rotation
(`rotateWebvhUpdateKey`) each read the log under the same pin store and the
account's DID, so a truncated or substituted log is refused before an entry
is built on it. Provisioning stays non-fatal either way (a hiccup must not
fail login), but a non-`rollback` continuity refusal is logged as an error
-- the later account-log reads in the same login hit the same pin and
surface it to the user.

**The pin inventory.** The session database holds four durable continuity
priors, in three shapes. The two chain-head pins -- the account log's and
the roster log's -- live in ONE keyed store (`sessionLogPinStore` in
`src/lib/sessionKey.ts`, implementing wallet-core's keyed
`ResourceLogPinStore`): `read` and `write` take a per-log slot key that
wallet-core itself derives (`accountLogPinId` / `userKeyRosterPinId`, both
`space/<spaceId>/<collection>/<resource>` under the hood), so one store
serves every log and two logs can never clobber each other's pin. The slot
key is deliberately host-free: a log served from a claimed new host lands in
the SAME slot and is checked against the pin already held, rather than
opening a fresh trust-on-first-use slate. A mirror under a freshly minted
Space id does get a fresh slot, but the did:webvh id embeds the Space id, so
the mirror necessarily resolves to a DIFFERENT DID than the account pointer
names -- the loud refusal every ceremony-path read already makes
(`expectedDid`, and `verifyAccountLog`'s own resolved-DID check). The
roster-epoch pin and the keyring-freshness pin keep their own shapes: the
epoch pin is keyed by the account DID (it guards a chainless value, so the
DID is the one identity a substituted pointer cannot change), the freshness
pin by the unlock Space. Because the chain-head slot is Space-keyed, the
pre-promotion window needs no special handling: the genesis ceremony's log
read runs under the same slot from true first contact on, and the published
DID is persisted locally keyed by the data Space id only so a later
pre-promotion heal login can state an `expectedDid` even though the pointer
has not caught up. Account deletion clears all of it (the two slots by
their builders, the epoch pin, the mapping, and each listed companion
generation's pin slot) beside the keyring retirement. Deletion also
reaches every unlock method and the companion before the account Space
dies: it walks the unlock-methods registry and deletes each entry's unlock
Space and local trio best-effort (`deleteUnlockMethodArtifacts` in
`src/session/unlockMethods.ts` -- removing the dangling existence-oracle
Spaces a probe could still find), then deletes the auxiliary companion
Space in one `space.delete()`. Both run BEFORE the fatal wipe, because
resolving the auxiliary Space's controller reads the account log out of
the account Space; a wipe failure after them leaves other methods' logins
already destroyed, accepted since the user's intent was deletion.

**Controller promotion by ordering.** The Space id is an independent random
identifier minted at signup (`mintSpaceId`) and carried in the account
pointer -- deliberately not a hash of any controller, since the did:webvh id
embeds the Space id and a derivation would be circular (unlock Spaces keep
their `hash(unlock did:key)` addressing -- discovery, not identity). That
deterministic unlock address is an accepted existence oracle for passphrase
guessing (derive a candidate address, probe the server); the bound is KDF
strength, not placement. The DID's embedded Space id also need not equal a
controlled Space's id -- one did:webvh may control several Spaces on the
host; a feature, not a check to add.
Provisioning creates the Space under the first client's did:key, publishes
the log, and then -- once the pointer durably names the did -- PUTs the
Space Description with `controller: <did:webvh>`, authorized by the stored
did:key (`StorageManager.ensurePromotedController`, which also swaps the
live session's signing to the promoted keyId and re-heals a signup torn
between the pointer backfill and the promotion PUT). From then on the
server resolves the controller by reading and fully verifying the log out
of its own storage (SCID-pinned, hash chain, prerotation, update-key
signatures) and authorizes by the **current-key-set rule**: an invocation
or delegation verifies iff its verification method is in the resolved
document now -- so a delegation signed by a since-revoked client stops
verifying the moment its VM leaves the document.

## Account genesis (`@interop/wallet-core/genesis`)

The stage order of a new account's provisioning is shared with the mobile
wallet rather than encoded here: `mintAccountKeySet` mints the whole key set
locally (Space id, client seed, user key, did:webvh update-key seeds), and
`ensureAccountGenesis` runs the ordered ceremony -- Space provisioning under
this client's did:key, the did:web key map, the did:webvh genesis, the user
key roster (strictly after the DID publication), and key epoch[0] on every
encrypted collection. Every stage detects its own completion from durable
state, so a torn run heals by re-running at the next login.

`StorageManager.#provisionUserCollections` is the one caller: it supplies
the did:web provisioning as the ceremony's `provideDidWebKeys` closure and
the roster store builder as `rosterStoreFor`, adopts the published DID in
`onDidPublished` (which also drops the verified-log memo), and maps the
ceremony's collected per-stage failures onto the warns each stage had
before. A session with no did:webvh (the flag off, no keystore agent, or no
client update keys / user key) keeps the reduced path: Space provisioning,
key epochs, did:web. A Space that never came up stays the one fatal stage:
the ceremony's `AccountGenesisSpaceError` is rethrown, so login fails rather
than continuing with nowhere to write.

What stays in freewallet's own flow: the keyring bind before any data Space
exists, the passphrase signup's `userExists` probe, the pointer backfill
after the DID is published, and the controller promotion after it -- so the
ceremony is called with `promoteController: false` and
`ensurePromotedController` keeps promoting (and healing) as before.

**The credential-anchored variant.** On a non-remembered browser with a WAS
server configured, the passphrase signup runs wallet-core's
`ensureCredentialAnchoredAccountGenesis` instead (through
`establishCredentialAnchoredAccount` in
`src/session/credentialAnchoredGenesis.ts`): no durable client is minted
anywhere. The Space is bootstrapped under the LADDER VM's bare did:key
(`ladderVmAgent` -- re-derivable from the unlock record's ladder seed, so a
tab death before promotion strands nothing a later login cannot finish); the
one-entry ladder-anchored did:webvh genesis is signed by ladder rung 0
(`updateKeys` = [rung 0], `nextKeyHashes` = [hash(rung 0), hash(rung 1)],
`portable` unchanged) with the ladder VM and the credential's `keyAgreement`
commitment folded in; the roster's epoch[0] wraps the user key to the
credential's standing KAK with a ladder-signed entry proof (the
ceremony-tail license's first-entry shape); and the collection epochs are
gated on the roster landing, since the user key exists only in the visit's
memory. There is no KMS stage -- the keystore defers to the first durable
enrollment. The ordering rule is the transposed persist-before-publish
invariant: the unlock record carrying the ladder seed (with an interim
bridge delegated by the ladder's bare did:key) is durably written BEFORE the
Space is created and before rung 0 publishes. After the genesis, the
establishment mints the companion generation under the same bootstrap
identity, embeds the ladder-VM-signed generation delegation, flips the
auxiliary Space's controller, appends the `#DelegatedClients` pointer as a
second rung-0-signed account-log entry, re-binds the record (full pointer,
ladder-VM-signed bridge and sibling, management zcap to the account DID),
writes the unlock-methods registry in the last root-invocation window, and
promotes the Space controller last. The visit then enters through the
ordinary transient composition, so a credential-anchored signup ends in a
transient session with zero local residue. The whole establishment is an
ensure: a torn signup converges by re-running, with the published log
adopted by ladder attribution (`createDID` timestamps the genesis entry, so
a naive re-create would mint a different SCID and its create-if-absent PUT
could never land). The `rememberBrowser: true` entry (the e2e seam today,
the signup form's remember choice when it lands) and every no-WAS deployment
keep the durable flow above; the passkey signup stays durable outright
(registering a passkey is itself a durable ceremony).

## Session persistence

Sessions are **in-memory only**. A fresh login builds the whole `Session` --
the root `keyAgent` (from this client's locally stored seed), the
user-key-backed vault KAK, and the `zcapClient` that signs every WAS request
with the root key. Nothing about the live session is written to disk
unwrapped (the client seed and user key persist only inside the wrapped
client-key record, under the unlock layer), so there is no refresh-survival:
reloading the browser drops
the session and the user logs in again. The vault is
therefore always unlocked while a session exists (the KAK is present) and
simply gone once it ends; there is no "locked vault" state.

**The posture seam** (`src/session/persistence.ts`): what a session may write
to LOCAL durable storage is decided once, at login, by the typed
`SessionPersistence` handle carried at `profile.persistence`. Durability is a
property of the handle's type; a write site consults no flag and takes no
branch (freewallet `decisions/0001-no-memory-overlay-storage-fork.md`). Every
posture-sensitive local family rides the handle: the keyed chain-head pin
store (the account log's and the roster log's), the roster-epoch pin, the
unlock-methods registry cache, the passkey-safety notice, the
descriptor/meta cache pair (one instance per scope per session), and the
`writerId` mint. The durable variant is today's behavior -- the
`freewallet-session` database (it alone carries the `idb` factory, so code
needing that database must hold the durable variant), the localStorage
caches, and the durable `writerId`. The transient variant -- a
public-terminal visit -- is in-memory throughout and dies with the tab: it
has no member reaching the session database, and the login that carries it
skips storage provisioning, the login-time sweeps, and the bare-Space-URL
`userExists` probe. Global UI prefs (theme, language) are not session state,
so they ride a sibling seam (`src/lib/prefsStorage.ts`): while a transient
session is live, pref writes land in an in-memory overlay that shadows
reads; reads still fall through to localStorage, which writes nothing.

**Replica-less, capability-bound storage.** A transient session constructs
no `BrowserStore` at all -- the versioned RxDB open alone durably creates
the per-user database -- so `StorageManager.initStorageClients` builds it
only for the durable posture, and a replica-less session serves every
synced-collection operation through the remote-direct backend (the CHAPI
popup's, over the remote WAS collections). The sync controller never starts
for a session with no local replica (there is no local end to replicate;
`StorageManager.hasLocalReplica` is its gate). The remote stack also takes a
delegated authority: `WASRemoteStore` accepts an optional invocation
capability (threaded from `profile.invocationCapability`) that every request
it makes rides -- the navigational handles through one private Space-handle
helper, the raw request sites directly -- and wallet-core's
`userKeyRosterDescriptorStore` takes the same option, so a session holding
only a delegated Space-subtree zcap (the transient posture's generation
delegation) can use the store and read the roster. Absent the option, every
request invokes the root capability, exactly as before.

**The transient login (the default on a non-remembered browser).** Both
keyring login entry points run a post-KDF posture decision
(`routeUnlockLogin` in `src/session/transientLogin.ts`): with a WAS server
configured, a browser holding this credential's client-key record proceeds
durable exactly as before (the record probe is create-nothing --
`hasClientKeyRecord` checks `indexedDB.databases()` before opening -- and
the ratchet is silent for now), while a browser holding none defaults to
the transient composition. An explicit `rememberBrowser` input forces
either side: `true` is the programmatic durable entry (the standing
self-enrollment; the signup probe and the recovery tail pass it, and e2e
sets it through a non-production seam), and `false` on a remembered
browser refuses (`AlreadyRememberedError`) rather than forking postures.
The composition (`transientSessionFromKeyringHit`): the transient
unlock-record fetch (`fetchTransientKeyring`, no durable operation), the
account log verified under the visit's in-memory pins, a per-visit key
minted in memory and enrolled into the companion generation through the
record's `delegatedClients` sibling delegation (wallet-core's
`enrollTransientClient` -- the loud entry before any authority, with the
GC-race re-read built in), the generation delegation taken as embedded
(never minted from here -- its mint takes a durable signer), the user key
unwrapped from the credential's standing roster wrap (the read signs as
`<companionDid>#<vm>` under the delegation; no escrow -- a transient
client never joins the roster), and a session on the replica-less storage
posture above. Transient sessions skip the KMS keystore, the login-time
roster read, provisioning, and every login-time sweep. Every unavailable
state -- a record without standing authority or the sibling, an
unpromoted account, no live generation or embedded delegation, no roster
-- refuses with a typed `TransientLoginUnavailableError` before any
ceremony byte is written (the login page maps it onto the not-enrolled
guidance for now), and network errors rethrow unchanged so a flap stays
distinguishable from a generation lapse.

Two of those refusals now carry a heal first, for the tears a torn
credential-anchored signup can leave (see "Account genesis"). A standing
record whose pointer names no did:webvh can only be a credential-anchored
establishment that died before its re-bind (durable-flow records gain
their ladder seed only after promotion), so the composition re-runs
`establishCredentialAnchoredAccount` -- every stage an ensure, the published
log adopted by ladder attribution -- and re-enters through the refreshed
record; without the derived credential in hand (a test double), or when
the re-run does not converge, the `unpromoted-account` refusal stands. And
a promoted account whose roster read comes back empty is the tear between
genesis and epoch[0] -- the user key died with the signup tab -- healed
here as the explicit carve-out from the sweeps-skipped rule: a fresh user
key is minted, epoch[0] lands with a ladder-signed entry proof wrapped to
the credential's standing KAK, and the collection epochs complete, every
write invoked as the companion VM under the generation delegation (the
`capability` option on `ensureWalletSpaceEpochs` and the roster store).
Nothing encrypted predates the heal (the ceremony installs collection
epochs only behind a landed roster), so the fresh key orphans nothing. A
roster read failing outright, rather than empty, additionally retries once
behind a bootstrap-signed promotion completion -- the one-request-wide
tear between the record re-bind and the promotion.

The handle also carries the posture's refusals. Update-key rotation requires
the durable posture outright (`DurableSessionRequiredError`): its subject is
this browser's durable update key, and its persist-before-publish invariant
needs a client-key record to persist into. The account-management ceremonies
(passphrase change, passphrase/passkey add and remove, client revocation,
enrollment approval, recovery-code issuance and revocation, account
deletion, Space export and import) refuse from a transient session with
`StepUpRequiredError`: they are reachable from a public terminal only inside
the step-up ceremony (a loudly enrolled in-memory client, bracketed by
ladder-signed enroll and retire entries), which is designed but not yet
implemented. Contacts are not reachable in the transient posture either --
the remote-direct backend rejects them today -- a stated reduction until
remote-direct contacts land.

## The user key wrap-set roster (`key-map/user-key.jsonl`)

The user key (formerly PUK) -- recipient zero of every encrypted collection --
has one remote home: a roster in the private, capability-gated `key-map`
collection (deliberately outside the synced collections; no local replica, no
background replication). Its state is a `CollectionEncryption` descriptor, and
**the roster's current key epoch IS the current user key**:
the epoch id is the user key's did:key, and the epoch secret -- the user
key's raw 32-byte key -- is wrapped once per enrolled wallet client, to that
client's own (identity) key-agreement key (`profile.clientKeyAgreementKey`,
the X25519 twin of the client's did:key). The roster is a delivery channel,
not a source of authority: each client keeps the user key in its own local
state under the unlock layer (the client-key record), and the roster's epoch
stamp marks a cached copy stale.

The roster is **log-governed**: it lives as the resource log
`key-map/user-key.jsonl`, with no point-state companion resource. wallet-core's
`userKeyRosterDescriptorStore` (`@interop/wallet-core/keys`) exposes that log
as an ordinary descriptor store -- reads resolve only to the log's VERIFIED
head (chain, entry proofs, and the durable chain-head pin all checked before
any descriptor is handed out), writes are signed log appends -- so was-client's
roster machinery (`initRecipients` / `addRecipient` / `removeRecipient`, with
their compare-and-swap retry loops) drives the log without knowing it, and no
descriptor logic is reimplemented wallet-side. The wiring is two builders in
`src/session/rosterStore.ts`: `accountRosterStore`, from the bare parts (a
signing client, a key agent, an account pointer naming a did:webvh), for
callers with no session profile -- the login-time read and the recovery
continuation -- and `sessionRosterStore` for a live session, which resolves the
controller view through the profile's verified-log memo so a ceremony that just
extended the account log anchors its appends at the post-edit head. The
chain-head pin is durable either way (`sessionLogPinStore` in the session
database, the keyed store shared with the account-log pin; wallet-core
derives the roster log's slot key from the Space id), so log continuity
spans logins.

Provisioning initializes the roster idempotently with the account's existing
user key as the first epoch, as the account-genesis ceremony's roster stage
(see "Account genesis" above) -- after did:webvh provisioning rather than
before it: the log's entry proofs anchor in the published account document,
so the genesis append needs a log to verify against. Login performs one direct read (`initSessionFromSeed`, before the
storage clients are built), gated on a promoted (did:webvh) account pointer,
that either confirms the cached user key current or -- on an epoch mismatch, a
rotation by another client -- unwraps the fresh user key with this client's own
key, adopts it for the session, and persists it into the client-key record.
A failed persist (the client-key record write or the epoch-pin advance) is
not a login failure: the adopted key authenticated against the verified
roster, so the session proceeds on it and the login page surfaces the
failure as "this browser could not be remembered"
(`session.userKeyPersistFailed`; the next login re-fetches the key). What a
failed persist is NOT allowed to do is masquerade as an offline start --
wallet-core propagates the adoption callback's throw instead of swallowing
it into the warn-and-null path, and the login wrapper catches it where its
meaning is known.

Three client-side guards are load-bearing against a tampering host. First the
resource log itself: roster state is adopted only from a verified head, whose
entry proofs must be signed by keys the independently verified did:webvh
document lists under `assertionMethod` at the anchored version
(`ResourceLogIntegrityError`), and whose chain-head pin refuses rollbacks,
forks, and SCID or method switches (`ResourceLogContinuityError`) -- log
verification subsumes both the retired detached epoch-configuration signature
and the retired `epochsMac`. At login the chain-head `rollback` reason is
the carve-out, matching the account-log pin's: a head behind the pin may be
nothing worse than a lagging replica, so wallet-core's login policy degrades
it to the transport class -- the session keeps the cached user key, nothing
rolled back is adopted, and the pin never regresses -- instead of locking
the user out of a healthy account. `fork` and the SCID/method switches stay
session-refusing. Second, the locally pinned latest-seen roster
epoch (`src/lib/sessionKey.ts`, beside the keyring-freshness pin): a served
roster that rolls back behind the pin is refused
(`UserKeyRosterContinuityError`, with no rollback carve-out -- the epoch pin
is chainless, so it cannot tell a rollback from a fork), and it is kept
beside the chain-head pin because it still guards a client whose chain-head
pin was lost with a reinstall. Third, at rotation time, a recipient resolver backed by the locally
verified did:webvh document -- a roster entry with no `keyAgreement`
verification method marked for that client is dropped and never receives a
wrap, so a server-injected
entry sits ignored (wraps are minted only by enrolled clients, against
log-verified keys).

## The client enrollment ceremony (`@interop/wallet-core/enrollment`)

Connecting a second wallet client (a fresh browser profile) to an existing
account, without any secret ever leaving either side. Since standing unlock
credentials landed, an ordinary fresh browser can self-enroll at login with
the credential alone (the programmatic durable entry -- see "Session & auth
flow"); this two-party ceremony
remains the path for records without standing authority, for onboarding
another wallet app over the rendezvous transport, and as the future opt-in
step-up approval policy. The new client mints
its whole key set locally -- client seed, did:webvh update-key seeds -- and
only PUBLIC halves travel, as a compact **connect code**
(`freewallet-connect:<base64url(JSON)>`) carried point-to-point: pasted
between two browsers, or carried over the rendezvous transport below. Nothing
travels back over the channel: the account pointer comes out of the keyring
(the enrollee holds the passphrase), and the user key comes back through the
wrap-set roster. Both screens display the new client's did:key fingerprint,
and the person running the ceremony compares them before approving -- the
point-to-point verification the roster wrap and the document VM then inherit.

The flow, quorum-of-one (any single enrolled client can enroll):

1. **Enrollee** (login page, from the not-enrolled state): "Connect this
   browser" mints the key set (`mintEnrollmentRequest`) and shows the code.
   Nothing is durable yet.
2. **Enrolling client** (Settings > Connect another wallet): pastes the code,
   compares the fingerprint, approves (`approveEnrollment`). Push, not pull,
   in the recovery-anchor order -- decryption material before authorization:
   the user key is wrapped to the new client's key-agreement key in
   `key-map/user-key.jsonl` FIRST (`addUserKeyRosterRecipient`, escrow
   semantics: every epoch, so pre-enrollment history decrypts), and only then
   the two
   did:webvh log entries (`enrollWebvhClient`) -- a sparse **commit** entry
   extending `nextKeyHashes` with the new client's update- and staged-key
   hashes (prerotation demands the commitment land one entry early), then the
   **add** entry publishing the new client's two verification methods and its
   update key. No authorized-but-blind window exists at any point.
3. **Enrollee** ("finish connecting"): verifies the enrollment from the
   world-readable log (resolved locally, checked against the pointer's DID),
   performs its first roster read -- signed with its just-published
   `<did:webvh>#<multibase>` key, authorized by the current-key-set rule --
   unwraps the user key, persists the key set into the local client-key record
   under the passphrase's unlock layer (stamping the account controller, so
   the login-time identity check binds the record to the account), and logs
   in as an ordinary enrolled client.

**The connect code's keys must be canonical.** The enrolling client refuses a
code whose key-agreement key is not the canonical X25519 twin of its signing
key (`assertCanonicalEnrollmentKeys`, run inside the connect-code parse, so
the refusal lands before anything is published). That is what keeps the
document's controller marker honest: a client's key-agreement method is
published under `controller: did:key:<its signing multibase>`, a claim every
reader trusts to pair the two, and without the check an enrollee could
publish a key-agreement key nobody else can pair with its signing key. The
refusal reaches both approval surfaces -- the paste dialog shows it under the
code field, and a scanned onboarding response ends the invite with the
generate-a-fresh-code copy.

Every stage is idempotent and the ceremony is resumable from durable state
alone -- re-running with the same code converges: a tear after the roster
write leaves an orphan wrap (invisible to authorization, harmless), a tear
between the log entries is detected from the standing `nextKeyHashes`
commitments (the add entry alone is appended, never a fork).

**The rendezvous transport (onboarding another wallet).** When the enrollee
is a camera-holding wallet rather than a browser with a paste box, the same
ceremony runs over the WAS server's ephemeral-exchanges facet
(`/workflows/ephemeral/exchanges` -- unauthenticated, capability-URL
posture: the unguessable exchange URL is the only access control, and it
travels point-to-point in the QR). Settings > Connected wallets > "Connect
another wallet" opens one card offering both halves of the ceremony -- the
QR invite and the paste-a-connect-code form. The invite side creates an
exchange whose stored request is a
`WalletOnboardingQuery` VPR carrying the account pointer and controller
(`composeWalletOnboardingRequest`), renders the exchange's interaction URL
(`.../protocols?iuv=1`) as a QR code, and polls
(`OnboardInviteCard`). The other wallet scans
it, begins the exchange, mints its key set, and posts back an
onboarding-response envelope -- the ordinary `freewallet-connect:` code
verbatim plus a suggested display label, nothing else
(`encodeOnboardingResponse` / `parseOnboardingResponse` in
`@interop/wallet-core/enrollment`; an oversize or malformed envelope is
refused whole, surfaced as "generate a new code and try again"). Poll
completion swaps the card to a consent panel (`OnboardConsentPanel`) that
leads with the fingerprint comparison -- the mandatory trust anchor, since
anyone holding the exchange URL could inject a response -- states the
full-peer consequence (an enrolled wallet reads and changes everything in
the Space, connects apps, onboards or disconnects other wallets, issues and
revokes recovery codes) and the honest disconnect ceiling, and prefills an
editable label from the envelope's suggestion. Approval drives the same
`approveEnrollment` + `setClientLabel` path as the paste dialog; the
enrollee then completes the ceremony off the world-readable log as usual.
The channel carries only the four public key multibases and the label: the
account pointer travels inside the stored request (the exchange URL is its
confidentiality bound), and the user key still comes back through the
wrap-set roster.

## Recovery codes (`@interop/wallet-core/recovery`)

The "lost my only client" answer: a 16-byte base58 **recovery code**, shown
exactly once at issuance, that restores the whole account from a fresh
browser with nothing else in hand. On the roster model a code is a
**minimal always-enrolled wallet client** whose entire key set derives
deterministically from its bytes (its own unlock identity under a distinct
single-expansion HKDF -- a code and a passphrase that stringify alike can
never derive the same unlock Space -- plus a client seed, one did:webvh
update key, and a binding MAC key), so the key material exists nowhere until
the code is typed.

Its posture is deliberately split. **Decryption stands**: the code's
`keyAgreement` verification method is published in the did:webvh document
(an ordinary, deliberately unmarked Multikey entry -- a recovery key is the
keyAgreement-only case, so client listings keyed on `capabilityInvocation`
never see it, and the document does not label which keyAgreement key is the
recovery one), and its user key wrap stands in the `key-map/user-key.jsonl`
roster -- both maintained for free by rotation fan-out. **Authority stays latent**:
the code's update key joins `updateKeys` nowhere; only its hash is committed
in `nextKeyHashes`, and the one bridge into the zcap profile is a pre-minted
PUT-on-`did.jsonl` delegation carried inside the code's unlock record beside
the account pointer (never a seed, never a key wrap -- the record stays a
pure pointer). The narrow scope keeps recovery **loud**: any use of a code,
legitimate or stolen, must first extend the world-readable, hash-chained log
before it can read a single byte.

The record itself splits into a **code-authenticated core and a re-mintable
shell**. The core is the account binding `{ controller, pointer }`: at
issuance it is MAC'd under a key derived from the code bytes (the storage
host never holds it), the tag riding the record frame in the clear, and
recovery verifies the tag BEFORE the pointer is trusted. This is what closes
the host-forgery redirect: the record's JWE recipient is the code's unlock
KAK, whose public half sits in the stored frame, so a malicious host can
re-encrypt a record of its own pointing at an attacker-controlled account
and sign it with that account's genuinely enrolled key -- every
signature-side check passes by construction, and only the binding, which no
one without the code bytes can compute, refuses it. The shell is the
record's plaintext frame (controller, pointer, timestamp) plus its sealed
`bridge` member -- the pre-minted delegation, wrapped on its own so a
re-mint can replace it -- under the frame proof, whose signer is mixed:
issuance signs with
the code-derived unlock key (verified before decrypt); the revocation
cascade's delegation re-mint signs with the re-minting client's account
verification method, verified after decrypt against the did:webvh document
of the account the code-authenticated pointer names. The re-mint reads the
standing record through its management zcap and preserves the binding tag
verbatim (it cannot recompute it and does not need to), so a re-mint can
never move the record to another account -- and since the tag covers the
pointer's host, codes must be re-issued when the account migrates hosts.
The record carries no email and the locate step shows none: a self-declared
display string was exactly the deception payload a forged record could show
as "this is your wallet", and with the pointer code-authenticated the cue is
unnecessary -- `/recover` confirms only that the code located an account.
The locate step keeps the module's error discipline: a network failure from
the account-log fetch rethrows unchanged and surfaces as "could not check",
and an account-log continuity refusal is never relabeled as a forged record
-- a `rollback` (possibly mere replication lag) reads as could-not-check,
while a fork or identity switch surfaces as its own continuity refusal.

Issuance (Settings > Recovery codes, `issueRecoveryCode` in
`src/session/recovery.ts`) runs in the recovery-anchor order -- decryption
material before authorization: roster wrap first (escrow: every epoch, so
recovery decrypts pre-issuance history), then the document entry (VM +
commitment), then the delegation and unlock record, then a registry entry
carrying public halves only. Nothing binds until the confirm-once dialog's
"I saved this code".

Recovery (`/recover`, `recoverAccountWithCode`): the typed code decrypts its
unlock record, the log is fetched and locally verified against the pointer,
a brand-new ordinary client key set is minted, and the delegation writes the
self-enrolling continuation -- a **reveal-and-commit** entry signed by the
code's pre-committed update key (with prerotation active, an entry verifies
against its own re-stated `updateKeys`, each hashing into the previous
entry's `nextKeyHashes` -- which is exactly what lets a committed key reveal
itself), then an **add-and-retire** entry signed by the new client's update
key: new client in (both VMs, all four signing relations, update authority),
the spent code's VM, update key, and hash out, and a replacement code's
posture in. The user key is unwrapped from the code's standing wrap and
**mandatorily rotated** off the spent code (recipients of the fresh epoch
resolved from the just-updated verified document); a replacement code is
pushed hard (shown once, must be confirmed saved before login unlocks); the
spent code's unlock Space is deleted (a typed code is a spent credential --
it thereafter fails with wording distinct from "wrong code"); and the new
client binds under a freshly chosen passphrase, ending in an ordinary
enrolled login. The fresh user key then fans out through the epoch cascade (see
"Client revocation" below): every encrypted collection re-epochs onto it,
so writes stop landing under epochs the spent code could read.

Revoking a code from Settings is the issuance reversal and is REAL (the
secret was only ever a pointer to the record): document entry out, user key
rotated off the code's wrap and the collections re-epoch'd by the same
cascade, unlock Space deleted, registry entry dropped; the live session
adopts the rotated user key in place. A login-time health check watches for
**delegation rot** -- the stored delegation stops chaining the moment its
signing client's verification method leaves the document (current-key-set
rule), which would brick recovery exactly when it is needed -- and for
**delegation expiry**: the delegation's TTL is one year (NIST SP 800-57
cryptoperiod guidance), so the registry entry records its `expires` and a
delegation expired or inside the 30-day renewal window is flagged the same
way. The check nudges regeneration; a client revocation re-mints the
affected delegations itself as part of its cascade, and the same expiry
predicate makes it refresh a near-lapse delegation too. The re-mint core
(the staleness checks, the skip policy, the binding-carried-forward
re-wrap) and the delegation builder live in
`@interop/wallet-core/recovery`; `src/session/recovery.ts` binds them to
the session's signers, the storage URL, and the unlock-methods registry.

Two standing boundary rules. First, the hash-commitment rule (which
replaced the retired "the passphrase must never become a recovery entry"
rule when every unlock method became a standing credential): **a
low-entropy-derived public key is never published in the world-readable
document**. The document carries a hash commitment of the key
(`MultikeyCommitment`); the real key rides in the capability-gated roster
entry, and the recipient resolver verifies it against the commitment.
Publishing the key verbatim would turn the server-gated guessing oracle
into a world-readable offline one, available to anyone who downloads
`did.jsonl`. A high-entropy credential's key (a passkey PRF output, a
recovery code) may publish verbatim. Second, the unlock-methods registry's
additive `method` enum is the explicit seam for a later quorum recovery
method (rejected for v1 as presupposing a contact roster most accounts
lack). The re-mint machinery above also covers the standing
passphrase/passkey credentials' bridge delegations (the cascade walks
every registry entry recording one, and a standing credential's own login
refreshes its bridge when it is inside the renewal window or when its
signing key has left the account document -- the signer-rot axis a
self-enrollment's ladder-VM removal makes routine).

## Client revocation and the epoch cascade

Disconnecting an enrolled wallet client from the account. The cascade is
`revokeAccountClient` in `@interop/wallet-core/clients` -- one orchestrator
for every wallet -- and `revokeEnrolledClient` in
`src/session/revocation.ts` supplies the freewallet-shaped stages around it
(the session preconditions, the collections source, the recovery re-mint,
and the adoption side effects), driven from the Settings "Connected wallets"
panel -- see "The Settings clients surface" below. Run in the revoking
client, synchronously, in dependency order:

1. **The document edit** (`revokeWebvhClient` in
   `@interop/wallet-core/webvh`): the revoked client's two verification
   methods (the key-agreement one found by its controller marker, never
   re-derived), its update key, and both its standing `nextKeyHashes`
   commitments (the carry-over hash and the staged hash -- the latter
   recovered by log attribution, since leaving an opaque committed hash
   behind would be a re-seizure credential via the reveal mechanism) leave
   in one log entry. Under the current-key-set rule this single edit is the
   revoked client's pull axis everywhere: its invocations, and every
   delegation and app grant it ever signed, stop verifying the moment its
   verification method leaves the document. There are no per-collection
   revoke calls anywhere in the cascade; apps a revoked client had
   connected reconnect through the ordinary App Connect flow.
2. **The user key rotation** in the `key-map/user-key.jsonl` roster
   (`rotateUserKeyRoster`), recipients resolved from the just-updated verified
   document -- the roster delivers, never sources, so the revoked client's
   entry is dropped even before the retire filter. An account with no roster
   yet stops here: the document edit has landed, so the wallet IS
   disconnected, with nothing to rotate. Anchoring at the post-edit head is
   enforced by the shared orchestrator rather than by the caller's wiring: it
   sets the roster store's controller floor (`setControllerFloor`) from the
   edit's own post-edit log before any roster-side work runs, so a stale
   cached controller view -- the session's verified-log memo, say -- can
   anchor neither the rotation nor the sealing append at a head that predates
   the removal. The store the session hands over is wallet-core's sealable
   store unwrapped, which is what keeps that contract reachable.
3. **The epoch cascade** (driven by wallet-core over the collections
   `src/session/userKeyCascade.ts` enumerates): every encrypted collection -- the
   encrypted standard collections plus every remotely listed collection
   whose Description carries an encryption descriptor -- is re-epoch'd onto
   the fresh user key in parallel, via was-client's `replaceRecipient` (~2
   requests per collection): the revoked user key generations are retired from
   the epoch rosters and the fresh user key is escrowed into every prior epoch,
   so every other replica keeps decrypting across the rotation. A
   collection is stale exactly when its current epoch names a non-current
   user key generation -- staleness is detected from durable state alone -- and
   a never-epoch'd collection gets the newest prior generation installed as
   its first epoch (the user key is the epoch construction, so pre-epoch
   envelopes ARE epoch-`oldUserKey` envelopes). A descriptor whose
   `currentEpoch` names no epoch in its own `epochs` list is refused
   fail-closed rather than evaluated against the last epoch, matching the
   roster read's own integrity refusal. Failures are collected per
   collection, never aborting the fan-out, so such a collection lands in the
   fan-out's `failed` report and the rest still rotate.
4. **The recovery re-PUTs** (`remintRecoveryDelegations`): recovery
   delegations the revoked client had signed stopped chaining at step 1;
   the revoking client re-mints them and re-PUTs the unlock records.
5. **The generation-delegation re-mint** (the `remintGenerationDelegation`
   closure, module-level in `src/session/revocation.ts`): the embedded
   generation delegation stopped chaining at step 1 too when the revoked
   client had signed it, so the closure runs
   `ensureGenerationDelegationCurrent` against the post-edit document (the
   stale-signer axis beside the expiry one) and replaces the delegation in
   place -- same fragment, no revocation POST, since the rotted chain no
   longer verifies anyway. It signs with the login credential's ladder
   seed, carried in-memory on `profile.ladderSeed`, and skips with a
   report (`outcome.generation`) when the seed or a promoted pointer is
   absent -- the mid-generation grant death that remains is a stated
   consequence of an ordinary disconnect. The closure runs in the
   no-roster early return as well.

The revoking session then adopts the fresh user key in place -- profile vault
keys swapped, storage ciphers rebuilt (`adoptRotatedVaultKeys`), the
unlock-methods registry re-wrapped -- so it keeps operating without a
re-login, and a wallet-activity record is written under the fresh epoch.
Self-revocation is refused up front (use another enrolled client, or a
recovery code). The cascade is convergent under a naive full re-run: the
log entry is idempotent, the roster no-ops once the entry is off the
current epoch, and the staleness rule finds exactly the stranded
collections -- so a mid-cascade crash strands nothing permanently. The
honest ceiling is unchanged: ciphertext the revoked client already fetched
stays readable to it, and old epochs open to keys it already held.

One key deliberately survives every rotation: a collection's blinded-index
HMAC key. It is minted with epoch[0] at provisioning and wrapped to each
recipient on the `encryption` descriptor, but it never rotates -- blinded
index tokens must compare across the collection's whole history, and a
fresh key would orphan every existing `indexed` entry. Recipient removal
only drops the leaver's wrap. A removed recipient therefore keeps the
blinding key and, colluding with the server, could confirm guessed
attribute values indefinitely. That is a guessing oracle, not a read path:
the server still gates the query endpoint on the pull grant, and the
content keys rotate as described above.

The standing backstop is the **cascade-completion sweep**: session creation
re-runs stages 2 and 3 in the background on every login whose roster read
succeeded, chained behind collection provisioning and exposed as
`session.userKeySweep` (best-effort -- a failed sweep never fails the login).
The roster stage runs first (`convergeUserKeyRosterToDocument`): a cascade torn
between its document edit and its rotation leaves the roster wrapping the
CURRENT key to a recipient the locally verified document no longer keys --
durable and silent, since the revoked client's document edit will never be
re-run -- so a current-epoch recipient the document-backed resolver cannot
answer for is rotated away from here, and the fresh key is adopted (client-key
record, epoch pin, live session vault keys and ciphers) before the collection
fan-out runs against it. Because staleness is durable-state-only, the fan-out
then completes a cascade another client crashed partway through, and on a
healthy account both stages read descriptors and write nothing. Together they
are the standing invariant check that the roster keys exactly the document's
clients and that no collection's current epoch names a retired user key
generation.

Recovery-code spend and revocation drive stages 2 and 3 of the same
cascade (their document edits are their own, described above, and a spent
code's replacement delegation is minted by its own ceremony rather than
the re-mint stage), which is what closes the "writes still land under
readable epochs" residue in both flows.

## The Settings clients surface ("Connected wallets")

The management surface over the enrolled-client roster
(`src/components/EnrolledClientsSection.tsx`, glue in
`src/session/clients.ts`): the place "disconnect this phone" lives, sibling
of the Applications page (apps are grantees, never enrolled, and stay in
their own revocation surface).

The listing is wallet-core's `listAccountClients`, which
`src/session/clients.ts` wraps with only what a session knows (where the log
lives, which key is this browser's, the label store): a read over the
locally verified did:webvh log -- the same `verifyAccountLog` step every
ceremony runs -- then `listEnrolledWebvhClients`, keyed on
`capabilityInvocation`. That keying is
the exclusion story: a recovery code's key is published under `keyAgreement`
only (deliberately unmarked), and the KMS-held convenience under
`authentication`, so neither can appear, structurally rather than by
filter. Two members are not readable off the current document
and are recovered by log attribution: each client's ACTIVE update key (the
flat `updateKeys` set has no per-client grouping; the entry that published
the client's verification methods revealed its initial key, and each entry
retiring the attributed key while revealing exactly one replacement is that
client's self-rotation -- an ambiguous attribution disables disconnect for
the row rather than guessing) and its enrollment moment (`versionTime` of
the publishing entry). A listed row with both key members -- its signing key
and its active update key -- is exactly a
`RevokedClientKeys` (`revokedClientKeysFor`), so Disconnect drives the
client-revocation epoch cascade verbatim. Which rows can be disconnected at
all is the shared `disconnectEligibility` policy (self, last-wallet, and
unattributed-update-key refusals) rather than UI state, and a partial
collection fan-out is reported through `cascadeCompletion` as the resumable
success it is.

**Labels live beside the keys, not in the document.** The document carries
key material only, so display labels go in `key-map/client-labels.json`
(wallet-core's `readClientLabels` / `setClientLabel` over a two-method
store seam; plaintext in the private, capability-gated `key-map` collection
-- the host already serves the world-readable log naming every client key,
so a label adds only the display name). A label is chosen at enrollment
approval (a field in the enroll dialog, written after the ceremony lands,
best-effort) and editable inline from the panel; the current client is
marked with a "This browser" chip (matched on the session's own signing
key) rather than by any stored state.

Disconnect confirms with the honest ceiling (re-keying stops future reads;
already-fetched ciphertext stays readable), runs the cascade with keep-this-
tab-open progress copy, and surfaces both failure modes as resumable ("try
again -- it picks up where it stopped"; a partial collection fan-out points
at the login-time sweep). The last enrolled client cannot be disconnected --
that would abandon the account's update authority (it is also always the
current client from its own session, and self-revocation is refused) -- and
the panel says so, pointing at recovery-code issuance instead. The
connect-another-wallet entry point (the enrollment ceremony's approving half:
one card offering both the QR onboarding invite and the pasted connect code)
lives in this panel.

**The Applications sibling knows the current-key-set rule.** The
Applications page (`src/lib/connectedApps.ts`) is the other revocation
surface of the account -- app grantees there, wallet clients here, with a
cross-pointer in each panel to the other. Its listing checks each recorded
App Connect grant's delegation signer (the full zcap, proof included, is
recorded on the Login activity) against the same verified document, via
`currentAccountSigningKeys` (wallet-core's, wrapped in
`src/session/clients.ts` so a guest degrades rather than throws) plus
`deriveAppGrantsState`, matched on the key-multibase fragment so the
did:key and promoted did:webvh spellings of one key agree). An app whose
recorded signers are all gone from the document is shown as orphaned --
its grants already stopped verifying with that client's revocation, and
reconnecting through the ordinary App Connect flow is the recovery path --
and revoking it skips the pointless per-grant revocation POSTs while still
rotating the app-provisioned collections' epochs and deleting the app key,
which remain meaningful. The check is best-effort: no verified document
this session (a guest, or the log unreachable) degrades to listing without
the marker, never to failing the page.

## Storage model (local-first)

The local `BrowserStore` (RxDB over Dexie/IndexedDB) is always the **active
replica**: every credential, public-link, and history read/write targets it,
online or offline, guest or not. One local database per user holds every
standard collection (`private-credentials`, `public-credentials`,
`wallet-activity`, `contacts`, `contacts-history`, `app-connections`) on the
generic synced-doc schema
(`{ id, updatedAt, version, data }`, see `src/lib/sync/syncedDocSchema.ts`).

The encrypted collections (all of the above except `public-credentials`) store
**EDV envelopes**, not plaintext -- encrypted-at-rest locally and opaque to
the server. A per-collection document cipher (`createEdvDocCipher` from
`@interop/was-client/edv`, built from the session's vault KAK) encrypts at write
time and decrypts at read time; the row id is content-derived (a hash of the
JWE ciphertext), so it is identical on every replica. Page-facing identity
stays the credential `cid` / activity `id`, recovered by decrypting at read
time; because JWE encryption is nondeterministic, dedupe keys on that content
identity, not the row id. `public-credentials` is plaintext for good (it is
public data) and keyed directly by `cid`.

When `VITE_WAS_SERVER_URL` is set (and the session is not a guest), a remote
WAS Space is attached as a **sync target**: the `SyncController`
(`src/stores/syncController.ts`) replicates every synced local collection to
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

Deleting a credential retracts its world-readable public copy before removing
the private credential (`StorageManager.deleteCredential`, matching the mobile
wallet's order): once the private credential is gone nothing is left to retract
the public copy with, so the reverse order can strand a world-readable orphan.
Retraction of a live public copy is blocking -- a public copy that cannot be
retracted refuses the delete (`PublicCopyRetractionError`) rather than deleting
anyway -- while the delete dialog's deliberate "keep public copy" choice skips
it, and a credential with no public copy deletes normally offline.

The world-readable share link a public copy gets
(`WASRemoteStore.publicCredentialUrl`, over wallet-core's
`publicCredentialUrl`) is built with was-client's paths helpers
(`spacePath` / `resourcePath` / `toUrl`), which join onto the storage
server's base path. On a sub-path deployment (a server URL like
`https://host/was`) the emitted link therefore addresses exactly the
resource replication wrote, with per-segment encoding guaranteed by the
same helpers; the earlier root-anchored form was drift, corrected in
wallet-core 0.39.1.

A user's remote Space is identified by an independent random `spaceId`
minted at signup and carried in the account pointer (unlock Spaces keep
`spaceId = base64url(SHA-256(unlock did:key))` as a discovery convention).
Collections created on first login: `private-credentials`, `public-credentials`,
`wallet-activity`, `contacts`, `contacts-history`, `app-connections`.

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
`Key-Epoch`), so the main app's replication pulls it cleanly. An
unknown-epoch read (a rekey by another client) drives the same one-time descriptor
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

- `app: { name, appUrl }` -- the display name for the consent screen and the
  application's canonical URL, which scopes the app-key identity within the
  requesting origin. The `appUrl` must parse as an absolute URL, carry no
  fragment, and be same-origin with the attested requesting origin; any
  violation makes the query malformed. Everything downstream stores and
  compares the parsed URL's serialization, so spellings differing only in a
  default port, percent-encoding case, or dot-segments do not name distinct
  applications;
- `capabilityQuery: [...]` -- the usual capability descriptors _minus_
  `controller` (the wallet fills it) and `reason` (the App Connect consent
  screen supersedes per-grant reasons).

An `AppConnectQuery` is one mental model per popup: mixing it with
`QueryByExample` or standalone capability queries is rejected at
classification time (the shared `appConnectRequestOf`), and wallets that
predate it fail closed
(the app surfaces an "update Freewallet" error) rather than degrading into a
partial generic flow.

The exchange's wire contract -- the `AppConnectQuery`, the app-key
credential, the descriptor vocabulary and action ceilings, and the response
presentation -- is specified normatively in the **App Connect companion
spec** (<https://github.com/interop-alliance/app-connect-spec>; local
checkout `../app-connect-spec` -- read `spec.md` there instead of fetching
the rendered version).

The whole app-key module -- the wire constants, the match and mint paths,
and the store-time refusal policy -- lives in
`@interop/wallet-core/request` (`appKey.ts` there), shared with DCW; the
`AppConnectQuery` validation (`appConnectRequestOf`) lives beside it in that
package's `classify.ts`. Freewallet's half is consent UI, credential storage,
and the delegation machinery.

The key design move: **the wallet mints the app-key seed**. The seed is a
client secret that must never transit a server, so on first run the wallet generates 32 random bytes, derives the did:key
via `CapabilityAgent.fromSeed({ seed, keyName: 'app-key' })` (the `keyName`
string is load-bearing -- it must match was-react's derivation exactly),
self-issues the credential (issuer == subject == seed-derived DID, seed
base64url-no-pad in `credentialSubject.seed`), and saves it to the dedicated
`app-connections` collection under the same consent -- no second popup. On a returning
visit the stored credential is matched by the `AppKeyCredential` marker type
AND `credentialSubject.appUrl === ` the request's serialized `appUrl` AND
`credentialSubject.origin === ` the CHAPI requesting origin, so a phishing
origin can neither recover nor be handed another origin's key, and two
applications sharing an origin are kept apart by their `appUrl`s (the app-side origin check in was-react's `parseSeedCredential`
stays as defense in depth).

A match additionally requires that the credential's subject DID **re-derive
from the seed the credential itself carries** (`appKeySeedBindsSubject`).
Self-issuance is a weak signal -- anyone can self-issue, and candidates are
ranked on an `issuanceDate` the credential itself states -- so without this a
credential planted through an import (before the store door below existed, or
injected into the Space directly) would win the
match and its DID would become the `controller` the wallet delegates to. The
check is local and deterministic (the seed is right there; re-derive with the
same `CapabilityAgent.fromSeed` call that minted it) and fails closed on an
absent, non-base64url, or wrong-length seed. Binding authenticates internal
consistency only, not provenance -- a fully attacker-generated credential (its
own fresh seed, the victim app's `origin` and `appUrl`) binds perfectly --
which is why the store-time refusal below, not the binding, is the door that
keeps plants out. Candidates are ranked latest-first over the _instant_ each
`issuanceDate` denotes rather than over the raw string, so a comparison
manipulable by the spelling of a date (a numeric offset, differing
fractional-second precision) cannot reopen the planted-credential path in a
narrower form; an absent or unparseable date sorts last.

**App keys live in their own collection.** Every app key is stored in
`app-connections` -- a synced, EDV-encrypted, content-addressed collection
just like the credential replica, but structurally separate from it: the
credential-wide surfaces (the dashboard list, credential detail, public-link
creation, credential delete, collection shares) are scoped to
`private-credentials` and can never reach a seed, with no filtering code.
The collection is never shareable (`shareable: false` on its roster spec)
and no grant may name it: a capability descriptor or URL naming the
collection is unsatisfiable in grant resolution, not merely read-only. (A
whole-Space read grant still covers its ciphertext, as for every private
collection -- the grantee is not an epoch recipient, so it decrypts
nothing.) Match and consent-preview candidates come from
`StorageManager.listAppKeys()`, so ordinary stored credentials never enter
the match. There is no migration from the old in-`private-credentials`
placement and no legacy (pre-`appUrl`) re-issue path: an idempotent
login-time sweep deletes stranded app-key rows from `private-credentials`
(marker-typed or matching the old self-issued-with-origin shape), and an
affected app reconnects through the ordinary flow as a first run -- its
prior identity, and whatever it encrypted under it, is deliberately
orphaned (the greenfield re-provision posture).

**Externally arriving app keys are refused at store time, unconditionally.**
Every minted app key carries the marker type `AppKeyCredential`
(`https://w3id.org/byoe#AppKeyCredential` -- one stable IRI for every app,
defined in the static inline `@context`), which turns "presents
as an app key" into a term check rather than a shape heuristic. Be clear about
what the marker is: the `type` array of a planted credential is
attacker-controlled like everything else in it, so the marker is a
**self-declaration, not evidence** -- which is exactly why the store-time rule
cannot be "binds, so it stores" (a planted credential can bind, see above) and
is instead: app keys are wallet-minted, never imported.
`StorageManager.addCredential` -- the one door every externally supplied
credential goes through (the CHAPI store popup, the URL / QR / manual-paste
import, the credentials half of a space import) -- refuses every marked
credential, binding or not (`assertStorableAppKey`, `AppKeyRefusedError`).
Refusing
beats storing-and-ignoring on two counts: future consumers of an app-key match
do not each have to remember to re-check provenance, and the wallet does not
present the user with a credential it will never act on. The marker is
_required_ at match time rather than merely tolerated, so a credential can
only reach the delegation path by carrying it -- which is exactly what the
store-time refusal screens. The wallet's own mint path stores through its own
door (`StorageManager.addMintedAppKey`, called only by `processAppConnect`,
writing into `app-connections`),
which itself asserts the mint invariants so it cannot be misused to store a
foreign key. Two ingest paths sit outside the door, deliberately: the
background sync pull writes pulled rows into the local replica directly, but
it replicates the account's own remote collections, which only the account's
enrolled wallet clients can write (`app-connections` is never grantable at
all, and `private-credentials` is a protected
collection -- RP and share grants on it are read-only) and each of those
clients enforces the same refusal at its own door; and the space half of an
import writes opaque resources into the user's own Space server-side. For
both, the match-time binding remains the backstop.

The credential's shape is identical for every application: the `type` array
is the fixed two-entry `["VerifiableCredential", "AppKeyCredential"]`, and
the inline `@context` is one static object mapping `appUrl`, `seed`, and
`origin` to their `https://w3id.org/byoe#` IRIs. Which application a
credential belongs to is the `credentialSubject.appUrl` claim, not a type.

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
Provisioning is idempotent: the collection gets epoch[0] wrapped to the owner
create-if-absent (`ensureIndexedFirstEpoch` from `@interop/wallet-core/keys`,
adopting an existing roster rather than overwriting it), then a first connect
or a reconnect after revoke escrows the
app into every epoch (`addRecipient(app)`); already present -> no-op.
Epoch[0] is minted together with the collection's blinded-index HMAC key,
wrapped to the same recipient roster, so the app can declare searchable
attributes and query the collection (was-client's `declareIndex` / `find`).
The blinded-index key is installed at provisioning or never: a collection
provisioned before blind-index support is adopted as-is and stays
unindexable. The wallet's own writes carry the same blinded `indexed`
entries a Collection-handle write does: each encrypted collection's doc
cipher installs the persisted index schema from the collection's stored
`/meta` (its `custom` is an opaque encrypted envelope, so it is fetched
without keys and decrypted by the cipher), acquired and cached beside the
encryption descriptors and refetched on the same unknown-epoch descriptor
refresh -- so an index declared mid-session reaches the ciphers at the next
descriptor refresh or login. The
wallet ensures the collection exists without
clobbering an existing `encryption` descriptor, so an established epoch roster is
never dropped. Public (`https://w3id.org/byoe#public-collection`) grants
stay plaintext and world-readable as before; only private app collections are
encrypted, and a public grant can only ever CREATE its collection -- one
naming an existing non-public collection is unsatisfiable, so no consent
approval can flip an established (encrypted or not) collection
world-readable. The
policy is that **the user is always a recipient of an encrypted collection in
their own Space** -- any future exception (an app collection the user is
deliberately not a recipient of) must be an explicit, separate consent surface,
never a silent default.

Because the user is recipient zero, the wallet decrypts these collections in
the storage browser as an ordinary recipient with its vault KAK, descriptor-driven
from the fetched Collection Description (no seed at read time). Revoking a
connected app rotates the epoch off the app's key for each such collection
(`removeRecipient`, which rotates then revokes the pull-axis grants
indivisibly), so a revoked app cannot decrypt future writes -- the honest
ceiling being that ciphertext it already fetched stays readable to it. The
blinded-index key is deliberately not rotated on revoke (see "Client
revocation and the epoch cascade" for the asymmetry): the revoked app keeps
the ability to compute blinded terms, while the query endpoint itself stays
behind the revoked pull grant.

## Sharing a wallet collection (`https://w3id.org/byoe#shared-wallet-collection`)

The collections above are ones an app created. **Sharing** is the other
direction: letting a grantee read and _decrypt_ one of the wallet's own
encrypted collections. It is asked for with a distinct invocation-target
descriptor -- `{ type: 'https://w3id.org/byoe#shared-wallet-collection', name }` --
in either channel (a standalone `AuthorizationCapabilityQuery`, or an
`AppConnectQuery.capabilityQuery`). A distinct descriptor type rather than a
flag on the existing shape is load-bearing: an unknown `type` already resolves
to unsatisfiable, so a wallet that predates the feature refuses visibly instead
of silently degrading to a ciphertext-only read.

**The two axes stay fused.** _Pull_ (a read-only Collection zcap) and _read_
(an epoch-key recipient entry) are granted together, by one call to
`StorageManager.shareCollection`, which returns the delegated zcap alongside
the refreshed descriptor so it rides back in the response VP's `zcap` array. A
share grant therefore leaves the ordinary delegation loop in `processZcaps`
entirely; there is no code path that grants one axis without the other.

**The recipient key is derived, not transmitted.** `name` must be one of the
shareable standard collections -- every `WALLET_STANDARD_COLLECTIONS` entry
whose roster spec carries `shareable: true`, so today `private-credentials`,
`wallet-activity`, `contacts`, and `contacts-history` -- since sharing is
meaningless where no epoch roster exists, and `app-connections` is encrypted
but deliberately never shareable (its rows carry app seeds). The grantee's X25519 key is derived
from the `did:key` the request
already names as `controller` (`x25519RecipientFromDidKey` from
`@interop/was-client/edv`, the same Ed25519-to-Montgomery conversion the
wallet applies to its own vault KAK). An explicit key field would let a request
pair controller DID A with recipient key B; deriving makes that substitution
impossible by construction. A controller with no Ed25519 twin (a did:web, an
X25519 did:key) makes the grant unsatisfiable.

**Consent states the ceiling before approval.** The share row on the consent
screen is visually distinct from every other grant and says three things: the
grant is read _and_ decrypt; it covers the collection's contents from the
moment of approval, not only future writes; and removing access later stops
future reads but cannot take back what has already been read. The second line
is stated without a hedge because the epoch model makes it true: every
encrypted collection carries epoch[0] from provisioning (wrapped to the user
key, recipient zero), so a share is always an `addRecipient` that escrows the
grantee into every existing epoch -- no rotation, and no envelope in the
collection sits outside an epoch the grantee now holds. An epoch-less
descriptor is refused fail-closed rather than seeded lazily at share time (it
can only mean an unprovisioned or torn collection), so there is no legacy
single-recipient residue a reader could fetch but not decrypt. Removal is the
shares dialog behind a collection row's "Shared" chip in the Storage
collection list (`unshareCollection`), not expiry -- the share TTL
(`SHARE_ZCAP_TTL_MS`) is deliberately long, because expiry would end the pull
axis while leaving the grantee in the key roster. A share also escrows the
grantee into the collection's blinded-index HMAC key when the descriptor
carries one; removal drops that wrap but never rotates the key (see "Client
revocation and the epoch cascade" for why, and what a removed grantee
keeps).

**The grantee's half lives in `@interop/was-react`.** An app declares the
wallet-owned collections it wants in `WasAppConfig.sharedCollections`, which
adds the `https://w3id.org/byoe#shared-wallet-collection` descriptors to its App
Connect request; on approval a `SharedCollectionReader` fetches the Collection Description through
the delegated read zcap, builds the epoch-aware cipher from the descriptor, and
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
  protected collection, and share read-only; public collections and
  app-provisioned private collections the full vocabulary), and the consent
  screen shows exactly what `resolveGrants` resolved. A grant left with no
  permitted action is unsatisfiable, never delegated empty. Resolution also
  consults the existing collections' state (a snapshot fetched from the
  Space, once for the consent preview and fresh again at delegation time,
  then kept current as the delegation loop provisions -- so duplicate names
  within one request resolve against what the request itself created): a
  public collection is only ever created public, never converted -- a
  `#public-collection` grant naming an existing non-public collection
  (another app's, possibly encrypted) is unsatisfiable, and the idempotent
  re-grant on an already-public collection delegates without re-provisioning
  -- and any target naming an already-public collection is classed
  public-collection and skips provisioning whether it arrives as a
  `#public-collection` descriptor, a `#private-collection` descriptor, or a plain
  URL string.
- **Challenge/domain**: unchanged DIDAuth verification app-side in
  was-react.
- **Per-user app identity**: an app key is minted from 32 fresh random bytes
  inside the connecting user's own wallet and stored in that user's own
  `app-connections` collection, so the app's DID -- and therefore the X25519 recipient
  key derived from it -- is scoped to the **(user, origin, `appUrl`)**
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
| `/recover`                               | `RecoverPage`            | Recovery-code account recovery       |
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

## What lives elsewhere (do not reimplement here)

Every `@interop/*` package is in-house (their checkouts sit beside this repo,
e.g. `../wallet-core`); a change needed in one of them is an in-house change --
export it from the owning package and import it, never copy or re-derive it
app-side. The map of the shared wallet layer is
[`../wallet-core/ARCHITECTURE.md`](../wallet-core/ARCHITECTURE.md) -- module
layers and dependency direction, the key hierarchy, the ceremonies and
cascades, and the permanent wire-level constants.

- **`@interop/wallet-core`** -- the correctness-critical logic shared with the
  DCW mobile wallet, imported by subpath. The sections above name them where
  they surface; the full set used here: `/webvh` (the did:webvh log and the
  document halves of the ceremonies), `/keys` (+ `/keys/clientKeyRecord`; the
  user key, its wrap-set roster, the client-key record codec, client labels),
  `/keyring` (the unlock layer), `/genesis` (the account-genesis key mint and
  ceremony), `/enrollment`, `/recovery`, `/clients`
  (listing, disconnect policy, the revocation cascade orchestrator, the
  login-time roster policy), `/descriptors`, `/identity`, `/space` (collection
  layout, activity builders, `was-link`), `/request` (classification,
  matching, VP composition, exchanges, and the App Connect app-key
  credential), `/display`, and `/sync` (only the
  contacts LWW conflict resolution -- freewallet keeps its own RxDB
  replication driver in `src/lib/sync/`, over the wire contract from
  `@interop/was-client/sync`).
- **`@interop/was-client`** (+ `/edv`, `/sync`) -- the WAS HTTP client, the
  sync wire contract the RxDB driver speaks, the EDV envelope cipher and
  key-epoch construction (`createEdvDocCipher`, `x25519RecipientFromDidKey`),
  and the descriptor-store seam.
- **`@interop/social-core`** -- the contacts collection specs and the
  `remotePayloadWins` LWW comparison.
- **`@interop/webkms-client`** and **`@interop/ezcap`** -- `CapabilityAgent`,
  `KmsClient` / `KeystoreAgent`, and `ZcapClient`.
- **`@interop/data-integrity-core`** -- loose VC/VP shape guards and the VPR
  type vocabulary.
- **`@interop/did-method-webvh`** -- the webvh log primitives (normally
  reached through `wallet-core/webvh`).
- **`@interop/verifier-core`** -- credential verification.

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
  the canonicalized credential JSON (`cidFrom()` from
  `@interop/was-client/sync`).
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
  origin, `appUrl`, and seed-to-subject binding, or minted wallet-side on
  first run)
  plus capabilities delegated to
  its subject DID, in a single signed presentation. See "App Connect" under
  Architecture.
- **App key** — a self-issued credential holding a 32-byte seed in
  `credentialSubject.seed`, bound to a requesting origin in
  `credentialSubject.origin` and to the application's canonical URL in
  `credentialSubject.appUrl`; issuer and subject are the seed-derived
  did:key (`CapabilityAgent.fromSeed`, `keyName: 'app-key'`). It is how a
  BYOE app keeps its identity/encryption root in the user's wallet
  (`@interop/wallet-core/request`). Every app key carries the marker type
  `AppKeyCredential` (`https://w3id.org/byoe#AppKeyCredential`); any
  externally arriving credential carrying the marker is refused at store
  time, binding or not -- app keys are wallet-minted, never imported.
  Stored in the dedicated `app-connections` collection (synced, encrypted,
  never shareable, never grantable), not among the user's credentials.
- **Client / `clientId`** — the keyed, custodied, revocable identity of an
  (app, user) pair: a keypair that can be a zcap grantee, a delegation
  `controller`, or an entry in a collection's key-epoch roster. For a BYOE app
  it is the **app key**'s subject DID above, scoped to
  `(user, origin, appUrl)` and stable across browsers because the
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
  (`src/lib/writerId.ts`, a `localStorage` key), dies with a wallet reset, and
  is deliberately not derived from any secret — so it is never an identity and
  must not be treated as one. Distinct from a `clientId` in lifetime and in
  trust: it can vanish and be re-minted with nothing carried over. Also not a
  `replicaId`: it is minted per browser profile while the local database is
  per user, so it is not 1:1 with a replica.
- **Share** — granting a third party read AND decrypt access to one of the
  wallet's own encrypted collections, asked for with a
  `https://w3id.org/byoe#shared-wallet-collection` invocation-target descriptor. One
  `shareCollection` call grants both axes: a read-only Collection zcap and an
  entry in every one of the collection's key epochs (escrowed by
  `addRecipient`, so the share covers what is already stored). Removed from
  the Storage page's collection list (the row's "Shared" chip opens the
  shares dialog), never by expiry. See "Sharing a wallet collection".
- **WAS (Wallet Attached Storage)** — an HTTP protocol for storing arbitrary
  resources in user-owned Spaces. Requests are authorized via ZCap.
  See [the spec](https://w3c-ccg.github.io/wallet-attached-storage-spec/).
- **Space** — a storage area on the WAS server. The account Space's id is an
  independent random identifier minted at signup and carried in the account
  pointer; unlock Spaces are addressed by
  `spaceId = base64url(SHA-256(unlock did:key))` (a discovery convention).
  Owned by one controller.
- **Collection** — a named grouping of Resources within a Space.
  Standard collections: `private-credentials`, `public-credentials`,
  `wallet-activity`, `contacts`, `contacts-history`, `app-connections`.
- **Resource** — an individual stored item (JSON or binary) within a
  Collection.
- **Controller** — the `did:key` DID that owns a Space. Its Ed25519 key signs
  all ZCap-authorized requests.
- **Current-key-set rule** — the server's authorization policy for a Space
  whose controller is a did:webvh: an invocation or delegation verifies iff
  its verification method is listed in the account document as resolved NOW
  (the server reads and fully verifies `did.jsonl` out of its own storage).
  Revoking a client is therefore one document edit: the moment its
  verification method leaves the document, its requests and every delegation
  it ever signed stop verifying. The deliberate asymmetry: log-entry and
  roster proofs instead anchor at a version, so a signature made while the
  key was listed verifies forever and history never rots. See "The
  did:webvh identity".
- **Standing unlock credential** — an unlock method (passphrase or passkey)
  in the standing posture: beside locating the account through its unlock
  record, it holds a wrap of the user key in the roster (kept alive by
  rotation fan-out) and latent self-enrollment authority — a bridge
  delegation and a ladder seed carried in its unlock record — so a fresh
  browser holding nothing but the credential can self-enroll at login (the
  programmatic durable entry; the default non-remembered login is the
  transient posture). The
  credential's entropy bounds everything server-held that it alone decrypts;
  the rotation ceremony is the remedy when it leaks. See "Session & auth
  flow".
- **Bridge delegation** — the pre-minted, narrowly scoped zcap carried
  inside an unlock or recovery record beside the account pointer: a
  PUT-on-`did.jsonl` capability (plus companion-log access where that
  applies) that is a credential's only bridge into the zcap profile. The
  narrow scope is what keeps credential use loud: the only thing the bridge
  can do is extend the world-readable log. Re-minted by the revocation
  cascade and refreshed near expiry by the credential's own login.
- **Ladder (update-key ladder)** — the chain of did:webvh update keys
  derived from a standing credential's random ladder seed. Each rung is
  committed ahead of use as a hash in `nextKeyHashes` (the method's
  prerotation), and a rung reveals itself exactly when the credential
  self-enrolls — a reveal-and-commit log entry signed by the current rung.
  It is how a credential extends the log with no durable client key in
  hand. The **ladder VM** (design stage, not yet implemented) is a
  document-visible verification method derived from the ladder that anchors
  an account while it has zero enrolled clients; its authority breadth is
  an open design question.
- **Roster** — three related uses. The **enrolled-client roster** is the
  did:webvh document itself (each client's verification methods). The
  **user key wrap-set roster** (`key-map/user-key.jsonl`) is the
  log-governed record whose current epoch IS the current user key, wrapped
  once per enrolled client's key-agreement key. A **key-epoch roster** is
  the per-collection recipient set on an encrypted collection's
  `encryption` descriptor. All three deliver key material or membership;
  none is a source of authority on its own (the document is verified
  independently, and wraps are minted only against log-verified keys).
- **Loudness** — the design property that any exercise of
  credential-derived authority must first extend a hash-chained, auditable
  log (the account log, or the companion log) before it can read or grant
  anything. The security stance it enables is detect-and-remediate rather
  than prevent: takeover with a phished credential is visible in the log
  and remediable by rotation, not prevented by a second-device gate. A
  mechanism "fails loudness" when it would let a credential exercise
  authority with no world-visible record.
- **Companion** (design stage, not yet implemented) — the transient-session
  counterpart of an enrolled client for the public-computer posture: a
  did:webvh whose log lives in a capability-gated sibling collection of the
  account Space, recording per-visit transient verification methods in
  GC'd **generations** instead of permanent account-log entries. Transient
  keys invoke as `<companionDid>#<vm>`; the companion never appears in the
  account document.
- **Generation delegation** (design stage, not yet implemented) — the one
  Space-scoped zcap per companion generation, delegated to the companion
  DID by the durable client that mints the generation (or by the ladder VM
  while the account has no durable client). Transient keys invoke under it,
  and an App Connect grant from a transient session chains one deeper
  (root, generation delegation, app). Its TTL is matched to the
  generation's GC cycle.
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
  EDV envelopes: the user key's (formerly PUK's) key-agreement key, recovered
  at login from the local client-key record with the unlock-derived key,
  then checked against the user key wrap-set roster
  (`key-map/user-key.jsonl`), which confirms the cached copy current or
  delivers a rotated one. Never replicated in unwrapped form
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
