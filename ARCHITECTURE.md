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
  external/         Requests arriving from outside the app without CHAPI
                    (ExternalRequestPage, the interaction-URL door)
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
  corsProxy.ts      The one CORS-proxy path (`VITE_CORS_PROXY_URL`): the
                    pasted-URL credential fetch and the registries fetch
  viewMappers/      Transform raw credential data into display-ready values
  walletRequest/    VPR classification + response assembly for CHAPI requests
    respond.ts      Compose, persist the Login activity, then deliver (the
                    CHAPI `get` approval sequence)
    externalRequest.ts  The interaction-URL entry point's pure half: the
                    deep-link parser, exchange opening, and pre-consent
                    refusal matrix
src/lib/sync/       Collection-agnostic WAS replication adapter (RxDB-based)
src/stores/         Global state
  authStore.ts      Zustand store -- holds the live Session object
  storageManager.ts StorageManager facade (local-first routing)
  browserStore.ts   BrowserStore -- the local RxDB active replica
  wasRemoteStore.ts WASRemoteStore -- the remote WAS backend
  syncController.ts Background replication lifecycle (start/stop/reSync)
  toastStore.ts     Transient success/info messages (`showToast`), rendered
                    by DashboardLayout as a Snackbar. Global, not
                    page-local: an action often redirects (delete returns
                    to the dashboard) before a local message could render.
src/session/        Session bootstrap (initSession.ts) and the account
                    ceremonies -- the ordered sequences pages drive but do
                    not own (React components keep rendering and
                    confirmation callbacks only)
  signup.ts         The two new-account provisioning sequences
  accountSettings.ts  The Settings ceremonies (passphrase, passkeys,
                    update-key rotation, account deletion's phase order)
  clients.ts        Enrolled-client listing + disconnect (a session-shaped
                    adapter over the shared clients surface)
  recovery.ts       Recovery-code issuance, spend, revocation
  shares.ts         Shared-collection listing + removal
  applications.ts   Connected-app listing + revocation
  wipe.ts           The shared wipe enumeration (the one list of durable
                    local account state and its snapshot-first executor)
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
Space -- the encrypted account pointer `{ did, spaceId, host }`, the
controller, the email, and (in the standing layout below) the sealed bridge
delegation and update-key ladder seed, never the account's content keys --
and it unwraps the local **client-key record** in the `freewallet-session`
IndexedDB, which holds this client's seed, a cached copy of the user key,
and this client's did:webvh update-key seeds:

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
document (`<did:webvh>#<multibase>`) instead of the did:key form: the data
Space's controller is the did:webvh, and under the current-key-set rule only
a keyId the resolved document lists can authorize anything. `user.id` stays
the client did:key (it is also the App Connect response VP's holder, which
app-side loaders must be able to resolve).

Every unlock method is a **standing credential** (the recovery-code
configuration minus spend-on-use): beside locating the account, it holds a
wrap in the user-key roster (escrowed into every epoch, kept alive by
rotation fan-out) and latent self-enrollment authority -- its record carries
a pre-minted PUT-on-`did.jsonl` bridge delegation and a random update-key
ladder seed (`@interop/wallet-core/unlock`; the bind-time establishment is
`src/session/standingUnlock.ts`, run at signup and at every
add/change-method ceremony). When the account points at a client annex
generation, the establishment also appends one atomic hash-restating annex
commit entry adding the new credential's rung-0 hash, signed by the login
credential's committed rung (`commitClientAnnexRung`; without it the fresh
credential could not enter the transient session until the next generation
swap). Best-effort: an acting rung the generation does not commit is
skipped.

A fresh browser holding nothing but the credential can therefore
**self-enroll** at login as an ordinary full client, with no second browser
involved -- today through the programmatic `rememberBrowser: true` entry,
since the DEFAULT login on a non-remembered browser is the transient session
(see "Session persistence" below); the login-form choice is a planned
follow-up. Two loud entries extend the world-readable log through the
bridge: a reveal-and-commit entry signed by the ladder's current rung, then
an add entry publishing the freshly minted client. Only then is the user
key unwrapped from the credential's standing wrap. Between the two entries
the required `onCommitted` seam writes the PENDING-shape client-key record
(seeds, controller, `pointerDid`, the `pending` group, no user key), so the
pivot never publishes a client only a live tab could re-derive; completion
writes the enrolled shape before the epoch pin (a rejecting pin write is
logged, not a login failure). A later login routes a pending record (the
discriminator is user-key absence; `pointerDid` is the resume's account
cross-check, not a routing member) to the
resume (`src/session/pendingEnrollment.ts`), decided from the verified log
history: a VM-listed record completes; a never-published one re-runs
seeded with the recorded key set (a log behind the recorded head refuses,
`BuiltOnHeadNotReachedError`); a published-then-removed one wipes (a
revoked client is never re-published); an unresumable record is discarded
and the browser routes record-less. The pending arm is fail-closed;
transport failures keep the record. On a ladder-anchored account the add
entry removes the ladder
VM, so a still-unexpired bridge delegation (and `delegatedClients` sibling)
it signed stops verifying; the same login's refresh block catches that --
its predicate covers signer rot beside expiry (`delegationKeyInDocument`,
against the memoized verified account document) -- re-signs both members
with the enrolled client's account key, and reseals the record. A durable
login also self-heals a rotted embedded generation delegation the same way
(`ensureGenerationDelegationCurrent` with the account-document axis, signed
by the login credential's ladder seed carried in-memory on
`profile.ladderSeed`). Detection replaces the old enrollment gate (see
Loudness in the Glossary). The document carries a passphrase-derived
`keyAgreement` key only as a hash commitment (`MultikeyCommitment`, which
the roster's recipient resolver verifies the roster-carried key against);
a passkey's PRF-derived key, being high-entropy, publishes verbatim (the
hash-commitment rule under "Recovery codes"). The connect-another-wallet
ceremony (see "The client enrollment ceremony" below) survives for records
without standing authority (a no-WAS bind) and for the rendezvous
onboarding flow, and as the future opt-in step-up approval policy; the
storage-partitioned CHAPI popup
never self-enrolls (a durable client per popup visit would litter the log)
and stays a degraded state.

The unlock record is **signed** by the unlock identity's own Ed25519 key,
and its proof is verified before the record is decrypted. That closes host
forgery: the record's JWE is sealed to the unlock KAK, whose public half
is derivable from the unlock did:key the server stores as the unlock
Space's controller, so a malicious host could otherwise seal a record of
its own that decrypts perfectly. The signing key derives from the typed
secret, so it never reaches the host, and a client that has only ever
typed the secret already holds the verification prior -- no bootstrap
window. A record whose proof does not verify is refused
(`KeyringRecordForgedError`). A standing record's account core
(controller, pointer, ladder seed) is additionally authenticated by a MAC
under a credential-derived key the host never holds (the recovery
record's construction), verified before the pointer is trusted; that
closes the redirect a re-mint-signed record would otherwise reopen (a
cascade re-mint signs with an enrolled client's account key, settled
against the account document at login). The unlock Space's request paths
(the record fetch and rewrite, and the management delegation's
`invocationTarget`) are built by was-client's paths helpers on both the
delegation and invocation side, so the bytes the server's `allowedTarget`
check compares cannot drift -- load-bearing on a sub-path deployment, and
doubly so since the record carries the recovery bridge (a broken target
would break login itself).

A signature cannot catch a REPLAY: a record the account has since moved off
stays authentic forever. So each client keeps a **freshness pin** (plaintext
local state, per unlock credential): the newest signed `createdAt` it has
accepted. A record older than the pin is refused as a rollback
(`KeyringRecordRolledBackError`); an equal or newer one is accepted and
advances the pin, which only moves forward (a transactional forward-only
compare-and-set). The stamps are wall-clock, made safe against
clock skew by advance-past stamping: every write site stamps `max(now,
fetched record's createdAt + 1ms, local pin + 1ms)`, so a rebind after a
fast-clock client's bind cannot wedge other clients into the rollback
refusal. Nothing compares pointers: a validly signed, non-stale
record naming an account this client has never seen is followed wherever it
points -- a rebind, a host migration, and a fresh account bound under a
reused passphrase are all legitimate, and all produce a newer signed record.

The bound on the whole construction: server-held material the unlock
credential alone decrypts (the record, and the credential's standing wrap
of the user key in the roster) is only as strong as that credential's
entropy. Against a malicious storage host running an offline KDF grind,
zcap scoping, TTLs, and revocation are worth nothing, so the unlock
credential's custodian must not be the storage host, and a wallet's
security is limited by its weakest standing unlock method. Logging in
from a public terminal is a core supported case (nothing need persist
locally to reach the account), which is why the record must stay
server-held and self-authenticating. Client revocation does not bound an
attacker who holds the credential itself (they re-derive and self-enroll
again); credential rotation is that remedy.

**The unlock-credential rotation ceremony** is that remedy: changing a
passphrase and removing a passkey both retire the old credential's standing
rather than merely rebinding the unlock record. The shared sequence is
wallet-core's `retireUnlockCredential` (`@interop/wallet-core/unlock`),
wrapped session-side by `rotateOffUnlockCredential`
(`src/session/credentialRotation.ts`). The credential's document inventory
leaves first, in one log entry: its `keyAgreement` entry (commitment or
verbatim) and its ladder's whole standing inventory, resolved from the log
itself rather than from the registry's recorded bind-time rung. With the
credential's ladder seed in hand (held by the passphrase change and the
tap-confirmed passkey removal), the entry also strikes the seed's ladder VM
when one stands -- the residue of a last-client forget torn after its
install entry. Then the credential's annex inventory (wallet-core's
`retireClientAnnexInventory` closure, between the document edit and the
roster tail): a strike entry on the annex log drops the retired credential's
revealed rung and standing hash when a distinct surviving credential's
committed rung can sign it; otherwise (a self-strike, or no committed
survivor) the whole generation swaps onto a surviving credential's ladder
(`swapClientAnnexGeneration`), the old generation left to orphan discovery.
A passphrase change signs with the NEW credential's ladder seed
(`survivingLadderSeed`). Which ladder the session's own login seed may fill
is settled against the pre-edit log by the retired entry's recorded update
key, not by seed comparison (vacuous with no retired seed in hand): the
login seed is the retired ladder when that key is one of its rungs up to
the attributed one, a survivor only when it provably is not, else neither
-- so a swap can never anchor the fresh generation on the credential being
removed. The stage is best-effort, reported on the outcome's `clientAnnex`
member. Then the same
roster-and-cascade tail the client revocation runs: the user key rotates off
the credential's wrap (pairing-free convergence onto the post-edit document)
and every encrypted collection re-epochs onto the fresh key. Inside that
tail's `onUserKeyAdopted` step the unlock-methods registry is re-sealed to
the rotated key in band, before the rotated key persists into the client-key
record (`adoptRotatedUserKeyInBand` in `src/session/userKeyAdoption.ts`):
the re-seal needs this browser's durable copy of the OLD key, which
persisting the rotated one destroys on a single-client account, so a run
torn anywhere after this step still leaves a registry the surviving keys
open. The callers then tear down the registry entry and the old unlock
Space, now under the ROTATED vault keys, and adopt the rotated key into the
live session's storage ciphers (`adoptRotatedUserKey`, which returns on its
id guard once the tail has re-sealed and swapped, and retries the re-seal in
the one case the tail leaves open -- a failed re-seal, where the session
stays on the pre-rotation keys rather than meeting a stale seal on its own
teardown writes) -- the `revokeRecoveryCode` ordering. The
document-removal-first order is load-bearing: a run torn after it leaves the
roster keying a recipient the document no longer backs, exactly what the
login-time sweep detects and finishes. The limitation is the cascade's:
ciphertext the credential's holder already fetched stays readable, and
Settings says so -- the ceremony is the documented "I think my passphrase
leaked" remedy there.

A passphrase change runs establish-first on a WAS account: the old
passphrase is verified read-only, the NEW passphrase's whole standing
establishment runs as the ceremony's first write, and only then are the
old record and unlock Space torn down and the old credential's retirement
run. A failed establishment fails the change outright with the old
credential fully intact -- record, Space, and standing configuration all
unchanged -- so the failure copy is true and a retry with the same new
passphrase converges on the establishment's idempotent stages. No plain
record is ever written for the new passphrase; the plain rebind survives
only where nothing can be standing (no WAS, a guest, an unpromoted
account). A change torn between the establishment and the teardown leaves
BOTH passphrases live and standing, retired by a retry or by the next
new-passphrase login's torn-retirement repair below.

The registry's passphrase entry is written only after the retirement has
reported, because the entry's standing configuration depends on how the
retirement ended. One that failed before its document edit landed leaves
the entry naming the new unlock Space but the OLD credential's whole
standing configuration -- the one state that still names the credential
left standing. While the entry stands pending, a second change from the same
session is refused (`PendingPassphraseRetirementError`, when the entry
records a credential the typed old passphrase does not derive): the
retirement would otherwise remove one credential's document inventory while
striking the other's ladder. Registry writes matched by unlock Space id
carry the acting credential's key-agreement multibase for the same reason,
and a mismatch writes nothing.

A BARE entry -- one carrying no identity members at all -- gets its own
outcome. A bare entry normally means the credential has no document
inventory to retire, so the change would report clean. When the typed old
credential is still standing in the document (or the document could not be
checked), that would be a silent failure on the leaked-credential remedy,
so the change reports `rotation: 'unretired'` instead. The entry is written
in the shape a retirement torn at the document edit leaves (the new unlock
Space naming the OLD credential's members, minting the registry first if
none existed); the establish-first order means this arm's entry always
names a standing new credential.

The next passphrase login's torn-retirement repair
(`repairTornPassphraseRetirement` in `src/session/pendingRetirement.ts`)
clears it: an entry naming a credential other than the one logging in, with
the login credential itself standing in the account document. It retires
the named credential and records its own standing configuration in the
entry. The login-credential check keeps it from firing in the other
direction, where an old passphrase whose unlock Space delete failed logs in
after a change that completed elsewhere. When the named credential is
already out of the document (the retirement landed and only the registry
write was lost) only the entry is rewritten; the roster and cascade residue
is the ordinary login sweep's.

The same repair also mends a BARE (or absent) passphrase entry, but only
when it names no credential at all, or names the login credential itself
with no recorded update key: in both cases nothing else is put at risk, so
the entry is rebuilt from the login credential's keyring hit. An entry
naming ANOTHER credential with no recorded update key is left alone: the
repair has no rung to attribute that credential's ladder by, and rebuilding
it could un-name a credential still standing. This is also the whole
migration for accounts an earlier shipped defect damaged this way; there is
no separate migration code.

A passkey login runs the sibling repair, `rebuildBarePasskeyEntry`, on its
own entry: a present-but-bare entry, matched by unlock Space, is rebuilt
from the keyring hit once the account document publishes that passkey's
`keyAgreement` key verbatim. An entry that was never written is left alone;
rebuilding it needs the WebAuthn credential id a login does not carry, so
that case stays the add-a-passkey ceremony's own registry write to make.

A registry left sealed to a superseded user key (a rotation whose in-band
re-seal was itself torn, or one run by a client from before that duty
existed) gets its own login-time repair (`repairStaleUnlockRegistrySeal` in
`src/session/registryReseal.ts`): a served record that fails to decrypt
under the current vault keys throws `UnlockRegistryStaleSealError` rather
than reading as absent, and the repair tries each prior user key generation
the roster still escrows, newest first, until one opens the record, then
re-seals it to the current key. Best-effort, and read-only when nothing is
stale. Settings shows the state with its own copy rather than the generic
load error while it stands.

At login, the user key sweep, the re-seal repair, the torn-retirement
repair, the bare-passkey rebuild, the registry backfill, the
standing-delegation self-refresh, the ladder-rung refresh, the did:webvh
pointer heal, and the generation-delegation self-heal all run on one ordered
promise chain (the annex GC sweep forks off its tail). The re-seal repair
runs first among the registry passes: every registry writer downstream
reads the record, and a stale seal would make each of them warn and skip on
a registry this same login can mend. The sweep is early in the chain because
its roster convergence may rotate the key and re-seal the registry; a
registry read-modify-write racing that re-seal would rewrite the record
under the pre-rotation keys and undo it within one login.

Navigation to the dashboard waits only on storage provisioning
(`session.storageReady`); the chain above runs after navigation, on a
separate `session.registryReady` promise that never rejects -- a failed
stage is logged and skipped rather than surfaced to the login page. A
Settings-entered ceremony that writes the unlock-methods registry
(passphrase change, passphrase or passkey add, rename, or remove, account
deletion, client disconnect, the forget ceremony, recovery-code issuance
and revocation) awaits `session.registryReady` at its own entry rather
than racing the chain's writes; so does update-key rotation, which writes
the same client-key record the sweep's adoption stage writes, and so do
the Settings registry load and the recovery-codes health check. When
storage provisioning itself fails the session is abandoned by the login
page and the chain never runs, but `registryReady` still settles. Every
registry PUT is also a compare-and-swap on the ETag of the fresh read it
was based on, with a bounded re-read retry on a lost race, so a concurrent
writer the ordered chain cannot serialize (another tab, another client)
conflicts and re-applies on the fresh record instead of silently
reverting it, and a stale tab's write cannot downgrade a rotation's
re-seal. The guard covers honest concurrency only; the registry's bound is
unchanged against a tampering host.

The `Session` object is stored in the Zustand `authStore`; it is
**in-memory only** (the passphrase is never persisted), so reloading the
browser logs the user out. Guest sessions use a random 32-byte seed directly
and never touch the WAS server or the KMS.

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
(`@interop/wallet-core/webvh`). Its document is the enrolled-client
roster: each enrolled wallet client contributes its Ed25519 verification
method (published under `authentication`, `assertionMethod`,
`capabilityInvocation`, AND `capabilityDelegation`) and its X25519 twin
under `keyAgreement`; ids are `<did:webvh>#<multibase>`. The signing
method carries `controller: <did:webvh>`; the key-agreement method carries
`controller: did:key:<the client's signing multibase>`, a marker saying
which client the key belongs to. Every reader (the client listing, the
revocation removal, the roster's recipient resolver) pairs a client with
its key-agreement key by that marker; nothing re-derives a twin to find
it. One KMS-held VM (`authentication`) remains as a server-side
convenience. The KMS-held `keyAgreement` VM is NOT in the document: that
relation is the source of record for user-key wrap recipients, and no
server-held key may ever be a wrap target. No KMS assertion key is minted:
the App Connect Resource Log Profile authorizes log appends by
`assertionMethod` membership, so that relation lists client signing keys
only.

**Update keys are client-held.** `updateKeys` carries one update key per
enrolled client (apps never), derived from 32-byte seeds that live in the
wrapped client-key record beside the client seed and the user key. The
server therefore cannot extend the log, making it the one self-certifying
artifact the server hosts. Prerotation stays on with a **carry-over
commitment convention**: `nextKeyHashes` commits each client's staged key
AND each active key's own hash, because the resolver re-checks every
entry's re-stated `updateKeys` against the previous entry's commitments;
without the active-key hashes no non-rotating entry (an enrollment commit,
a document edit) could resolve. Rotation is per-client self-rotation
(`rotateWebvhUpdateKey`: persist the rolled seeds into the client-key
record BEFORE the log entry publishes, then finalize), swapping only the
rotating client's own key. `keys.json`'s webvh block is `{ did }` only; key
roles do not live server-side.

**Conditional publish.** Every ceremony publishes `did.jsonl` as a
compare-and-swap on the ETag of the read its entry was built on, so
concurrent clients never silently erase each other's entries; a lost race
surfaces as wallet-core's typed `WebvhLogConflictError` and the ceremony
re-runs on the new head (`withLogConflictRetry`). The shared
`wasWebvhIdStore` carries the ETag and preconditions for every
enrolled-client ceremony; the recovery continuation's delegated store
(`delegatedLogStore` in `src/session/recovery.ts`) does the same over its
public log fetch and delegated PUT. The `did.json` projection PUT stays
unconditional: it runs only behind a won log CAS, and the log is the
source of truth.

**The account-log chain-head pin.** Resolving the world-readable log is
one-shot verification: a valid PREFIX of the real log carries the same
genesis, so the same SCID and DID, and a ceremony built on it would
republish erased enrollments and undone revocations. So every
`verifyAccountLog` read carries a durable chain-head pin
(`sessionLogPinStore` in the session database, shared with the roster
log): a served log that is a rollback, a fork, or an SCID/method switch
against the pinned head is refused (`@interop/vh-resource-log`'s
`ResourceLogContinuityError`). The pin is established at first contact
(trust-on-first-use), advanced only by a log verifying past it, never
regressed. It rides the verified-log memo (`src/session/verifiedLog.ts`),
the bare-parts roster store's controller resolution, the recovery flows'
direct reads, and the enrollment completion's first contact; the login
page renders the refusal (`auth.errors.accountLogContinuity`). A
`rollback` may be nothing worse than replication lag: nothing rolled back
is adopted, and a caller with a cached document view may carry on with it.
Ceremony-path `did.jsonl` reads additionally check the resolved DID
against the account pointer (`expectedDid` on the revocation cascade and
the recovery ceremonies). This repo's own two log-publishing ceremonies,
`ensureDidWebvh` (login-time provisioning) and `rotateWebvhUpdateKey` (the
settings-page update-key rotation), read the log under the same pin store
and the account's DID, so a truncated or substituted log is refused
before an entry is built on it. Provisioning stays non-fatal (a hiccup
must not fail login), but a non-`rollback` continuity refusal is logged as
an error; later account-log reads in the same login hit the same pin and
surface it to the user.

**The pin inventory.** The session database holds four durable continuity
priors, in three shapes. The two chain-head pins (the account log's and
the roster log's) live in ONE keyed store (`sessionLogPinStore` in
`src/lib/sessionKey.ts`, implementing `@interop/vh-resource-log`'s keyed
`ResourceLogPinStore`): `read` and `write` take a per-log slot key
wallet-core derives (`accountLogPinId` / `userKeyRosterPinId`, both
`space/<spaceId>/<collection>/<resource>` under the hood), so one store
serves every log and two logs can never clobber each other's pin. The slot
key is host-free: a log served from a claimed new host lands in the same
slot and is checked against the pin already held. A mirror under a freshly
minted Space id gets a fresh slot, but the did:webvh id embeds the Space
id, so the mirror resolves to a DIFFERENT DID than the account pointer
names and every ceremony-path read refuses it (`expectedDid`, and
`verifyAccountLog`'s own resolved-DID check). The roster-epoch pin is keyed
by the account DID (it guards a chainless value, and the DID is the one
identity a substituted pointer cannot change); the keyring-freshness pin by
the unlock Space. Because the chain-head slot is Space-keyed, the genesis
ceremony's log read runs under the same slot from first contact, and the
published DID persists locally keyed by the data Space id so a later
pre-promotion heal login can state an `expectedDid` before the pointer has
caught up. Account deletion clears all of it through the shared wipe
enumeration (below) beside the keyring retirement. Before the account
Space dies, deletion also walks the unlock-methods registry and deletes
each entry's unlock Space and local trio best-effort
(`deleteUnlockMethodArtifacts` in `src/session/unlockMethods.ts`, removing
the dangling existence-oracle Spaces a probe could still find), then
deletes the auxiliary annex Space in one `space.delete()`. Both run BEFORE
the fatal wipe, because resolving the auxiliary Space's controller reads
the account log out of the account Space; a wipe failure after them leaves
other methods' logins already destroyed, accepted since the intent was
deletion.

**The shared wipe enumeration** (`src/session/wipe.ts`) is the one list of
durable local state an account leaves on a browser and the one executor
that deletes it, consumed by the deletion-shaped ceremonies (account
deletion, the guest wipe, the forget ceremony; the orphan-client heal is
designed onto the same seam). It is snapshot-first: every target derives
from the live session before anything is deleted. The client-keyed families
(the unlock-methods cache, the passkey-safety notice, the replica-database
prefix, the local-mode cache scope) derive from this browser's own client
did:key, not the account controller. Each unlock method's local trio
derives from the registry walked across every method, always including the
session's own login credential (`profile.unlockMethod` and the standing
members' unlock Space id), so a registry read lost to a transient server
error narrows the trio enumeration to the other methods only and is
reported on the wipe outcome (`unlock-methods-registry`) rather than
leaving this browser's client-key record behind a wipe that reads clean.
The epoch pin derives from the account DID; the chain-head pin slots by
Space-scoped prefix, which also clears every annex generation's slot
without needing the generation ids; then the Space-to-DID mapping and the
per-account localStorage families (the descriptor and meta caches under
both scope schemes, the migration markers). Cross-tab teardown precedes the
replica delete (a broadcast asks sibling tabs to drop open handles), and
completion is verified by re-probing rather than resolved while blocked.
Global UI prefs stay out; the global `writerId` clears only on the forget
grade. Limits no enumeration reaches: deleted IndexedDB data stays
forensically recoverable (plaintext `public-credentials` rows included),
the CHAPI popup's partitioned third-party buckets are unreachable from any
top-level wipe, and the mediator-origin (authn.io) handler-registration bit
records that a wallet was used on the terminal; only clearing the browser
profile removes those. `indexedDB.databases()` is a discovery and
verification aid, not the deletion gate: the session and replica databases
go by known name whether or not the engine can enumerate, and a deletion
the executor could not confirm, or a replica prefix `databases()` alone
would have named, is reported on the outcome's `unverified` list rather
than folded into a clean wipe.

**The forget affordance** (`src/session/forget.ts`) removes this browser
from an account, in two grades split by whether the unlock credential is in
hand. From a live durable session (Settings > Connected wallets, the
current client's row) it is the **forget ceremony**, wallet-core's
`forgetDurableClient`: the user key rotates off this client's roster wrap
and every encrypted collection re-epochs, both under this client's
still-standing authority (the self-forget inversion of the revocation's
document-edit-first order, forced by the entry-proof and current-key-set
rules; wallet-core decision 0008); then ONE atomic ladder-signed removal
entry through the login credential's bridge takes the client's whole
document inventory out; only then does the local wipe run
(`clearWriter: true`, the wipe's one writerId consumer). Wipe-last is the
tear story: a run torn before the entry reads as "not forgotten" and a
re-click resumes; the removal-published-but-wipe-torn direction is caught
at the next login by the **forgotten-browser detector**
(`assertClientStillEnrolled`): an enrolled client-key record (its user
key present) still
present while the cleanly verified account document no longer lists this
client's verification method finishes the wipe from what the keyring hit
alone derives and surfaces "this browser's access was removed", never raw
authorization errors; nothing about the detection is persisted. The detector
is reached only past a record-to-account cross-check, pointer-based like
the resume's: an enrolled-shape record whose stamped `pointerDid` names a
DIFFERENT account than the unlock record points at is stale residue, not a
forgotten browser -- a prior account under a reused passphrase whose
account is gone server-side, so no wipe ever touched this browser. The
stale wipe clears what the record alone derives (the dead account's
replica, caches, and pins, and the credential's whole local trio, the
record included) and the login re-routes once as a record-less browser, so
it never reaches the detector at all. A
pending-shape record is spared for the resume instead (`decisions/0007`),
whose published-then-removed branch hands the removal case back to the same
wipe. The ceremony needs the standing members the login stamped on the profile
(`profile.standingUnlock` beside `profile.ladderSeed`), re-seals the
unlock-methods registry to the rotated user key while this client still
invokes (its surviving readers would otherwise find it sealed to a retired
generation), writes no re-mint stages (a replacement signed by a key that
dies at the removal entry would rot moments later; the standing self-heals
cover it), and refuses the account's last durable client with
wallet-core's name-stable `LastDurableClientForgetError`.

That refusal routes to the **last-client transition** (the same
`forgetThisBrowser` entry with `lastClient: true`, chosen from the listing
and confirmed against transition-stating copy; a stale listing's refusal
flips the dialog to that copy for a second confirm): wallet-core's
`forgetLastDurableClient`, the two-entry ceremony that lands the account
client-less and ladder-anchored, the state a credential-anchored signup and
a transient recovery produce (wallet-core decision 0004's 2026-08-21
amendment). The ladder VM's install entry goes first, while the client's
inventory stays (the both-present transitional state); then: the roster
rotation off this client's wrap, ladder-signed and anchored at the install
entry (the ceremony-tail license's inventory-changing version) but
HTTP-invoked under the still-standing client -- the roster store is built
with the ladder VM's signer over the ceremony-supplied post-install log
(`ladderSignedRosterStoreFor`), so the roster head stays signed by a key
the post-removal document lists and needs no seal repair on an account
with no login sweep ever again; the collection fan-out; the forced
replacement of the embedded generation delegation with a fresh
ladder-signed one, and the revocation, through this client's `WasClient`,
of every still-unexpired ladder-signed delegation the annex history
embedded; the OTHER unlock methods' records (the standing passphrase and
passkey credentials, the recovery codes) through the ceremony's
`unlockMethods` reach (`unlockMethodsRemintReach`) -- the cascade's
re-mint pass (`remintEntriesOf`, shared with the cascade) walks every
registry entry but the login credential's, signs each bridge and sibling
with the ladder VM, re-seals each record through its management zcap
(invoked under this still-standing client), and writes the refreshed
fields back; then the login credential's own record
(`rebindLoginCredentialRecord`, the ceremony's required `onBeforeRemoval`
seam, the one stage that reaches it): its bridge delegation and
`delegatedClients` sibling are re-signed by the ladder VM and the record
re-sealed through the keyring hit's re-bind closure (stamped on
`profile.standingUnlock` at login beside the credential's unlock Space
id), with the registry pair refreshed in this client's last window of
registry authority. All of this precedes the removal entry because the
removed client's signatures rot there, and on a client-less account no
durable login's refresh block will ever heal them. The removal entry lands
last, then the local wipe.

The transition's refusals. A record the re-mint pass cannot re-seal, or an
entry it skips as pending-shaped (whose bridge the removal would rot just
as surely), withholds the removal entry with wallet-core's name-stable
`RecordRemintFailedError`, rendered by the settings dialog as a retryable
stop naming the methods: the browser stays connected and a re-click resumes
at the re-mint. A registry the transition cannot read refuses up front for
the same reason, as does a session whose hit carried no re-bind closure. A
pending-shaped passphrase entry (its recorded unlock key-agreement key is
not the credential the record at its unlock Space is sealed to, the residue
of a passphrase change torn before its retirement landed) refuses up front
too (`PendingRetirementForgetError`; the record itself is the detector,
since an entry naming another credential is also what a superseded
passphrase's own login sees on a healthy account): that state's only mender
is the torn-retirement repair, which needs a durable enrolled login, and
the transition ends durable logins forever. So does a registry that does
not name every standing credential the account document publishes
(`UnrecordedCredentialForgetError`): each document `keyAgreement` entry
carrying no enrolled-client controller marker is compared against the
registry entries' recorded key-agreement multibase, in both published
forms (the verbatim id a passkey or recovery code publishes, the
commitment id a passphrase publishes). Every walk is registry-driven, so
an unnamed credential would keep a bridge delegation the removal entry
rots with no replacement. Readers settle a re-minted record's proof
against `currentAccountRecordSigners` (the enrolled clients' signing keys
plus the ladder VMs the document lists), since on a client-less account
the ladder VM is the only record signer left.

From the login page's authenticity and continuity refusals (reachable from
passkey failures with no typed passphrase, reset between attempts) it is
the **no-unlock-material grade**: nothing can be derived or signed, so no
ceremony runs and the wipe is whole-database and browser-scoped ("forget
all wallet data on this browser": every replica database, the session
database, the per-account localStorage families), with the cross-account
blast radius stated in the confirm copy. Each account's standing document
client remains, unflagged anywhere, with the copy pointing at the Connected
wallets disconnect from a logged-in client; a never-remembered browser is
told it holds nothing to delete.

**Controller promotion by ordering.** The Space id is an independent random
identifier minted at signup (`mintSpaceId`) and carried in the account
pointer, not a hash of any controller: the did:webvh id embeds the Space id
and a derivation would be circular (unlock Spaces keep their
`hash(unlock did:key)` addressing, discovery rather than identity). That
deterministic unlock address is an accepted existence oracle for passphrase
guessing (derive a candidate address, probe the server); the bound is KDF
strength, not placement. The DID's embedded Space id need not equal a
controlled Space's id: one did:webvh may control several Spaces on the
host, a feature rather than a check to add. Every WAS signup now bootstraps
the Space under the ladder VM's bare did:key inside the credential-anchored
establishment (see "The credential-anchored variant" below), publishes the
log, and PUTs the Space Description with `controller: <did:webvh>` as one of
the establishment's own stages, before any durable client ever exists.
`StorageManager.ensurePromotedController` remains the login-time healer: it
swaps the live session's signing to the promoted keyId and re-runs the
promotion PUT when a session finds it still missing. Only a no-WAS
deployment's plain durable genesis still promotes on this login-time path
from scratch. From then on the server
resolves the controller by reading and fully verifying the log out of its
own storage (SCID-pinned, hash chain, prerotation, update-key signatures)
and authorizes by the **current-key-set rule** (see Glossary).

## Account genesis (`@interop/wallet-core/genesis`)

Shared with the mobile wallet: `mintAccountKeySet` mints the whole key set
locally (Space id, client seed, user key, did:webvh update-key seeds), and
`ensureAccountGenesis` runs the ordered ceremony -- Space provisioning under
this client's did:key, the did:web key map, the did:webvh genesis, the user
key roster (strictly after the DID publication), and key epoch[0] on every
encrypted collection. Every stage detects its own completion from durable
state; a torn run heals by re-running at the next login.

`StorageManager.#provisionUserCollections` is the one caller: it supplies the
did:web provisioning as the ceremony's `provideDidWebKeys` closure and the
roster store builder as `rosterStoreFor`, adopts the published DID in
`onDidPublished` (which also drops the verified-log memo), and maps the
ceremony's per-stage failures onto warns. A session with no did:webvh (the
flag off, no keystore agent, or no client update keys / user key) keeps the
reduced path: Space provisioning, key epochs, did:web. A Space that never came
up is the one fatal stage: `AccountGenesisSpaceError` is rethrown and login
fails.

What stays in freewallet's own flow: the keyring bind before any data Space
exists. On a WAS deployment this path is now the no-WAS deployment's own
plain durable signup and the login-time heal for any account this ceremony
provisioned; every WAS signup instead runs the credential-anchored
establishment below, whose genesis order already promotes the controller
inline. `ensureAccountGenesis` is called with `promoteController: false`
and `ensurePromotedController` promotes and heals on that reduced path. The
durable passphrase signup's own `userExists` probe and its pointer-backfill
step are gone: the credential-anchored establishment's create-nothing probe
(`fetchTransientKeyring`) is the one signup-time existence check left on a
WAS deployment.

**The credential-anchored variant.** Every WAS signup -- passphrase or
passkey, remembered or not -- now runs this establishment first, through
`establishCredentialAnchoredAccount` in
`src/session/credentialAnchoredGenesis.ts` (wallet-core's
`ensureCredentialAnchoredAccountGenesis`): no durable client is minted by
the establishment itself. A non-remembered browser then enters through the
ordinary transient composition below. A `rememberBrowser: true` signup (the
signup form's remember choice, or the e2e seam) instead follows the
establishment with the ordinary durable login, whose self-enrollment makes
this browser a durable client from the record the establishment just wrote
-- two loud log entries on top of the establishment's own. The durable
login's chain-head pin store is seeded by the establishment's own
publication rather than trust-on-first-use, and the credential-anchored
bind floors its record stamp over the caller's local keyring-freshness pin
so a stale pin cannot make the login refuse its own signup's record as a
rollback. A signup torn before the durable login's self-enrollment is
resumed by a later `rememberBrowser: true` login attempt, which re-runs the
establishment from the record's own ladder seed and then self-enrolls; see
"The transient login" below for the same heal's non-remembered entry. The
Space is bootstrapped under the LADDER VM's bare did:key
(`ladderVmAgent`, re-derivable from the unlock record's ladder seed, so a
tab death before promotion strands nothing). The one-entry ladder-anchored
did:webvh genesis is signed by ladder rung 0 (`updateKeys` = [rung 0],
`nextKeyHashes` = [hash(rung 0), hash(rung 1)], `portable` unchanged) with
the ladder VM and the credential's `keyAgreement` commitment folded in. The
roster's epoch[0] wraps the user key to the credential's standing KAK with a
ladder-signed entry proof (the ceremony-tail license's first-entry shape).
The collection epochs gate on the roster landing AND on its current epoch
being the key the ceremony was handed (the user key exists only in tab
memory): a re-run that adopts an earlier run's roster skips the stage
(`epochsSkipped`) and the heal branch installs the missing epochs under the
roster's real key. When `KMS_SERVER_URL` is set, the establishment also
runs a KMS stage: the keystore is created under the ladder VM's bare
did:key before the genesis, the did:web keys are minted and
`keys.json`/`did.json` published under that same identity, the genesis
entry carries the KMS `authentication` VM, and the keystore controller is
promoted to the did:webvh in the establishment's existing promotion stage,
mirroring the Space's. The stage is best-effort with a timeout: a failed
or hung KMS leaves the account keystore-less, Settings shows the state,
and a later keystore-creation pass heals it. The ordering rule is the
transposed persist-before-publish
invariant: the unlock record carrying the ladder seed (with an interim
bridge delegated by the ladder's bare did:key) is durably written BEFORE
the Space is created and before rung 0 publishes. After the genesis, the
establishment
mints the client annex generation under the same bootstrap identity, embeds
the ladder-VM-signed generation delegation, flips the auxiliary Space's
controller, appends the `#DelegatedClients` pointer as a second rung-0-signed
account-log entry, re-binds the record (full pointer, ladder-VM-signed bridge
and sibling, management zcap to the account DID), writes the unlock-methods
registry in the last root-invocation window (read-first: the entry is upserted
into an existing registry, and a refused read skips the write rather than
starting from an empty one, since the heal re-run fires the same hook), and
promotes the Space controller last. The visit then enters through the ordinary
transient composition, with zero local residue. The whole establishment is an
ensure: a torn signup converges by re-running, the published log adopted by
ladder attribution (`createDID` timestamps the genesis entry, so a naive
re-create would mint a different SCID and never land). This establishment
now runs for every WAS signup; only a no-WAS deployment keeps the plain
durable flow above (`ensureAccountGenesis` under `promoteController:
false`). A `rememberBrowser: true` entry (the e2e seam today, the signup
form's remember choice when it lands) continues past this establishment
into the durable login's self-enrollment, described above. The passkey
signup follows the identical fold under the WebAuthn PRF-derived
credential -- WebAuthn `create` runs first, then this establishment, then
the durable passkey login; registering a passkey is itself a durable
ceremony, so the passkey flow was already durable outright, and it too
begins here now.

## Session persistence

Sessions are **in-memory only**. A fresh login builds the whole `Session` --
the root `keyAgent` (from this client's stored seed), the user-key-backed
vault KAK, and the `zcapClient` that signs every WAS request with the root
key. Nothing about the live session is written to disk unwrapped (the client
seed and user key persist only inside the wrapped client-key record), so a
reload drops the session. The vault is always unlocked while a session exists
and gone once it ends; there is no "locked vault" state. Navigation to the
dashboard is gated on storage provisioning alone (`session.storageReady`); the
login-time registry passes run afterward on `session.registryReady` (see
"Session & auth flow").

**The durability seam** (`src/session/persistence.ts`): what a session may
write to LOCAL durable storage is decided once, at login, by the typed
`SessionPersistence` handle carried at `profile.persistence`. Durability is a
property of the handle's type; a write site consults no flag and takes no
branch (freewallet `decisions/0001-no-memory-overlay-storage-fork.md`). The
families riding the handle: the keyed chain-head pin store (the account log's
and the roster log's), the roster-epoch pin, the unlock-methods registry
cache, the passkey-safety notice, the descriptor/meta cache pair (one instance
per scope per session), and the `writerId` mint. The durable variant is the
`freewallet-session` database (it alone carries the `idb` factory, so code
needing that database must hold the durable variant), the localStorage caches,
and the durable `writerId`. The transient variant -- a public-terminal visit
-- is in-memory throughout and dies with the tab: it has no member reaching
the session database, and the login that carries it skips storage
provisioning, the login-time sweeps, and the bare-Space-URL `userExists`
probe. The transient variant also carries the visit's client-annex
identity -- the annex DID every WAS request signs under and the
generation delegation every request rides -- as a required member of its
handle type (`TransientSessionPersistence`), built from the pre-session
in-memory store family (`TransientSessionStores`, from
`transientSessionStores()`) plus that identity
(`transientSessionPersistence({ stores, clientAnnex })`). Session assembly
reads both off the handle rather than a separate option, so durability and
the annex signing that comes with it are declared exactly once; they still
surface to the storage layer as `profile.invocationCapability`. Global UI
prefs (theme, language) are not session state and ride a
sibling seam (`src/lib/prefsStorage.ts`): during a transient session, pref
writes land in an in-memory overlay that shadows reads, which still fall
through to localStorage.

The logging seam is a third arrangement, module-global rather than
session-scoped: `src/lib/log.ts` wires `@interop/logger`'s namespaced loggers
at bootstrap and rides neither the durability handle nor the prefs overlay.
Its one localStorage touch, guarded by the package, is a single lazy read of
the `interop:logger` debug filter key at the first debug-level dispatch.
Nothing in the seam writes durable state, so a transient session stays
residue-free.

**Replica-less, capability-bound storage.** A transient session constructs no
`BrowserStore` at all (the versioned RxDB open alone durably creates the
per-user database), so `StorageManager.initStorageClients` builds it only for
a durable session, and a replica-less session serves every synced-collection
operation through the remote-direct backend (the CHAPI popup's, over the
remote WAS collections). The sync controller never starts for a session with
no local replica (`StorageManager.hasLocalReplica` is its gate). The remote
stack also takes a delegated authority: `WASRemoteStore` accepts an optional
invocation capability (threaded from `profile.invocationCapability`) that
every request rides -- the navigational handles through one private
Space-handle helper, the raw request sites directly -- and wallet-core's
`userKeyRosterDescriptorStore` takes the same option, so a session holding
only a delegated Space-subtree zcap (the generation delegation) can use the
store and read the roster. Absent the option, every request invokes the root
capability.

**The transient login (the default on a non-remembered browser).** Both
keyring login entry points run a post-KDF durability decision
(`routeUnlockLogin` in `src/session/transientLogin.ts`): with a WAS server
configured, a browser holding this credential's client-key record proceeds
durable; one holding none defaults to the transient composition. A record
whose stamped `pointerDid` names a different account than the unlock
record points at is stale residue of a prior account under a reused
passphrase; its residue is wiped and the login re-routes once as if the
browser held none. The record
probe is create-nothing: `hasClientKeyRecord` checks `indexedDB.databases()`
before opening, and on an engine with no `databases()` falls back to a
versionless open whose `versionchange` transaction is aborted on
`oldVersion === 0`; the ratchet is silent for now. An explicit
`rememberBrowser` input forces either side: `true` is the programmatic
durable entry (the standing self-enrollment; a remembered signup's own
login half, its durable resume, and the recovery tail all pass it, and
e2e sets it through a non-production seam), and
`false` on a remembered browser refuses (`AlreadyRememberedError`) rather
than forking the durability decision. A PENDING-shape record counts as
remembered (the resume is its one mender); the resume's discard outcome
deletes it, so the next attempt probes record-less again. The composition
(`transientSessionFromKeyringHit`): the transient unlock-record
fetch (`fetchTransientKeyring`, no durable operation), the account log
verified under the visit's in-memory pins, a per-visit key minted in memory
and enrolled into the client annex generation through the record's
`delegatedClients` sibling delegation (wallet-core's
`enrollClientAnnexTransientClient` -- the loud entry before any authority,
with the GC-race re-read built in), the generation delegation taken as
embedded (its mint takes a durable signer), the user key unwrapped from the
credential's standing roster wrap (the read signs as `<clientAnnexDid>#<vm>`
under the delegation; no escrow, since a transient client never joins the
roster), and a session on the replica-less storage variant above. Transient
sessions skip the KMS keystore, the login-time roster read, provisioning, and
every login-time sweep. Every unavailable state -- a record without standing
authority or the sibling, an unpromoted account, no live generation or
embedded delegation, no roster -- refuses with a typed
`TransientLoginUnavailableError` before any ceremony byte is written (the
login page renders per-reason refusal copy, and no reason opens the
connect-this-browser card); network errors rethrow unchanged so a flap
stays distinguishable from a lapse.

Two of those refusals carry a heal first, for the tears a torn
credential-anchored signup can leave. A standing record whose pointer names
no did:webvh can only be a credential-anchored establishment that died
before its re-bind, so the composition re-runs
`establishCredentialAnchoredAccount` and re-enters through the refreshed
record; without the derived credential in hand (a test double), or when the
re-run does not converge, the `unpromoted-account` refusal stands. Every WAS
signup runs this same establishment now, so the heal also mends a
`rememberBrowser: true` signup torn before its durable login's
self-enrollment: the non-remembered entry above and a fresh
`rememberBrowser: true` login attempt both re-run the same establishment
from the record's own ladder seed. A promoted account whose roster read
comes back empty is the tear between genesis and epoch[0] (the user key
died with the signup tab), healed as the explicit carve-out from the
sweeps-skipped rule: a fresh user key is minted, epoch[0] lands with a
ladder-signed entry proof wrapped to the credential's standing KAK, and the
collection epochs complete, every write invoked as the annex VM under the
generation delegation (the `capability` option on `ensureWalletSpaceEpochs`
and the roster store). Nothing encrypted predates the heal, so the fresh
key orphans nothing. A roster read failing outright, rather than empty,
retries once behind a bootstrap-signed promotion completion -- the
one-request-wide tear between the record re-bind and the promotion.

The handle also carries the durability refusals. Update-key rotation requires
the durable variant outright (`DurableSessionRequiredError`): its subject is
this browser's durable update key, and its persist-before-publish invariant
needs a client-key record to persist into. The account-management ceremonies
(passphrase change, passphrase/passkey add and remove, client revocation,
enrollment approval, recovery-code issuance and revocation, account deletion,
Space export and import) refuse from a transient session with
`StepUpRequiredError`: they are reachable from a public terminal only inside
the step-up ceremony (a loudly enrolled in-memory client, bracketed by
ladder-signed enroll and retire entries), designed but not yet built. Contacts
are not reachable in a transient session either (the remote-direct backend
rejects them) until remote-direct contacts land.

## The user key wrap-set roster (`key-map/user-key.jsonl`)

The user key (formerly PUK) -- recipient zero of every encrypted collection --
has one remote home: a roster in the private, capability-gated `key-map`
collection (outside the synced collections; no local replica, no background
replication). Its state is a `CollectionEncryption` descriptor, and **the
roster's current key epoch IS the current user key**: the epoch id is the user
key's did:key, and the epoch secret (the user key's raw 32-byte key) is
wrapped once per enrolled wallet client, to that client's own identity
key-agreement key (`profile.clientKeyAgreementKey`, the X25519 twin of the
client's did:key). The roster is a delivery channel, not a source of
authority: each client keeps the user key in its own client-key record, and
the roster's epoch stamp marks a cached copy stale.

The roster is **log-governed**: it lives as the resource log
`key-map/user-key.jsonl`, with no point-state companion resource.
wallet-core's `userKeyRosterDescriptorStore` (`@interop/wallet-core/keys`)
exposes that log as an ordinary descriptor store -- reads resolve only to the
log's VERIFIED head (chain, entry proofs, and the durable chain-head pin all
checked first), writes are signed log appends -- so was-client's roster
machinery (`initRecipients` / `addRecipient` / `removeRecipient`, with their
compare-and-swap retry loops) drives the log without knowing it. The wiring is
two builders in `src/session/rosterStore.ts`: `accountRosterStore`, from the
bare parts (a signing client, a key agent, an account pointer naming a
did:webvh), for callers with no session profile (the login-time read and the
recovery continuation), and `sessionRosterStore` for a live session, which
resolves the controller view through the profile's verified-log memo so a
ceremony that just extended the account log anchors its appends at the
post-edit head. The chain-head pin is durable either way (`sessionLogPinStore`
in the session database, the keyed store shared with the account-log pin;
wallet-core derives the roster log's slot key from the Space id), so log
continuity spans logins.

Provisioning initializes the roster idempotently with the account's existing
user key as the first epoch, as the account-genesis ceremony's roster stage --
after did:webvh provisioning, because the log's entry proofs anchor in the
published account document. Login performs one direct read
(`initSessionFromSeed`, before the storage clients are built), gated on a
promoted (did:webvh) account pointer, that either confirms the cached user key
current or -- on an epoch mismatch, a rotation by another client -- unwraps
the fresh user key with this client's own key, adopts it for the session, and
persists it into the client-key record. A failed persist (the client-key
record write or the epoch-pin advance) is not a login failure: the adopted key
authenticated against the verified roster, so the session proceeds on it and
the login page surfaces the failure as "this browser could not be remembered"
(`session.userKeyPersistFailed`; the next login re-fetches the key). A failed
persist must not masquerade as an offline start: wallet-core propagates the
adoption callback's throw rather than swallowing it into the warn-and-null
path, and the login wrapper catches it.

Three client-side guards are load-bearing against a tampering host. First the
resource log itself: roster state is adopted only from a verified head, whose
entry proofs must be signed by keys the independently verified did:webvh
document lists under `assertionMethod` at the anchored version
(`ResourceLogIntegrityError`), and whose chain-head pin refuses rollbacks,
forks, and SCID or method switches (`ResourceLogContinuityError`). At login
the chain-head `rollback` reason is the carve-out, matching the account-log
pin's: a head behind the pin may be nothing worse than a lagging replica, so
wallet-core's login policy degrades it to the transport class (the session
keeps the cached user key, nothing rolled back is adopted, and the pin never
regresses) instead of locking the user out of a healthy account. `fork` and
the SCID/method switches stay session-refusing. Second, the locally pinned
latest-seen roster epoch (`src/lib/sessionKey.ts`, beside the
keyring-freshness pin): a served roster that rolls back behind the pin is
refused (`UserKeyRosterContinuityError`, with no rollback carve-out, since the
chainless epoch pin cannot tell a rollback from a fork). It is kept because it
still guards a client whose chain-head pin was lost with a reinstall. Third,
at rotation time, a recipient resolver backed by the locally verified
did:webvh document: a roster entry with no `keyAgreement` verification method
marked for that client is dropped and never receives a wrap, so a
server-injected entry sits ignored.

## The client enrollment ceremony (`@interop/wallet-core/enrollment`)

Connecting a second wallet client (a fresh browser profile) to an existing
account, without any secret leaving either side. A fresh browser holding a
standing unlock credential can self-enroll at login on its own (see
"Session & auth flow"); this two-party ceremony remains the path for
records without standing authority, for onboarding another wallet app over
the rendezvous transport, and as the future opt-in step-up approval policy.
The new client mints its whole key set locally (client seed, did:webvh
update-key seeds) and only PUBLIC halves travel, as a compact **connect
code** (`freewallet-connect:<base64url(JSON)>`) carried point-to-point:
pasted between two browsers, or over the rendezvous transport below.
Nothing travels back over the channel: the account pointer comes out of the
keyring (the enrollee holds the passphrase), and the user key comes back
through the wrap-set roster. Both screens display the new client's did:key
fingerprint, and the person running the ceremony compares them before
approving -- the point-to-point verification the roster wrap and the
document VM inherit.

The flow, quorum-of-one (any single enrolled client can enroll):

1. **Enrollee** (login page, from the not-enrolled state): "Connect this
   browser" mints the key set (`mintEnrollmentRequest`) and shows the code.
   Nothing is durable yet.
2. **Enrolling client** (Settings > Connect another wallet): pastes the
   code, compares the fingerprint, approves (`approveEnrollment`). Push,
   not pull, in the recovery-anchor order (decryption material before
   authorization): the user key wraps to the new client's key-agreement
   key in `key-map/user-key.jsonl` FIRST (`addUserKeyRosterRecipient`,
   escrow semantics: every epoch, so pre-enrollment history decrypts),
   then the two did:webvh log entries (`enrollWebvhClient`): a sparse
   **commit** entry extending `nextKeyHashes` with the new client's
   update- and staged-key hashes (prerotation demands the commitment land
   one entry early), then the **add** entry publishing the new client's
   two verification methods and its update key. No authorized-but-blind
   window exists at any point.
3. **Enrollee** ("finish connecting"): verifies the enrollment from the
   world-readable log (resolved locally, checked against the pointer's
   DID), performs its first roster read signed with its just-published
   `<did:webvh>#<multibase>` key, unwraps the user key, persists the key
   set into the local client-key record under the passphrase's unlock
   layer (stamping the account controller, so the login-time identity
   check binds the record to it), and logs in as an ordinary enrolled
   client.

**The connect code's keys must be canonical.** The enrolling client refuses
a code whose key-agreement key is not the canonical X25519 twin of its
signing key (`assertCanonicalEnrollmentKeys`, run inside the connect-code
parse, so the refusal lands before anything publishes). A client's
key-agreement method publishes under `controller:
did:key:<its signing multibase>`, a claim every reader trusts to pair the
two; without the check an enrollee could publish a key-agreement key
nobody can pair with its signing key. The refusal reaches both approval
surfaces: the paste dialog under the code field, and a scanned onboarding
response ending the invite with the generate-a-fresh-code copy.

Every stage is idempotent and the ceremony is resumable from durable state
alone; re-running with the same code converges. A tear after the roster
write leaves an orphan wrap (invisible to authorization, harmless); a tear
between the log entries is detected from the standing `nextKeyHashes`
commitments (the add entry alone is appended, never a fork).

**The rendezvous transport (onboarding another wallet).** When the enrollee
is a camera-holding wallet rather than a browser with a paste box, the same
ceremony runs over the WAS server's ephemeral-exchanges facet
(`/workflows/ephemeral/exchanges`, unauthenticated: the unguessable
exchange URL is the only access control, and it travels point-to-point in
the QR). Settings > Connected wallets > "Connect another wallet" opens one
card offering both halves of the ceremony, the QR invite and the
paste-a-connect-code form. The invite side creates an exchange whose stored
request is a `WalletOnboardingQuery` VPR carrying the account pointer and
controller (`composeWalletOnboardingRequest`), renders the exchange's
interaction URL (`.../protocols?iuv=1`) as a QR code, and polls
(`OnboardInviteCard`). The other wallet scans it, begins the exchange, mints
its key set, and posts back an onboarding-response envelope: the ordinary
`freewallet-connect:` code verbatim plus a suggested display label, nothing
else (`encodeOnboardingResponse` / `parseOnboardingResponse` in
`@interop/wallet-core/enrollment`; an oversize or malformed envelope is
refused whole, surfaced as "generate a new code and try again"). Poll
completion swaps the card to a consent panel (`OnboardConsentPanel`) that
leads with the fingerprint comparison (the mandatory trust anchor, since
anyone holding the exchange URL could inject a response), states the
full-peer consequence (an enrolled wallet reads and changes everything in
the Space, connects apps, onboards or disconnects other wallets, issues and
revokes recovery codes) and the disconnect limitation, and prefills an
editable label from the envelope's suggestion. Approval drives the same
`approveEnrollment` + `setClientLabel` path as the paste dialog, and the
enrollee completes the ceremony off the world-readable log as usual. The
channel carries only the four public key multibases and the label; the
account pointer travels inside the stored request (the exchange URL is its
confidentiality bound), and the user key comes back through the wrap-set
roster.

## Recovery codes (`@interop/wallet-core/recovery`)

The "lost my only client" answer: a 16-byte base58 **recovery code**, shown
exactly once at issuance, that restores the whole account from a fresh
browser with nothing else in hand. On the roster model a code is a
**minimal always-enrolled wallet client** whose entire key set derives
deterministically from its bytes: its own unlock identity under a distinct
single-expansion HKDF (so a code and a passphrase that stringify alike can
never derive the same unlock Space), a client seed, one did:webvh update
key, and a binding MAC key. The key material exists nowhere until the code
is typed.

Its inventory is split. **Decryption stands**: the code's `keyAgreement`
verification method is published in the did:webvh document as an ordinary,
unmarked Multikey entry (the keyAgreement-only case, so client listings
keyed on `capabilityInvocation` never see it, and the document does not
label which keyAgreement key is the recovery one), and its user key wrap
stands in the `key-map/user-key.jsonl` roster; both are maintained for free
by rotation fan-out. **Authority stays latent**: the code's update key joins
`updateKeys` nowhere; only its hash is committed in `nextKeyHashes`, and
the one bridge into the zcap profile is a pre-minted PUT-on-`did.jsonl`
delegation carried inside the code's unlock record beside the account
pointer (never a seed, never a key wrap; the record stays a pure pointer).
The narrow scope keeps recovery **loud**: any use of a code, legitimate or
stolen, must first extend the world-readable, hash-chained log before it
can read a single byte.

The record splits into a **code-authenticated core and a re-mintable
shell**. The core is the account binding `{ controller, pointer }`: at
issuance it is MAC'd under a key derived from the code bytes (the storage
host never holds it), the tag riding the record frame in the clear, and
recovery verifies the tag BEFORE the pointer is trusted. This closes the
host-forgery redirect: the record's JWE recipient is the code's unlock KAK,
whose public half sits in the stored frame, so a malicious host could
otherwise seal a record of its own pointing at an attacker-controlled
account and sign it with that account's genuinely enrolled key; every
signature-side check passes, and only the binding, which needs the code
bytes, refuses it. The shell is the record's plaintext frame (controller,
pointer, timestamp) plus its sealed `bridge` member (the pre-minted
delegation, wrapped on its own so a re-mint can replace it) under the frame
proof, whose signer is mixed: issuance signs with the code-derived unlock
key (verified before decrypt); the revocation cascade's delegation re-mint
signs with the re-minting client's account verification method, verified
after decrypt against the did:webvh document the code-authenticated
pointer names. The re-mint reads the standing record through its
management zcap and preserves the binding tag verbatim (it cannot
recompute it and does not need to), so a re-mint can never move the record
to another account; since the tag covers the pointer's host, codes must be
re-issued when the account migrates hosts. The record carries no email and
the locate step shows none: a self-declared display string is exactly the
deception payload a forged record could show as "this is your wallet", so
`/recover` confirms only that the code located an account. The locate step
keeps the module's error discipline: a network failure from the
account-log fetch rethrows unchanged and surfaces as "could not check",
and an account-log continuity refusal is never relabeled as a forged
record. A `rollback` (possibly mere replication lag) reads as
could-not-check; a fork or identity switch surfaces as its own continuity
refusal.

Issuance (Settings > Recovery codes, `issueRecoveryCode` in
`src/session/recovery.ts`) runs in the recovery-anchor order: roster wrap
first (escrow: every epoch, so
recovery decrypts pre-issuance history), then the document entry (VM +
commitment), then the delegation and unlock record, then a registry entry
carrying public halves only. Nothing binds until the confirm-once dialog's
"I saved this code". The confirm gates the writes, not the tears: an
issuance torn after its document entry leaves a code the user saved that
locates no account (its unlock record never landed) plus a document
`keyAgreement` entry and roster wrap nothing names. The login sweep
rotates the orphan wrap away, but the registry-driven health check cannot
see the code, so the saved code stays silently dead; the retire-and-
reissue mender for the orphaned document entry is not built yet, and the
last-client transition refuses while the entry stands.

Recovery (`/recover`, `recoverAccountWithCode`): the typed code decrypts
its unlock record, the log is fetched and locally verified against the
pointer, and the delegation writes the self-enrolling continuation: a
**reveal-and-commit** entry signed by the code's pre-committed update key
(prerotation is what lets a committed key reveal itself), then an
**add-and-retire** entry.
The continuation enrolls what the durability decision would at login. With `rememberBrowser` (the programmatic remember entry)
a fresh ordinary client key set is minted; inside the continuation's
required `onCommitted` seam (between the reveal and add-and-retire
entries) the successors become durable: the new
passphrase's unlock record in the standing LAYOUT (bridge, ladder seed --
its standing property completes post-pivot), the PENDING client-key
record (seeds, controller, `pointerDid`, the pending group: built-on
head, unwrap key, replacement-code bytes; no user key), and the
replacement code's record and bridge. A colliding unlock record (another
credential's) refuses up front. The add-and-retire entry
then brings in the new client, retires the spent code's inventory, and
adds the replacement code's. The tail makes the passphrase standing (its
roster wrap, then its commitment + rung-0 entry, before the rotation);
the user key unwraps from the code's wrap and **mandatorily rotates** off
it; the registry mutation (spent entry out, successors in) runs between
the re-seal and the cascade; the replacement code is pushed hard (the
save confirm also completes the local record, clearing the carrier); the
spent code's unlock Space is deleted (a spent code thereafter fails
distinctly); an ordinary enrolled login follows. A
post-entry tab death leaves the pending record; the next login's spend
resume finishes it -- escrows re-derived from the unwrap key, standing
and registry backfilled, the code re-displayed until confirmed saved, the
sweep completing rotation and cascade.

The DEFAULT on a non-remembered browser is the **transient recovery
variant** (wallet-core's `recoverWebvhLadderAnchored`): no durable client is
minted anywhere. The add-and-retire entry publishes the fresh credential's
ladder VM in its place (`assertionMethod` and `capabilityDelegation` only)
beside the new passphrase's `keyAgreement` commitment and the replacement
code's inventory, retires every standing ladder VM (the stale-third-party
retirement no other ceremony performs), and the account lands client-less
and ladder-anchored. Inside the continuation's persist-before-publish seam
(after the reveal entry validates the code, before the ladder VM publishes)
the ceremony mints a fresh annex generation under the new ladder's bootstrap
did:key (a recovery record carries no annex sibling, so the old generation
is unreachable and falls to orphan discovery) and durably writes the new
passphrase's unlock record (ladder seed inside, bridge and sibling
ladder-VM-signed) and the replacement code's record, so a tab death can
never publish an anchor nobody can derive. The seam names the fresh
generation back to the ceremony, so the `#DelegatedClients` pointer moves
to it inside the SAME add-and-retire entry: that entry retires the
pre-recovery credential's ladder VM, and a pointer written after it would
leave a window where the document names a generation no surviving record's
sibling delegation targets and neither credential could enroll. The
per-visit transient client is loudly enrolled into the fresh generation
inside the same seam, written controller-tier while the auxiliary Space
still answers to the bootstrap key (it exercises no authority there: the
generation delegation it will invoke under is signed by a ladder VM the
document does not list yet). The placement buys the window after the entry:
the mandatory rotation -- the ONE ladder-signed roster append the
ceremony-tail license admits (`replaceUserKeyRosterRecipients`: spent code
retired, fresh credential and replacement code escrowed, fresh epoch
minted, one write anchored at the add-and-retire entry) -- is the first
request after the entry, with no enrollment and no pre-read between the
typed code dying in the document and the new credential gaining its wrap.
The pre-rotation user key the registry update needs is unwrapped
afterwards, from the superseded epoch's escrow to the fresh credential. The
epoch cascade and the unlock-methods registry update (spent entry out,
replacement and new-passphrase entries in, re-sealed to the rotated user
key) ride the generation delegation, and the visit then enters through the
ordinary transient composition with zero local residue (the locate step's
chain-head pin rides in memory too). Two residues remain. A tear inside the
append leaves the spent code dead (its key left the document, so a re-run
refuses it as spent) and the current epoch wrapped to the removed code
alone; on a client-less account no login sweep runs, so the mender is a
repair holding both the spent code (to unwrap the epoch) and the new
passphrase (its record's ladder seed and sibling), running the same append
under the ceremony-tail license's still-unused shot -- not built yet. A
rotation torn mid-fan-out on a client-less account has no repair yet
either; a stranded collection stays keyed to the spent code until the next
durable login or a spend re-run.

Revoking a code from Settings is the issuance reversal and is REAL (the
secret was only ever a pointer to the record): document entry out, user key
rotated off the code's wrap and the collections re-epoch'd by the same
cascade, unlock Space deleted, registry entry dropped; the live session
adopts the rotated user key in place. A login-time health check watches
for **delegation rot** (the stored delegation stops chaining the moment
its signing client's verification method leaves the document, which would
brick recovery exactly when needed) and for **delegation expiry**: the
delegation's TTL is one year (NIST SP 800-57 cryptoperiod guidance), so
the registry entry records its `expires`, and a delegation expired or
inside the 30-day renewal window is flagged the same way. The check
nudges regeneration; a client revocation re-mints the affected delegations
as part of its cascade, and the same expiry predicate makes it refresh a
near-lapse delegation too. The passes skip a pending-shaped entry (one
whose record is sealed to a credential other than the one its identity
members name, the residue of a passphrase change torn before its
retirement) rather than sealing a fresh bridge into a half-retired
credential's record. The re-mint core (the staleness checks, the skip
policy, the binding-carried-forward re-wrap) and the delegation builder
live in `@interop/wallet-core/recovery`; `src/session/recovery.ts` binds
them to the session's signers, the storage URL, and the registry.

Two standing boundary rules. First, the hash-commitment rule: **a
low-entropy-derived public key is never published in the world-readable
document**. The document carries a hash commitment of the key
(`MultikeyCommitment`); the real key rides in the capability-gated roster
entry, and the recipient resolver verifies it against the commitment (the
oracle argument is in "Session & auth flow"). A high-entropy credential's
key (a passkey PRF output, a recovery code) may publish verbatim. Second,
the unlock-methods registry's additive `method` enum is the explicit seam
for a later quorum recovery method (rejected for v1 as presupposing a
contact roster most accounts lack). The re-mint machinery above also
covers the standing passphrase/passkey credentials' bridge delegations:
the cascade walks every registry entry recording one, and a standing
credential's own login refreshes its bridge inside the renewal window or
when its signing key has left the account document (the signer-rot axis a
self-enrollment's ladder-VM removal makes routine).

## Client revocation and the epoch cascade

Disconnecting an enrolled wallet client from the account. The cascade is
`revokeAccountClient` in `@interop/wallet-core/clients` (one orchestrator
for every wallet); `revokeEnrolledClient` in `src/session/revocation.ts`
supplies the freewallet-shaped stages around it (session preconditions,
the collections source, the recovery re-mint, the adoption side effects),
driven from the Settings "Connected wallets" panel (see "The Settings
clients surface" below). Run in the revoking client, synchronously, in
dependency order:

1. **The document edit** (`revokeWebvhClient` in
   `@interop/wallet-core/webvh`): the revoked client's two verification
   methods (the key-agreement one found by its controller marker, never
   re-derived), its update key, and both standing `nextKeyHashes`
   commitments (the carry-over hash and the staged hash, the latter
   recovered by log attribution -- an opaque committed hash left behind
   would be a re-seizure credential via the reveal mechanism) leave in one
   log entry. Under the current-key-set rule this one edit pulls the
   revoked client's whole authority at once: its invocations, and every
   delegation and app grant it ever signed, stop verifying. The cascade
   makes no per-collection revoke calls; apps it had connected reconnect
   through the ordinary App Connect flow.
2. **The user key rotation** in the `key-map/user-key.jsonl` roster
   (`rotateUserKeyRoster`), recipients resolved from the just-updated
   verified document (the roster delivers, never sources, so the revoked
   client's entry is dropped even before the retire filter). An account
   with no roster yet stops here: the document edit landed, so the wallet
   IS disconnected. The orchestrator enforces anchoring at the post-edit
   head: it sets the roster store's controller floor
   (`setControllerFloor`) from the edit's own post-edit log before any
   roster-side work, so a stale cached controller view (the session's
   verified-log memo) can anchor neither the rotation nor the sealing
   append at a head predating the removal. The session hands over
   wallet-core's sealable store unwrapped, keeping that contract reachable.
3. **The epoch cascade** (driven by wallet-core over the collections
   `src/session/userKeyCascade.ts` enumerates): every encrypted collection
   (standard plus any remotely listed collection whose Description carries
   an encryption descriptor) is re-epoch'd onto the fresh user key in
   parallel via was-client's `replaceRecipient` (~2 requests per
   collection): the revoked user key generations retire from the epoch
   rosters and the fresh user key escrows into every prior epoch, so every
   other replica keeps decrypting across the rotation. A collection is
   stale exactly when its current epoch names a non-current user key
   generation (durable state alone), and a never-epoch'd collection gets
   the newest prior generation installed as its first epoch (the user key
   is the epoch construction, so pre-epoch envelopes ARE
   epoch-`oldUserKey` envelopes). A descriptor whose `currentEpoch` names
   no epoch in its own `epochs` list is refused fail-closed, matching the
   roster read's integrity refusal. Failures collect per collection into
   the fan-out's `failed` report; the rest still rotate.
4. **The recovery re-PUTs** (`remintRecoveryDelegations`): recovery
   delegations the revoked client had signed stopped chaining at step 1;
   the revoking client re-mints them and re-PUTs the unlock records.
5. **The generation-delegation re-mint** (the `remintGenerationDelegation`
   closure, module-level in `src/session/revocation.ts`): an embedded
   generation delegation the revoked client had signed also stopped
   chaining at step 1, so the closure runs `ensureGenerationDelegationCurrent`
   against the post-edit document (the stale-signer axis beside expiry) and
   replaces the delegation in place -- same fragment, no revocation POST,
   since the rotted chain no longer verifies anyway. It signs with the
   login credential's ladder seed (`profile.ladderSeed`, in-memory) and
   skips with a report (`outcome.generation`) when the seed or a promoted
   pointer is absent; the mid-generation grant death that remains is a
   stated consequence of an ordinary disconnect. The closure runs in the
   no-roster early return too.

The revoking session then adopts the fresh user key in place (profile vault
keys swapped, storage ciphers rebuilt via `adoptRotatedVaultKeys`, the
unlock-methods registry re-wrapped), so it keeps operating without a
re-login, and a wallet-activity record is written under the fresh epoch.
Self-revocation is refused up front (use another enrolled client, or a
recovery code). The cascade is convergent under a naive full re-run: the
log entry is idempotent, the roster no-ops once the entry is off the
current epoch, and the staleness rule finds exactly the stranded
collections, so a mid-cascade crash strands nothing permanently. The
limitation: ciphertext the revoked client already fetched stays readable to
it, and old epochs open to keys it already held.

One key survives every rotation: a collection's blinded-index HMAC key.
Minted with epoch[0] at provisioning and wrapped to each recipient on the
`encryption` descriptor, it never rotates: blinded index tokens must
compare across the collection's whole history, and a fresh key would
orphan every existing `indexed` entry. Recipient removal only drops the
leaver's wrap, so a removed recipient keeps the blinding key and, colluding
with the server, could confirm guessed attribute values indefinitely -- a
guessing oracle, not a read path: the server still gates the query endpoint
on the pull grant, and the content keys rotate as above.

The standing backstop is the **cascade-completion sweep**: session creation
re-runs stages 2 and 3 on every login whose roster read succeeded, chained
behind collection provisioning as the first stage of the login-time promise
chain exposed as `session.registryReady` (best-effort: a failed sweep is
logged and skipped, never fails the login). That chain runs after the
dashboard has rendered (see "Session & auth flow"), so a write made in the
navigation window before the sweep finishes (a Login activity, an import)
can seal under an epoch a disconnect's rotation has not yet caught up to,
readable by a client the revoke already removed from the document. Whether
to hold such writes until the sweep completes is an open decision, tracked
separately. The roster stage runs first
(`convergeUserKeyRosterToDocument`): a cascade torn between its document
edit and its rotation leaves the roster wrapping the CURRENT key to a
recipient the locally verified document no longer keys, durably and
silently, since the revoked client's document edit will never be re-run.
A current-epoch recipient the document-backed resolver cannot answer for
is rotated away from here, and the fresh key is adopted (client-key
record, epoch pin, live session vault keys and ciphers) before the
collection fan-out runs against it. Because staleness is
durable-state-only, the fan-out then completes a cascade another client
crashed partway through; on a healthy account both stages read descriptors
and write nothing. Together they are the standing invariant check that the
roster keys exactly the document's clients and that no collection's
current epoch names a retired user key generation.

Recovery-code spend and revocation drive stages 2 and 3 of the same
cascade (their document edits are their own, and a spent code's
replacement delegation is minted by its own ceremony rather than the
re-mint stage), which closes the "writes still land under readable epochs"
residue in both flows.

## The Settings clients surface ("Connected wallets")

The management surface over the enrolled-client roster
(`src/components/EnrolledClientsSection.tsx`, glue in
`src/session/clients.ts`): where "disconnect this phone" lives, sibling of
the Applications page (apps are grantees, never enrolled, and stay in their
own revocation surface).

The listing is wallet-core's `listAccountClients`, which
`src/session/clients.ts` wraps with only what a session knows (where the log
lives, which key is this browser's, the label store): a read over the
locally verified did:webvh log (the same `verifyAccountLog` step every
ceremony runs), then `listEnrolledWebvhClients`, keyed on
`capabilityInvocation`. That keying is the exclusion story: a recovery
code's key is published under `keyAgreement` only (unmarked), and the
KMS-held convenience under `authentication`, so neither can appear,
structurally rather than by filter. Two members are not readable off the
current document and are recovered by log attribution: each client's ACTIVE
update key (the flat `updateKeys` set has no per-client grouping; the entry
that published the client's verification methods revealed its initial key,
and each entry retiring the attributed key while revealing exactly one
replacement is that client's self-rotation; an ambiguous attribution
disables disconnect for the row rather than guessing) and its enrollment
moment (`versionTime` of the publishing entry). A listed row with both key
members (signing key and active update key) is exactly a
`RevokedClientKeys` (`revokedClientKeysFor`), so Disconnect drives the
client-revocation epoch cascade verbatim. Which rows can be disconnected is
the shared `disconnectEligibility` policy (self, last-wallet, and
unattributed-update-key refusals) rather than UI state, and a partial
collection fan-out is reported through `cascadeCompletion` as a resumable
success.

**Labels live beside the keys, not in the document.** The document carries
key material only, so display labels go in `key-map/client-labels.json`
(wallet-core's `readClientLabels` / `setClientLabel` over a two-method
store seam; plaintext in the private, capability-gated `key-map` collection,
since the host already serves the world-readable log naming every client
key, and a label adds only the display name). A label is chosen at
enrollment approval (a field in the enroll dialog, written after the
ceremony lands, best-effort) and editable inline from the panel; the
current client is marked with a "This browser" chip (matched on the
session's own signing key) rather than by any stored state.

Disconnect confirms with the limitation (re-keying stops future reads;
already-fetched ciphertext stays readable), runs the cascade with keep-this-
tab-open progress copy, and surfaces both failure modes as resumable ("try
again -- it picks up where it stopped"; a partial collection fan-out points
at the login-time sweep). The last enrolled client cannot be disconnected:
that would abandon the account's update authority (it is also always the
current client from its own session, and self-revocation is refused), and
the panel says so, pointing at recovery-code issuance instead. The
connect-another-wallet entry point (the enrollment ceremony's approving
half: one card offering both the QR onboarding invite and the pasted
connect code) lives in this panel.

**The Applications sibling knows the current-key-set rule.** The
Applications page (`src/lib/connectedApps.ts`) is the account's other
revocation surface (app grantees there, wallet clients here, with a
cross-pointer in each panel). Its listing checks each recorded App Connect
grant's delegation signer (the full zcap, proof included, is recorded on
the Login activity) against the same verified document, via
`currentAccountSigningKeys` (wallet-core's, wrapped in
`src/session/clients.ts` so a guest degrades rather than throws) plus
`deriveAppGrantsState`, matched on the key-multibase fragment so the
did:key and promoted did:webvh forms of one key agree. An app whose
recorded signers are all gone from the document is shown as orphaned (its
grants already stopped verifying with that client's revocation;
reconnecting through the ordinary App Connect flow is the recovery path),
and revoking it skips the pointless per-grant revocation POSTs while still
rotating the app-provisioned collections' epochs and deleting the app key.
The check is best-effort: no verified document this session (a guest, or
the log unreachable) degrades to listing without the marker, never to
failing the page.

The same panel's agent rows (see "The interaction-URL request page" above)
run the identical signer check against `currentAccountSigningKeys`, over
the recorded grant's `controller` instead of an app-key subject, so an
agent whose signing client has been disconnected shows as orphaned too.
The marker is display-only for agent rows: revoking one always POSTs the
recorded revocations, because a grant delegated from a transient session
is signed by an annex key the document never lists yet chains under a
generation delegation alive until its own TTL, so "signer gone" does not
mean "chain dead" there. A dead chain comes back as a skipped revocation.

## Storage model (local-first)

The local `BrowserStore` (RxDB over Dexie/IndexedDB) is always the **active
replica**: every credential, public-link, and history read/write targets it,
online or offline, guest or not. One local database per user holds every
standard collection (`private-credentials`, `public-credentials`,
`wallet-activity`, `contacts`, `contacts-history`, `app-connections`) on the
generic synced-doc schema (`{ id, updatedAt, version, data }`, see
`src/lib/sync/syncedDocSchema.ts`).

The encrypted collections (all of the above except `public-credentials`)
store **EDV envelopes**, not plaintext -- encrypted at rest locally and
opaque to the server. A per-collection document cipher
(`createEdvDocCipher` from `@interop/was-client/edv`, built from the
session's vault KAK) encrypts at write time and decrypts at read time. The
row id is content-derived (a hash of the JWE ciphertext), so it is identical
on every replica. Page-facing identity stays the credential `cid` /
activity `id`, recovered by decrypting at read time; JWE encryption is
nondeterministic, so dedupe keys on that content identity, not the row id.
`public-credentials` is plaintext (public data) and keyed directly by `cid`.

When `VITE_WAS_SERVER_URL` is set (and the session is not a guest), a remote
WAS Space is attached as a **sync target**: the `SyncController`
(`src/stores/syncController.ts`) replicates every synced local collection to
its remote WAS Collection counterpart in the background via the
collection-agnostic adapter in `src/lib/sync/`, which ships stored bodies
(plaintext or envelope) verbatim and never touches keys. Each replication
(and `WASRemoteStore` request) is signed with the session's root key.

`WASRemoteStore` does not serve credential reads/writes; it keeps the Space
lifecycle (create/exists/wipe), the storage-browser read-through
(`/storage/**` pages work directly over remote collections), export/import,
and quotas. `StorageManager` is the facade; pages and components always talk
to it, never directly to a backend class.

Deleting a credential retracts its world-readable public copy before
removing the private credential (`StorageManager.deleteCredential`, matching
the mobile wallet's order): once the private credential is gone nothing is
left to retract the public copy with. Retraction of a live public copy is
blocking -- one that cannot be retracted refuses the delete
(`PublicCopyRetractionError`). The interactive delete decides on the local
replica, so a credential with no local public copy deletes normally offline.
The unattended app-key sweep has retraction consult the remote
`public-credentials` collection too (`consultRemote`): the local replica
cannot prove a remote copy absent (a fresh enrollment or a replication run
stuck in retry backoff may not have pulled it yet), and an unreachable
remote then refuses the delete. The delete dialog's "keep public copy"
choice skips retraction entirely.

The world-readable share link a public copy gets
(`WASRemoteStore.publicCredentialUrl`, over wallet-core's
`publicCredentialUrl`) is built with was-client's paths helpers
(`spacePath` / `resourcePath` / `toUrl`), which join onto the storage
server's base path, so on a sub-path deployment (a server URL like
`https://host/was`) the link addresses exactly the resource replication
wrote, with per-segment encoding (a root-anchored form was drift, corrected
in wallet-core 0.39.1).

A user's remote Space is identified by an independent random `spaceId`
minted at signup and carried in the account pointer (unlock Spaces keep
`spaceId = base64url(SHA-256(unlock did:key))` as a discovery convention).
Collections created on first login: `private-credentials`,
`public-credentials`, `wallet-activity`, `contacts`, `contacts-history`,
`app-connections`.

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
   iframe** -- outside the normal app shell and `ProtectedRoute`.
3. The popup page calls `receiveCredentialEvent()` to intercept the CHAPI
   event, shows a minimal login form, initialises a full `Session` in-popup,
   then calls `chapiEvent.respondWith(...)` to return the result to the site.

The CHAPI pages (`src/pages/chapi/`) are not wrapped in `ProtectedRoute` and
do not use the main app layout.

**Remote-direct popup storage.** The popup runs in a third-party iframe, so
its own IndexedDB is a partitioned bucket no `SyncController` ever drives: a
credential stored there would be stranded and a credential list would always
come back empty. Every synced-collection read/write in `StorageManager` goes
through one `SyncedCollectionStore` backend chosen once at construction
(`src/stores/remoteDirectStore.ts`): the local `BrowserStore` in the normal
case, or a `RemoteDirectStore` for the popup (selected via `remoteDirect`,
threaded from `loginWithPassphrase({ remoteDirectStorage: true })` in both
popup pages). The remote-direct backend serves credential, history, and
public-link reads/writes straight over the remote WAS collections
(`WASRemoteStore.listSyncedResources` / `getSyncedResource` /
`putSyncedResource` / `deleteSyncedResource`), with the same per-collection
ciphers the local store uses, so the envelope, id, and key-epoch logic lives
once. A write reproduces verbatim what background replication would have
pushed (the raw EDV envelope under its content-derived envelope-hash id,
created with `If-None-Match: *`, stamped with the same `Key-Epoch`), so the
main app's replication pulls it cleanly. An unknown-epoch read (a rekey by
another client) drives the same one-time descriptor refresh the local
backend uses, so a fresh-epoch credential is never dropped. Contacts are not
reachable in a popup, so the remote-direct backend rejects them. The backend
is selected only when a remote store is configured; a guest or no-WAS
session always uses the local `BrowserStore`. Reads gate on
`StorageManager.ready()` -- the local collections being open, or nothing at
all in remote-direct mode.

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
  compares the parsed URL's serialization, so forms differing only in a
  default port, percent-encoding case, or dot-segments do not name distinct
  applications;
- `capabilityQuery: [...]` -- the usual capability descriptors _minus_
  `controller` (the wallet fills it) and `reason` (the App Connect consent
  screen supersedes per-grant reasons).

An `AppConnectQuery` is one mental model per popup: mixing it with
`QueryByExample` or standalone capability queries is rejected at
classification time (the shared `appConnectRequestOf`), and wallets that
predate it fail closed (the app surfaces an "update Freewallet" error)
rather than degrading into a partial generic flow.

The wire contract -- the `AppConnectQuery`, the app-key credential, the
descriptor vocabulary and action limitations, and the response presentation --
is specified normatively in the **App Connect companion spec**
(<https://github.com/interop-alliance/app-connect-spec>; local checkout
`../app-connect-spec` -- read `spec.md` there instead of fetching the
rendered version). The whole app-key module -- the wire constants, the match
and mint paths, and the store-time refusal policy -- lives in
`@interop/wallet-core/request` (`appKey.ts` there), shared with DCW; the
`AppConnectQuery` validation (`appConnectRequestOf`) lives beside it in that
package's `classify.ts`. Freewallet's half is consent UI, credential
storage, and the delegation machinery.

The key design move: **the wallet mints the app-key seed**. The seed is a
client secret that must never transit a server, so on first run the wallet
generates 32 random bytes, derives the did:key via
`CapabilityAgent.fromSeed({ seed, keyName: 'app-key' })` (the `keyName`
string is load-bearing -- it must match was-react's derivation exactly),
self-issues the credential (issuer == subject == seed-derived DID, seed
base64url-no-pad in `credentialSubject.seed`), and saves it to the
dedicated `app-connections` collection under the same consent -- no second
popup. On a returning visit the stored credential is matched by the
`AppKeyCredential` marker type AND `credentialSubject.appUrl === ` the
request's serialized `appUrl` AND `credentialSubject.origin === ` the
CHAPI requesting origin, so a phishing origin can neither recover nor be
handed another origin's key, and two applications sharing an origin stay
apart by their `appUrl`s (the app-side origin check in was-react's
`parseSeedCredential` stays as defense in depth).

A match additionally requires that the credential's subject DID **re-derive
from the seed the credential itself carries** (`appKeySeedBindsSubject`).
Self-issuance is a weak signal (anyone can self-issue, and candidates rank
on an `issuanceDate` the credential itself states), so without this a
credential planted through an import or injected into the Space directly
would win the match and its DID would become the `controller` the wallet
delegates to. The check is local and deterministic (the same
`CapabilityAgent.fromSeed` call that minted it) and fails closed on an
absent, non-base64url, or wrong-length seed. Binding authenticates internal
consistency only, not provenance -- a fully attacker-generated credential
(its own fresh seed, the victim app's `origin` and `appUrl`) binds
perfectly -- so the store-time refusal below, not the binding, keeps
plants out. Candidates rank latest-first over the _instant_ each
`issuanceDate` denotes rather than the raw string, so a date's textual form
(a numeric offset, differing fractional-second precision) cannot reopen
the planted-credential path; an absent or unparseable date sorts last.

**App keys live in their own collection.** Every app key is stored in
`app-connections` -- a synced, EDV-encrypted, content-addressed collection
like the credential replica, but structurally separate: the credential-wide
surfaces (the dashboard list, credential detail, public-link creation,
credential delete, collection shares) are scoped to `private-credentials`
and can never reach a seed, with no filtering code. The collection is never
shareable (`shareable: false` on its roster spec) and no grant may name it:
a capability descriptor or URL naming it is unsatisfiable in grant
resolution, not merely read-only. (A whole-Space read grant still covers
its ciphertext, as for every private collection; the grantee is not an
epoch recipient, so it decrypts nothing.) Match and consent-preview
candidates come from `StorageManager.listAppKeys()`, so ordinary stored
credentials never enter the match. That call reports what its scan skipped:
rows whose key epoch is still unknown after the one descriptor refresh,
rows in a known epoch this session holds no wrap for, and envelopes that
will not decrypt at all. A match scan that found nothing but skipped such
rows refuses to mint, since "no match" does not mean "never connected" and
a fresh mint would orphan the app's prior identity. The refresh is spent at
most once per collection per session and swallows a failed fetch, so an
unknown-epoch row can still reach the match path, hence reported rather
than assumed resolved. Undecryptable rows are purgeable from the
Applications page; the other two kinds are real data and stay unpurged.
There is no migration from the old in-`private-credentials` placement and
no legacy (pre-`appUrl`) re-issue path: an idempotent login-time sweep
deletes stranded app-key rows from `private-credentials` (marker-typed or
matching the old self-issued-with-origin shape), and an affected app
reconnects through the ordinary flow as a first run -- its prior identity,
and whatever it encrypted under it, is orphaned (the greenfield
re-provision rule). The same sweep also retracts app-key public copies
left with no private row behind them (a pre-upgrade app key kept through
"keep public copy"), through the remote-aware retraction path under
"Storage model".

**Externally arriving app keys are refused at store time, unconditionally.**
Every minted app key carries the marker type `AppKeyCredential`
(`https://w3id.org/byoe#AppKeyCredential` -- one stable IRI for every app,
defined in the static inline `@context`), which turns "presents as an app
key" into a term check rather than a shape heuristic. The `type` array of a
planted credential is attacker-controlled like everything else in it, so the
marker is a **self-declaration, not evidence**; the store-time rule cannot
be "binds, so it stores" (a planted credential can bind too, see above).
App keys are wallet-minted; an imported one is refused outright.
`StorageManager.addCredential` -- the one door every externally supplied
credential goes through (the CHAPI store popup, the URL / QR / manual-paste
import, the credentials half of a space import) -- refuses every marked
credential, binding or not (`assertStorableAppKey`, `AppKeyRefusedError`).
Refusing beats storing-and-ignoring: consumers of an app-key match do not
each re-check provenance, and the wallet does not show a credential it will
never act on. The marker is _required_ at match time rather than merely
tolerated, so a credential can only reach the delegation path by carrying
it -- exactly what the store-time refusal screens. The wallet's own mint
path stores through its own door (`StorageManager.addMintedAppKey`, called
only by `processAppConnect`, writing into `app-connections`), which asserts
the mint invariants so it cannot be misused to store a foreign key. Two
ingest paths sit outside the door: the background sync pull writes pulled
rows into the local replica directly, but it replicates the account's own
remote collections, which only the account's enrolled wallet clients can
write (`app-connections` is never grantable, and `private-credentials` is a
protected collection -- RP and share grants on it are read-only) and each
of those clients enforces the same refusal at its own door; and the space
half of an import writes opaque resources into the user's own Space
server-side. For both, the match-time binding is the backstop.

The credential's shape is identical for every application: the `type` array
is the fixed two-entry `["VerifiableCredential", "AppKeyCredential"]`, and
the inline `@context` is one static object mapping `appUrl`, `seed`, and
`origin` to their `https://w3id.org/byoe#` IRIs. Which application a
credential belongs to is the `credentialSubject.appUrl` claim, not a type.

Because the wallet delegates to the subject DID of the credential it just
matched or minted, the request never needs to name a controller DID, which
is what makes the flow single-round. Delegation reuses `resolveGrants` /
`processZcaps` verbatim (descriptor resolution, provisioning, the
per-target-class action limitations, TTLs, protected-collection rules). The
response VP embeds the credential, the `zcap` array, and a wallet-provided
`appConnect: { firstRun }` member (a JSON-literal term in the VP
`@context`), all before signing so the DIDAuth proof covers them
(`processAppConnect` in `src/lib/walletRequest/appConnect.ts`).
`WalletGetPage` renders a dedicated app-centric consent panel ("Connect
{app}?") in place of the three generic sections; approval also records an
app-connect Login activity.

**App-provisioned collection encryption (day-one policy).** When an App
Connect `capabilityQuery` provisions a **private** (non-public) collection,
the wallet declares it EDV-encrypted and sets up a multi-recipient key-epoch
roster in which **the user's vault KAK is always a recipient (recipient
zero)** alongside the app's **identity KAK** -- the X25519 (Montgomery) twin
of the `did:key` the wallet is delegating to, derived with the same
`x25519RecipientFromDidKey` a share uses. One recipient-derivation rule
covers app and person alike, and the app seed never enters the grant path:
the wallet derives the app's recipient key from a public identifier it
already has, and the app derives the private half from its own controller
key. Both read the collection; the WAS server only ever stores ciphertext.
Provisioning is idempotent: the collection gets epoch[0] wrapped to the
owner create-if-absent (`ensureIndexedFirstEpoch` from
`@interop/wallet-core/keys`, adopting an existing roster rather than
overwriting it), then a first connect or a reconnect after revoke escrows
the app into every epoch (`addRecipient(app)`); already present -> no-op.
Epoch[0] is minted together with the collection's blinded-index HMAC key,
wrapped to the same recipient roster, so the app can declare searchable
attributes and query the collection (was-client's `declareIndex` / `find`).
The blinded-index key is installed at provisioning or never: a collection
provisioned before blind-index support is adopted as-is and stays
unindexable. The wallet's own writes carry the same blinded `indexed`
entries a Collection-handle write does: each encrypted collection's doc
cipher installs the persisted index schema from the collection's stored
`/meta` (an opaque encrypted envelope, fetched without keys and decrypted
by the cipher), cached beside the encryption descriptors and refetched on
the same unknown-epoch refresh -- an index declared mid-session reaches the
ciphers at the next refresh or login. The wallet ensures the collection
exists without clobbering an existing `encryption` descriptor, so an
established epoch roster is never dropped. Public
(`https://w3id.org/byoe#public-collection`) grants stay plaintext and
world-readable; only private app collections are encrypted, and a public
grant can only ever CREATE its collection -- one naming an existing
non-public collection is unsatisfiable, so no consent approval can flip an
established collection world-readable. The policy: **the user is always a
recipient of an encrypted collection in their own Space**; any future
exception must be its own explicit consent surface, not a silent default.

Because the user is recipient zero, the wallet decrypts these collections in
the storage browser as an ordinary recipient with its vault KAK,
descriptor-driven from the fetched Collection Description (no seed at read
time). Revoking a connected app rotates the epoch off the app's key for each
such collection (`removeRecipient`, which rotates then revokes the pull-axis
grants indivisibly), so a revoked app cannot decrypt future writes;
ciphertext it already fetched stays readable to it. The blinded-index key is
not rotated on revoke (see "Client revocation and the epoch cascade" for the
asymmetry): the revoked app keeps the ability to compute blinded terms,
while the query endpoint stays behind the revoked pull grant.

## The interaction-URL request page (`/external/request`)

A request can also arrive from outside the app, with no CHAPI popup and no
attested requesting origin: an agent's `di was request-grant` prints an
interaction URL (`<exchange>/protocols?iuv=1`) plus the wallet deep link
`/external/request?url=<percent-encoded interaction URL>`. The same URL
can be pasted into Add Credential or scanned from a terminal QR
(`resolveWalletInput` returns it as a typed `interaction-url` outcome and
both callers route to the page). The page
(`src/pages/external/ExternalRequestPage.tsx`) is the `WalletGetPage`
shape minus CHAPI: it opens the exchange with wallet-core's
`openInteractionRequest`, classifies the VPR with the shared
`classifyRequest`, renders the storage-access consent panel, delegates
through the ordinary grant engine, and POSTs the unsigned zcap-only
presentation back through `composeAndDeliverResponse` with the exchange
URL. A session already live in the app is used directly; otherwise the
page runs the ordinary login in place (the same durability decision
`/login` makes) and adopts it app-wide. The Login activity records the
grant under the fixed origin marker `n/a (API request)`, which the
Applications page keys agent rows on. A request may name its requester
through the VPR's root `agent: { name }` member (the parallel of App
Connect's `app.name`, sent by `di was request-grant --name`): the consent
panel renders it as "an agent calling itself ..." beside the grantee key,
marked self-declared, and the activity records it as `object.actor` (the
ActivityStreams member; the activity's own `actor` stays the user). The
shared classifier enforces the limits (trimmed, 1 to 64 characters, no
control characters); a name outside them is refused as malformed.

The entry point is stricter than the popup, because the only requester
signals are the grantee DID and request-supplied text (the `reason` and
the agent name), all chosen by whoever wrote the link. Every refusal is
decided before consent renders, in the pure module
`src/lib/walletRequest/externalRequest.ts`, each with its own copy: a deep
link that is not an interaction URL (a bare exchange URL included); a gone
exchange (a 404 on either fetch, worded as expired-or-wrong-link since the
server answers the same for both), unreachable, or answering with no
readable VPR; a request asking for no storage access; a
`DIDAuthentication` query in either form and a `domain` on any request
(freewallet requires a `domain` for DID Auth and there is no origin to
match it against); an `AppConnectQuery` (App Connect stays CHAPI-only); a
VPR-named presentation endpoint (`interact.service`) on another origin
than the exchange, since delivery prefers that endpoint and the consent
panel names the resolved delivery host; and any grant class outside the
allowlist. Only `#public-collection` and `#private-collection` targets
(plain collection URLs resolving to those classes included) are granted
from a link: a share would hand the grantee decryption of the user's own
encrypted collections, and a whole-Space or protected-collection read
covers the plaintext `public-credentials` (`barredGrants`, run once the
grants are resolved, the first point a target's class is known). Widening
the allowlist is a documented decision, not a code change. A failed
exchange POST-back leaves the grant recorded and offers the composed
response for manual delivery; a decline abandons the exchange, which
expires on its own.

Grants answered here are listed and revocable from the Applications page,
as agent rows keyed by the grant's `controller` did:key
(`listConnectedAgents` in `src/lib/connectedApps.ts`). A row is titled by
the request's `agent.name` when sent, else by the grantee key's
fingerprint. Its grants are the union over every agent Login for that
controller newer than the latest matching Revoke activity (same origin
marker, no `appConnect`, the controller in `object.controller`), since a
later request can add a grant without retiring an earlier one; a row whose
every grant has expired is dropped. Revoking an agent row POSTs every
recorded capability's revocation, regardless of the orphaned marker, and
records the Revoke with its `created` floored to the latest Login's stamp
plus one millisecond so a fast-clocked terminal cannot leave the row
standing. There is no app key to delete and no collection epoch to
rotate: an agent is never a key-epoch recipient.

A grant delegated from a transient session chains under the session's
generation delegation (`profile.invocationCapability`) rather than the
Space root (which would be signed by an annex key the account document
never lists), with its `expires` clamped to the parent's. A generation
delegation that is expired or inside its renewal window refuses the
approval (`GenerationDelegationStaleError`) instead of minting a silently
short grant; the blocking renewal stage is a follow-up once the transient
profile carries the ladder members a ladder-signed replacement needs.

## Sharing a wallet collection (`https://w3id.org/byoe#shared-wallet-collection`)

The collections above are ones an app created. **Sharing** is the other
direction: letting a grantee read and _decrypt_ one of the wallet's own
encrypted collections. It is asked for with a distinct invocation-target
descriptor -- `{ type: 'https://w3id.org/byoe#shared-wallet-collection', name }` --
in either channel (a standalone `AuthorizationCapabilityQuery`, or an
`AppConnectQuery.capabilityQuery`). A distinct `type` rather than a flag is
load-bearing: an unknown `type` already resolves to unsatisfiable, so a
wallet that predates the feature refuses visibly instead of degrading to a
ciphertext-only read.

**The two axes stay fused.** _Pull_ (a read-only Collection zcap) and _read_
(an epoch-key recipient entry) are granted together, by one call to
`StorageManager.shareCollection`, which returns the delegated zcap alongside
the refreshed descriptor so it rides back in the response VP's `zcap` array.
A share grant therefore bypasses the ordinary delegation loop in
`processZcaps`; no code path grants one axis without the other.

**The recipient key is derived, not transmitted.** `name` must be one of the
shareable standard collections -- every `WALLET_STANDARD_COLLECTIONS` entry
whose roster spec carries `shareable: true`, so today `private-credentials`,
`wallet-activity`, `contacts`, and `contacts-history` -- since sharing is
meaningless where no epoch roster exists, and `app-connections` is encrypted
but never shareable (its rows carry app seeds). The grantee's X25519 key is
derived from the `did:key` the request already names as `controller`
(`x25519RecipientFromDidKey` from `@interop/was-client/edv`, the same
Ed25519-to-Montgomery conversion the wallet applies to its own vault KAK),
so a request can never pair controller DID A with recipient key B. A
controller with no Ed25519 twin (a did:web, an X25519 did:key) makes the
grant unsatisfiable.

**Consent states the limitations before approval.** The share row on the
consent screen is visually distinct from every other grant and says three
things: the grant is read _and_ decrypt; it covers the collection's
contents from the moment of approval, not only future writes; and removing
access later stops future reads but cannot take back what has already been
read. The second holds without a hedge because every encrypted collection
carries epoch[0] from provisioning (wrapped to the user key, recipient
zero), so a share is always an `addRecipient` that escrows the grantee into
every existing epoch -- no rotation, and no envelope sits outside an epoch
the grantee now holds. An epoch-less descriptor is refused fail-closed
rather than seeded lazily at share time (it can only mean an unprovisioned
or torn collection), so no single-recipient residue exists that a reader
could fetch but not decrypt. Removal is the shares dialog behind a
collection row's "Shared" chip in the Storage collection list
(`unshareCollection`), not expiry -- the share TTL (`SHARE_ZCAP_TTL_MS`) is
long, because expiry would end the pull axis while leaving the grantee in
the key roster. A share also escrows the grantee into the collection's
blinded-index HMAC key when the descriptor carries one; removal drops that
wrap but never rotates the key (see "Client revocation and the epoch
cascade" for why, and what a removed grantee keeps).

**The grantee's half lives in `@interop/was-react`.** An app declares the
wallet-owned collections it wants in `WasAppConfig.sharedCollections`, which
adds the `https://w3id.org/byoe#shared-wallet-collection` descriptors to its
App Connect request; on approval a `SharedCollectionReader` fetches the
Collection Description through the delegated read zcap, builds the
epoch-aware cipher from the descriptor, and decrypts the raw envelopes
locally. It decrypts with the app's IDENTITY key-agreement key -- the X25519
twin of its own controller DID, exactly what `x25519RecipientFromDidKey`
derived wallet-side, so both sides land on the same `kid` with nothing on
the wire. It is the same key an app-provisioned collection admits the app
with: one recipient identity per app, whoever owns the collection.

Security notes:

- **Seed confidentiality**: the seed exists only in the wallet and the app
  (browser-direct CHAPI channel); no server ever sees it.
- **Origin binding**: enforced twice -- wallet-side at match/mint time
  (against the CHAPI requesting origin) and app-side in was-react's
  `parseSeedCredential`.
- **Grant scope**: unchanged from the generic capability-query model; the
  requested actions are normalized against the closed WAS action vocabulary
  and intersected with the limitation for the target's class (whole Space,
  protected collection, and share read-only; the full vocabulary for public
  collections and app-provisioned private collections), and the consent
  screen shows exactly what `resolveGrants` resolved. A grant left with no
  permitted action is unsatisfiable; it is not delegated empty. Resolution
  also consults the existing collections' state (a snapshot fetched from
  the Space, once for the consent preview and fresh again at delegation
  time, then kept current as the delegation loop provisions, so duplicate
  names within one request resolve against what the request itself
  created). A public collection is only ever created public, not converted
  (see "App Connect"): the idempotent re-grant on an already-public
  collection delegates without re-provisioning, and any target naming an
  already-public collection is classed public-collection and skips
  provisioning whether it arrives as a `#public-collection` descriptor, a
  `#private-collection` descriptor, or a plain URL string.
- **Challenge/domain**: unchanged DIDAuth verification app-side in
  was-react.
- **Per-user app identity**: an app key is minted from 32 fresh random bytes
  inside the connecting user's own wallet and stored in that user's own
  `app-connections` collection, so the app's DID -- and the X25519 recipient
  key derived from it -- is scoped to the **(user, origin, `appUrl`)**
  triple. The same app connected by two users gets two unrelated DIDs:
  independent randomness per user, not a derivation over (app, user), so
  there is no cross-user linkability and compromising one user's app key
  reveals nothing about another's, where a shared-root KDF would break
  every user at once. "Encrypted to the app's key" throughout this document
  therefore means _that user's_ instance of the app.

  This holds on the App Connect path, where the wallet mints the key and
  fills `controller` itself. A standalone `AuthorizationCapabilityQuery`
  names its own `controller`, so an app taking that route could supply one
  static DID for every user, wrapping each user's (still distinct) epoch
  secret to one app-held key. The wallet cannot detect this (it sees only
  one user's view), so it is an ecosystem expectation of app authors, not
  an enforced invariant: **a grantee DID SHOULD NOT be shared across
  users.** Either way the recipient key derives from the named controller,
  so a request can never pair controller DID A with recipient key B.

## Route map

| Path                                     | Component                | Notes                                |
| ---------------------------------------- | ------------------------ | ------------------------------------ |
| `/`                                      | `LandingPage`            | Public landing / wallet registration |
| `/login`                                 | `LoginPage`              | Passphrase login                     |
| `/signup`                                | `SignupPage`             | New account creation                 |
| `/recover`                               | `RecoverPage`            | Recovery-code account recovery       |
| `/guest-login`                           | `GuestLoginPage`         | Ephemeral guest session              |
| `/logout`                                | `LogoutPage`             | Clears session                       |
| `/wallet/get`                            | `WalletGetPage`          | CHAPI popup -- share a VC            |
| `/wallet/store`                          | `WalletStorePage`        | CHAPI popup -- accept a VC           |
| `/external/request`                      | `ExternalRequestPage`    | Interaction-URL request (no CHAPI)   |
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

## Ceremony inventory

The account ceremonies in one place -- the set the design gate in AGENTS.md
governs. The shared stage orders are canonical in wallet-core's
ARCHITECTURE.md ("Ceremonies and cascades"); this table lists the
freewallet-side wrappers and the app-only ceremonies, each row pointing at
the module that drives it. The mender column names how a torn run gets
finished (see Tear mending in the Glossary).

| Ceremony                                | Entry point                                                                                                              | Module                                                            | Shared half                 | Mender                                                                                                                                                                                                        |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Account genesis (durable)               | no-WAS signup; healed at every login                                                                                     | `src/session/signup.ts`                                           | `/genesis`                  | re-run (every stage an ensure)                                                                                                                                                                                |
| Credential-anchored genesis             | every WAS signup (default entry, non-remembered; the remembered and passkey flavors continue into self-enrollment below) | `src/session/credentialAnchoredGenesis.ts`                        | `/clientAnnex`              | re-run; the transient login's heal branch re-runs it, and mends a remembered signup torn before self-enrollment too                                                                                           |
| Self-enrollment at login                | durable login on a fresh browser; also the second half of a remembered or passkey signup                                 | `src/session/initSession.ts` + `src/session/pendingEnrollment.ts` | `/clientAnnex`              | pending record persisted pre-pivot; the next login's resume finishes it (a remembered signup's own resume entry included)                                                                                     |
| Client enrollment (two-party)           | Settings > Connected wallets + login page                                                                                | `src/components/EnrolledClientsSection.tsx`                       | `/enrollment`               | re-run with the same connect code                                                                                                                                                                             |
| Client revocation + epoch cascade       | Settings > Connected wallets                                                                                             | `src/session/revocation.ts`                                       | `/clients`                  | re-run; cascade-completion sweep                                                                                                                                                                              |
| Recovery-code issuance                  | Settings > Recovery codes                                                                                                | `src/session/recovery.ts`                                         | `/recovery`                 | re-run (nothing binds until the confirm)                                                                                                                                                                      |
| Recovery spend (durable and transient)  | `/recover`                                                                                                               | `src/session/recovery.ts`                                         | `/recovery`, `/clientAnnex` | durable: pending record pre-pivot + spend resume; transient: re-run, open gaps (below)                                                                                                                        |
| Recovery-code revocation                | Settings > Recovery codes                                                                                                | `src/session/recovery.ts`                                         | `/recovery`                 | re-run; cascade-completion sweep                                                                                                                                                                              |
| Unlock-credential rotation              | Settings (passphrase change, passkey removal)                                                                            | `src/session/credentialRotation.ts`                               | `/unlock`                   | torn-retirement repair at next passphrase login; login sweep; re-seal repair; a passphrase change's failed establishment fails the change with the old credential intact (establish-first), mended by a retry |
| Forget ceremony                         | Settings > Connected wallets, own row                                                                                    | `src/session/forget.ts`                                           | `/clientAnnex`              | re-run (wipe last); forgotten-browser detector at the next login                                                                                                                                              |
| Last-client transition                  | same row, `lastClient` confirm                                                                                           | `src/session/forget.ts`                                           | `/clientAnnex`              | re-run; the re-mint refusal is a retryable stop; refused outright on a pending passphrase entry or an unrecorded standing credential                                                                          |
| Update-key rotation                     | Settings                                                                                                                 | `src/session/accountSettings.ts`                                  | `/webvh`                    | re-run (persist-before-publish)                                                                                                                                                                               |
| Account deletion                        | Settings                                                                                                                 | `src/session/accountSettings.ts` + `wipe.ts`                      | app-side phase order        | re-run; a wipe failure after the unlock-method walk is accepted                                                                                                                                               |
| Shared wipe (executor, not user-facing) | consumed by the deletion-shaped ceremonies                                                                               | `src/session/wipe.ts`                                             | app-side                    | re-probe verification; the `unverified` report                                                                                                                                                                |
| Step-up ceremony                        | designed, not built                                                                                                      | ---                                                               | ---                         | ---                                                                                                                                                                                                           |

The open gaps (stated residues with no mender yet; see Tear mending in
the Glossary). Two are unbuilt repairs on client-less accounts, where no
login sweep will ever run: the transient recovery's roster-append repair,
and one for a user-key rotation torn mid-fan-out.

## What lives elsewhere (do not reimplement here)

Every `@interop/*` package is in-house (their checkouts sit beside this repo,
e.g. `../wallet-core`); a change needed in one of them is an in-house change --
export it from the owning package and import it, never copy or re-derive it
app-side. The map of the shared wallet layer is
[`../wallet-core/ARCHITECTURE.md`](../wallet-core/ARCHITECTURE.md) -- module
layers and dependency direction, the key hierarchy, the ceremonies and
cascades, and the permanent wire-level constants.

- **`@interop/wallet-core`** -- the correctness-critical logic shared with
  the DCW mobile wallet, imported by subpath. The sections above name them
  where they surface; the full set used here: `/webvh` (the did:webvh log
  and the document halves of the ceremonies), `/clientAnnex` (the client
  annex: the ladder, the annex log and its GC, and the ladder-anchored
  ceremonies -- credential-anchored genesis, self-enrollment, transient
  recovery; the verify-side halves stay in the base subpaths), `/keys`
  (+ `/keys/clientKeyRecord`; the user key, its wrap-set roster, the
  client-key record codec, client labels), `/keyring` (the unlock layer),
  `/genesis` (the account-genesis key mint and ceremony), `/enrollment`,
  `/recovery`, `/clients` (listing, disconnect policy, the revocation
  cascade orchestrator, the login-time roster policy), `/descriptors`,
  `/identity`, `/space` (collection layout, activity builders, `was-link`),
  `/request` (classification, matching, VP composition, exchanges, and the
  App Connect app-key credential), `/display`, `/resourceLog` (the
  wallet-domain residue of the resource-log client side: the did:webvh
  controller adapter `webvhResourceLogController` and the ceremony-tail
  license), and `/sync` (contacts LWW conflict resolution only --
  freewallet keeps its own RxDB replication driver in `src/lib/sync/`,
  over the wire contract from `@interop/was-client/sync`).
- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic client
  side: chain verification, the chain-head pin port (`ResourceLogPinStore`,
  `ResourceLogHeadPin`, `memoryResourceLogPinStore`) and its host-free slot
  keys, and the continuity/integrity refusal classes. Freewallet imports the
  pin port and refusal classes directly; the did:webvh controller adapter
  stays on `@interop/wallet-core/resourceLog`.
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

This is the repo's ubiquitous language: one canonical term per concept, used
the same way in code, tests, docs, and conversation. Where an entry ends with
`Avoid:`, that list names the synonyms this repo does not use. The convention
is canonical in isomorphic-lib-template's ARCHITECTURE.md, Glossary section.

Containment hierarchy (remote mode): **Space > Collection > Resource**.

- **VC (Verifiable Credential)** -- a W3C-standard JSON-LD document asserting
  claims about a subject, signed by an issuer.
- **VP (Verifiable Presentation)** -- a wrapper around one or more VCs, used
  when sharing credentials with a verifier.
- **DID (Decentralised Identifier)** -- a W3C-standard identifier. Freewallet
  uses only `did:key` DIDs, derived deterministically from an Ed25519 key pair.
- **did:key** -- a DID method where the identifier encodes the public key
  directly. No blockchain or registry needed. Freewallet derives each user's
  DID from their passphrase via `CapabilityAgent.fromSecret()`.
- **CID (Content-addressed Identifier)** -- a base64url-encoded SHA-256 hash
  of the canonicalized credential JSON (`cidFrom()` from
  `@interop/was-client/sync`). The primary key for stored credentials.
- **ZCap (Authorization Capability)** -- the authorization model for HTTP
  requests to the WAS server. Clients sign requests with their Ed25519 key;
  the server verifies the signature against the Space controller's DID. See
  the WAS server AGENTS.md for details.
- **CHAPI (Credential Handler API)** -- a browser standard that lets websites
  delegate credential operations to a registered wallet via a popup. The
  mediator is `authn.io`.
- **App Connect** -- the one-popup app login: a CHAPI `get` whose VPR carries
  an `AppConnectQuery`, answered with an app-key credential (matched by
  origin, `appUrl`, and seed-to-subject binding, or minted wallet-side on
  first run) plus capabilities delegated to its subject DID, in a single
  signed presentation. See "App Connect".
- **App key** -- a self-issued credential holding a 32-byte seed in
  `credentialSubject.seed`, bound to a requesting origin in
  `credentialSubject.origin` and to the application's canonical URL in
  `credentialSubject.appUrl`; issuer and subject are the seed-derived
  did:key (`CapabilityAgent.fromSeed`, `keyName: 'app-key'`). It is how a
  BYOE app keeps its identity/encryption root in the user's wallet
  (`@interop/wallet-core/request`). Every app key carries the marker type
  `AppKeyCredential` (`https://w3id.org/byoe#AppKeyCredential`); an
  externally arriving credential carrying the marker is refused at store
  time. Stored in the dedicated `app-connections` collection (synced,
  encrypted, never shareable, never grantable). See "App Connect".
- **Client / `clientId`** -- the keyed, custodied, revocable identity of an
  (app, user) pair: a keypair that can be a zcap grantee, a delegation
  `controller`, or an entry in a collection's key-epoch roster. For a BYOE
  app it is the app key's subject DID above, scoped to
  `(user, origin, appUrl)` and stable across browsers because the wallet
  custodies the seed and re-issues it on a browser-attested origin match (a
  client-only SPA holds no durable secret of its own). Not a "device": one
  machine hosts many clients (browser profiles, apps, accounts), and a
  client is not tied to hardware. "App session" is informal prose for one
  live session of a client; nothing named `appSessionId` is persisted.
  Avoid: device, device id.
- **Agent** -- a connected app whose key is agent-held rather than
  wallet-custodied: a CLI or LLM agent that mints its own did:key and asks
  the wallet for scoped, expiring, revocable grants through a standalone
  `AuthorizationCapabilityQuery`, with itself as `controller`. An agent is a
  zcap grantee, the same slot a BYOE app occupies; it is not a wallet
  client and holds neither the user key nor the unlock credential. Its
  grants are listed and revoked on the Applications page, keyed by its
  did:key. A future CLI-class wallet is a wallet client, not an agent.
  Avoid: transient client (the annex inventory), agent client, bot.
- **`writerId`** -- an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision. Its only jobs are history
  attribution and breaking last-write-wins ties; it is minted locally
  (`src/lib/writerId.ts`, a `localStorage` key), dies with a wallet reset,
  and is not derived from any secret, so it is never an identity. Unlike a
  `clientId` it can vanish and be re-minted with nothing carried over. Not
  a `replicaId` either: it is minted per browser profile while the local
  database is per user. Avoid: replicaId, device id, session id.
- **Share** -- granting a third party read AND decrypt access to one of the
  wallet's own encrypted collections, asked for with a
  `https://w3id.org/byoe#shared-wallet-collection` invocation-target
  descriptor. One `shareCollection` call grants both axes: a read-only
  Collection zcap and an entry in every one of the collection's key epochs
  (`addRecipient`, so the share covers what is already stored). Removed
  from the Storage page's collection list, never by expiry. See "Sharing a
  wallet collection".
- **WAS (Wallet Attached Storage)** -- an HTTP protocol for storing arbitrary
  resources in user-owned Spaces. Requests are authorized via ZCap.
  See [the spec](https://w3c-ccg.github.io/wallet-attached-storage-spec/).
- **Space** -- a storage area on the WAS server, owned by one controller.
  The account Space's id is an independent random identifier minted at
  signup and carried in the account pointer; unlock Spaces are addressed by
  `spaceId = base64url(SHA-256(unlock did:key))` (a discovery convention).
- **Collection** -- a named grouping of Resources within a Space.
  Standard collections: `private-credentials`, `public-credentials`,
  `wallet-activity`, `contacts`, `contacts-history`, `app-connections`.
- **Resource** -- an individual stored item (JSON or binary) within a
  Collection.
- **Controller** -- the `did:key` DID that owns a Space. Its Ed25519 key
  signs all ZCap-authorized requests.
- **Current-key-set rule** -- the server's authorization policy for a Space
  whose controller is a did:webvh: an invocation or delegation verifies iff
  its verification method is listed in the account document as resolved NOW
  (the server reads and fully verifies `did.jsonl` out of its own storage).
  Revoking a client is therefore one document edit: its requests and every
  delegation it ever signed stop verifying the moment its verification
  method leaves the document. Log-entry and roster proofs instead anchor at
  a version, so history never rots. See "The did:webvh identity".
- **Standing unlock credential** -- an unlock method (passphrase or passkey)
  in the standing configuration: beside locating the account through its
  unlock record, it holds a wrap of the user key in the roster (escrowed
  into every epoch, kept alive by rotation fan-out) and latent
  self-enrollment authority carried in that record -- a bridge delegation,
  the `delegatedClients` sibling delegation into the client annex, and a
  random ladder seed. A fresh browser holding nothing but the credential
  can self-enroll at login as a durable client (`rememberBrowser: true`)
  or enter the transient session (the default on a non-remembered
  browser). The credential's entropy bounds everything server-held that it
  alone decrypts; the rotation ceremony is the remedy when it leaks. See
  "Session & auth flow".
- **Bridge delegation** -- the pre-minted, narrowly scoped zcap carried
  inside an unlock or recovery record beside the account pointer: a
  PUT-on-`did.jsonl` capability (plus annex-log access where that applies)
  that is a credential's only bridge into the zcap profile; all it can do
  is extend the world-readable log, which keeps credential use loud.
  Re-minted by the revocation cascade and refreshed near expiry by the
  credential's own login.
- **Unlock trio** -- the three durable local artifacts one unlock method
  leaves on a browser, all keyed by its unlock Space id: the keyring cache,
  the wrapped client-key record, and the keyring-freshness pin. It is the
  whole of what a credential owns locally, so a fourth per-credential
  artifact joins it rather than each retiring site. "The trio" is the short
  form in prose; the code names it the local trio (`deleteUnlockLocalTrio`
  in `src/lib/sessionKey.ts`, the one deleter). The shared wipe enumeration
  walks one per registered unlock method (see "The shared wipe
  enumeration"). Avoid: local state, unlock artifacts, credential residue.
- **Ladder (update-key ladder)** -- the chain of did:webvh update keys
  derived from a standing credential's random ladder seed. Each rung is
  committed ahead of use as a hash in `nextKeyHashes` (the method's
  prerotation), and a rung reveals itself when the credential self-enrolls
  (a reveal-and-commit log entry signed by the current rung) -- how a
  credential extends the log with no durable client key in hand. The
  **ladder VM** is the verification method derived from the ladder
  (published under `assertionMethod` and `capabilityDelegation`; no
  invocation relation) that anchors an account with zero enrolled clients:
  installed by the credential-anchored genesis, the transient recovery, and
  the last-client forget transition; it signs the roster's entry proofs,
  the generation delegation, and the unlock records' re-minted bridges on
  such an account, and is struck from the document when its credential
  retires. Its bare did:key (`ladderVmAgent`) is the bootstrap identity the
  credential-anchored genesis creates the Space under.
- **Roster** -- three related uses. The **enrolled-client roster** is the
  did:webvh document itself (each client's verification methods). The
  **user key wrap-set roster** (`key-map/user-key.jsonl`) is the
  log-governed record whose current epoch IS the current user key, wrapped
  once per enrolled client's key-agreement key. A **key-epoch roster** is
  the per-collection recipient set on an encrypted collection's
  `encryption` descriptor. All three deliver key material or membership;
  none is a source of authority on its own (the document is verified
  independently, and wraps are minted only against log-verified keys).
- **Inventory** -- a credential's or client's set of durable entries in the
  account document, the annex log, or the ladder: its `keyAgreement` entry
  or commitment, its ladder VMs, its committed rung hashes, its annex rung
  hashes. Ceremonies install it; retirement sweeps it out (wallet-core's
  `removeUnlockKey`, the annex rung strike). An entry is
  inventory-changing iff the set differs from the previous version's (the
  ceremony-tail license's test). A named arrangement of an inventory is a
  qualified "configuration" phrase (the split, carry-over, or standing
  configuration), never bare. Avoid: posture, footprint.
- **Loudness** -- the design property that any exercise of
  credential-derived authority must first extend a hash-chained, auditable
  log (the account log, or the annex log) before it can read or grant
  anything. The stance it enables is detect-and-remediate rather than
  prevent: takeover with a phished credential is visible in the log and
  remediable by rotation. A mechanism "fails loudness" when it would let a
  credential exercise authority with no world-visible record.
- **Ceremony** -- an ordered sequence of durable writes across the
  account's systems (the account log, the roster, the unlock records,
  collection epochs, local storage) whose stage order carries an invariant:
  persist-before-publish, document-edit-first,
  decryption-material-before-authorization. Every stage detects its own
  completion from durable state, and every tear point has a stated mender
  (see Tear mending). Every ceremony has a **pivot**: the first durable
  write past which backward recovery is impossible. The derivability rule
  governs both sides of it -- a write sits before the pivot and stays
  inert until the pivot lands, or after it and is re-derivable from the
  pivot entry plus durable state alone (canonical in wallet-core's
  `decisions/0010-post-pivot-derivability-rule.md`, checked per-write at
  the design gate for every new or changed ceremony). The full list is the
  "Ceremony inventory" section; the shared stage orders are canonical in
  wallet-core's ARCHITECTURE.md ("Ceremonies and cascades"). Avoid: flow,
  workflow, wizard.
- **Tear mending** -- the umbrella for how a ceremony interrupted mid-run
  (a torn ceremony) gets finished. Three menders exist: a converging re-run
  (the same ceremony retried; every stage detects its own completion), a
  standing sweep (a background login-time pass, e.g. the
  cascade-completion sweep), and a repair (below). The derivability rule
  makes these menders sufficient: a post-pivot write is by construction
  re-derivable, so a re-run, sweep, or repair can always roll it forward
  from durable state. A write that fails the rule is a defect with its own
  work item, not a documented limitation. A stated residue with no mender
  is an open gap. Avoid: tear closure.
- **Repair** -- the mender of last resort: code waiting at the one entry
  point where the authority a torn state needs reassembles, detecting that
  state from durable state alone and finishing the ceremony. Used where
  neither a re-run nor a login sweep can fire (typically a client-less
  account, where no durable login ever runs a sweep). Always qualified by
  its torn state ("the torn-retirement repair",
  `repairTornPassphraseRetirement`), never bare. Avoid: completer, finisher,
  fixup.
- **Client annex** (`clientAnnex`) -- the transient-session counterpart of
  an enrolled client for the public-computer case: a did:webvh whose log
  lives in a capability-gated auxiliary Space beside the account Space,
  recording per-visit transient verification methods in GC'd
  **generations** instead of permanent account-log entries ("the annex" in
  prose). Enrolled clients live in the account document; delegated and
  transient clients live in the client annex. Transient keys invoke as
  `<clientAnnexDid>#<vm>`, and the annex itself never appears in the
  account document.
- **Generation delegation** -- the one Space-scoped zcap per annex
  generation, delegated to the annex DID by the durable client that mints
  the generation (or by the ladder VM while the account has no durable
  client). Transient keys invoke under it, and an App Connect grant from a
  transient session chains one deeper (root, generation delegation, app).
  Its TTL is matched to the generation's GC cycle.
- **CapabilityAgent** -- from `@interop/webkms-client`. Wraps the Ed25519
  key pair derived from the passphrase and exposes `getSigner()`.
- **ZcapClient** -- from `@interop/ezcap`. Wraps the session's root-key
  signer and adds ZCap headers to HTTP requests.
- **WebKMS / keystore** -- the key management server (`KMS_SERVER_URL`, by
  default the WAS server's `/kms` facet). Holds a per-controller
  **keystore** in which operational keys can live server-side; the
  passphrase-derived `keyAgent` remains the keystore's controller,
  client-side only. Accessed via `KmsClient`/`KeystoreAgent` from
  `@interop/webkms-client`; provisioned at login by `src/lib/kms.ts`.
- **Vault KAK** -- the X25519 key-agreement key that encrypts/decrypts the
  EDV envelopes: the user key's key-agreement key, recovered at login from
  the local client-key record and checked against the user key wrap-set
  roster (`key-map/user-key.jsonl`), which confirms it current or delivers
  a rotated one. Never replicated in unwrapped form and never held by the
  KMS; present for the life of every session. Avoid: PUK.
- **Session** -- the in-memory object (`src/types/auth.ts`) holding the
  logged-in user, their `ControllerProfile` (keyAgent + zcapClient), and
  their `StorageManager` instance.
- **Session durability** -- the axis deciding what a session may write to
  LOCAL durable storage, fixed once at login by the typed
  `SessionPersistence` handle at `profile.persistence` (see "Session
  persistence"). Two variants: durable (the `freewallet-session` database,
  the localStorage caches, the durable `writerId`) and transient (in-memory
  throughout, dies with the tab). A write site consults no flag. Avoid:
  posture, tier, mode.
- **StorageManager** -- the facade class in `src/stores/storageManager.ts`.
  Routes all wallet reads/writes to the local `BrowserStore` (the active
  replica) and exposes the optional `WASRemoteStore` for background
  replication and remote-only features (storage browser, export/import,
  quotas).
- **BrowserStore** -- the always-on local active replica, using RxDB /
  IndexedDB (Dexie). Holds every standard wallet collection on the generic
  synced-doc schema.
- **WASRemoteStore** -- remote storage client. Speaks the WAS protocol via
  `ZcapClient`. Handles the Space lifecycle, the storage-browser
  read-through over arbitrary collections and resources, export/import, and
  quotas; wallet data reaches it via background replication.
- **SyncController** -- the lifecycle around background replication
  (`src/stores/syncController.ts`): starts per-collection
  `replicateRxCollection` state machines on login, cancels on logout,
  re-syncs on reconnect. Uses the collection-agnostic adapter in
  `src/lib/sync/`.
- **DCC Known Registries** -- a public JSON registry of trusted issuer DIDs
  fetched from GitHub (`KNOWN_REGISTRIES_URL` in `app.config.ts`) and used
  during credential verification.

## ZCap Structure

A zcap answers "**who** can do **what**, **with** which resource, **given** what
restrictions": `controller` (who, a DID) / `allowedAction` (what, e.g. HTTP
verbs) / `invocationTarget` (with, a URL) / caveats like `expires` (given). A
delegated zcap also carries `parentCapability` and a `proof` with a
`capabilityChain`; a root zcap carries none of those.

**Root vs delegated invocation** (the `Capability-Invocation` header):

- Root: `zcap id="urn:zcap:root:<url-encoded target>"` -- just the id.
- Delegated: `zcap capability="<base64url(gzip(json))>",action="GET"` -- the full
  capability and its `proof.capabilityChain`, embedded and compressed.

**Signing:** requests are signed with Cavage HTTP Signatures Draft 12 (not yet
RFC 9421). The `Authorization` header signs `(key-id) (created) (expires)
(request-target) host capability-invocation`, plus `content-type digest` when
there's a body. The `Digest` header is a multihash (`mh=`, sha256). See the
[zCap Developer Guide](https://github.com/interop-alliance/zcap-developer-guide).
