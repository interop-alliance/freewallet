# Architecture

How Freewallet is structured -- layer map, session and auth flow,
storage model, CHAPI and App Connect flows, domain model, where shared
logic lives, and ZCap authorization structure. For contribution
conventions see [CONTRIBUTING.md](CONTRIBUTING.md); for agent-facing rules
(tech stack, env vars) see [AGENTS.md](AGENTS.md).

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
                    PRF retry prompt, clipboard, search)
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
  Repairs / sweeps  registryPasses.ts (the login-time registry chain),
                    pendingEnrollment.ts, pendingRetirement.ts,
                    registryReseal.ts, userKeyAdoption.ts, userKeyCascade.ts,
                    appKeySweep.ts, clientAnnexGc.ts, credentialCoverage.ts
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

## Session & auth flow

There is no external identity provider, and nothing about the account
derives from the passphrase. The passphrase (or a passkey PRF output)
derives only an **unlock identity** (`src/session/keyring.ts`), which
locates the account's **unlock record** in its own minimal unlock Space. The
unlock record carries none of the account's content keys.

One post-KDF question decides the rest (`routeUnlockLogin` in
`src/session/transientLogin.ts`). Does this browser hold a client-key record
for this credential? A browser holding none takes the transient composition,
the default (see "The transient login" under "Session persistence"). A
browser holding one proceeds as the **enrolled client** that record names. A
no-WAS deployment always proceeds on the browser-local tier.

An enrolled client's random 32-byte **client seed** is minted locally at
the step that enrolled it, and its private halves stay on the client. The
record gets there through an opt-in remembering step: self-enrollment, the
two-party client enrollment ceremony, or a remembered recovery spend.

```
unlock secret (passphrase | passkey PRF output)
  -> deriveUnlockSeed(KDF), expanded twice:
       unlock identity           -> unlock Space -> unlock record
                                      { controller, email,
                                        pointer { did, spaceId, host },
                                        bridge delegation, ladder seed
                                          (standing layout only) }
       standing client identity  -> { standing client seed,
                                      binding MAC key }
  -> routeUnlockLogin: this browser holds a client-key record?

     no (the default) -> transient composition
       mint a per-visit key in tab memory, enroll it into the client annex
       generation (one loud annex entry), unwrap the user key from the
       credential's standing roster wrap
       -> keyAgent + zcapClient signing as <clientAnnexDid>#<vm>, under
          the generation delegation
       -> in-memory persistence strategy, replica-less storage

     yes, or rememberBrowser: true -> enrolled client
       unwrap local client-key record (freewallet-session IndexedDB)
         -> { clientSeed, userKey, webvhUpdateKeys }
       -> agentsFromSeed(clientSeed) -> keyAgent (keyAgent.id === a did:key)
       -> ZcapClient(invocationSigner) -> zcapClient (ZCap-signed HTTP)
       -> browser-local persistence strategy, local replica

  -> { user: { id }, profile: { keyAgent, zcapClient, userKey } }
  -> StorageManager.initStorageClients()
  -> Session { user, profile, storage, isGuest }
```

An enrolled client's signing follows the account pointer. When the pointer
names a did:webvh (every promoted account), `zcapClient` signs with the same
client Ed25519 key under its verification-method id in that document
(`<did:webvh>#<multibase>`) rather than the did:key form. Only a keyId the
resolved document lists can authorize anything (the current-key-set rule, in
the Glossary). `user.id` stays the client did:key, also the App Connect
response VP's holder. A transient visit signs as its annex verification
method instead, and its response VP holds as the visit key's bare did:key.

On a WAS deployment with a promoted account, every unlock method is a
**standing credential**. Three cases cannot be standing, and their records
stay plain account pointers: a no-WAS deployment, a guest, and an account
not yet promoted. Besides locating the account, a standing record holds a
user-key roster wrap (escrowed into every epoch) and latent self-enrollment
authority: a pre-minted PUT-on-`did.jsonl` bridge delegation and a random
update-key ladder seed (`@interop/wallet-core/unlock`, bound by
`src/session/standingUnlock.ts`). On an account pointing at a client annex
generation, that establishment also appends one atomic hash-restating annex
commit entry with the new credential's rung-0 hash, signed by the login
credential's committed rung. Without it the credential could not enter a
transient session until the next generation swap. The append is
best-effort.

The document carries a passphrase-derived `keyAgreement` key only as a hash
commitment (`MultikeyCommitment`), which the roster's recipient resolver
verifies the roster-carried key against. A passkey's PRF-derived key is
high-entropy and publishes verbatim (see "Recovery codes").

The connect-another-wallet ceremony (see "The client enrollment ceremony")
survives for records without standing authority, for the rendezvous
onboarding flow, and as the future opt-in step-up approval policy. The
storage-partitioned CHAPI popup takes the transient session, since an
enrolled client per popup visit would litter the log.

**The remembered branch.** A fresh browser holding only the credential can
self-enroll at login as an enrolled client. It runs through the programmatic
`rememberBrowser: true` entry; a login-form choice is a planned follow-up.
Two loud entries extend the world-readable log through the bridge: a
reveal-and-commit entry signed by the ladder's current rung, then an add
entry publishing the minted client. Only then does the user key unwrap from
the credential's standing wrap. A self-enrollment is visible in the log and
remediable by rotation (see Loudness in the Glossary).

Between the two entries the required `onCommitted` seam writes the
pending-shape client-key record (seeds, controller, `pointerDid`, the
`pending` group, no user key), so the pivot publishes nothing only a live
tab could re-derive. Completion writes the enrolled shape, then advances the
visit's epoch pin; a rejecting pin write is logged and the login proceeds.

A later login routes a pending record to the resume
(`src/session/pendingEnrollment.ts`), discriminating on user-key absence.
`pointerDid` is the resume's account cross-check rather than a routing
member. The verified log history decides the arm. A VM-listed record
completes. A never-published one re-runs seeded with the recorded key set,
and
`BuiltOnHeadNotReachedError` refuses a log behind the recorded head. A
published-then-removed one wipes. An unresumable one is discarded and the
browser routes record-less. Fail-closed, and transport failures keep the
record.

The add entry leaves the credential's ladder VM standing, so its bridge
delegation and `delegatedClients` sibling keep verifying. That login's
refresh block renews both near expiry against the memoized verified account
document, re-signs them with the enrolled client's account key, and reseals
the record. Rot is tested under `capabilityDelegation` specifically, the
relation a delegation proof verifies against. A rotted embedded generation
delegation self-heals the same way (`ensureGenerationDelegationCurrent`),
signing with the ladder seed on `profile.ladderSeed`.

**Record authenticity.** The unlock identity's own Ed25519 key signs the
unlock record, the proof is verified before decryption, and a record whose
proof does not verify is refused (`KeyringRecordForgedError`). That closes
host forgery, since the record's JWE is sealed to the unlock KAK and a
malicious host could otherwise seal a record of its own that decrypts
perfectly. A standing record's account core (controller, pointer, ladder
seed) is also MAC'd under a credential-derived key the host never holds,
verified before the pointer is trusted, which closes the redirect a record
signed by another credential would reopen.

was-client's paths helpers build the unlock Space's request paths on both
the delegation and invocation side, so the bytes the server's
`allowedTarget` check compares cannot drift.

**The replay bound.** A signature cannot catch a replay, and a record the
account has moved off stays authentic forever. Catching one needs a pin from
an earlier visit, and this wallet keeps none
(`decisions/0012-no-durable-continuity-pins.md`), so a replay is a stated
bound rather than a refusal. Record stamps stay wall-clock: every write site
stamps `max(now, fetched record's createdAt + 1ms)`, so a lagging clock
still writes a record that supersedes the one it overwrites. Nothing
compares pointers either, since a rebind, a host migration, and a fresh
account under a reused passphrase all produce a newer signed record.

The bound on the whole construction: server-held material the unlock
credential alone decrypts is only as strong as that credential's entropy.
Against a malicious storage host running an offline KDF grind, zcap scoping,
TTLs, and revocation are worth nothing. So the unlock credential's custodian
must not be the storage host, and a wallet's security is limited by its
weakest standing unlock method. Client revocation does not bound an attacker
holding the credential itself, since they re-derive and self-enroll again.
Rotation is that remedy.

**The unlock-credential rotation ceremony.** A passphrase change and a
passkey removal both retire the old credential's standing rather than merely
rebinding the unlock record. wallet-core's `retireUnlockCredential`
(`@interop/wallet-core/unlock`) is the shared sequence, wrapped session-side
by `rotateOffUnlockCredential` (`src/session/credentialRotation.ts`). The
stage order is canonical in wallet-core's ARCHITECTURE.md: document
inventory first, then the annex inventory, then the roster-and-cascade tail
the client revocation runs (see "Client revocation and the epoch cascade").

A retirement that cannot claim the retired credential's ladder VM refuses
instead of completing, since a leftover VM stays a live delegation signer
holding a DELETE-only capability on the account Space. wallet-core raises
the name-stable `UnclaimedLadderVmRetirementError` before its entry
publishes, so the log is unchanged and the credential still stands. Both
ceremonies run that gate read-only as a pre-flight
(`preflightCredentialRetirement`), before establishment and before any
write, so a refusal never leaves a pending-shaped registry entry that only a
seeded run could clear. The in-retirement gate stays as defense in depth,
and a refusal there propagates rather than being recorded as a failed
retirement. Every caller matches the refusal by name. Recovery-code
revocation is unaffected, a code carrying no ladder.

Freewallet supplies the annex strike's invocation. On a transient session it
goes through the surviving credential's `delegatedClients` sibling
delegation, since the annex Space answers to the account did:webvh and a
root-invoked strike is refused as the masked 404 an absent resource returns.
A passphrase change uses the NEW credential's sibling and signs with its
ladder seed, the old credential's ladder VM having left the document in the
same edit. A passkey removal uses the acting credential's own. Which ladder
the session's login seed may fill is settled against the pre-edit log, so a
generation swap can never anchor on the credential being removed.

The tail's `onUserKeyAdopted` step re-seals the unlock-methods registry to
the rotated key in band, before that key persists into the client-key record
(`adoptRotatedUserKeyInBand`, `src/session/userKeyAdoption.ts`). The re-seal
needs this browser's stored copy of the OLD key, which persisting the
rotated one destroys on a single-client account, so a run torn after this
step still leaves a registry the surviving keys open. It fires before the
collection fan-out, while every collection still carries the epoch the
rotation retires, so it takes the key material alone. The callers then tear
down the registry entry and the old unlock Space under the ROTATED vault
keys, and adopt the rotated key into the live session's ciphers past the
fan-out (`adoptRotatedUserKey`), which is where the ciphers rebuild.

Document-removal-first is load-bearing. A run torn after it leaves the
roster keying a recipient the document no longer backs, exactly what the
login-time sweep detects and finishes. The limitation is the cascade's, and
Settings says so, since the ceremony is its documented "I think my
passphrase leaked" remedy. Ciphertext the credential's holder already
fetched stays readable.

A passphrase change runs establish-first on a WAS account. The old
passphrase is verified read-only, the NEW passphrase's whole standing
establishment is the first write, and only then are the old record and
unlock Space torn down and the old credential retired. A failed
establishment fails the change outright, leaving the old credential's
record, Space, and standing configuration unchanged, so a retry converges.
The plain rebind survives only where nothing can be standing. A change torn
between establishment and teardown leaves BOTH passphrases live and
standing.

The registry's passphrase entry is written only after the retirement
reports, because the entry's standing configuration depends on how the
retirement ended. Each degenerate state below has its own detector and
mender.

**Pending entry.** A retirement that failed before its document edit landed
leaves the entry naming the new unlock Space but the OLD credential's
standing configuration, the one state that still names a credential left
standing. While it stands pending, a second change from the same session is
refused (`PendingPassphraseRetirementError`), since the retirement would
otherwise remove one credential's document inventory while striking the
other's ladder. For the same reason registry writes matched by unlock Space
id carry the acting credential's key-agreement multibase, and a mismatch
writes nothing.

**Bare entry.** An entry carrying no identity members normally means the
credential has no document inventory to retire, so the change reports clean.
When the typed old credential still stands in the document, or the document
could not be checked, the change reports `rotation: 'unretired'` instead
rather than failing silently on the leaked-credential remedy.

**Torn-retirement repair.** The next passphrase login clears a pending entry
(`repairTornPassphraseRetirement`, `src/session/pendingRetirement.ts`): one
naming a credential other than the one logging in, with the login credential
itself standing in the account document. It retires the named credential and
records its own standing configuration. The login-credential check stops it
firing in reverse, where an old passphrase whose unlock Space delete failed
logs in after a change completed elsewhere. When the named credential
already left the document, only the entry is rewritten.

The same repair mends a BARE or absent passphrase entry, but only when it
names no credential at all, or names the login credential itself with no
recorded update key. An entry naming ANOTHER credential with no recorded
update key is left alone, the repair having no rung to attribute that
credential's ladder by.

**Bare passkey entry.** A passkey login runs the sibling repair,
`rebuildBarePasskeyEntry`, on its own present-but-bare entry, matched by
unlock Space and rebuilt from the keyring hit once the account document
publishes that passkey's `keyAgreement` key verbatim. An entry never written
is left alone, since rebuilding it needs the WebAuthn credential id a login
does not carry.

**Stale registry seal.** A registry sealed to a superseded user key gets its
own login-time repair (`repairStaleUnlockRegistrySeal`,
`src/session/registryReseal.ts`). A served record that fails to decrypt
under the current vault keys throws `UnlockRegistryStaleSealError` rather
than reading as absent. The repair tries each prior user key generation the
roster still escrows, newest first, then re-seals to the current key.
Best-effort, and read-only when nothing is stale.

At a remembered login the user key sweep, the re-seal repair, the
torn-retirement repair, the bare-passkey rebuild, the registry backfill, the
standing-delegation self-refresh, the ladder-rung refresh, the did:webvh
pointer heal, and the generation-delegation self-heal run on one ordered
promise chain; the annex GC sweep forks off its tail. A transient login runs
four of those passes on an ordered chain of its own: the re-seal repair, the
torn-retirement repair, the bare-passkey rebuild, and the registry backfill.
Each rides the visit's generation delegation and unwraps with the
credential's standing key. The user key sweep and the annex GC stay
remembered-only, neither having a ladder-anchored branch yet. The re-seal
repair runs first, since every registry writer downstream reads the record
and a stale seal would make each warn and skip. The sweep is early because
its roster convergence may rotate the key and re-seal the registry, and a
read-modify-write racing that re-seal would undo it within one login.

Navigation to the dashboard waits only on storage provisioning
(`session.storageReady`). The chain runs after navigation, on a separate
`session.registryReady` promise that never rejects; a failed stage is logged
and skipped. Both session types set that promise. A Settings-entered
ceremony that writes the unlock-methods registry (passphrase change,
passphrase or passkey add, rename, or remove, account deletion, client
disconnect, the forget ceremony, recovery-code issuance and revocation)
awaits `session.registryReady` at its own entry rather than racing the
chain's writes. So do update-key rotation, the Settings registry load, and
the recovery-codes health check. When storage provisioning fails, the login
page abandons the session, but `registryReady` still settles.

Every registry PUT is also a compare-and-swap on the ETag of the fresh read
it was based on, with a bounded re-read retry on a lost race. A concurrent
writer the ordered chain cannot serialize re-applies on the fresh record
instead of silently reverting it. The guard covers honest concurrency only;
the registry's bound is unchanged against a tampering host.

The `Session` object lives in the Zustand `authStore` and is in-memory only
(the passphrase is never persisted), so reloading the browser logs the user
out. Guest sessions use a random 32-byte seed directly and never touch the
WAS server or the KMS.

All four session entry points (login, signup, both CHAPI popup pages) funnel
through `initSessionFromSeed`. With a KMS configured (`KMS_SERVER_URL`), it
also provisions a WebKMS keystore for the controller (`ensureKeystore` in
`src/lib/kms.ts`, one keystore per controller by convention) and binds a
`KeystoreAgent` as `profile.keystoreAgent`. Operational keys can live
server-side there while the controlling key stays strictly client-side. The
keystore is created under the first client's did:key, and its controller is
promoted to the account's did:webvh alongside the Space's (non-fatal). No
server-held key is ever an update key or an encryption-roster recipient, and
the one key minted there today is the `authentication` key the account
document publishes (see "The KMS stage"). Provisioning failure is logged and
non-fatal. Only a remembered login provisions and binds the keystore, a
transient visit holding no key the keystore's controller document lists; the
ladder-signed delegation that would let it in is not built yet. Settings
shows whether the account document records the KMS-held key rather than
whether this session bound the keystore.

## The did:webvh identity (per-client keys, promoted controller)

The account's stable id is a `did:webvh` whose hash-chained log lives as
`did.jsonl` in the world-readable `id` collection
(`@interop/wallet-core/webvh`). Its document is the enrolled-client roster.
Each enrolled client contributes an Ed25519 verification method under
`authentication`, `assertionMethod`, `capabilityInvocation`, AND
`capabilityDelegation`, plus its X25519 twin under `keyAgreement`. Ids are
`<did:webvh>#<multibase>`. The signing method carries `controller:
<did:webvh>`. The key-agreement method carries `controller: did:key:<the
client's signing multibase>`, a marker naming its client. Every reader pairs
a client with its key-agreement key by that marker; nothing re-derives a
twin.

One KMS-held VM (`authentication`) stands in the document, a DIDAuth signing
key the wallet invokes client-side. It is the only KMS-held key the wallet
mints. No KMS `keyAgreement` key is minted, since that relation is the
source of record for user-key wrap recipients and no server-held key may be
a wrap target. No KMS assertion key is minted either, since log appends are
authorized by `assertionMethod` membership. That relation carries standing
credentials' ladder VMs beside client signing keys.

**Update keys are client-held.** `updateKeys` carries one update key per
enrolled client; apps get none. They derive from 32-byte seeds in the
wrapped client-key record, so the server cannot extend the log. Prerotation
stays on under a carry-over commitment convention: `nextKeyHashes` commits each
client's staged key AND each active key's own hash. The resolver re-checks
every entry's re-stated `updateKeys` against the previous entry's
commitments, so without the active-key hashes no non-rotating entry could
resolve. Rotation is per-client self-rotation (`rotateWebvhUpdateKey`),
swapping only that client's key: persist the rolled seeds into the
client-key record BEFORE the log entry publishes, then finalize.
`keys.json`'s webvh block is `{ did }` only; key roles do not live
server-side.

**Conditional publish.** Every ceremony publishes `did.jsonl` as a
compare-and-swap on the ETag of the read its entry was built on, so
concurrent clients cannot silently erase each other's entries. A lost race
surfaces as wallet-core's typed `WebvhLogConflictError`, and the ceremony
re-runs on the new head (`withLogConflictRetry`). The `did.json` projection
PUT stays unconditional, since it runs only behind a won log CAS. That
projection is the only producer of `id/did.json`; the wallet assembles no
did:web document of its own, so did:web and did:webvh resolution of one
account cannot disagree. It is the whole document with its ids rewritten.

**The projection's freshness on a credential-anchored account.** A
ladder-signed entry writes `did.jsonl` alone, since the bridge delegation is
a PUT on exactly that resource. So the ceremonies a standing credential runs
do not republish the projection, and a stale one keeps naming a client or a
credential the log has struck. That is a revocation bypass for a did:web
verifier rather than lag. WAS authorization is untouched, since the server
resolves a Space's controller out of `did.jsonl` and reads `did.json`
nowhere
(`decisions/0018-did-web-projection-refreshed-by-the-annex-writer.md`).

Three writers close it. The removal ceremonies PUT the post-removal
projection under the still-standing enrolled client's own root authority
immediately before their removal entry (see "The forget affordance"). A
ladder-branch ceremony that strikes an inventory -- a client disconnect, a
credential retirement, a recovery-code revocation -- PUTs it immediately
before its own entry too, through the account Space's `id` collection under
the visit's generation delegation, the store resolving that delegation at
each use. A failed PUT is warned and the entry still publishes, since a
projection under-listing a key the log still carries is the safe residue.
And every transient visit runs wallet-core's `ensureDidWebProjection`, which
re-derives the projection from the resolved log and republishes only on a
difference, invoking under the generation delegation. That delegation
targets the account Space's items subtree, which covers `id/did.json`, so no
bridge is widened.

The ensure's write is ordered twice over, since a difference alone does not
say which side is stale. It re-resolves the log under the visit's pins and
writes only if the refreshed derivation still differs, and the PUT is a
compare-and-swap on the ETag of the read it was based on. The window that
remains is between a ladder-signed entry and the next visit that runs the
ensure. A self-enrollment's add entry leaves the fail-closed
direction instead, a projection under-listing a client the log has. The
projection carries no signature and no chain, so a host may freeze it or
serve a different body per verifier; did:webvh resolution is the answer to
that.

**Log continuity within a session.** Resolving the world-readable log is
one-shot verification, and a valid PREFIX of the real log passes it: the
SCID, the DID check, the entry proofs, and chain verification all hold on a
prefix. A ceremony built on one would republish erased enrollments and
undone revocations. So every `verifyAccountLog` read carries
a chain-head pin (`persistence.logPins`, `@interop/vh-resource-log`'s keyed
`ResourceLogPinStore`), and a served log that is a rollback, a fork, or an
SCID or method switch against the pinned head is refused
(`ResourceLogContinuityError`). The pin is established at the visit's first
contact and advanced only by a log verifying past it; it never regresses.
One keyed store serves every log this session reads, under a per-log slot
key wallet-core derives of the form
`space/<spaceId>/<collection>/<resource>`, so two logs cannot clobber each
other's pin. The slot key is host-free, so a log served from a claimed new
host is checked against the pin already held. Every encrypted collection's
descriptor log takes a slot of its own
(`space/<spaceId>/<collectionId>/meta/log`).

The pin is a property of the store rather than an argument of the
ceremonies. Every did:webvh store this wallet builds carries
`persistence.logPins` under the slot for the log it serves, and a store
cannot be built without one. So the pin store exists BEFORE the first
account-log read: a login builds its persistence ahead of the keyring fetch,
and a caller whose own reads precede the login builds the persistence itself
and hands it in. The one read left on a fresh per-call store is the
`/recover` page's locate probe.

The pin store is in-memory on both persistence strategies
(`decisions/0012-no-durable-continuity-pins.md`). Continuity is checked
within a session and not across sessions. One login makes many log reads,
and the pin catches a host serving inconsistent versions across them.
Nothing carries a pin from one visit to the next, on any browser, so
remembered and transient sessions have identical continuity properties. The
successor to a pin is witnessing, which this wallet does not consume.

The bound is a visit's first read: a prefix served to a fresh visit is not
detected. That visit sees a stale document view, a revoked client still
listed or a retired credential still standing, and a rotation against it can
re-wrap the fresh user key to a client the account has revoked. That takes
host malice plus a previously-revoked client colluding. Against a passphrase
account the same malicious host can grind the credential offline anyway.

The pin rides the verified-log memo (`src/session/verifiedLog.ts`), the
recovery flows' direct reads, and the enrollment completion's first contact;
the login page renders the refusal (`auth.errors.accountLogContinuity`). A
`rollback` may be nothing worse than replication lag: nothing rolled back is
adopted, and a caller with a cached document view may carry on.
Ceremony-path `did.jsonl` reads also check the resolved DID against the
account pointer (`expectedDid`, which `verifyAccountLog` checks itself).
That is what refuses a mirror, since the did:webvh id embeds the Space id
and a mirror under a freshly minted Space id resolves to a DIFFERENT DID.
Login-time provisioning stays non-fatal, but a non-`rollback` refusal is
logged as an error and later account-log reads in the same login surface it
to the user.

**The Space-to-DID mapping.** One browser-local continuity artifact outlives
the visit, and it is not a pin: the account DID a data Space's log published
as, recorded by the client that published it (`saveAccountDidForSpace` in
`src/lib/sessionKey.ts`). It records what this browser did rather than a
version some host served. A signup torn between the publication and the
account-pointer backfill heals at a later login whose pointer still names no
did:webvh, and this mapping lets that heal state an `expectedDid` anyway.
Account deletion clears it through the shared wipe enumeration below.

The deletion ceremony runs from any session type. It re-derives the
credential fresh at its own confirm step rather than trusting the live
session's cached key, so a session held by anyone but the credential's owner
cannot complete it. A remembered session stops background replication and
closes the local replica first, so replication cannot race the local wipe.

Discovery comes next. The walk verifies the account log under the visit's
pins and requires this credential's ladder VM in the resolved document,
refusing the whole ceremony when the document anchors none. It reads the
unlock-methods registry under the visit's own authority and refuses on a
failed read, since a partial walk would strand Spaces the account can no
longer name. A registry sealed to a superseded user key is repaired in place
instead. A pending-shaped passphrase entry, and a standing credential the
registry never recorded, each name an unlock Space the walk cannot reach, so
each is reported as a residue and left for that credential's own next login.
Discovery also enumerates every `#DelegatedClients` value the account log's
history ever published, unioned with the acting record's own sibling target,
since a superseded pointer entry is append-only and its Space can still be
live. Every Space discovery finds gets its own probe, so the deletes that
follow can read a 404 as already-deleted rather than as a masked refusal.

The walk then deletes, in this order: the auxiliary annex Space(s); the KMS
keystore, when one exists, through its own route once that route exists
(skipped and reported until then); the sibling unlock Spaces other than the
acting credential's; the account Space; and, last, the acting credential's
own unlock Space, before the local wipe. Everything runs before the account
Space because every ladder-signed delegation the walk mints verifies against
the account document, which lives there.

Each delete but the last two rides a capability minted immediately before
its own DELETE and used once. On a transient session that is a ten-minute
DELETE-only child of the Space's own root, delegated to and invoked by the
ladder VM's own bare did:key re-derived at the confirm step, which resolves
from its own bytes and so outlives every Space the walk deletes. A sibling
unlock Space goes instead through a freshly minted DELETE-only child of that
entry's management zcap, the parent's `invocationTarget` copied verbatim. A
remembered session root-invokes the account and annex Spaces and signs a
sibling's child with the enrolled client's own account key.

Five states on a sibling refuse locally before anything is minted and are
reported as named residues rather than refusing the run or skipping in
silence: an entry recording no management zcap, one already expired, one
naming a delegatee this session cannot act as, one whose target is not this
deployment's URL, and one whose recorded actions lack the verb the child
would carry. That credential's own next login
re-delegates. A management zcap allowing DELETE but not GET leaves its Space
deletable and unprobeable, so the walk skips the probe and grades that
delete from an unknown discovery rather than refusing the whole run. A
sibling's DELETE is its REMOTE half alone, since every other credential's
browser-local state waits for the local wipe past the pivot, so a run that
refuses at the account Space has not quietly un-remembered this browser.

A `not-found` from any of these deletes is the server's masked 404, absent
OR unauthorized. Every discovery probe is status-exact for the same reason:
a read that resolves empty for a 404 and for an unparsable success alike
could record a live Space as absent, and an absence is what lets a later 404
grade as a deletion. The server admits the ladder-signed child under the
client-annex clause's third predicate: a ladder-signed delegation whose
target is a bare Space URL equal to its parent's unchanged (the parent a
delegated capability or the Space's own root) and whose action set is
exactly `['DELETE']` or exactly `['GET']`. The clause's locked property:
every ladder delegation either needs a loud companion entry to resolve, can
only write a log, or is a target-exact single-verb read or delete of one
Space of the delegator's own account. That delete is the one ladder
authority whose exercise leaves no record.

The account Space's delete is the pivot: past it the account is gone for the
acting credential, and nothing after it can fail the run. A 404 on a Space's
first delete counts as already-deleted only when discovery's own probe of
that same Space already returned 404 and the account log independently
corroborates the absence, or when this run already sent that same delete and
got a success. Every other 404 fails the run. Every phase before the pivot
refuses the whole run on failure, so a torn annex-Space or sibling-Space
delete leaves the account alive, enterable, and re-runnable. The acting
credential's own unlock Space is the one exception: past the pivot, a failed
delete there is retried in-run and then reported rather than failed, since
reporting failure would tell the user the account survived. The next login
with that credential offers to remove it instead. A wipe failure past the
pivot is accepted the same way, naming the surviving replica as an
unverified residue.

**The shared wipe enumeration** (`src/session/wipe.ts`) is the one list of
browser-local state an account leaves on a browser, and the one executor
that deletes it. Account deletion, the guest wipe, and the forget ceremony
consume it. It is snapshot-first, so every target derives from the live
session before anything is deleted. What it enumerates:

- The client-keyed families (the unlock-methods cache, the passkey-safety
  notice, the replica-database prefix, the local-mode cache scope), derived
  from this browser's own client did:key rather than the account controller.
- Each unlock method's unlock-local state, derived from the registry walked
  across every method and always including the session's own login
  credential. A registry read lost to a transient server error narrows the
  enumeration to the other methods and is reported on the wipe outcome
  (`unlock-methods-registry`), instead of leaving this browser's client-key
  record behind a wipe that reads clean.
- The Space-to-DID mapping, keyed by the account Space id.
- The per-account localStorage families: the descriptor and meta caches
  under both scope schemes.

No continuity pin is enumerated, because none is stored (see "Log continuity
within a session"). Cross-tab teardown precedes the replica delete, a
broadcast asking sibling tabs to drop open handles, and completion is
verified by re-probing rather than resolved while blocked. Global UI prefs
stay out; the global `writerId` clears only on the forget grade.

`indexedDB.databases()` is a discovery and verification aid rather than the
deletion gate: the session and replica databases go by known name whether or
not the engine can enumerate. A deletion the executor could not confirm, or
a replica prefix `databases()` alone would have named, is reported on the
outcome's `unverified` list rather than counted as a clean wipe.

Limits no enumeration reaches: deleted IndexedDB data stays forensically
recoverable, plaintext `public-credentials` rows included; the CHAPI popup's
partitioned third-party buckets are unreachable from any top-level wipe; and
the mediator-origin (authn.io) handler-registration bit records that a
wallet was used in this browser. Only clearing the browser profile removes
those. One more, on the client axis: a SIBLING enrolled client's replica and
caches survive a deletion run from a transient session, since the
client-keyed families are named by the acting session's own client did:key
and a sibling's lives only inside its own sealed record. What survives is
ciphertext with no key, but it survives.

**The forget affordance** (`src/session/forget.ts`) removes this browser
from an account, in two grades split by whether the unlock credential is in
hand.

From a live remembered session (Settings > Connected wallets, the current
client's row) it is the **forget ceremony**, wallet-core's
`forgetEnrolledClient`; the stage order is canonical in wallet-core's
ARCHITECTURE.md. The user key rotates off this client's roster wrap and
every encrypted collection re-epochs, both under this client's
still-standing authority, the self-forget inversion of the revocation's
document-edit-first order (wallet-core decision 0008). Then ONE atomic
ladder-signed removal entry through the login credential's bridge takes the
client's whole document inventory out. Immediately before that entry
publishes, the post-removal did:web projection is PUT through this client's
own root-authority `id` store, which is required (see "The projection's
freshness on a credential-anchored account"). The idempotent
already-forgotten path writes no projection at all, and the next transient
visit's ensure is that projection's mender. Only then does the
local teardown run: background replication stops first, so the poll timer is
not left driving a re-sync against a replica the next stage deletes, then
the local wipe (`clearWriter: true`, the wipe's one writerId consumer).

Wipe-last is the tear story. A run torn before the entry reads as "not
forgotten", and a re-click resumes. A run torn between the projection PUT
and the entry leaves `did.json` omitting a client the log still lists, the
fail-closed direction, and the re-run re-PUTs it. The other direction,
removal published but wipe torn, is caught at the next login by the
**forgotten-browser detector** (`assertClientStillEnrolled`): an enrolled
client-key record (its user key present) still here while the cleanly
verified account document no longer lists this client's verification method.
The detector finishes the wipe from what the keyring hit alone derives and
surfaces "this browser's access was removed" in place of raw authorization
errors. It persists nothing.

The detector sits past a record-to-account cross-check. An enrolled-shape
record whose stamped `pointerDid` names a DIFFERENT account than the unlock
record points at is stale residue rather than a forgotten browser: a prior
account under a reused passphrase, gone server-side, so no wipe ever touched
this browser. The stale wipe clears what the record alone derives (the dead
account's replica and caches, and the credential's whole unlock-local
state), and the login re-routes once as a record-less browser without
reaching the detector. A pending-shape record is spared for the
resume instead (`decisions/0007`), whose published-then-removed branch hands
the removal case back to the same wipe.

The ceremony needs the standing members the login stamped on the profile
(`profile.standingUnlock` beside `profile.ladderSeed`). It re-seals the
unlock-methods registry to the rotated user key while this client still
invokes, since surviving readers would otherwise find it sealed to a retired
generation. It writes no unlock record: every record's frame proof, bridge,
and sibling delegation are signed by its own credential's unlock identity
and ladder VM, which this removal entry does not strike. It refuses the
account's last enrolled client with wallet-core's name-stable
`LastEnrolledClientForgetError`.

That refusal routes to the **last-client transition**: the same
`forgetThisBrowser` entry with `lastClient: true`, chosen from the listing
and confirmed against transition-stating copy (a stale listing's refusal
flips the dialog to that copy for a second confirm). It runs wallet-core's
`forgetLastEnrolledClient`, the two-entry ceremony that lands the account
client-less and ladder-anchored (wallet-core decision 0004). Its stages, in
order:

1. The ladder VM's install entry, while the client's inventory stays.
2. The roster rotation off this client's wrap: ladder-signed and anchored at
   the install entry (the ceremony-tail license's inventory-changing
   version), but HTTP-invoked under the still-standing client. The
   roster store is the session store with the ladder VM's signer, so the
   roster head stays signed by a key the post-removal document lists. The
   ceremony anchors that store's controller view itself
   (`setMinimumControllerVersion`): at the pre-transition head for its
   opening probe, and at the post-install head for the rotation.
3. The collection fan-out.
4. The forced replacement of the embedded generation delegation with a fresh
   ladder-signed one, and the revocation of every still-unexpired
   ladder-signed delegation the annex history embedded.
5. The login credential's own record (`rebindLoginCredentialRecord`, the
   ceremony's required `onBeforeRemoval` seam): its bridge delegation and
   `delegatedClients` sibling re-signed by the ladder VM, the record
   re-sealed through the keyring hit's re-bind closure, and the registry
   pair refreshed in this client's last window of registry authority. It is
   the only unlock record the transition writes.
6. The removal entry, with the post-removal did:web projection PUT through
   this client's root-authority `id` store immediately before it publishes.
7. The local teardown: replication stopped, then the local wipe.

Stages 2 through 5 precede the removal entry because the removed client's
signatures rot there, and on a client-less account no remembered login's
refresh block will ever heal them.

The transition's refusals:

- A registry the transition cannot read refuses up front, since the pending
  check below is computed from it, as does a session whose hit carried no
  re-bind closure.
- A pending-shaped passphrase entry refuses up front with
  `PendingRetirementForgetError`: one recording an unlock key-agreement key
  that is not the credential the record at its unlock Space is sealed to,
  the residue of a passphrase change torn before its retirement landed. The
  record itself is the detector, since an entry naming another credential is
  also what a superseded passphrase's own login sees on a healthy account.
  Its mender is the torn-retirement repair, which runs on a transient login
  too, so the next login with a different standing credential clears it.

Readers settle a record's proof against `currentAccountRecordSigners`, the
enrolled clients' signing keys plus the ladder VMs the document lists.

From the login page's authenticity and continuity refusals (reachable from
passkey failures with no typed passphrase, reset between attempts) it is the
**no-unlock-material grade**. Nothing can be derived or signed, so no
ceremony runs. The wipe is whole-database and browser-scoped: every replica
database, the session database, and the per-account localStorage families,
with the cross-account blast radius stated in the confirm copy. Each
account's standing document client remains, unflagged anywhere, and the copy
points at the Connected wallets disconnect from a logged-in client. A
never-remembered browser is told it holds nothing to delete.

**Controller promotion by ordering.** The Space id is an independent random
identifier minted at signup (`mintSpaceId`) and carried in the account
pointer, rather than a hash of any controller: the did:webvh id embeds the
Space id, so a derivation would be circular. Unlock Spaces keep their
`hash(unlock did:key)` addressing, a discovery convention rather than an
identity. That deterministic unlock address is an accepted existence oracle
for passphrase guessing; the bound is KDF strength rather than placement.
The DID's embedded Space id need not equal a controlled Space's id, since
one did:webvh may control several Spaces on the host.

Every WAS signup bootstraps the Space under the ladder VM's bare did:key
inside the credential-anchored establishment, publishes the log, and PUTs
the Space Description carrying `controller: <did:webvh>`, before any
enrolled client exists. `StorageManager.ensurePromotedController` is the
login-time healer: it swaps the live session's signing to the promoted keyId
and re-runs the promotion PUT when a session finds it missing. Only a no-WAS
deployment's plain genesis promotes on that path from scratch. From then on
the server resolves the controller by reading and fully verifying the log
out of its own storage (SCID-pinned, hash chain, prerotation, update-key
signatures), and authorizes by the current-key-set rule (see Glossary).

## Account genesis (`@interop/wallet-core/genesis`)

The signup wizard starts the ceremony in its own click handler, since the
passkey path spends the WebAuthn user gesture there, and navigates to the
lobby (`/lobby`) at once, so the run outlives the page that began it. The
ceremonies report stage boundaries through an observational `onStage`
notifier. The lobby renders that as a step feed and routes from the settled
outcome: the dashboard, `/login` when the credential already had a wallet,
or back to the wizard with the error copy.

Every WAS signup runs the credential-anchored establishment below, whose
genesis order promotes the Space controller inline. It mints no enrolled
client, so the account lands ladder-anchored and is reachable by the
credential alone from any browser. The plain genesis
(`ensureAccountGenesis`) is the other path: a no-WAS deployment's signup,
and the login-time heal for any account it provisioned.

**The credential-anchored establishment.** Every WAS signup, passphrase or
passkey and remembered or not, runs this establishment first, through
wallet-core's `establishCredentialAnchoredAccount`
(`@interop/wallet-core/clientAnnex`). The stage order is canonical in
wallet-core's ARCHITECTURE.md, "Ceremonies and cascades".
`src/session/credentialAnchoredGenesis.ts` is a thin binding over that
orchestrator, supplying the app-specific hooks: the unlock-record codec, the
roster store builder, the KMS-authentication thunk and keystore-promotion
closure, and the callers' registry-write `beforePromotion` hook. That
registry write is read-first. The entry is upserted into an existing
registry, and a refused read skips the write rather than starting from an
empty one, since the heal re-run fires the same hook. The establishment's
own entries end with the `#DelegatedClients` pointer, a second rung-0-signed
account-log entry, and the Space controller is promoted last.

Persist-before-publish applies transposed. The unlock record carrying the
ladder seed, with an interim bridge delegated by the ladder's bare did:key,
is durably written BEFORE the Space is created and before rung 0 publishes.
The Space is bootstrapped under the ladder VM's bare did:key, re-derivable
from the record's ladder seed, so a tab death before promotion strands
nothing. The roster's epoch[0] wraps the user key to the credential's
standing KAK under a ladder-signed entry proof.

Entry paths. A non-remembered browser continues into the transient
composition (see "Session persistence"), with zero local residue. A
`rememberBrowser: true` signup follows the establishment with the remembered
login, whose self-enrollment makes this browser an enrolled client from the
record just written; that login builds its own pin store and meets the
account log at first contact. A signup torn before the self-enrollment is
resumed by a later `rememberBrowser: true` attempt, which re-runs the
establishment from the record's own ladder seed and then self-enrolls. The
passkey signup is the same shape under the WebAuthn PRF-derived credential:
WebAuthn `create`, this establishment, then the remembered passkey login.

The establishment is an ensure, so a torn signup converges by re-running,
the published log adopted by ladder attribution. `createDID` timestamps the
genesis entry, so a naive re-create would mint a different SCID and never
land.

**The KMS stage** (`kms-authentication`, `ensureKmsAuthentication` in
`src/lib/kms.ts`). With `KMS_SERVER_URL` set, the establishment provisions
the one KMS-held key the account document publishes: a single Ed25519
`authentication` key, in a keystore created under the ladder VM's bare
did:key, recorded as `{ authentication: { vmId, kmsKeyId } }` in
`key-map/keys.json`. The genesis entry then carries that key under the
account's own controller, and the promotion stage moves the keystore
controller to the did:webvh beside the Space's. Nothing else is minted here,
since no server-held key may be a wrap recipient or stand under
`assertionMethod`.

The stage runs alongside Space provisioning, joined before the genesis
entry, and orders its own Space-touching half on a `spaceReady` promise.
Only the `keys.json` read and write touch the Space. The probe starts at
once, over a plaintext codec, so a 404 from an absent Space reads as the
same absence an unwritten `keys.json` does, and the keystore the mint path
needs is acquired only past the probe's miss. The write joins on
`spaceReady` and carries `If-None-Match: *`; the genesis then rewrites the
same resource under `If-Match` on that ETag, adding the `webvh: { did }`
block. A lost race adopts the served map.

A served map is adopted only when the multibase in its `vmId` names a key
this session's own keystore lists. The genesis takes that `vmId` verbatim
into the world-readable document, so a host serving a map naming an
attacker's key would otherwise get it published under `authentication` and
signed by the account. The check creates nothing. A non-creating keystore
lookup that finds nothing, and a `listKeys` listing that does not name the
key, are both the integrity verdict and refuse at once. A lookup or listing
that THROWS is transport instead, retried briefly (three attempts, well
inside the stage timeout) and then refused with the last error as its
cause.

The stage is best-effort, with a timeout that starts once the Space is ready
so slow Space provisioning cannot eat it. A timeout can still win with the
`keys.json` write in flight and leave a map the genesis entry does not
publish; the next run adopts that map after the same listing check. A failed
or hung KMS leaves the account with no `authentication` relation in its
document, which is a complete account presenting did:key, and Settings shows
the state. Because the stage's failure is collected rather than thrown, the
account pointer still binds and no re-run fires the stage again. That
residue is an open gap (see "Ceremony inventory").

**The plain genesis.** `ensureAccountGenesis` is shared with the mobile
wallet, and `mintAccountKeySet` mints the whole key set locally: Space id,
client seed, user key, did:webvh update-key seeds. The order is Space
provisioning under this client's did:key, the KMS authentication binding
(the one stage that overlaps its neighbour), the did:webvh genesis, the user
key roster strictly after the DID publication, and key epoch[0] on every
encrypted collection. Every stage detects its own completion from durable
state, so a torn run heals by re-running at the next login.
`StorageManager.#provisionUserCollections` is the one caller: it supplies
the KMS stage and the roster store builder, adopts the published DID (also
dropping the verified-log memo unless it already holds a settled document
for that DID), and maps per-stage failures onto warns.

There is no opt-out (`decisions/0017-did-webvh-always-provisioned.md`).
Every WAS account provisions did:webvh, and the reduced path is reached only
by a session that structurally cannot produce a log: one with no keystore
agent, or no client update keys or user key. It runs Space provisioning, key
epochs, and the KMS binding alone, publishes no `did.json`, and so presents
did:key. A Space that never came up is the one fatal stage:
`AccountGenesisSpaceError` is rethrown and login fails.

The plain path keeps the keyring bind before any data Space exists, is
called with `promoteController: false`, and leaves promotion and healing to
`ensurePromotedController`. The no-WAS plain signup keeps its own
`userExists` probe; on a WAS deployment the establishment's create-nothing
probe (`fetchTransientKeyring`) is the one signup-time existence check.

## Session persistence

Sessions are in-memory only. A login builds the whole `Session`: a
`keyAgent`, the user-key-backed vault KAK, and the `zcapClient` signing
every WAS request. A transient login, the default, builds it from a
per-visit key minted in tab memory and the user key unwrapped from the
credential's standing roster wrap, and persists none of it. A remembered
login builds it from this client's stored seed and cached user key, and
signs with that root key. The client seed and user key persist only inside
the wrapped client-key record, so nothing live is written unwrapped and a
reload drops the session. The vault is unlocked while a session exists and
gone once it ends; there is no "locked vault" state. Navigation to the
dashboard is gated on `session.storageReady` alone, and the login-time
registry passes run afterward on `session.registryReady`.

**The persistence strategy** (`src/session/persistence.ts`). Which storage
tier a session may write to is decided once at login, by the typed
`SessionPersistence` object at `profile.persistence`. The tier is a property
of the strategy's type, so a write site consults no flag and takes no branch
(`decisions/0001-no-memory-overlay-storage-fork.md`). Riding the strategy:
the unlock-methods registry cache, the passkey-safety notice, the
descriptor/meta cache pair (one instance per scope per session), and the
`writerId` mint. The keyed chain-head pin store and the roster-epoch pin
ride it without varying by tier, being in memory on both variants
(`decisions/0012-no-durable-continuity-pins.md`).

The in-memory variant is the default, carried by every transient login. Its
whole reach is the pre-session in-memory store family, no member of which
reaches the session database, and it dies with the tab. The login carrying
it skips storage provisioning, the KMS keystore, the login-time roster read,
every login-time sweep, and the bare-Space-URL `userExists` probe. The
variant also carries the visit's client-annex identity as a required member
of its type (`InMemorySessionPersistence`): the annex DID every WAS request
signs under, and the generation delegation every request rides. Both surface
to the storage layer as `profile.invocationCapability`.

The browser-local variant is the opt-in one, carried by a login on a browser
that holds a client-key record and by a guest session. It is the
`freewallet-session` database, the localStorage caches, and the persistent
`writerId`. It alone carries the `idb` factory, so code needing that
database must hold it.

Global UI prefs (theme, language) are not session state and ride a sibling
seam (`src/lib/prefsStorage.ts`): during a transient session, pref writes
land in an in-memory overlay that shadows reads, which still fall through to
localStorage. The logging seam (`src/lib/log.ts`) is module-global, rides
neither the strategy nor the overlay, and writes no stored state; its one
localStorage touch is a lazy read of the `interop:logger` debug filter
key.

**Replica-less, capability-bound storage.** A transient session constructs
no `BrowserStore` at all, since the versioned RxDB open alone creates the
per-user database. `StorageManager.initStorageClients` builds one only on
the browser-local strategy, and a replica-less session serves every
synced-collection operation through the remote-direct backend, over the
remote WAS collections. The sync controller never starts without a local
replica; `StorageManager.hasLocalReplica` is its gate. The transient CHAPI
popup is this same shape (see "Remote-direct popup storage").

`WASRemoteStore` accepts an optional invocation capability, threaded from
`profile.invocationCapability`, that every request rides. wallet-core's
`userKeyRosterDescriptorStore` takes the same option, so a session holding
only a delegated Space-subtree zcap (the generation delegation) can read the
roster. Absent the option, every request invokes the root capability.

**The transient login (the default on a non-remembered browser).** Both
keyring login entry points run one post-KDF routing decision
(`routeUnlockLogin` in `src/session/transientLogin.ts`). With a WAS server
configured, a browser holding no client-key record for this credential takes
the transient composition; one holding such a record proceeds remembered. A
record whose stamped `pointerDid` names a different account than the unlock
record points at is stale residue of a prior account under a reused
passphrase: it is wiped and the login re-routes once as if the browser held
none. A PENDING-shape record counts as remembered, the resume being its one
mender; the resume's discard outcome deletes it, so the next attempt probes
record-less again.

The record probe is create-nothing. `hasClientKeyRecord` checks
`indexedDB.databases()` before opening, and on an engine with no
`databases()` falls back to a versionless open whose `versionchange`
transaction is aborted on `oldVersion === 0`. Nothing surfaces the route it
picks, since the login form carries no remember-this-browser control.
The CHAPI popup runs the same routing with the Storage Access API handle as
the probe's factory (see "The popup follows the browser's routing").

An explicit `rememberBrowser` input forces either side. `true` is the
programmatic remembered entry, the standing self-enrollment, passed by a
remembered signup's own login half, its resume, and the recovery tail.
`false` on a remembered browser refuses (`AlreadyRememberedError`) rather
than forking the routing decision.

The composition (`transientSessionFromKeyringHit`) runs the create-nothing
unlock-record fetch, the account log verified under the visit's pins, the
client-annex generation-readiness stage, a per-visit key minted in memory
and enrolled into the generation, the user key unwrapped from the
credential's standing roster wrap, and a session on the replica-less storage
variant. A signup hands the establishment's final head in as an already-read
log, so the verification runs with no fetch.

The readiness stage (`ensureClientAnnexGenerationReady`) runs on every
visit: a no-op report on a healthy ladder-anchored account, otherwise a
ladder-signed mend. The mend mints a missing generation, renews an expiring
or expired generation delegation, re-mints a missing or misaimed sibling
delegation, and renews the record's own bridge delegation when it has
expired, entered its 30-day renewal window, or lost its signer (the key left
`capabilityDelegation`). It re-seals the fresh bridge and sibling into the
remote unlock record, and the visit stamps the renewed bridge rather than
the served one. A mend that moves the account-log pointer re-verifies the
log before enrollment. On an account whose document anchors no ladder VM of
this credential's, the stage refuses with
`ClientAnnexGenerationUnavailableError`, resolved as a value: the
composition falls back to the record's own `delegatedClients` sibling
delegation and the pointed generation's embedded delegation.

The per-visit key enrolls through whichever sibling delegation the readiness
stage produced (wallet-core's `enrollTransientClient`, the loud entry before
any authority). Its first attempt builds on the generation head that stage
verified, and a lost compare-and-swap re-reads the head under the same pin.
The roster read signs as `<clientAnnexDid>#<vm>` under the generation
delegation. A transient client never joins the roster, so nothing
escrows.

Every unavailable state refuses with a typed
`TransientLoginUnavailableError`: a record without standing authority, an
unpromoted account, no reachable generation or generation delegation on
either path, no roster. The readiness stage's own refusal rides as `cause`
when it ran and failed first. The login page and the CHAPI popup render
per-reason refusal copy from one shared mapping, `transientRefusalKey`, and
no reason opens the connect-this-browser card. Network errors rethrow
unchanged, so a flap stays distinguishable from a lapse.

The session primes the verified-log memo (`profile.verifiedLog`) from the
composition's latest verified head, and stamps `profile.ladderSeed` and
`profile.standingUnlock` from the credential's standing members, the fields
a remembered login stamps too, so a mid-session ceremony can sign as the
ladder with no enrolled-client signer in hand.

**The did:web projection ensure.** The visit also keeps `id/did.json`
current (see "The projection's freshness on a credential-anchored
account"). It runs wallet-core's `ensureDidWebProjection` after the
per-visit key is enrolled, since an invocation under the generation
delegation needs that key's verification method in the annex document first.
The store is aimed at the account Space's `id` collection under that
delegation, signing as the annex VM, and the collection is world-readable,
so the freshness read is an unauthenticated GET. The visit supplies the
ensure's `refresh` over `persistence.logPins`, so a write lands only when
the re-verified derivation still differs. The ensure is best-effort, not
awaited, and warn-logged on failure. A CHAPI popup visit runs it, unlike the
registry chain below, and a visit whose mend arm published skips it.

**The management-zcap mint and refresh.** The record fetch also mints the
unlock Space's management zcap, a local signature by the unlock identity's
own client that costs no request. The visit writes it to the acting
credential's registry entry when the stored copy is absent, expiring, or
narrower than the mint (`refreshTransientManageCapability` in
`src/session/unlockMethods.ts`). Without this pass every credential's
management zcap would lapse a year after its bind on an account that never
remembers a browser, taking the account's own deletion path with it.

This is the one registry write a healthy transient login makes, and every
constraint on it narrows. It creates no registry and no entry, touches no
entry but the acting credential's (matched on unlock Space id), skips a
pending-shaped entry recording another credential's key-agreement multibase,
rides the visit's generation delegation as the annex VM inside the
registry's own compare-and-swap, and warns and skips on a read that throws.
It runs as the LAST stage of the registry chain below, since it
compare-and-swaps the same entry those passes rewrite. A CHAPI popup visit
skips it.

**The login-time registry chain.** The visit runs four of the login-time
registry passes on its own `session.registryReady` promise after navigation:
the stale-seal repair, the torn-retirement repair, the bare-passkey rebuild,
and the registry backfill, with the management-zcap refresh above as the
last stage (the chain's ordering is under "Session & auth flow"). Each rides
the visit's generation delegation and unwraps with the credential's standing
key, each failure is logged and skipped, and the chain is not awaited. A
CHAPI popup visit skips it, and the user key sweep and the annex generation
GC do not run here. Nothing in the registry's write protocol turns on the
session tier.

The tears a torn credential-anchored signup can leave are mended by
wallet-core's `mendCredentialAnchoredAccount`; the app binding sits beside
the establishment's in `src/session/credentialAnchoredGenesis.ts`, and the
arm order is canonical in wallet-core's ARCHITECTURE.md. Four arms fire at
most once per invocation, each detecting its state from durable state alone:
the establishment arm (a standing record whose pointer names no did:webvh,
re-binding the record instead when the log already resolves and the ladder
attributes it), the promotion arm, the roster-and-epochs arm (an absent
roster: a fresh user key, epoch[0] wrapped to the credential's standing KAK,
the collection epochs installed under the key the roster delivers), and the
registry arm, which re-fires the read-first registry hook when an earlier
arm mended. Nothing encrypted predates the roster arm's mint, so a fresh
user key orphans nothing. A partial collection fan-out is not a refusal: the
stranded collections are named in a warn, the only trace on a client-less
account no login sweep revisits.

The composition maps the mend's report onto its typed refusals:

- `unpromoted-account` -- a non-converged establishment arm. A
  transport-class arm failure rethrows unchanged instead, so a flap stays a
  flap;
- `no-user-key-roster` -- the roster is still absent;
- `no-user-key-wrap` -- the roster carries no wrap for this credential, a
  state no retry can help. Both paths it arrives by map here: the mend's own
  `no-wrap` outcome, and the roster read's unwrap throw;
- `roster-mint-refused` -- the roster arm's preconditions refused the mint
  (an account log that did not resolve, a foreign key-agreement entry in the
  document, or a collection already carrying an epoch). Every retry re-runs
  the same refusal.

The remembered resume of a `rememberBrowser: true` signup torn before its
self-enrollment runs the same mend. A mend that leaves the pointer naming no
did:webvh rethrows the arm's error rather than sending a self-enrollment at
a pointer it cannot use.

The strategy also carries the tier refusals, and two ceremonies keep one.
Update-key rotation requires the browser-local variant outright
(`BrowserLocalSessionRequiredError`), its persist-before-publish invariant
needing a client-key record to persist into. The forget ceremony asserts the
same variant, its subject being this browser's own enrollment. No other
ceremony refuses on the kind of session it runs in.

**The account-ceremony context.** Which authorities a ceremony acts on is
resolved once from the live session (`accountCeremonyContext` in
`src/session/accountCeremonyContext.ts`). A remembered session resolves the
enrolled kind: this client's did:webvh update keys sign the account-log
entry, its key agent signs the roster append, and every request
root-invokes. A transient session holding a standing unlock credential
resolves the ladder kind: a rung of the credential's update-key ladder signs
the entry through the record's bridge delegation, the credential's ladder VM
signs the licensed roster append, and the per-visit annex VM invokes every
request under the generation delegation. A guest, a no-WAS session, and a
transient session whose record carries no standing members resolve to
neither. The ladder kind also carries its own members: the ladder VM's
delegation signer, the DELETE-only child mint the account-deletion walk
uses, a remote-only unlock-record binder, the credential's
`delegatedClients` sibling delegation, management zcap, unlock Space id and
standing key-agreement key, and a `renew()` that replaces the generation
delegation in place. The UI gates derive from the same resolution, so a gate
and its ceremony cannot disagree.

The credential ceremonies run on both kinds: the passphrase change, the
passphrase add, the passkey add, and the passkey remove. So do Space export
and import, enrollment approval, and client disconnect, so a transient
session reaches every account-management ceremony but the two whose subject
is this browser. One refusal is left there. Removing the passkey a transient
session entered on would take the ladder VM all three of its stages act
through, so it refuses (`ActingCredentialRemovalError`); a remembered
session may still remove its own login passkey.

A passphrase change on the ladder branch replaces the generation delegation
before its strike entry lands, and adopts the replacement into the live
session (the profile stamp, the persistence strategy, the remote store). The
old credential's ladder VM may be what signed the delegation the visit's
every request rides, and the strike takes that VM out of the document. The
replacement is minted by the new credential's ladder VM and installed
through that credential's sibling delegation. Every App Connect grant the
visit chained under the old delegation ends with it.

Contacts are reachable in a transient session. The remote-direct backend
serves all seven contact operations against the remote `contacts` and
`contacts-history` collections. Head rows are read and written in place
under compare-and-swap on the served ETag, and a lost race re-reads the
fresh head and re-applies the edit, bounded to a few attempts. Revisions
append content-addressed to `contacts-history`, the shape a local replica's
own writes take, and the tie-break `writerId` they carry is the visit's
in-memory one.

## The user key wrap-set roster (`key-map/user-key.jsonl`)

The user key is recipient zero of every encrypted collection. Its one remote
home is a roster in the private, capability-gated `key-map` collection,
outside the synced collections, with no local replica and no replication.
Its state is a `CollectionEncryption` descriptor, and the roster's current
key epoch IS the current user key. The epoch id is the user key's did:key,
and the epoch secret (its raw 32-byte key) is wrapped once per enrolled
client, to that client's identity key-agreement key, the X25519 twin of its
did:key. The roster delivers key material and sources no authority. Each
client caches the user key in its own client-key record, and the epoch stamp
marks that copy stale.

The roster is log-governed: the resource log `key-map/user-key.jsonl`.
wallet-core's `userKeyRosterDescriptorStore` (`@interop/wallet-core/keys`)
exposes it as a descriptor store over verified-head reads and signed
appends. `src/session/rosterStore.ts` holds two builders:
`accountRosterStore` for callers with no session profile, and
`sessionRosterStore` for a live session, which resolves the controller view
through the profile's verified-log memo so a ceremony that just extended the
account log anchors its appends at the post-edit head. Both pin on the
session's own store (`persistence.logPins`), under the slot wallet-core
derives from the Space id.

Provisioning initializes the roster idempotently with the account's existing
user key as the first epoch. That stage runs after did:webvh provisioning,
because the log's entry proofs anchor in the published account document.
Login makes one direct read before the storage clients are built, gated on a
promoted account pointer. It confirms the cached user key current, or, on an
epoch mismatch from another client's rotation, unwraps the fresh key, adopts
it, and persists it into the client-key record. A failed persist does not
fail the login, since the adopted key authenticated against the verified
roster; the session proceeds on it and the login page shows
`session.userKeyPersistFailed`. A failed persist must not read as an offline
start, so the adoption callback's throw propagates rather than being
swallowed.

Three client-side guards are load-bearing against a tampering host.

First, the resource log. Roster state is adopted only from a verified head.
Its entry proofs must be signed by keys the independently verified did:webvh
document lists under `assertionMethod` at the anchored version
(`ResourceLogIntegrityError`). Its chain-head pin refuses rollbacks, forks,
and SCID or method switches within the visit (`ResourceLogContinuityError`;
see "Log continuity within a session"). At login the `rollback` reason is
the carve-out, degraded to the transport class instead of locking the user
out of a healthy account. The session keeps the cached user key and adopts
nothing rolled back. `fork` and the SCID or method switches stay
session-refusing.

Second, the visit's latest-seen roster epoch (`memoryEpochPinStore` in
`src/session/persistence.ts`). A served roster behind that pin is refused
(`UserKeyRosterContinuityError`), with no rollback carve-out, since a
chainless epoch pin cannot tell a rollback from a fork. The log pin does not
cover a chainless value, so this guard stands on its own.

Third, at rotation time, a recipient resolver backed by the locally verified
did:webvh document. It drops any roster entry with no `keyAgreement`
verification method marked for that client, so a server-injected entry never
receives a wrap and sits ignored.

## Per-collection descriptor logs

Every encrypted collection's `encryption` descriptor, the key-epoch roster
carrying its recipients, is governed by a resource log of its own at the
collection's `meta/log` sub-resource. wallet-core's
`collectionDescriptorLogStore` is the store over it. Reads resolve to the
verified head, writes are signed appends, and a create is the log's genesis.

The verification is the roster's. Entry proofs must be signed by keys the
verified did:webvh document lists under `assertionMethod` at the anchored
version, and each log pins its chain head in its own slot of the visit's
keyed pin store (`space/<spaceId>/<collectionId>/meta/log`; see "Log
continuity within a session"). The form buys client-side detection of
descriptor tampering. A recipient the host inserts is an entry either absent
or signed by a key the document does not list. The server's own monotonicity
checks remain the host's promise about itself.

The placement is the collection's own URL subtree, so the read capability a
share grantee or a connected app already holds covers the log, with no
second grant and no capability over the account's `key-map` collection.
Being a sub-resource rather than a Resource keeps the log out of listings
and the changes feed, and outside the encrypted collection's envelope rule,
so it stays plaintext JSON Lines and replication never ships it as a row.

**The wallet writes the log alone.** The server derives the Collection
Description's `encryption` member from the log head. No ceremony writes that
member, and no `configure` call carries it forward. Provisioning creates an
encrypted collection bare (`WASRemoteStore.ensureGovernedCollection`, a
guarded create), and the epoch[0] install through the collection's own store
is the genesis that declares it governed (`ensureIndexedFirstEpoch`). A
re-run adopts the standing log, and a lost create race resolves on the
collection that stands, so exactly one epoch[0] ever exists per collection.
A collection already carrying a client-written `encryption` member cannot be
governed, and provisioning refuses it up front. The wallet opens a governed
log by its placement rather than following a pointer in the Description.
Every recipient change is one signed full-state append: a share, an unshare,
an App Connect provisioning, an app revoke, and each collection's rotation
in the user key cascade.

**The two builders** in `src/session/collectionLogStore.ts` mirror the
roster's pair: `accountCollectionStores` for callers with no session
profile, and `sessionCollectionStores` for a live session, which reaches
each collection through the remote store's handle, so every request rides
the capability the session holds at call time. Both return a lookup keyed by
collection id and resolve the controller view once per lookup.
`sessionCollectionDescriptorSource` is the read-only counterpart the storage
layer reads descriptors through, held beside it by `StorageManager` as
`DescriptorLogs { source, storeFor }` when the account pointer names a
did:webvh.

**Which key signs** follows the session kind. A remembered session signs
with the enrolled client's own account key. A transient visit's per-visit
key stands in no account document, so it signs with the login credential's
ladder VM, read off the profile at each call since a passphrase change
restamps the seed. A descriptor log admits a ladder-signed append on
`assertionMethod` membership alone, since the ceremony-tail license binds
the user key roster log and not these, so no descriptor-writing ceremony
refuses on the kind of session it runs in.

Three ceremonies name their signer instead. The forget ceremony and the
last-client transition sign the collection appends with the login
credential's ladder VM, since their removal entry strikes this client's own
key and an append that key signed could not seal the logs behind it. The
passphrase change signs with the surviving credential's ladder VM, the
retiring credential's VM leaving the document in the same edit.

**The cascade is these logs' sealing pass.** A document edit that strikes an
`assertionMethod` key leaves every governed log needing an entry at or past
the post-edit version. So every sealable collection store takes the
ceremony's post-edit controller view as its minimum controller version,
before that collection's first append. A store on a stale view would anchor
its rotation ahead of the edit and seal nothing, and a ladder-signed append
there would be refused for naming a version the edit is not in. A rotation
that appends
nothing still seals. Which collections it covers is decided from the same
logs: the Space listing only enumerates collections, and whether one is
encrypted is answered by reading its own governing log, so a host omitting
the derived `encryption` member cannot keep a collection out of a rotation.

**The read path and the cache.** A descriptor is the verified head of its
collection's log, read at login and on the unknown-epoch refresh. The
browser-local descriptor cache holds the last head this browser verified,
and three cases are handled by error name. A verifier refusal (integrity, or
a continuity refusal other than a rollback) throws rather than falling back
to the cache, so a descriptor is adopted only from a verified head. A
transport failure serves the cached copy, and a rollback refusal falls
through to it the same way. That copy never seeds the
visit's pin, since localStorage is same-origin writable and a forged pin
could lock the user out. A served head listing fewer epochs than the cached
copy is warned about and then written (`regressionWarningCache`), since a
log behind the cache looks like replication lag. The in-memory strategy has
no cache, so a transient visit offline reads nothing.

A session with no did:webvh to verify against holds neither half. Its
descriptors come from the cache alone, no descriptor write can run, and
collection key-epoch provisioning is skipped with a warn, since each
epoch[0] is a log genesis anchored in the account document.

## The client enrollment ceremony (`@interop/wallet-core/enrollment`)

Connecting a second wallet client (a fresh browser profile) to an existing
account, with no secret leaving either side. A fresh browser holding a
standing unlock credential self-enrolls at login instead (see "Session &
auth flow"). This two-party ceremony remains the path for records without
standing authority, for onboarding another wallet app over the rendezvous
transport below, and as the future opt-in step-up approval policy.

The new client mints its whole key set locally (client seed, did:webvh
update-key seeds). Only PUBLIC halves travel, as a compact **connect code**
(`freewallet-connect:<base64url(JSON)>`) carried point-to-point, and nothing
travels back over the channel. The account pointer comes out of the keyring
and the user key out of the wrap-set roster. Both screens show the new
client's did:key fingerprint, compared by the person running the ceremony
before approving.

The flow is quorum-of-one. Any single enrolled client can enroll, and so can
any transient session on a standing unlock credential. The stage order is
canonical in wallet-core's ARCHITECTURE.md.

1. **Enrollee** (the login page's connect-this-browser card):
   `mintEnrollmentRequest` mints the key set and shows the code. Nothing is
   written yet.
2. **The approving side** (Settings > Connect another wallet) pastes the
   code, compares the fingerprint, and approves (`approveEnrollment`). The
   session's account-ceremony kind decides where the escrow falls.

   An ENROLLED client escrows first, decryption material before
   authorization. The user key wraps to the new client's key-agreement key
   in `key-map/user-key.jsonl`, into every epoch, so pre-enrollment history
   decrypts. The commit entry follows, then the add entry publishing the
   client's two verification methods and its update key, and no
   authorized-but-blind window opens.

   A LADDER signer runs commit, add, then escrow, since a ladder-signed
   roster append is licensed only at the inventory-changing version its own
   add entry mints. The window that opens is the branch's stated cost. The
   new client stands in the document holding `assertionMethod` and its own
   update key while holding no wrap. It is one request wide on the happy
   path, mended by a re-run with the same connect code or by the
   escrow-direction convergence of any later ladder-branch ceremony, and
   visible as a row in Connected wallets. The label write is best-effort on
   both kinds.

3. **Enrollee** ("finish connecting") verifies the enrollment from the
   world-readable log against the pointer's DID, makes its first roster read
   signed with its `<did:webvh>#<multibase>` key, unwraps the user key,
   persists the key set into the client-key record under the passphrase's
   unlock layer, stamped with the account controller, and logs in as an
   enrolled client.

**The connect code's keys must be canonical.** The enrolling client refuses
a code whose key-agreement key is not the canonical X25519 twin of its
signing key (`assertCanonicalEnrollmentKeys`, run inside the connect-code
parse, so the refusal lands before anything publishes). A client's
key-agreement method publishes under `controller: did:key:<its signing
multibase>` and every reader pairs the two by that claim, so without the
check an enrollee could publish a key-agreement key nobody can pair. Both
approval surfaces refuse.

Every stage is idempotent and the ceremony resumes from durable state alone,
so re-running with the same code converges. A tear after the roster write
leaves an orphan wrap, invisible to authorization and harmless. A tear
between the log entries is detected from the standing `nextKeyHashes`
commitments, so the add entry alone is appended and no fork is written.

**The rendezvous transport (onboarding another wallet).** When the enrollee
is a camera-holding wallet rather than a browser with a paste box, the same
ceremony runs over the WAS server's ephemeral-exchanges facet
(`/workflows/ephemeral/exchanges`). That facet is unauthenticated. The
unguessable exchange URL is the only access control, and it travels
point-to-point in the QR. Settings > Connected wallets > "Connect another
wallet" offers both halves, the QR invite and the paste-a-connect-code form.

The invite side creates an exchange whose stored request is a
`WalletOnboardingQuery` VPR carrying the account pointer and controller,
renders the interaction URL (`.../protocols?iuv=1`) as a QR code, and polls.
The other wallet scans it, mints its key set, and posts back an
onboarding-response envelope of the ordinary `freewallet-connect:` code plus
a suggested display label. An oversize or malformed envelope is refused
whole.

Poll completion swaps the card to a consent panel that must state four
things: the fingerprint comparison, leading, since anyone holding the
exchange URL could inject a response; the full-peer consequence (an enrolled
wallet reads and changes everything in the Space, connects apps, onboards or
disconnects other wallets, issues and revokes recovery codes); the
disconnect limitation; and an editable label prefilled from the envelope's
suggestion. Approval drives the same approve-and-label path as the paste
dialog. The channel carries only the four public key multibases and the
label, and the account pointer rides inside the stored request, bounded in
confidentiality by the exchange URL.

## Recovery codes (`@interop/wallet-core/recovery`)

The "lost my only client" answer: a 16-byte base58 **recovery code**, shown
exactly once at issuance, that restores the whole account from a fresh
browser with nothing else in hand. A code is a minimal wallet client that
stands in the user key roster while publishing no `capabilityInvocation`
relation, so it is not an enrolled client. Its whole key set derives
deterministically from its bytes: an unlock identity under a distinct
single-expansion HKDF (so a code and a passphrase that stringify alike
cannot reach the same unlock Space), a client seed, an update-key ladder
seed, and a binding MAC key. The material exists nowhere until the code is
typed.

A code is a standing unlock credential with a ladder of its own. Rung 0 is
the update key whose hash the document commits, so the spend's
reveal-and-commit entry is the ordinary ladder reveal, and the ladder VM
signs the code's own bridge delegation. A code retires on spend, so no rung
past 0 is ever revealed. Its 16 uniform bytes are high-entropy, which is
what admits both the verbatim `keyAgreement` (the hash-commitment rule
below) and the ladder itself. A passphrase-derived ladder would be a
standing offline grind oracle against a revealed rung.

Its inventory is split. Decryption stands: the `keyAgreement` verification
method publishes in the did:webvh document as an ordinary, unmarked Multikey
entry, and its user key wrap stands in the `key-map/user-key.jsonl` roster.
Being keyAgreement-only, it never shows in client listings keyed on
`capabilityInvocation`, and the document does not label which keyAgreement
key is the recovery one. Its ladder VM publishes beside them under
`assertionMethod` and `capabilityDelegation`. Update authority stays latent.
Rung 0 joins `updateKeys` nowhere, only its hash is committed in
`nextKeyHashes`, and the one bridge into the zcap profile is a pre-minted
PUT-on-`did.jsonl` delegation inside the code's unlock record, signed by the
code's own ladder VM. The record holds no seed and no key wrap. That narrow
scope keeps recovery loud: any use of a code must extend the world-readable,
hash-chained log before it can read a byte. Without a reveal entry the
standing ladder VM reaches only the account-deletion walk's DELETE-only
child and one licensed roster append to recipients the verified document
already lists.

The record splits into a code-authenticated core and a shell the binding
does not cover. The core is the account binding `{ controller, pointer }`,
MAC'd at issuance under a code-derived key the host never holds. The tag
rides the frame in the clear, and recovery verifies it BEFORE trusting the
pointer. That closes the host-forgery redirect, where a malicious host seals
a record of its own naming an account it controls and every signature-side
check passes on it. The tag covers the pointer's host, so codes need
re-issuing when the account migrates hosts. The shell is the plaintext frame
(controller, pointer, timestamp) plus the sealed `bridge` member under the
frame proof, signed with the code-derived unlock key and verified before
decrypt. No ceremony re-mints any unlock record's bridge: each is signed by
its own credential's ladder VM, and another credential's strike cannot rot
it.

The record carries no email and the locate step shows none, since a
self-declared display string is the deception payload a forged record could
show as "this is your wallet". `/recover` confirms only that the code
located an account. A network failure and a `rollback` both surface as
"could not check"; a fork or identity switch surfaces as its own continuity
refusal.

Issuance (Settings > Recovery codes, `issueRecoveryCode` in
`src/session/recovery.ts`) runs from either session kind. The code's unlock
record and its self-signed bridge are written first on both, inert twice
over: the ladder VM stands in no document, and rung 0 is uncommitted. The
document half then splits by signer kind. An enrolled client's roster append
needs no license, so the escrow comes first, into every epoch, and one entry
carries the code's whole inventory. A ladder-signed append is licensed only
at the inventory-changing version its own entry mints, so the ladder branch
publishes the `keyAgreement` alone (the pivot), escrows anchored at that
entry, then publishes the ladder VM and the rung-0 commitment together. The
registry entry of public halves comes last on both, recording rung 0's
multibase as the anchor a later revocation attributes the ladder VM from.

That boundary is load-bearing both ways. A code that could spend before it
could decrypt would strike every standing credential and then fail, since
the spend unwraps every epoch through the code's own wrap. Publishing the
ladder VM first would leave a torn issuance with a code that cannot spend
and can still delete the account. Every stage converges on a re-run with the
same code.

Nothing binds until the confirm-once dialog's "I saved this code". An
issuance torn after its document entry leaves a saved code that locates no
account, plus a document `keyAgreement` entry and roster wrap nothing names.
The login sweep rotates the orphan wrap away, but the registry-driven health
check cannot see the code, so the saved code stays silently dead. The
retire-and-reissue mender for that orphaned entry is not built, and the
last-client transition refuses while it stands.

Recovery (`/recover`, `recoverAccountWithCode`): the typed code decrypts its
unlock record, the log is fetched and locally verified against the pointer,
and the delegation writes the self-enrolling continuation. That is a
**reveal-and-commit** entry signed by the code's pre-committed update key,
then an **add-and-retire** entry. The continuation enrolls what the login's
routing decision would, and its stage order is canonical in wallet-core's
ARCHITECTURE.md.

On a non-remembered browser, the default, the continuation is the
**transient recovery** (wallet-core's `recoverWebvhLadderAnchored`), and no
enrolled client is minted anywhere. The add-and-retire entry publishes the
fresh credential's ladder VM in the new client's place (`assertionMethod`
and `capabilityDelegation` only), beside the new passphrase's `keyAgreement`
commitment and the replacement code's inventory. It retires every other
standing credential, passphrases, passkeys, and unspent codes alike: the
`keyAgreement` member, the ladder VM, the committed rung hashes, and any
revealed rung still held. The remembered continuation strikes the same set.
Rungs are attributed from the log alone, and a credential the log cannot
attribute is reported on the outcome's `unclaimedCredentialVmIds` rather
than struck, keeping a committed rung it could still reveal. A retired
credential's bridge delegation is not revoked, but the entry strikes the
ladder VM that signed it, so it stays live and inert. The account lands
client-less and ladder-anchored, reachable by the new passphrase and the
replacement code alone, and the recovery page says so.

The continuation's persist-before-publish seam runs after the reveal entry
validates the code and before the ladder VM publishes. It mints a fresh
annex generation under the new ladder's bootstrap did:key, loudly enrolls
the per-visit transient client into it, and durably writes two unlock
records: the new passphrase's (ladder seed inside, bridge and sibling signed
by that credential's ladder VM) and the replacement code's, whose bridge is
signed by the REPLACEMENT CODE's own ladder VM and published by the same
entry, so no other credential's later strike can rot it. A recovery record
carries no annex sibling, so the old generation falls to orphan discovery.
The seam names the fresh generation back to the ceremony, so the
`#DelegatedClients` pointer moves to it inside the SAME add-and-retire
entry. A pointer written afterwards would leave a window in which neither
credential could enroll.

The mandatory rotation is the first request past the entry, so nothing is
enrolled and nothing is read between the typed code dying in the document
and the new credential gaining its wrap. It is the ONE ladder-signed roster
append the ceremony-tail license admits (`replaceUserKeyRosterRecipients`:
spent code retired, fresh credential and replacement code escrowed, fresh
epoch minted, one write anchored at the add-and-retire entry). The
pre-rotation user key the registry update needs is unwrapped afterwards, out
of the superseded epoch's escrow. The epoch cascade and the unlock-methods
registry update (spent entry out, every retired credential's entry out with
it, replacement and new-passphrase entries in, re-sealed to the rotated user
key) ride the generation delegation. Which entries are retired is keyed on
the continuation's own report (`retiredCredentialVmIds`) inside the
compare-and-swap. An entry the report lists as unclaimed is kept, since it
still records the rung-0 anchor a later retirement attributes the credential
by. Each retired entry's unlock Space is then deleted best-effort through a
DELETE-only child of its own management zcap, and only once the registry
write dropping the entries has landed, since a registry naming a deleted
Space breaks every later registry-driven walk. The visit then enters through
the ordinary transient composition with zero local residue.

Three residues remain, none of them mended here. A tear inside the append
leaves the spent code dead (a re-run refuses it as spent) and the current
epoch wrapped to the removed code alone; the mender would be a repair
holding both the spent code and the new passphrase, and it is not built. A
rotation torn mid-fan-out strands a collection keyed to the spent code until
the next remembered login or a spend re-run. A tail torn between the
registry drop and the deletes leaves the retired credentials' unlock Spaces
standing with nothing naming them, and a failed registry write leaves their
entries standing with no pass here to drop them. Both of the last are inert,
and a lingering retired entry is dropped by the next spend's own registry
pass.

The remembered spend, the `rememberBrowser` entry, mints a fresh
enrolled-client key set instead. Its required `onCommitted` seam, between
the two entries, writes the successors: the new passphrase's unlock record
in the standing LAYOUT, the browser-local PENDING client-key record (seeds,
controller, `pointerDid`, the pending group of built-on head, unwrap key and
replacement-code bytes; no user key), and the replacement code's record and
bridge. A colliding unlock record refuses up front. The add-and-retire entry
brings in the new client, retires the spent code's inventory, and adds the
replacement code's. The tail then makes the passphrase standing before the
rotation, and the registry mutation, keyed on the same report, runs between
the re-seal and the cascade. The new enrolled client then deletes each
retired entry's unlock Space and this browser's unlock-local state for it,
best-effort, under the same registry-write-first ordering. A failed write
leaves the entries named and their Spaces standing for the spend resume's
registry pass, which drops and deletes them on every arm. The resume never
re-enters the continuation, so it reads the same report back off the log
(`recoverySpendRetirementFromLog`). The replacement code's save confirm
completes the local record and clears the carrier. The spent code's unlock
Space is deleted, so a spent code thereafter fails distinctly. A post-entry
tab death leaves the pending record for that resume, which backfills the
standing configuration and the registry, re-displays the code until
confirmed saved, and completes the rotation and cascade.

Revoking a code from Settings is the issuance reversal and is REAL, since
the secret was only ever a pointer to the record. It runs from either
session kind, in the retirement order: the retirement gate read-only, the
post-removal did:web projection on the ladder kind (see "The projection's
freshness on a credential-anchored account"), the document entry out, the
user key rotated off the code's wrap and the collections re-epoch'd by the
same cascade, the unlock Space deleted, the registry entry dropped. The live
session adopts the rotated user key in place.

The document entry takes the code's whole inventory: its `keyAgreement`, its
committed rung-0 hash, and its ladder VM. The revoker holds neither the code
bytes nor its ladder seed, so the VM claim is seedless, anchored on the
rung-0 update-key multibase the registry recorded at issuance. It is
required rather than best-effort. A claim no attribution arm makes refuses
the whole revocation with `UnclaimedLadderVmRetirementError` before anything
is written, since a standing ladder VM whose credential is otherwise retired
keeps its delegation authority. The Space goes through a DELETE-only child
of the entry's management zcap, behind the deletion walk's five pre-mint
refusals. A refusal or a masked 404 is reported as a residue rather than
failing the run.

A login-time health check watches for delegation rot and delegation expiry,
either of which bricks recovery when it is needed. A stored delegation rots
the moment its signing key's verification method leaves the document, and
it stops chaining from then on. The bridge TTL is one
year (NIST SP 800-57 cryptoperiod guidance), so the registry entry records
its `expires`, and a delegation expired or inside the 30-day renewal window
is flagged the same way. No ceremony re-mints a bridge on another
credential's behalf, so for a recovery code the check is the whole remedy
and re-issuing the code is the fix. A standing passphrase or passkey
refreshes its own bridge at its own login, on those same three staleness
axes. The predicates (`delegationKeyInDocument`, `zcapExpiring`) and the
delegation builder live in `@interop/wallet-core/recovery`.

Two standing boundary rules. First, the hash-commitment rule: **a
low-entropy-derived public key is never published in the world-readable
document**. The document carries a hash commitment of the key
(`MultikeyCommitment`); the real key rides in the capability-gated roster
entry, and the recipient resolver verifies it against the commitment (the
oracle argument is in "Session & auth flow"). A high-entropy credential's
key (a passkey PRF output, a recovery code) may publish verbatim. Second,
the unlock-methods registry's additive `method` enum is the explicit seam
for a later quorum recovery method, rejected for v1 as presupposing a
contact roster most accounts lack.

## Client revocation and the epoch cascade

Disconnecting an enrolled wallet client from the account. The cascade is
`revokeAccountClient` in `@interop/wallet-core/clients`, and its stage order
is canonical in wallet-core's ARCHITECTURE.md. `revokeEnrolledClient` in
`src/session/revocation.ts` is the freewallet binding, supplying the session
preconditions, the collections source, the generation-delegation re-mint,
and the adoption side effects. The Settings "Connected wallets" panel drives
it, synchronously and in dependency order, in the session that disconnects.
The four stages, in the enrolled kind's form:

1. **The document edit** (`revokeWebvhClient`): one log entry removes the
   revoked client's two verification methods, its update key, and both
   standing `nextKeyHashes` commitments, the carry-over hash and the staged
   hash recovered by log attribution. An opaque committed hash left behind
   would be a re-seizure credential through the reveal mechanism. Under the
   current-key-set rule that one edit pulls the client's whole authority at
   once. The cascade makes no per-collection revoke calls; apps it had
   connected reconnect through the ordinary App Connect flow.
2. **The user key rotation** in the `key-map/user-key.jsonl` roster,
   recipients resolved from the just-updated verified document. An account
   with no roster yet stops here, the document edit having landed. First the
   orchestrator sets the store's minimum controller version from the
   post-edit log, so a stale cached controller view can anchor neither the
   rotation nor the sealing append at a head predating the removal. Every
   collection store the fan-out writes through takes that same view.
3. **The epoch cascade**, over the collections `src/session/userKeyCascade.ts`
   enumerates: every encrypted collection, standard plus any remotely listed
   one whose Description carries an encryption descriptor, re-epoch'd onto
   the fresh user key in parallel. Each rotation is a signed append on that
   collection's governing log, so it signs with the key the calling ceremony
   is licensed to append with. Revoked generations retire from the epoch
   rosters and the fresh key escrows into every prior epoch, so other
   replicas keep decrypting. A collection is stale exactly when its current
   epoch names a non-current user key generation, decided from stored state
   alone; a never-epoch'd one takes the newest prior generation as its first
   epoch. A descriptor whose `currentEpoch` names no epoch in its own
   `epochs` list is refused fail-closed. Failures collect per collection;
   the rest still rotate.
4. **The generation-delegation re-mint** (`remintGenerationDelegation` in
   `src/session/revocation.ts`): an embedded generation delegation the
   revoked client had signed also stopped chaining at step 1. It is replaced
   in place, same fragment and no revocation POST, since the rotted chain no
   longer verifies. It signs with the login credential's ladder seed, and
   skips with a report when that seed or a promoted pointer is absent. It
   runs in the no-roster early return too. Grants chained under the old
   delegation die with it, a stated consequence of an ordinary disconnect.

The revoking session then adopts the fresh user key in place: vault keys
swapped, storage ciphers rebuilt on the re-epoch'd descriptors, the
unlock-methods registry re-wrapped. It keeps operating without a re-login.
Self-revocation is refused up front; use another enrolled client, or a
recovery code. A naive full re-run converges, since the log entry is
idempotent and the staleness rule finds exactly the stranded collections.
The limitation: ciphertext the revoked client already fetched stays readable
to it, and old epochs open to keys it already held.

One key survives every rotation: a collection's blinded-index HMAC key,
minted with epoch[0] and wrapped to each recipient on the `encryption`
descriptor. Rotating it would orphan every existing `indexed` entry, since
blinded index tokens must compare across the collection's whole history.
Recipient removal only drops the leaver's wrap, so a removed recipient
colluding with the server could confirm guessed attribute values
indefinitely. That is a guessing oracle rather than a read path: the query
endpoint stays behind the pull grant, and the content keys rotate above.

The standing backstop is the **cascade-completion sweep**: session creation
re-runs stages 2 and 3 on every login whose roster read succeeded, as the
first stage of the login-time chain on `session.registryReady`, best-effort.
That chain runs after the dashboard has rendered (see "Session & auth
flow"), so a write in the navigation window can seal under an epoch a
disconnect's rotation has not caught up to, readable by a client the revoke
already removed. Whether to hold such writes until the sweep completes is an
open decision.

The roster stage runs first (`convergeUserKeyRosterToDocument`). A cascade
torn between its document edit and its rotation leaves the roster wrapping
the CURRENT key to a recipient the locally verified document no longer keys,
silently, since that document edit will never be re-run. Such a recipient is
rotated away here, and the fresh key adopted (client-key record, epoch pin,
live session vault keys and ciphers) before the fan-out runs against it.
Staleness being decided from stored state alone, the fan-out completes a
cascade another client crashed partway through. Together the two stages
check that the roster keys exactly the document's clients and that no
collection's current epoch names a retired user key generation. The roster
stage writes through the store instance the login read came through, so it
acquires the roster log no second time.

Recovery-code spend and revocation drive stages 2 and 3 of the same cascade.
Their document edits are their own, and a spent code's replacement
delegation is minted by its own ceremony.

**The ladder branch.** A transient session on a standing unlock credential
runs the same cascade with the credential's ladder in the enrolled client's
seat. The removal entry is signed by a rung of that ladder through the
record's bridge delegation, the convergence append by its ladder VM, and
every request is invoked by the per-visit annex key under the generation
delegation. Two refusals lift with the signer (`disconnectEligibility` takes
its kind): a ladder has no self to refuse, and the last enrolled client is
removable, since the account lands ladder-anchored rather than stranded.

Two refusals run first, before anything is written. A registry this session
cannot read is one, since the check below is computed from it. A
pending-shaped passphrase entry is the other, the torn-retirement repair
being its only mender; the in-band registry re-seal at the tail would
otherwise rewrite a half-retired entry. The refusal names the method and its
mender.

The rule for a struck signer runs next, before the pivot. On an account
whose annex generation was minted by the client being removed, that client's
account key signed the generation delegation this visit's every request
rides, and the removal entry strikes it. The replacement is minted by the
acting credential's ladder VM, installed in place through the credential's
sibling delegation and adopted into the live session before the entry lands.

No unlock record is written on either branch, since every record's frame
proof, bridge, and sibling delegation are signed by its OWN credential's
unlock identity and ladder VM, which this entry does not strike. The
post-removal did:web projection is PUT immediately BEFORE the removal entry,
through the account Space's `id` collection under the visit's generation
delegation (see "The projection's freshness on a credential-anchored
account"). The store resolves that delegation at each use, so the PUT rides
the replacement the re-mint just installed. A failed PUT is warned and the
entry still publishes.

The residue the branch leaves is the roster. A disconnect torn after the
removal entry leaves the current key wrapped to the removed client. An
account that still has an enrolled client gets it mended by the
remembered-login sweep. The account a last-client disconnect produces has no
mender: the row is gone from the listing, so there is no re-click, and no
sweep runs there. The retire-direction convergence of any later
ladder-branch ceremony is the only one left, and the user may never run one.
That is an open gap, recorded in the Ceremony inventory.

## The Settings clients surface ("Connected wallets")

The management surface over the enrolled-client roster
(`src/components/EnrolledClientsSection.tsx`, glue in
`src/session/clients.ts`): where "disconnect this phone" lives. Apps are
grantees rather than enrolled clients and stay on the sibling Applications
page. The connect-another-wallet entry point lives here too, one card
offering both the QR onboarding invite and the pasted connect code.

The listing is wallet-core's `listAccountClients` over the locally verified
did:webvh log, keyed on `capabilityInvocation`. That keying excludes
structurally rather than by filter: a recovery code's key publishes under
`keyAgreement` only, the KMS-held DIDAuth signing key under
`authentication`.

Two members come from log attribution rather than the current document. One
is each client's active update key, since the flat `updateKeys` set has no
per-client grouping: the entry publishing a client's verification methods
revealed its initial key, and each later entry retiring the attributed key
while revealing exactly one replacement is that client's self-rotation. An
ambiguous attribution disables disconnect for the row. The other is the
enrollment moment, the `versionTime` of the publishing entry.

Disconnect drives the client-revocation cascade verbatim, on a row carrying
both key members. Eligibility is the shared `disconnectEligibility` policy
(self, last-wallet, and unattributed-update-key refusals) rather than UI
state, and the policy takes the signer that would sign the removal entry. It
confirms the limitation first: re-keying stops future reads, and
already-fetched ciphertext stays readable. A partial collection fan-out is
reported as a resumable success pointing at the login-time sweep.

On the enrolled branch the last enrolled client cannot be disconnected,
since it is always the current one from its own session and self-revocation
is refused. Its row offers the last-client transition instead (see "The
forget affordance"). On a transient session only the unattributed-update-key
refusal survives, so every row offers Disconnect and the last row states the
transition it makes: the account lands ladder-anchored, reached by the
sign-in credentials alone. No row carries the "This browser" chip there, and
the forget ceremony's entry point does not appear, since a transient session
runs as no enrolled client. Its resumable-failure copy says the remaining
re-keying resumes at the next disconnect or passphrase change, no transient
login running the cascade sweep.

**Labels** live beside the keys rather than in the document, which carries
key material only: `key-map/client-labels.json`, over wallet-core's
`readClientLabels` / `setClientLabel` store seam. They are plaintext in the
private, capability-gated `key-map` collection, since the host already
serves the world-readable log naming every client key. A label is chosen at
enrollment approval, written best-effort, and editable inline. A "This
browser" chip marks the current client, matched on the session's own signing
key rather than on stored state. The store rides the remote store's bound
invocation capability, so a transient session reads and writes labels under
its generation delegation.

**The Applications sibling** knows the current-key-set rule. That page
(`src/lib/connectedApps.ts`) holds app grantees where this panel holds
wallet clients, with a cross-pointer in each. Its listing checks each
recorded App Connect grant's delegation signer against the same verified
document, matched on the key-multibase fragment so a key's did:key and
promoted did:webvh forms agree; the full zcap is recorded on the Login
activity. An app whose recorded signers have all left the document shows as
orphaned, and reconnecting through the ordinary App Connect flow is the
recovery path. A grant minted in a transient session is signed by an annex
key the account document never lists, so that signer derives as unknown and
the row carries no marker. The marker is display-only and does not gate
revocation: revoking an app POSTs every recorded revocation, rotates the
app-provisioned collections' epochs, and deletes the app key, and a dead
chain comes back as a skipped revocation. The check is best-effort, so with
no verified document this session the page lists without the marker rather
than failing. Agent rows run the identical check over the recorded grant's
`controller` instead of an app-key subject, and revoking an agent likewise
always POSTs the recorded revocations.

## Storage model (local-first)

Every credential, public-link, and history read/write goes through one
`SyncedCollectionStore` backend, chosen once at session construction by the
session's storage tier (see "Replica-less, capability-bound storage" under
"Session persistence"). A session with a local replica (a remembered login,
a guest, a no-WAS session) serves them from the local `BrowserStore` (RxDB
over Dexie/IndexedDB), online or offline. A transient session is
replica-less and serves them remote-direct over the remote WAS collections;
so does a remembered CHAPI popup, which constructs a `BrowserStore` and
routes past it (see "Remote-direct popup storage"). One local database per
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
the host serves (see "Per-collection descriptor logs").

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

A user's remote Space is identified by an independent random `spaceId`
minted at signup and carried in the account pointer; unlock Spaces keep
`spaceId = base64url(SHA-256(unlock did:key))` as a discovery convention.
The six standard collections above are created on first login.

## CHAPI integration

CHAPI (Credential Handler API) lets a website trigger a credential
request/store via a browser pop-up without the site ever seeing the user's
wallet passphrase.

Flow:

1. On login, `registerWallet()` (`src/lib/registerWallet.ts`) registers
   `/wallet/get` and `/wallet/store` as this wallet's handler URLs with the
   CHAPI mediator (`authn.io`).
2. A third-party site's `navigator.credentials.get/store()` opens
   `/wallet/get` or `/wallet/store` in a CHAPI-managed popup iframe, outside
   the normal app shell and `ProtectedRoute`.
3. The popup page intercepts the CHAPI event with
   `receiveCredentialEvent()`, shows a minimal login form, initialises a
   full `Session` in-popup, then returns the result to the site with
   `chapiEvent.respondWith(...)`.

The CHAPI pages (`src/pages/chapi/`) are not wrapped in `ProtectedRoute` and
do not use the main app layout.

**The DIDAuth holder follows the request.** A `DIDAuthentication` query may
carry `acceptedMethods`. `presentationSignerFor`
(`src/lib/walletRequest/composeVP.ts`) reads it and picks the holder in the
order `webvh`, `web`, `key`
(`decisions/0016-didauth-holder-dispatches-on-accepted-methods.md`). An
unconstrained request takes the did:web projection id when the session can
present it, and the client did:key otherwise.

A session can present the account's did:webvh or did:web form when its
pointer names a did:webvh and the resolved account document lists a
verification method it holds a signer for under `authentication`. That is
settled against the verified-log memo, read as a cache: no fetch, no throw,
and false when the memo is cold. A stored key map is not evidence, since the
map is written on paths that do not edit the document. The did:web arm's
holder is the projection id (`didWebFromSpace`). A remembered session signs
an account-form holder with the enrolled client's own account key. The
KMS-held key signs where no client key exists.

Refusal splits by position. Pre-login, the `didAuthMethodSupported` gate
judges deployment capability (`key` always, plus `web` and `webvh` when a
KMS is configured), so a method no session here could ever present is
refused before a password box renders. After login, a session that can
present none of the listed methods gets the block screen in place of the
consent panel.

**The popup follows the browser's routing.** It runs the same post-KDF
routing every login runs (`routeUnlockLogin`, see "Session persistence"),
with the Storage Access API handle threaded in as the record probe's `idb`
factory. A denied handle probes the partitioned bucket, finds no record, and
routes transient, as does every engine offering no unpartitioned-IndexedDB
request at all (Safari's and Firefox's steady state). That uniform routing
is `decisions/0009-popup-denied-storage-access-goes-transient.md`, reached
by construction rather than by a popup arm of the routing. A transient popup
session composes like any other, and its App Connect response VP holds and
signs as the visit key's bare did:key. A granted handle probes the
first-party client-key record instead, so a remembered browser proceeds as
that enrolled client.

The popup marker is a `popup` option on `loginWithPassphrase`,
`loginWithPasskey`, `sessionFromKeyringHit`, and `initSessionFromSeed`. It
gates only what the partitioning implies, and only in the remembered arm:
remote-direct storage (below), suppressed localStorage caches, and that
arm's popup refusals (the record-less branch's self-enrollment, the
pending-enrollment resume, and the login-time chain passes carrying the
guard). The Storage Access handle does not reach localStorage, so a
persisted descriptor or meta cache would be partitioned residue no top-level
wipe can reach. The popup's cache pair is therefore in-memory for the visit,
on a WAS deployment. On a no-WAS deployment the same
store is the only record of the locally minted key epochs, so a local-mode
popup keeps its persistent pair. Three chain passes carry no popup guard
today: the standing-delegation self-refresh, the ladder-rung refresh, and
the did:webvh pointer heal. Whether they should is an open decision.

Handler registration is not on the persistence axis. `registerWallet()` runs
at mount on the login page, before the routing decides, so a transient login
registers the handler too. It writes nothing to the wallet origin, since the
registration bit lives on the mediator's, and that mediator-origin bit
remains the stated limit no top-level wipe reaches.

**Remote-direct popup storage.** The popup's own IndexedDB is a partitioned
bucket no `SyncController` ever drives, so a credential stored there would
be stranded. A transient popup session is replica-less and reaches the
remote-direct backend as every transient session does. A remembered popup
session gets there by routing: every synced-collection operation goes to a
`RemoteDirectStore` (`src/stores/remoteDirectStore.ts`, selected via
`remoteDirect`, threaded from the `popup` option) rather than to the local
`BrowserStore`, which it still constructs with nothing routed to it.

That backend serves credential, history, and public-link reads and writes
straight over the remote WAS collections, with the same per-collection
ciphers the local store uses, so the envelope, id, and key-epoch logic lives
once. A listing is was-client's `Collection.documents()`, the snapshot walk
over the `changes` feed, one request per page; the feed's tombstones drop
out and a resource rewritten mid-walk keeps its latest state. A write
reproduces verbatim what background replication would have pushed: the raw
EDV envelope under its content-derived envelope-hash id, created with
`If-None-Match: *`, stamped with the same `Key-Epoch`. An unknown-epoch read
drives the same one-time descriptor refresh the local backend uses, so a
fresh-epoch credential is never dropped.

Contacts are reachable in the popup over the same path. Head rows are
mutable and updated in place under `If-Match` compare-and-swap, with ids and
epoch stamps matching what replication would have pushed, so a local replica
pulls the popup's contact edits cleanly. A delete leaves the server's own
tombstone, which the pull side maps to a removal like any other.

The remote-direct backend is selected only when a remote store is
configured. Reads gate on `StorageManager.ready()`: the local collections
being open, or nothing at all in remote-direct mode.

## App Connect (one-popup app login)

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
`@interop/wallet-core/request`'s `appKey.ts`, shared with DCW: wire
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
permitted action is unsatisfiable rather than delegated empty. So is a
whole-Space target asked for by a session whose grants chain under a
generation delegation, since that delegation is scoped to the Space's items
subtree; the consent screen words that refusal for itself. Resolution
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
installs the persisted index schema from the collection's stored `/meta`, an
opaque encrypted envelope the cipher decrypts. The schema is cached beside
the encryption descriptors and refetched on the same unknown-epoch refresh.
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
on revoke (see "Client revocation and the epoch cascade"), so the revoked
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

## The interaction-URL request page (`/external/request`)

A request can also arrive from outside the app, with no CHAPI popup and no
attested requesting origin. An agent's `di was request-grant` prints an
interaction URL (`<exchange>/protocols?iuv=1`) plus the wallet deep link
`/external/request?url=<percent-encoded interaction URL>`. The same URL
pasted into Add Credential or scanned from a QR reaches the page too:
`resolveWalletInput` returns it as a typed `interaction-url` outcome.

The page (`src/pages/external/ExternalRequestPage.tsx`) is the
`WalletGetPage` shape minus CHAPI. It opens the exchange, classifies the
VPR, renders the storage-access consent panel, delegates through the
ordinary grant engine, and POSTs the unsigned zcap-only presentation back
with the exchange URL. Without a live app session it runs the ordinary login
in place and adopts it app-wide. The Login activity records the grant under
the fixed origin marker `n/a (API request)`, which the Applications page
keys agent rows on.

A request may name its requester through the VPR's root `agent: { name }`
member. The consent panel renders it beside the grantee key, marked
self-declared, and the activity records it as `object.actor`; the activity's
own `actor` stays the user. The shared classifier requires the name trimmed,
1 to 64 characters, with no control characters, and refuses anything else as
malformed.

The entry point is stricter than the popup, because the only requester
signals are the grantee DID and request-supplied text, all chosen by whoever
wrote the link. Every refusal is decided before consent renders, in the pure
module `src/lib/walletRequest/externalRequest.ts`, each with its own copy:

- a deep link that is not an interaction URL, a bare exchange URL included;
- a gone exchange (a 404 on either fetch, worded as expired-or-wrong-link
  since the server answers the same for both), an unreachable one, or one
  answering with no readable VPR;
- a request asking for no storage access;
- a `DIDAuthentication` query in either form, and a `domain` on any request
  (freewallet requires a `domain` for DID Auth and there is no origin to
  match it against);
- an `AppConnectQuery` (App Connect stays CHAPI-only);
- a VPR-named presentation endpoint (`interact.service`) on another origin
  than the exchange, since delivery prefers that endpoint and the consent
  panel names the resolved delivery host;
- any grant class outside the allowlist.

Only `#public-collection` and `#private-collection` targets are granted from
a link, plain collection URLs resolving to those classes included. A share
would hand the grantee decryption of the user's own encrypted collections,
and a whole-Space or protected-collection read covers the plaintext
`public-credentials`. `barredGrants` runs once the grants are resolved, the
first point a target's class is known. Widening the allowlist is a
documented decision rather than a code change. A failed POST-back leaves the
grant recorded and offers the composed response for manual delivery; a
decline abandons the exchange, which expires on its own.

Grants answered here are listed and revocable on the Applications page as
agent rows, keyed by the grant's `controller` did:key (`listConnectedAgents`
in `src/lib/connectedApps.ts`) and titled by `agent.name`, or by the grantee
key's fingerprint when no name was sent. A row's grants are the union over
every agent Login for that controller newer than the latest matching Revoke
activity (same origin marker, no `appConnect`, the controller in
`object.controller`), since a later request can add a grant without retiring
an earlier one. A row whose grants have all expired is dropped. Revoking a
row POSTs every recorded capability's revocation regardless of the orphaned
marker, and stamps the Revoke's `created` at least one millisecond past the
latest Login, so a fast-clocked terminal cannot leave the row standing.
There is no app key to delete and no collection epoch to rotate, an agent
never being a key-epoch recipient.

A grant delegated from a transient session chains under the session's
generation delegation (`profile.invocationCapability`) rather than the Space
root, which an annex key the account document never lists would have to
sign, and its `expires` cannot exceed the parent's. A generation delegation
that is expired, inside its renewal window, or signed by a key the session's
memoized verified account document no longer lists under
`capabilityDelegation` runs a blocking renewal stage first: a fresh
ladder-signed delegation, minted through the credential's sibling
delegation, installed in place and adopted by the live session. The approval
refuses (`GenerationDelegationStaleError`) only when the renewal cannot run
at all (the account document does not anchor this credential's ladder VM) or
when it fails, rather than minting a silently short grant.

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
`SharedCollectionReader` reads the Collection Description through the
delegated read zcap, builds the epoch-aware cipher from it, and decrypts the
envelopes locally with the X25519 twin of its own controller DID, the key
the wallet derived, so both sides land on the same `kid` with nothing on the
wire. That is the same recipient identity an app-provisioned collection
admits the app with. The `encryption` member it reads is the server's
derivation of the governing log head, and the delegated read zcap covers
that log, so a grantee can verify the descriptor's history for itself.

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
account that may never run one is an open gap instead, listed below.

| Ceremony                                  | Entry point                                                     | Module                                                            | Shared half                 | Mender                                                                                                                                                    |
| ----------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credential-anchored genesis               | every WAS signup, remembered or not (the default)               | `src/session/credentialAnchoredGenesis.ts`                        | `/clientAnnex`              | re-run; the transient login's heal branch                                                                                                                 |
| Recovery spend (remembered and transient) | `/recover`                                                      | `src/session/recovery.ts`                                         | `/recovery`, `/clientAnnex` | remembered: pending record pre-pivot + spend resume; transient: re-run, open gaps (below)                                                                 |
| Self-enrollment at login                  | remembered login on a fresh browser                             | `src/session/initSession.ts` + `src/session/pendingEnrollment.ts` | `/clientAnnex`              | pending record pre-pivot; the next remembered login's resume                                                                                              |
| Client enrollment (two-party)             | Settings > Connected wallets, any session type                  | `src/lib/enrollment.ts` (UI in `EnrolledClientsSection.tsx`)      | `/enrollment`               | re-run with the same connect code; the escrow-direction convergence of any later ladder-branch ceremony                                                   |
| Client revocation + epoch cascade         | Settings > Connected wallets, any session type                  | `src/session/revocation.ts`                                       | `/clients`                  | re-run; the cascade-completion sweep; on the ladder branch, the retire-direction convergence of any later ladder-branch ceremony (open gap below)         |
| Recovery-code issuance                    | Settings > Recovery codes, any session type                     | `src/session/recovery.ts`                                         | `/recovery`                 | re-run with the same code (every stage detects its own completion); a tear after the document entry has no mender                                         |
| Recovery-code revocation                  | Settings > Recovery codes, any session type                     | `src/session/recovery.ts`                                         | `/recovery`                 | re-run; the cascade-completion sweep                                                                                                                      |
| Unlock-credential rotation                | Settings (passphrase change, passkey removal), any session type | `src/session/credentialRotation.ts`                               | `/unlock`                   | torn-retirement repair at the next passphrase login (transient or remembered); remembered-login sweep; re-seal repair                                     |
| Forget ceremony                           | Settings > Connected wallets, own row, browser-local only       | `src/session/forget.ts`                                           | `/clientAnnex`              | re-run (wipe last); forgotten-browser detector at the next remembered login                                                                               |
| Last-client transition                    | same row, `lastClient` confirm, browser-local only              | `src/session/forget.ts`                                           | `/clientAnnex`              | re-run                                                                                                                                                    |
| Update-key rotation                       | Settings, browser-local only                                    | `src/session/accountSettings.ts`                                  | `/webvh`                    | re-run (persist-before-publish)                                                                                                                           |
| Account genesis (plain)                   | a no-WAS deployment's signup only; healed at every login        | `src/session/signup.ts`                                           | `/genesis`                  | re-run (every stage an ensure)                                                                                                                            |
| Account deletion                          | Settings, any session type                                      | `src/session/accountSettings.ts` + `wipe.ts`                      | app-side phase order        | re-run; an in-run retry for the acting credential's own unlock Space; otherwise the next login with that credential offering to remove it (not yet built) |
| Shared wipe (executor, not user-facing)   | consumed by the deletion-shaped ceremonies                      | `src/session/wipe.ts`                                             | app-side                    | re-probe verification; the `unverified` report                                                                                                            |

A WAS signup's remembered and passkey flavors continue into the
self-enrollment row, and the credential-anchored genesis heal branch also
mends a remembered signup torn before its self-enrollment.

The open gaps come in two classes. First, a stated residue with no mender
built:

- The transient recovery's roster-append repair, on a client-less account.
- A user-key rotation torn mid-fan-out on a client-less account.
- An establishment torn between the record re-bind and the promotion leaves
  the KMS keystore's controller on the ladder's bare did:key, outside the
  current-key-set rule. A mender could run from a transient visit, the
  keystore ensure not depending on the Space.
- A recovery-code issuance torn after its document entry leaves a saved code
  that locates no account, plus a document `keyAgreement` entry and a roster
  wrap nothing names. The login sweep rotates the orphan wrap away, but the
  registry-driven health check cannot see the code, so the retire-and-reissue
  mender is unbuilt.
- A sibling unlock Space an account deletion could not remove, whose
  credential is never used again. That credential's own next use is the only
  mender, and an unspent recovery code is the sharp case.
- On a KMS deployment, a keystore orphaned by an account deletion that ran
  before the keystore-deletion route lands. A server-side reaper is not a
  wallet mender.
- A signup whose KMS stage failed or timed out publishes a document with no
  `authentication` relation, and nothing adds one. The failure is collected
  rather than thrown, so the account pointer binds and no establishment
  re-run fires the stage again, leaving a remembered login this account may
  never see as the only other trigger. The account presents did:key and
  refuses a `web` or `webvh` request; closing it means a ladder-signed entry
  adding the verification method after the fact.
- A ladder-branch disconnect of the account's last enrolled client, torn
  after its removal entry, leaves the roster wrapping the current key to the
  removed client. The row is gone from the listing and that account runs no
  remembered-login sweep, so the only mender is the retire-direction
  convergence of a later ladder-branch ceremony, which the user may never
  run.
- The retired credentials' unlock Spaces on a recovery spend torn between
  the landed registry drop and the deletes. The entries are gone, so nothing
  names the Spaces again. The residue is inert, and is the class the
  registry-driven account-deletion walk already leaves behind.

Second, a residue whose only mender is a remembered login:

- The collection descriptor logs behind a forget ceremony's removal entry.
  Both forget grades run their collection fan-out before the entry, so every
  append anchors at a version that still lists the forgotten client's key,
  and that key can keep appending there until a still-listed key appends
  past the removal. An ordinary forget leaves that to the next remembered
  login's sweep. The last-client transition leaves an account nothing seals,
  since the departing client's authority ends at its own entry and the
  transient login runs no collection seal.
- The annex generation GC, which runs from the remembered-login chain only.
  On a client-less account the pointed generation's log grows by one entry
  per transient visit with nothing collecting it, and every visit resolves
  that log from genesis. A `gen-` collection orphaned by a crashed first
  visit waits for the same sweep, an account-log pointer entry left by one
  is append-only, and an auxiliary Space stranded between its mint and its
  pointer entry has no deleter at all. The constraint is authority: the swap
  re-points the account log, the collect fan-out is controller-tier, and a
  ladder VM can sign neither.

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
  - `/clientAnnex` (the ladder, the annex log and its GC, and the
    ladder-anchored ceremonies: credential-anchored genesis, self-enrollment,
    transient recovery). The verify-side halves stay in the base subpaths.
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
  - `/request` (classification, matching, VP composition, exchanges, the App
    Connect app-key credential)
  - `/resourceLog` (the did:webvh controller adapter
    `webvhResourceLogController` and the ceremony-tail license)
  - `/sync` (contacts head-conflict resolution,
    `resolveContactHeadConflict`, over social-core's comparison; the change
    engine beside it is the mobile wallet's).
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
- **`@interop/webkms-client`** and **`@interop/ezcap`** --
  `CapabilityAgent`, `KmsClient` / `KeystoreAgent`, and `ZcapClient`.
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
- **Tear mending** -- the umbrella for how a torn ceremony (one interrupted
  mid-run) gets finished, by a converging re-run, a standing sweep, or a
  repair. A mender counts only if a credential-only visit can fire it, so a
  residue whose one trigger is the remembered-login chain is an open gap
  (`decisions/0010-remembered-login-is-not-a-mender-trigger.md`). Avoid:
  tear closure.
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
- **CapabilityAgent** -- from `@interop/webkms-client`. Wraps the Ed25519
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
  logged-in user, their `ControllerProfile` (keyAgent + zcapClient, and the
  persistence strategy at `profile.persistence`), and their `StorageManager`
  instance.
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
- **Persistence strategy** -- the typed object at `profile.persistence`
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
