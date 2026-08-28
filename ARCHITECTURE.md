# Architecture

How Freewallet is structured -- the layer map, session and auth flow,
storage model, CHAPI and App Connect flows, the domain model, where shared
logic lives, and the ZCap authorization structure. For contribution
conventions see [CONTRIBUTING.md](CONTRIBUTING.md); for agent-facing rules
(tech stack, env vars) see [AGENTS.md](AGENTS.md).

## Layer map

```
src/pages/          Route-level React components (one file per page)
  auth/             Login, Signup, Recover, GuestLogin, Logout
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
  kms.ts            WebKMS keystore provisioning (ensureKeystore)
  resolveWalletInput.ts  The one door for free-form text (paste box, QR),
                    over the shared wallet-input classifier
  sessionKey.ts     freewallet-session IndexedDB state (keyring cache,
                    client-key records, unlock methods, passkey-safety
                    notices)
  registryManager.ts     The unlock-methods registry read/write protocol
  storageAccess.ts  Storage Access API handle for the CHAPI popup
  corsProxy.ts      The one CORS-proxy path (`VITE_CORS_PROXY_URL`): the
                    pasted-URL credential fetch and the registries fetch
  writerId.ts, prefsStorage.ts, log.ts   The writerId mint, the global UI
                    prefs seam, the @interop/logger wiring
  connectedApps.ts  Connected-app and agent listings for the Applications page
  viewMappers/      Transform raw credential data into display-ready values
  walletRequest/    VPR classification + response assembly for CHAPI requests
    respond.ts      Compose, persist the Login activity, then deliver (the
                    CHAPI `get` approval sequence)
    externalRequest.ts  The interaction-URL entry point's pure half: the
                    deep-link parser, exchange opening, and pre-consent
                    refusal matrix
  sync/             Collection-agnostic WAS replication adapter (RxDB-based)
src/stores/         Global state
  authStore.ts      Zustand store -- holds the live Session object
  storageManager.ts StorageManager facade (local-first routing)
  browserStore.ts   BrowserStore -- the local RxDB active replica
  remoteDirectStore.ts   The replica-less backend (transient and popup sessions)
  wasRemoteStore.ts WASRemoteStore -- the remote WAS backend
  syncController.ts Background replication lifecycle (start/stop/reSync)
  toastStore.ts     Transient success/info messages (`showToast`), rendered
                    by DashboardLayout as a Snackbar. Global, not
                    page-local: an action often redirects (delete returns
                    to the dashboard) before a local message could render.
src/session/        Session bootstrap and the account ceremonies -- the
                    ordered sequences pages drive but do not own (React
                    components keep rendering and confirmation callbacks
                    only). Grouped by role:
  Login             initSession.ts, keyring.ts, transientLogin.ts,
                    persistence.ts, verifiedLog.ts, loginErrorKey.ts
  Signup            signup.ts, provisionNewWallet.ts,
                    credentialAnchoredGenesis.ts, standingUnlock.ts
  Settings          accountSettings.ts, credentialRotation.ts,
                    unlockMethods.ts, clients.ts, shares.ts, applications.ts
  Ceremonies        recovery.ts, revocation.ts, forget.ts, wipe.ts,
                    ceremonies.ts
  Repairs / sweeps  pendingEnrollment.ts, pendingRetirement.ts,
                    registryReseal.ts, userKeyAdoption.ts, userKeyCascade.ts,
                    appKeySweep.ts, clientAnnexGc.ts
  Shared parts      rosterStore.ts, annexReach.ts, recordEnvelope.ts,
                    enrolledContext.ts, completePopupLogin.ts,
                    walletLoginActivity.ts
src/types/          Shared TypeScript interfaces
src/i18n/           i18next config + locale JSON files
src/styles/, src/themes/   MUI sx-object style constants and theme config
src/fixtures/       Seed data (default contacts, welcome credential)
src/app.config.ts   Environment variable exports + app-wide constants
```

## Session & auth flow

There is no external identity provider, and nothing about the account
derives from the passphrase. Each wallet client (a browser profile) mints a
random 32-byte **client seed** locally on first run: the Ed25519 pair behind
its did:key, plus the X25519 twin. The private halves stay on the client.

The passphrase (or a passkey PRF output) derives only an **unlock identity**
(the keyring v2 seam, `src/session/keyring.ts`). At login it fetches the
**unlock record** from its own minimal unlock Space, and unwraps the local
**client-key record** in the `freewallet-session` IndexedDB, which holds
this client's seed, a cached copy of the user key, and its did:webvh
update-key seeds. The unlock record carries none of the account's content
keys.

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
                                    (credential-derived, deterministic;
                                     NOT the enrolled client's randomly
                                     minted seed below)
  -> unwrap local client-key record -> { clientSeed, userKey, webvhUpdateKeys }
     (or, on a fresh browser: self-enroll through the record's bridge, then
      persist the freshly minted key set as this record)
  -> agentsFromSeed(clientSeed)   -> keyAgent (keyAgent.id === a did:key DID)
  -> ZcapClient(invocationSigner) -> zcapClient (signs HTTP requests with ZCap)
  -> { user: { id: did:key }, profile: { keyAgent, zcapClient, userKey } }
  -> StorageManager.initStorageClients()
  -> Session { user, profile, storage, isGuest }
```

When the account pointer names a did:webvh (every promoted account; see "The
did:webvh identity"), `zcapClient` signs with the same client Ed25519 key
under its verification-method id in that document
(`<did:webvh>#<multibase>`) rather than the did:key form. The data Space's
controller is the did:webvh, and under the current-key-set rule only a keyId
the resolved document lists can authorize anything. `user.id` stays the
client did:key, also the App Connect response VP's holder that app-side
loaders must resolve.

On a WAS deployment with a promoted account, every unlock method is a
**standing credential**: the recovery-code configuration minus spend-on-use.
Three cases cannot be standing, and their records stay plain account
pointers with none of what follows: a no-WAS deployment, a guest, and an
account not yet promoted. Beside locating the account a standing record
holds a user-key roster wrap (escrowed into every epoch, kept alive by
rotation fan-out) and latent self-enrollment authority: a pre-minted
PUT-on-`did.jsonl` bridge delegation and a random update-key ladder seed
(`@interop/wallet-core/unlock`, bound by `src/session/standingUnlock.ts` at
signup and at every add/change-method ceremony). On an account pointing at a
client annex generation, that establishment also appends one atomic
hash-restating annex commit entry with the new credential's rung-0 hash,
signed by the login credential's committed rung (`commitClientAnnexRung`);
without it the credential could not enter a transient session until the next
generation swap. Best-effort: an acting rung the generation does not commit
is skipped.

**Self-enrollment.** A fresh browser holding only the credential can
self-enroll at login as an ordinary full client, no second browser involved.
It runs today through the programmatic `rememberBrowser: true` entry, since
a non-remembered browser defaults to the transient session (see "Session
persistence"); a login-form choice is a planned follow-up. Two loud entries
extend the world-readable log through the bridge: a reveal-and-commit entry
signed by the ladder's current rung, then an add entry publishing the minted
client. Only then does the user key unwrap from the credential's standing
wrap.

Before standing credentials, the unlock credential alone could not make a
browser a client. A login on a fresh browser stopped at a not-enrolled
state, and enrolling it took a second browser already enrolled on the
account. Detection replaces that gate: a self-enrollment is visible in the
log and remediable by rotation, rather than prevented by requiring another
browser (see Loudness in the Glossary).

Between the two entries the required `onCommitted` seam writes the
pending-shape client-key record (seeds, controller, `pointerDid`, the
`pending` group, no user key), so the pivot publishes nothing only a live
tab could re-derive. Completion writes the enrolled shape, then advances the
visit's epoch pin; a rejecting pin write is logged and the login proceeds.

A later login routes a pending record to the resume
(`src/session/pendingEnrollment.ts`), discriminating on user-key absence;
`pointerDid` is the resume's account cross-check, not a routing member. The
verified log history decides the arm: a VM-listed record completes; a
never-published one re-runs seeded with the recorded key set
(`BuiltOnHeadNotReachedError` refuses a log behind the recorded head); a
published-then-removed one wipes, since a revoked client is never
re-published; an unresumable one is discarded and the browser routes
record-less. Fail-closed, and transport failures keep the record.

On a ladder-anchored account the add entry removes the ladder VM, so the
still-unexpired bridge delegation and the `delegatedClients` sibling it
signed stop verifying. That same login's refresh block catches it, its
predicate covering signer rot beside expiry (`delegationKeyInDocument`,
against the memoized verified account document), re-signs both with the
enrolled client's account key, and reseals the record. A remembered login
self-heals a rotted embedded generation delegation the same way
(`ensureGenerationDelegationCurrent`, account-document axis), signing with
the login credential's ladder seed held on `profile.ladderSeed`.

The document carries a passphrase-derived `keyAgreement` key only as a hash
commitment (`MultikeyCommitment`), which the roster's recipient resolver
verifies the roster-carried key against. A passkey's PRF-derived key is
high-entropy and publishes verbatim (the hash-commitment rule under
"Recovery codes").

The connect-another-wallet ceremony (see "The client enrollment ceremony")
survives for records without standing authority (a no-WAS bind), for the
rendezvous onboarding flow, and as the future opt-in step-up approval
policy. The storage-partitioned CHAPI popup takes the transient session
instead of self-enrolling, since an enrolled client per popup visit would
litter the log.

**Record authenticity.** The unlock identity's own Ed25519 key signs the
unlock record; the proof is verified before decryption, and a record whose
proof does not verify is refused (`KeyringRecordForgedError`). That closes
host forgery: the record's JWE is sealed to the unlock KAK, whose public
half derives from the unlock did:key the server stores as the unlock Space's
controller, so a malicious host could otherwise seal a record of its own
that decrypts perfectly. The signing key derives from the typed secret, so
it never reaches the host, and a client that has only typed the secret
already holds the verification key -- no bootstrap window.

A standing record's account core (controller, pointer, ladder seed) is also
MAC'd under a credential-derived key the host never holds (the recovery
record's construction), verified before the pointer is trusted. That closes
the redirect a re-mint-signed record would otherwise reopen; a cascade
re-mint signs with an enrolled client's account key, settled against the
account document at login.

was-client's paths helpers build the unlock Space's request paths on both
the delegation and invocation side (the record fetch and rewrite, and the
management delegation's `invocationTarget`), so the bytes the server's
`allowedTarget` check compares cannot drift. That is load-bearing on a
sub-path deployment, doubly so since the record carries the recovery bridge:
a broken target would break login itself.

**The replay bound.** A signature cannot catch a replay: a record the
account has moved off stays authentic forever. Catching one needs a pin from
an earlier visit, and this wallet keeps none
(`decisions/0012-no-durable-continuity-pins.md`; the rule and its successor
are stated once under "Log continuity within a session"). A replayed unlock
record is therefore a stated bound rather than a refusal. A login can land
in an account the user has moved off and show its contents, visible for
exactly that reason and reversible by logging in again once the host serves
the current record. Record stamps stay wall-clock and advance past what they
replace: every write site stamps `max(now, fetched record's createdAt +
1ms)`, so a lagging clock still writes a record that supersedes the one it
overwrites. Nothing compares pointers either: a validly signed record naming
an account this client has never seen is followed wherever it points, since
a rebind, a host migration, and a fresh account bound under a reused
passphrase are all legitimate and all produce a newer signed record.

The bound on the whole construction: server-held material the unlock
credential alone decrypts (the record, and the credential's standing wrap of
the user key in the roster) is only as strong as that credential's entropy.
Against a malicious storage host running an offline KDF grind, zcap scoping,
TTLs, and revocation are worth nothing, so the unlock credential's custodian
must not be the storage host, and a wallet's security is limited by its
weakest standing unlock method. Logging in from a public terminal is a core
supported case (nothing need persist locally to reach the account), which is
why the record must stay server-held and self-authenticating. Client
revocation does not bound an attacker who holds the credential itself, since
they re-derive and self-enroll again. Credential rotation is that remedy.

**The unlock-credential rotation ceremony.** A passphrase change and a
passkey removal both retire the old credential's standing rather than merely
rebinding the unlock record. wallet-core's `retireUnlockCredential`
(`@interop/wallet-core/unlock`) is the shared sequence, wrapped session-side
by `rotateOffUnlockCredential` (`src/session/credentialRotation.ts`).

The credential's document inventory leaves first, in one log entry: its
`keyAgreement` entry (commitment or verbatim) and its ladder's whole
standing inventory, resolved from the log rather than from the registry's
recorded bind-time rung. With the ladder seed in hand (held by the
passphrase change and the tap-confirmed passkey removal), that entry also
strikes the seed's ladder VM when one stands, the residue of a last-client
forget torn after its install entry.

The annex inventory follows, between the document edit and the roster tail
(wallet-core's `retireClientAnnexInventory` closure). A strike entry on the
annex log drops the retired credential's revealed rung and standing hash
when a distinct surviving credential's committed rung can sign it. Otherwise
(a self-strike, or no committed survivor) the whole generation swaps onto a
surviving credential's ladder (`swapClientAnnexGeneration`), leaving the old
generation to orphan discovery. A passphrase change signs with the NEW
credential's ladder seed (`survivingLadderSeed`).

Which ladder the session's login seed may fill is settled against the
pre-edit log by the retired entry's recorded update key, since seed
comparison is vacuous with no retired seed in hand. That seed is the retired
ladder when the key is one of its rungs up to the attributed one, a survivor
only when it provably is not, otherwise neither, so a swap can never anchor
the fresh generation on the credential being removed. Best-effort, reported
on the outcome's `clientAnnex` member.

Then the roster-and-cascade tail the client revocation runs (see "Client
revocation and the epoch cascade"): the user key rotates off the
credential's wrap, a pairing-free convergence onto the post-edit document,
and every encrypted collection re-epochs onto the fresh key. That tail's
`onUserKeyAdopted` step re-seals the unlock-methods registry to the rotated
key in band, before that key persists into the client-key record
(`adoptRotatedUserKeyInBand`, `src/session/userKeyAdoption.ts`). The re-seal
needs this browser's stored copy of the OLD key, destroyed on a
single-client account by persisting the rotated one, so a run torn after
this step still leaves a registry the surviving keys open.

The callers then tear down the registry entry and the old unlock Space under
the ROTATED vault keys, and adopt the rotated key into the live session's
storage ciphers (`adoptRotatedUserKey`, the `revokeRecoveryCode` ordering).
That call returns on its id guard once the tail has re-sealed and swapped,
and retries the re-seal in the one case the tail leaves open: a failed
re-seal, where the session stays on the pre-rotation keys rather than
meeting a stale seal on its own teardown writes.

Document-removal-first is load-bearing: a run torn after it leaves the
roster keying a recipient the document no longer backs, exactly what the
login-time sweep detects and finishes. The limitation is the cascade's, and
Settings says so, since the ceremony is its documented "I think my
passphrase leaked" remedy: ciphertext the credential's holder already
fetched stays readable.

A passphrase change runs establish-first on a WAS account. The old
passphrase is verified read-only, the NEW passphrase's whole standing
establishment is the first write, and only then are the old record and
unlock Space torn down and the old credential retired. A failed
establishment fails the change outright, with the old credential's record,
Space, and standing configuration unchanged, so the failure copy is true and
a retry with the same new passphrase converges on the establishment's
idempotent stages. No plain record is written for the new passphrase; the
plain rebind survives only where nothing can be standing (no WAS, a guest,
an unpromoted account). A change torn between establishment and teardown
leaves BOTH passphrases live and standing, retired by a retry or by the
torn-retirement repair below.

The registry's passphrase entry is written only after the retirement
reports, because the entry's standing configuration depends on how the
retirement ended. Each degenerate state below has its own detector and
mender.

**Pending entry.** A retirement that failed before its document edit landed
leaves the entry naming the new unlock Space but the OLD credential's whole
standing configuration, the one state that still names the credential left
standing. While it stands pending, a second change from the same session is
refused (`PendingPassphraseRetirementError`, when the entry records a
credential the typed old passphrase does not derive); the retirement would
otherwise remove one credential's document inventory while striking the
other's ladder. For the same reason registry writes matched by unlock Space
id carry the acting credential's key-agreement multibase, and a mismatch
writes nothing.

**Bare entry.** An entry carrying no identity members normally means the
credential has no document inventory to retire, so the change reports clean.
When the typed old credential still stands in the document, or the document
could not be checked, that would be a silent failure on the
leaked-credential remedy, so the change reports `rotation: 'unretired'`
instead. Its entry takes the shape a retirement torn at the document edit
leaves (the new unlock Space naming the OLD credential's members), minting
the registry first if none existed. Establish-first means this arm's entry
always names a standing new credential.

**Torn-retirement repair.** The next passphrase login clears a pending entry
(`repairTornPassphraseRetirement`, `src/session/pendingRetirement.ts`): one
naming a credential other than the one logging in, with the login credential
itself standing in the account document. It retires the named credential and
records its own standing configuration in the entry. The login-credential
check stops it firing in reverse, where an old passphrase whose unlock Space
delete failed logs in after a change completed elsewhere. When the named
credential already left the document (only the registry write was lost),
only the entry is rewritten; the roster and cascade residue is the ordinary
login sweep's.

The same repair mends a BARE or absent passphrase entry, but only when it
names no credential at all, or names the login credential itself with no
recorded update key; nothing else is at risk either way, so the entry is
rebuilt from the login credential's keyring hit. An entry naming ANOTHER
credential with no recorded update key is left alone: the repair has no rung
to attribute that credential's ladder by, and rebuilding it could un-name a
credential still standing. This is also the whole migration for accounts an
earlier shipped defect damaged this way; there is no separate migration
code.

**Bare passkey entry.** A passkey login runs the sibling repair,
`rebuildBarePasskeyEntry`, on its own entry: a present-but-bare entry,
matched by unlock Space, rebuilt from the keyring hit once the account
document publishes that passkey's `keyAgreement` key verbatim. An entry
never written is left alone, since rebuilding it needs the WebAuthn
credential id a login does not carry; that case stays the add-a-passkey
ceremony's registry write to make.

**Stale registry seal.** A registry sealed to a superseded user key (a
rotation whose in-band re-seal was itself torn, or one run by a client from
before that duty existed) gets its own login-time repair
(`repairStaleUnlockRegistrySeal`, `src/session/registryReseal.ts`). A served
record that fails to decrypt under the current vault keys throws
`UnlockRegistryStaleSealError` rather than reading as absent. The repair
tries each prior user key generation the roster still escrows, newest first,
until one opens the record, then re-seals it to the current key.
Best-effort, and read-only when nothing is stale. While it stands, Settings
shows the state with its own copy instead of the generic load error.

At login the user key sweep, the re-seal repair, the torn-retirement repair,
the bare-passkey rebuild, the registry backfill, the standing-delegation
self-refresh, the ladder-rung refresh, the did:webvh pointer heal, and the
generation-delegation self-heal run on one ordered promise chain; the annex
GC sweep forks off its tail. The re-seal repair runs first among the
registry passes: every registry writer downstream reads the record, and a
stale seal would make each warn and skip on a registry this login can mend.
The sweep is early because its roster convergence may rotate the key and
re-seal the registry, and a read-modify-write racing that re-seal would
rewrite the record under the pre-rotation keys and undo it within one login.

Navigation to the dashboard waits only on storage provisioning
(`session.storageReady`). The chain runs after navigation, on a separate
`session.registryReady` promise that never rejects; a failed stage is logged
and skipped rather than surfaced to the login page. A Settings-entered
ceremony that writes the unlock-methods registry (passphrase change,
passphrase or passkey add, rename, or remove, account deletion, client
disconnect, the forget ceremony, recovery-code issuance and revocation)
awaits `session.registryReady` at its own entry rather than racing the
chain's writes. So do update-key rotation, which writes the same client-key
record the sweep's adoption stage writes, the Settings registry load, and
the recovery-codes health check. When storage provisioning fails, the login
page abandons the session and the chain never runs, but `registryReady`
still settles.

Every registry PUT is also a compare-and-swap on the ETag of the fresh read
it was based on, with a bounded re-read retry on a lost race. A concurrent
writer the ordered chain cannot serialize (another tab, another client)
conflicts and re-applies on the fresh record instead of silently reverting
it, and a stale tab's write cannot downgrade a rotation's re-seal. The guard
covers honest concurrency only; the registry's bound is unchanged against a
tampering host.

The `Session` object lives in the Zustand `authStore` and is in-memory only
(the passphrase is never persisted), so reloading the browser logs the user
out. Guest sessions use a random 32-byte seed directly and never touch the
WAS server or the KMS.

All four session entry points (login, signup, both CHAPI popup pages) funnel
through `initSessionFromSeed`. With a KMS configured (`KMS_SERVER_URL`), it
also provisions a WebKMS keystore for the controller (`ensureKeystore` in
`src/lib/kms.ts`: list-by-controller, create on miss, one keystore per
controller by convention) and binds a `KeystoreAgent` as
`profile.keystoreAgent`. Operational keys can live server-side there while
the controlling key stays strictly client-side: the keystore is created
under the first client's did:key, and its controller is promoted to the
account's did:webvh alongside the Space's (the same
`promoteKeystoreController` sequence, non-fatal). No server-held key is ever
an update key or an encryption-roster recipient. Provisioning failure is
logged and non-fatal, and the settings page shows the state.

## The did:webvh identity (per-client keys, promoted controller)

The account's stable id is a `did:webvh` whose hash-chained log lives as
`did.jsonl` in the world-readable `id` collection
(`@interop/wallet-core/webvh`). Its document is the enrolled-client roster.
Each enrolled client contributes an Ed25519 verification method under
`authentication`, `assertionMethod`, `capabilityInvocation`, AND
`capabilityDelegation`, plus its X25519 twin under `keyAgreement`. Ids are
`<did:webvh>#<multibase>`. The signing method carries `controller:
<did:webvh>`; the key-agreement method carries `controller: did:key:<the
client's signing multibase>`, a marker naming its client. The client
listing, the revocation removal, and the roster's recipient resolver pair a
client with its key-agreement key by that marker; nothing re-derives a twin.

One KMS-held VM (`authentication`) is a server-side convenience. The
KMS-held `keyAgreement` VM is NOT in the document: that relation is the
source of record for user-key wrap recipients, and no server-held key may be
a wrap target. No KMS assertion key is minted, since the App Connect
Resource Log Profile authorizes log appends by `assertionMethod` membership,
so that relation lists client signing keys only.

**Update keys are client-held.** `updateKeys` carries one update key per
enrolled client; apps get none. They derive from 32-byte seeds in the
wrapped client-key record, beside the client seed and the user key. The
server cannot extend the log, which makes it the one self-certifying
artifact the server hosts. Prerotation stays on under a **carry-over
commitment convention**: `nextKeyHashes` commits each client's staged key
AND each active key's own hash. The resolver re-checks every entry's
re-stated `updateKeys` against the previous entry's commitments, so without
the active-key hashes no non-rotating entry (an enrollment commit, a
document edit) could resolve. Rotation is per-client self-rotation
(`rotateWebvhUpdateKey`), swapping only that client's key: persist the
rolled seeds into the client-key record BEFORE the log entry publishes, then
finalize. `keys.json`'s webvh block is `{ did }` only; key roles do not live
server-side.

**Conditional publish.** Every ceremony publishes `did.jsonl` as a
compare-and-swap on the ETag of the read its entry was built on, so
concurrent clients cannot silently erase each other's entries. A lost race
surfaces as wallet-core's typed `WebvhLogConflictError`, and the ceremony
re-runs on the new head (`withLogConflictRetry`). The shared
`wasWebvhIdStore` carries the ETag and preconditions for every
enrolled-client ceremony; the recovery continuation's `delegatedLogStore`
(`src/session/recovery.ts`) does the same over its public log fetch and
delegated PUT. The `did.json` projection PUT stays unconditional: it runs
only behind a won log CAS, and the log is the source of truth.

**Log continuity within a session.** Resolving the world-readable log is
one-shot verification, and a valid PREFIX of the real log passes it. The
prefix carries the genuine genesis, so the same SCID and DID, and
`expectedDid`, the entry proofs, and chain verification all hold on it. A
ceremony built on one would republish erased enrollments and undone
revocations. So every `verifyAccountLog` read carries a chain-head pin
(`persistence.logPins`, `@interop/vh-resource-log`'s keyed
`ResourceLogPinStore`), and a served log that is a rollback, a fork, or an
SCID/method switch against the pinned head is refused
(`ResourceLogContinuityError`). The pin is established at the visit's first
contact and advanced only by a log verifying past it; it never regresses.
One keyed store serves every log this session reads: `read` and `write` take
a per-log slot key wallet-core derives (`accountLogPinId` /
`userKeyRosterPinId`, both `space/<spaceId>/<collection>/<resource>`), so
two logs cannot clobber each other's pin. The slot key is host-free, so a
log served from a claimed new host is checked against the pin already held.

The pin store is in-memory on both persistence strategies
(`decisions/0012-no-durable-continuity-pins.md`). The rule, stated once here
for the whole document: continuity is checked within a session and not
across sessions. One login makes many log reads, a transient visit resolving
the annex log three times beside the account log and the roster, and the pin
catches a host serving inconsistent versions across them. Nothing carries a
pin from one visit to the next, on any browser, so remembered and transient
sessions have identical continuity properties. The successor to a pin is
witnessing, which belongs to the log layer rather than to this wallet.
`@interop/did-method-webvh` implements witness proofs and this wallet
consumes none; `@interop/vh-resource-log` would need an equivalent before
the roster and annex logs were covered. Every other continuity claim in this
document rests on this paragraph.

The bound is a visit's first read: a prefix served to a fresh visit is not
detected. That visit sees a stale document view, a revoked client still
listed or a retired credential still standing, and a rotation against it can
re-wrap the fresh user key to a client the account has revoked. That takes
host malice plus a previously-revoked client colluding. Against a passphrase
account the same malicious host can grind the credential offline anyway.
"Session & auth flow" states the same bound.

The pin rides the verified-log memo (`src/session/verifiedLog.ts`), the
bare-parts roster store's controller resolution, the recovery flows' direct
reads, and the enrollment completion's first contact; the login page renders
the refusal (`auth.errors.accountLogContinuity`). A `rollback` may be
nothing worse than replication lag: nothing rolled back is adopted, and a
caller with a cached document view may carry on. Ceremony-path `did.jsonl`
reads also check the resolved DID against the account pointer (`expectedDid`
on the revocation cascade and the recovery ceremonies; `verifyAccountLog`
makes the same check itself). That is what refuses a mirror, since the
did:webvh id embeds the Space id and a mirror under a freshly minted Space
id resolves to a DIFFERENT DID. Two log-publishing ceremonies run on this
repo's paths: `ensureDidWebvh` for login-time provisioning (wallet-core's,
reached through `ensureAccountGenesis`) and `rotateWebvhUpdateKey` for the
settings-page update-key rotation. Both read under the same pin store and
account DID, so the refusals above cover them. Provisioning stays non-fatal,
since a hiccup must not fail login, but a non-`rollback` refusal is logged
as an error, and later account-log reads in the same login hit the same pin
and surface it to the user.

**The Space-to-DID mapping.** One browser-local continuity artifact outlives
the visit, and it is not a pin: the account DID a data Space's log published
as, recorded by the client that published it (`saveAccountDidForSpace` in
`src/lib/sessionKey.ts`). It records what this browser did rather than a
version some host served. A signup torn between the log publication and the
account-pointer backfill heals at a later login whose pointer still names no
did:webvh, and this mapping lets that heal state an `expectedDid` anyway.
Account deletion clears it through the shared wipe enumeration below, beside
the keyring retirement. Before the account Space dies, deletion also walks
the unlock-methods registry, deleting each entry's unlock Space and
unlock-local state best-effort (`deleteUnlockMethodArtifacts` in
`src/session/unlockMethods.ts`, removing the dangling existence-oracle
Spaces a probe could still find), then deletes the auxiliary annex Space in
one `space.delete()`. Both run BEFORE the fatal wipe, because resolving the
auxiliary Space's controller reads the account log out of the account Space.
A wipe failure after them leaves other methods' logins already destroyed,
accepted since the intent was deletion.

**The shared wipe enumeration** (`src/session/wipe.ts`) is the one list of
browser-local state an account leaves on a browser, and the one executor
that deletes it. The deletion-shaped ceremonies consume it: account
deletion, the guest wipe, and the forget ceremony (the orphan-client heal is
designed onto the same seam). It is snapshot-first, so every target derives
from the live session before anything is deleted. What it enumerates:

- The client-keyed families (the unlock-methods cache, the passkey-safety
  notice, the replica-database prefix, the local-mode cache scope), derived
  from this browser's own client did:key rather than the account controller.
- Each unlock method's unlock-local state, derived from the registry walked
  across every method and always including the session's own login
  credential (`profile.unlockMethod` and the standing members' unlock Space
  id). A registry read lost to a transient server error narrows the
  enumeration to the other methods and is reported on the wipe outcome
  (`unlock-methods-registry`), instead of leaving this browser's client-key
  record behind a wipe that reads clean.
- The Space-to-DID mapping, keyed by the account Space id.
- The per-account localStorage families: the descriptor and meta caches
  under both scope schemes, and the migration markers.

No continuity pin is enumerated, because none is stored (see "Log continuity
within a session"). Cross-tab teardown precedes the replica delete, a
broadcast asking sibling tabs to drop open handles, and completion is
verified by re-probing rather than resolved while blocked. Global UI prefs
stay out; the global `writerId` clears only on the forget grade.

`indexedDB.databases()` is a discovery and verification aid rather than the
deletion gate: the session and replica databases go by known name whether or
not the engine can enumerate. A deletion the executor could not confirm, or
a replica prefix `databases()` alone would have named, is reported on the
outcome's `unverified` list rather than folded into a clean wipe.

Limits no enumeration reaches: deleted IndexedDB data stays forensically
recoverable, plaintext `public-credentials` rows included; the CHAPI popup's
partitioned third-party buckets are unreachable from any top-level wipe; and
the mediator-origin (authn.io) handler-registration bit records that a
wallet was used on the terminal. Only clearing the browser profile removes
those.

**The forget affordance** (`src/session/forget.ts`) removes this browser
from an account, in two grades split by whether the unlock credential is in
hand.

From a live remembered session (Settings > Connected wallets, the current
client's row) it is the **forget ceremony**, wallet-core's
`forgetEnrolledClient`. The user key rotates off this client's roster wrap
and every encrypted collection re-epochs, both under this client's
still-standing authority: the self-forget inversion of the revocation's
document-edit-first order, forced by the entry-proof and current-key-set
rules (wallet-core decision 0008). Then ONE atomic ladder-signed removal
entry through the login credential's bridge takes the client's whole
document inventory out. Only then does the local wipe run (`clearWriter:
true`, the wipe's one writerId consumer).

Wipe-last is the tear story. A run torn before the entry reads as "not
forgotten", and a re-click resumes. The other direction, removal published
but wipe torn, is caught at the next login by the **forgotten-browser
detector** (`assertClientStillEnrolled`): an enrolled client-key record (its
user key present) still here while the cleanly verified account document no
longer lists this client's verification method. The detector finishes the
wipe from what the keyring hit alone derives and surfaces "this browser's
access was removed" in place of raw authorization errors. It persists
nothing.

The detector sits past a record-to-account cross-check, pointer-based like
the resume's. An enrolled-shape record whose stamped `pointerDid` names a
DIFFERENT account than the unlock record points at is stale residue rather
than a forgotten browser: a prior account under a reused passphrase, gone
server-side, so no wipe ever touched this browser. The stale wipe clears
what the record alone derives (the dead account's replica and caches, and
the credential's whole unlock-local state, the record included), and the
login re-routes once as a record-less browser, never reaching the detector.
A pending-shape record is spared for the resume instead (`decisions/0007`),
whose published-then-removed branch hands the removal case back to the same
wipe.

The ceremony needs the standing members the login stamped on the profile
(`profile.standingUnlock` beside `profile.ladderSeed`). It re-seals the
unlock-methods registry to the rotated user key while this client still
invokes, since surviving readers would otherwise find it sealed to a retired
generation. It writes no re-mint stages, because a replacement signed by a
key that dies at the removal entry would rot moments later. The standing
self-heals are what mend them, with the reach limit stated under "Ceremony
inventory". It refuses the account's last enrolled client with wallet-core's
name-stable `LastEnrolledClientForgetError`.

That refusal routes to the **last-client transition**: the same
`forgetThisBrowser` entry with `lastClient: true`, chosen from the listing
and confirmed against transition-stating copy (a stale listing's refusal
flips the dialog to that copy for a second confirm). It runs wallet-core's
`forgetLastEnrolledClient`, the two-entry ceremony that lands the account
client-less and ladder-anchored, the state a credential-anchored signup and
a transient recovery produce (wallet-core decision 0004's 2026-08-21
amendment). Its stages, in order:

1. The ladder VM's install entry, while the client's inventory stays (the
   both-present transitional state).
2. The roster rotation off this client's wrap: ladder-signed and anchored at
   the install entry (the ceremony-tail license's inventory-changing
   version), but HTTP-invoked under the still-standing client. The roster
   store is built with the ladder VM's signer over the ceremony-supplied
   post-install log (`ladderSignedRosterStoreFor`), so the roster head stays
   signed by a key the post-removal document lists and needs no seal repair
   on an account that never runs a login sweep again.
3. The collection fan-out.
4. The forced replacement of the embedded generation delegation with a fresh
   ladder-signed one, and the revocation, through this client's `WasClient`,
   of every still-unexpired ladder-signed delegation the annex history
   embedded.
5. The OTHER unlock methods' records (the standing passphrase and passkey
   credentials, the recovery codes) through the ceremony's `unlockMethods`
   reach (`unlockMethodsRemintReach`). The cascade's re-mint pass
   (`remintEntriesOf`, shared with the cascade) walks every registry entry
   but the login credential's, signs each bridge and sibling with the ladder
   VM, re-seals each record through its management zcap (invoked under this
   still-standing client), and writes the refreshed fields back.
6. The login credential's own record (`rebindLoginCredentialRecord`, the
   ceremony's required `onBeforeRemoval` seam, the one stage that reaches
   it): its bridge delegation and `delegatedClients` sibling re-signed by
   the ladder VM, the record re-sealed through the keyring hit's re-bind
   closure (stamped on `profile.standingUnlock` at login beside the
   credential's unlock Space id), and the registry pair refreshed in this
   client's last window of registry authority.
7. The removal entry.
8. The local wipe.

Stages 2 through 6 precede the removal entry because the removed client's
signatures rot there, and on a client-less account no remembered login's
refresh block will ever heal them.

The transition's refusals:

- A record the re-mint pass cannot re-seal, or an entry it skips as
  pending-shaped (whose bridge the removal would rot just as surely),
  withholds the removal entry with wallet-core's name-stable
  `RecordRemintFailedError`. The settings dialog renders a retryable stop
  naming the methods: the browser stays connected and a re-click resumes at
  the re-mint.
- A registry the transition cannot read refuses up front for the same
  reason, as does a session whose hit carried no re-bind closure.
- A pending-shaped passphrase entry refuses up front with
  `PendingRetirementForgetError`: one recording an unlock key-agreement key
  that is not the credential the record at its unlock Space is sealed to,
  the residue of a passphrase change torn before its retirement landed. The
  record itself is the detector, since an entry naming another credential is
  also what a superseded passphrase's own login sees on a healthy account.
  That state's only mender is the torn-retirement repair, which needs a
  remembered login, and the transition ends remembered logins forever.
- A registry that does not name every standing credential the account
  document publishes refuses with `UnrecordedCredentialForgetError`. Each
  document `keyAgreement` entry carrying no enrolled-client controller
  marker is compared against the registry entries' recorded key-agreement
  multibase, in both published forms: the verbatim id a passkey or recovery
  code publishes, and the commitment id a passphrase publishes. Every walk
  is registry-driven, so an unnamed credential would keep a bridge
  delegation the removal entry rots with no replacement.

Readers settle a re-minted record's proof against
`currentAccountRecordSigners` (the enrolled clients' signing keys plus the
ladder VMs the document lists), since on a client-less account the ladder VM
is the only record signer left.

From the login page's authenticity and continuity refusals (reachable from
passkey failures with no typed passphrase, reset between attempts) it is the
**no-unlock-material grade**. Nothing can be derived or signed, so no
ceremony runs. The wipe is whole-database and browser-scoped ("forget all
wallet data on this browser"): every replica database, the session database,
and the per-account localStorage families, with the cross-account blast
radius stated in the confirm copy. Each account's standing document client
remains, unflagged anywhere, and the copy points at the Connected wallets
disconnect from a logged-in client. A never-remembered browser is told it
holds nothing to delete.

**Controller promotion by ordering.** The Space id is an independent random
identifier minted at signup (`mintSpaceId`) and carried in the account
pointer, rather than a hash of any controller: the did:webvh id embeds the
Space id, so a derivation would be circular. Unlock Spaces keep their
`hash(unlock did:key)` addressing, a discovery convention rather than an
identity. That deterministic unlock address is an accepted existence oracle
for passphrase guessing (derive a candidate address, probe the server); the
bound is KDF strength rather than placement. The DID's embedded Space id
need not equal a controlled Space's id, since one did:webvh may control
several Spaces on the host, a feature rather than a check to add.

Every WAS signup bootstraps the Space under the ladder VM's bare did:key
inside the credential-anchored establishment (see "The credential-anchored
variant" below), publishes the log, and PUTs the Space Description carrying
`controller: <did:webvh>` as one of the establishment's own stages, before
any enrolled client exists. `StorageManager.ensurePromotedController`
remains the login-time healer: it swaps the live session's signing to the
promoted keyId and re-runs the promotion PUT when a session finds it
missing. Only a no-WAS deployment's plain genesis still promotes on that
path from scratch. From then on the server resolves the controller by
reading and fully verifying the log out of its own storage (SCID-pinned,
hash chain, prerotation, update-key signatures), and authorizes by the
current-key-set rule (see Glossary).

## Account genesis (`@interop/wallet-core/genesis`)

Shared with the mobile wallet. `mintAccountKeySet` mints the whole key set
locally: Space id, client seed, user key, did:webvh update-key seeds.
`ensureAccountGenesis` runs the ordered ceremony: Space provisioning under
this client's did:key, the did:web key map, the did:webvh genesis, the user
key roster (strictly after the DID publication), and key epoch[0] on every
encrypted collection. Every stage detects its own completion from durable
state, so a torn run heals by re-running at the next login.

`StorageManager.#provisionUserCollections` is the one caller. It supplies
did:web provisioning as the ceremony's `provideDidWebKeys` closure and the
roster store builder as `rosterStoreFor`, adopts the published DID in
`onDidPublished` (which also drops the verified-log memo), and maps
per-stage failures onto warns. A session with no did:webvh (the flag off, no
keystore agent, or no client update keys / user key) keeps the reduced path:
Space provisioning, key epochs, did:web. A Space that never came up is the
one fatal stage: `AccountGenesisSpaceError` is rethrown and login fails.

Freewallet's own flow keeps the keyring bind before any data Space exists.
That path is now the no-WAS deployment's plain signup plus the login-time
heal for any account this ceremony provisioned. Every WAS signup runs the
credential-anchored establishment below instead, whose genesis order
promotes the controller inline. `ensureAccountGenesis` is called with
`promoteController: false`, and `ensurePromotedController` promotes and
heals on that reduced path. The plain passphrase signup's own `userExists`
probe and its pointer-backfill step are gone. The establishment's
create-nothing probe (`fetchTransientKeyring`) is the one signup-time
existence check left on a WAS deployment.

**The credential-anchored variant.** Every WAS signup -- passphrase or
passkey, remembered or not -- runs this establishment first, through
wallet-core's `establishCredentialAnchoredAccount`
(`@interop/wallet-core/clientAnnex`, wrapping
`ensureCredentialAnchoredAccountGenesis`). It mints no enrolled client. Its
stage sequence and ordering rules are canonical in wallet-core's
ARCHITECTURE.md, "Ceremonies and cascades", "The credential-anchored
establishment"; what follows is the account-level summary.

`src/session/credentialAnchoredGenesis.ts` is a thin binding over that
orchestrator, supplying only the app-specific hooks: the unlock-record codec
(`bindRecord` over `bindCredentialAnchoredUnlockSecret`), the roster store
builder, the KMS/did:web thunk and keystore-promotion closure, and the
callers' registry-write `beforePromotion` hook.

Entry paths. A non-remembered browser continues into the ordinary transient
composition below, with zero local residue. A `rememberBrowser: true` signup
(the e2e seam today; the signup form's remember choice when it lands)
follows the establishment with the ordinary remembered login, whose
self-enrollment makes this browser an enrolled client from the record just
written -- two loud log entries on top of the establishment's own. That
login carries nothing over: it builds its own pin store and meets the
account log at first contact, like every other login. The
credential-anchored bind advances its record stamp past the served record's
stamp alone. A signup torn before the self-enrollment is resumed by a later
`rememberBrowser: true` attempt, which re-runs the establishment from the
record's own ladder seed and then self-enrolls; "The transient login" below
covers the same heal's non-remembered entry. The passkey signup is the
identical fold under the WebAuthn PRF-derived credential: WebAuthn `create`,
then this establishment, then the remembered passkey login. Registering a
passkey remembers the browser by construction, so that flow already ran
remembered outright, and it too begins here now.

The Space is bootstrapped under the ladder VM's bare did:key
(`ladderVmAgent`), re-derivable from the record's ladder seed, so a tab
death before promotion strands nothing. The one-entry ladder-anchored
genesis is signed by ladder rung 0 (`updateKeys` = [rung 0], `nextKeyHashes`
= [hash(rung 0), hash(rung 1)], `portable` unchanged), with the ladder VM
and the credential's `keyAgreement` commitment folded in. The roster's
epoch[0] wraps the user key to the credential's standing KAK under a
ladder-signed entry proof (the ceremony-tail license's first-entry shape).
The collection epochs gate on the roster landing and on its current epoch
being the key the ceremony was handed, since the user key exists only in tab
memory. A re-run adopting an earlier run's roster skips the stage
(`epochsSkipped`), and the heal branch installs the missing epochs under the
roster's real key.

Persist-before-publish applies transposed, and wallet-core's ARCHITECTURE.md
states the rule. The unlock record carrying the ladder seed, with an interim
bridge delegated by the ladder's bare did:key, is durably written BEFORE the
Space is created and before rung 0 publishes.

After the genesis the establishment mints the client annex generation under
the same bootstrap identity (`ensurePointedClientAnnexGeneration`), embeds
the ladder-VM-signed generation delegation before flipping the auxiliary
Space's controller, appends the `#DelegatedClients` pointer as a second
rung-0-signed account-log entry, re-binds the record (full pointer,
ladder-VM-signed bridge and sibling, management zcap to the account DID),
writes the unlock-methods registry in the last root-invocation window, and
promotes the Space controller last. The registry write is read-first: the
entry is upserted into an existing registry, and a refused read skips the
write rather than starting from an empty one, since the heal re-run fires
the same hook.

The establishment is an ensure, so a torn signup converges by re-running,
the published log adopted by ladder attribution. `createDID` timestamps the
genesis entry, so a naive re-create would mint a different SCID and never
land.

**The KMS stage.** With `KMS_SERVER_URL` set, the establishment also creates
the keystore under the ladder VM's bare did:key before the genesis, mints
the did:web keys and publishes `keys.json` / `did.json` under that identity,
carries the KMS `authentication` VM in the genesis entry, and promotes the
keystore controller to the did:webvh in the existing promotion stage,
mirroring the Space's. The stage is best-effort with a timeout: a failed or
hung KMS leaves the account keystore-less, Settings shows the state, and a
later keystore-creation pass heals it.

## Session persistence

Sessions are in-memory only. A fresh login builds the whole `Session`: the
root `keyAgent` (from this client's stored seed), the user-key-backed vault
KAK, and the `zcapClient` signing every WAS request with the root key.
Nothing live is written to disk unwrapped -- the client seed and user key
persist only inside the wrapped client-key record -- so a reload drops the
session. The vault is unlocked while a session exists and gone once it ends;
there is no "locked vault" state. Navigation to the dashboard is gated on
`session.storageReady` alone; the login-time registry passes run afterward
on `session.registryReady` (see "Session & auth flow").

**The persistence strategy** (`src/session/persistence.ts`). Which storage
tier a session may write to is decided once at login, by the typed
`SessionPersistence` object at `profile.persistence`. The tier is a property
of the strategy's type, so a write site consults no flag and takes no branch
(freewallet `decisions/0001-no-memory-overlay-storage-fork.md`). Riding the
strategy: the unlock-methods registry cache, the passkey-safety notice, the
descriptor/meta cache pair (one instance per scope per session), and the
`writerId` mint. The keyed chain-head pin store and the roster-epoch pin
ride it too, without varying by tier: they are in memory on both variants
(`decisions/0012-no-durable-continuity-pins.md`).

The browser-local variant is the `freewallet-session` database, the
localStorage caches, and the persistent `writerId`. It alone carries the
`idb` factory, so code needing that database must hold it. The in-memory
variant, a public-terminal visit, dies with the tab: no member reaches the
session database, and the login carrying it skips storage provisioning, the
KMS keystore, the login-time roster read, every login-time sweep, and the
bare-Space-URL `userExists` probe.

The in-memory variant also carries the visit's client-annex identity -- the
annex DID every WAS request signs under, and the generation delegation every
request rides -- as a required member of its type
(`InMemorySessionPersistence`). It is built from the pre-session in-memory
store family (`TransientSessionStores`, from `transientSessionStores()`)
plus that identity (`inMemorySessionPersistence({ stores, clientAnnex })`).
Session assembly reads both off the strategy rather than a separate option,
so the storage tier and its annex signing are declared exactly once. They
surface to the storage layer as `profile.invocationCapability`.

Global UI prefs (theme, language) are not session state and ride a sibling
seam (`src/lib/prefsStorage.ts`): during a transient session, pref writes
land in an in-memory overlay that shadows reads, which still fall through to
localStorage.

The logging seam is a third arrangement, module-global rather than
session-scoped. `src/lib/log.ts` wires `@interop/logger`'s namespaced
loggers at bootstrap and rides neither the persistence strategy nor the
prefs overlay. Its one localStorage touch, guarded by the package, is a
single lazy read of the `interop:logger` debug filter key at the first
debug-level dispatch. Nothing in the seam writes stored state, so a
transient session stays residue-free.

**Replica-less, capability-bound storage.** A transient session constructs
no `BrowserStore` at all, since the versioned RxDB open alone creates the
per-user database. `StorageManager.initStorageClients` builds one only for a
session on the browser-local strategy, and a replica-less session serves
every synced-collection operation through the remote-direct backend, over
the remote WAS collections. The sync controller never starts for a session
with no local replica; `StorageManager.hasLocalReplica` is its gate. A
transient CHAPI popup session is this same shape, so nothing provisions a
replica in the popup's partitioned bucket.

The remote stack also takes a delegated authority. `WASRemoteStore` accepts
an optional invocation capability, threaded from
`profile.invocationCapability`, that every request rides: the navigational
handles through one private Space-handle helper, the raw request sites
directly. wallet-core's `userKeyRosterDescriptorStore` takes the same
option, so a session holding only a delegated Space-subtree zcap (the
generation delegation) can use the store and read the roster. Absent the
option, every request invokes the root capability.

**The transient login (the default on a non-remembered browser).** Both
keyring login entry points run one post-KDF routing decision
(`routeUnlockLogin` in `src/session/transientLogin.ts`). With a WAS server
configured, a browser holding this credential's client-key record proceeds
remembered; one holding none takes the transient composition. A record whose
stamped `pointerDid` names a different account than the unlock record points
at is stale residue of a prior account under a reused passphrase: it is
wiped and the login re-routes once as if the browser held none. A
PENDING-shape record counts as remembered, the resume being its one mender;
the resume's discard outcome deletes it, so the next attempt probes
record-less again.

The record probe is create-nothing. `hasClientKeyRecord` checks
`indexedDB.databases()` before opening, and on an engine with no
`databases()` falls back to a versionless open whose `versionchange`
transaction is aborted on `oldVersion === 0`. Nothing surfaces the route the
probe picks: the login form carries no remember-this-browser control, so a
browser holding the record proceeds remembered with no notice (FW-214).

The CHAPI popup runs this same table with the Storage Access API handle as
the probe's factory, so a remembered browser takes the remembered route from
the popup and a denied or unsupported handle routes transient (see "The
popup follows the browser's ratchet state").

An explicit `rememberBrowser` input forces either side. `true` is the
programmatic remembered entry, the standing self-enrollment: a remembered
signup's own login half, its resume, and the recovery tail all pass it, and
e2e sets it through a non-production seam. `false` on a remembered browser
refuses (`AlreadyRememberedError`) rather than forking the routing decision.

The composition (`transientSessionFromKeyringHit`) runs the transient
unlock-record fetch (`fetchTransientKeyring`, create-nothing), the account
log verified under the visit's pins, the client-annex generation-readiness
stage, a per-visit key minted in memory and enrolled into the generation,
the user key unwrapped from the credential's standing roster wrap, and a
session on the replica-less storage variant above.

The readiness stage (`ensureClientAnnexGenerationReady`, over wallet-core's
`ensureCredentialClientAnnexGeneration`) runs on every visit rather than
only a broken one: a no-op report on a healthy ladder-anchored account,
otherwise a ladder-signed mend that mints a missing generation, renews an
expiring or expired generation delegation, and re-mints a missing or
misaimed sibling delegation. It re-seals the fresh sibling into the unlock
record through its re-bind closure (`standingRecordRebinder`, shared between
the remembered and transient shapes; the transient shape writes the remote
record only, nothing local). A mend that moves the account-log pointer
re-verifies the log before enrollment. On an account whose document anchors
no ladder VM of this credential's (enrolled clients, or another credential's
ladder) the stage refuses with `ClientAnnexGenerationUnavailableError`,
resolved as a value: the composition falls back to the prior path, the
record's own `delegatedClients` sibling delegation and the pointed
generation's embedded delegation.

The per-visit key enrolls through whichever sibling delegation the readiness
stage produced (wallet-core's `enrollClientAnnexTransientClient`, the loud
entry before any authority, with the GC-race re-read built in). The
generation delegation is the embedded one, or the one the readiness stage
returned when it just installed or renewed one. The roster read signs as
`<clientAnnexDid>#<vm>` under that delegation; a transient client never
joins the roster, so nothing escrows.

Every unavailable state refuses with a typed
`TransientLoginUnavailableError`: a record without standing authority, an
unpromoted account, no reachable generation or generation delegation on
either path, no roster. The readiness stage's own refusal rides as `cause`
when it ran and failed first. The login page and the CHAPI popup render
per-reason refusal copy from one shared mapping, `transientRefusalKey`, and
no reason opens the connect-this-browser card. Network errors rethrow
unchanged, so a flap stays distinguishable from a lapse.

The session stamps `profile.ladderSeed` and `profile.standingUnlock` from
the credential's standing members, the same fields a remembered login
stamps, so a mid-session ceremony (the App Connect grant path's
generation-delegation renewal below) can sign as the ladder with no
enrolled-client signer in hand.

The tears a torn credential-anchored signup can leave are mended by the
shared mend ceremony, wallet-core's `mendCredentialAnchoredAccount`
(`@interop/wallet-core/clientAnnex`; the app binding sits beside the
establishment's in `src/session/credentialAnchoredGenesis.ts`). Each arm
fires at most once per invocation and detects its state from durable state
alone:

- the establishment arm re-runs the whole establishment for a standing
  record whose pointer names no did:webvh. When the account log already
  resolves and the ladder attributes it re-binds the record instead, since a
  stage-1 re-run would brick a record downgraded by a stale heal;
- the promotion arm completes the Space controller promotion under the
  ladder VM's bare did:key and retries the failed delegated read once (the
  one-request-wide tear between the record re-bind and the promotion);
- the roster-and-epochs arm, when the roster is absent, mints a fresh user
  key behind its preconditions, lands epoch[0] ladder-signed and wrapped to
  the credential's standing KAK, and installs the collection epochs under
  the key the roster delivers, invoking as the annex VM under the generation
  delegation;
- the registry arm re-fires the read-first registry hook when an earlier arm
  mended.

Nothing encrypted predates the roster arm's mint, so a fresh user key
orphans nothing. A partial collection fan-out is not a refusal: the stranded
collections are named in a warn, the only trace on a client-less account no
login sweep revisits. Without the derived credential in hand (a test double)
no arm runs and the refusals below stand.

The composition maps the mend's report onto its typed refusals:

- `unpromoted-account` -- a non-converged establishment arm. Its throw rides
  the report rather than escaping the login raw; a transport-class arm
  failure rethrows unchanged instead, so a flap stays a flap;
- `no-user-key-roster` -- the roster is still absent;
- `no-user-key-wrap` -- the roster carries no wrap for this credential. It
  has its own reason because a retry cannot help. Both paths that state
  arrives by map here: the mend's own `no-wrap` outcome, and the roster
  read's unwrap throw, which would otherwise escape into the remembered
  path's connect-this-browser copy;
- `roster-mint-refused` -- the roster arm's preconditions refused the mint
  (an account log that did not resolve, a foreign key-agreement entry in the
  document, or a collection already carrying an epoch). Every retry re-runs
  the same refusal.

The promotion arm's still-failing retry rethrows the original roster error
unchanged. The remembered resume of a `rememberBrowser: true` signup torn
before its self-enrollment runs the same mend
(`healUnpromotedRememberedAccount`), supplying the registry hook. A mend
that leaves the pointer naming no did:webvh rethrows the arm's error rather
than sending a self-enrollment at a pointer it cannot use.

The strategy also carries the tier refusals. Update-key rotation requires
the browser-local variant outright (`BrowserLocalSessionRequiredError`): its
subject is this browser's own update key, and its persist-before-publish
invariant needs a client-key record to persist into. The account-management
ceremonies (passphrase change, passphrase/passkey add and remove, client
revocation, enrollment approval, recovery-code issuance and revocation,
account deletion, Space export and import) refuse from a transient session
with `StepUpRequiredError`. They are reachable from a public terminal only
inside the step-up ceremony, a loudly enrolled in-memory client bracketed by
ladder-signed enroll and retire entries, designed but not yet built.

Contacts ARE reachable in a transient session: the remote-direct backend
serves all seven contact operations directly against the remote `contacts`
and `contacts-history` collections. Head rows are read and written in place
under compare-and-swap on the served ETag; a lost race re-reads the fresh
head and re-applies the edit, bounded to a few attempts. Revisions append
content-addressed to `contacts-history`, the same shape a local replica's
own writes take. The tie-break `writerId` a revision carries is the visit's
in-memory one.

## The user key wrap-set roster (`key-map/user-key.jsonl`)

The user key (formerly PUK) is recipient zero of every encrypted collection.
Its one remote home is a roster in the private, capability-gated `key-map`
collection: outside the synced collections, no local replica, no background
replication. Its state is a `CollectionEncryption` descriptor, and the
roster's current key epoch IS the current user key. The epoch id is the user
key's did:key; the epoch secret (its raw 32-byte key) is wrapped once per
enrolled client, to that client's identity key-agreement key
(`profile.clientKeyAgreementKey`, the X25519 twin of its did:key). The
roster delivers key material and sources no authority: each client keeps the
user key in its own client-key record, and the epoch stamp marks a cached
copy stale.

The roster is log-governed: the resource log `key-map/user-key.jsonl`, with
no point-state companion resource. wallet-core's
`userKeyRosterDescriptorStore` (`@interop/wallet-core/keys`) exposes it as
an ordinary descriptor store over verified-head reads (the guards below) and
signed log appends, so was-client's roster machinery (`initRecipients` /
`addRecipient` / `removeRecipient`, with their compare-and-swap retry loops)
drives the log without knowing it. `src/session/rosterStore.ts` holds two
builders. `accountRosterStore` takes bare parts (a signing client, a key
agent, an account pointer naming a did:webvh) for callers with no session
profile: the login-time read and the recovery continuation.
`sessionRosterStore` serves a live session and resolves the controller view
through the profile's verified-log memo, so a ceremony that just extended
the account log anchors its appends at the post-edit head. Both pin on the
session's own store (`persistence.logPins`, the keyed store the account log
rides too; wallet-core derives the roster log's slot key from the Space id).

Provisioning initializes the roster idempotently with the account's existing
user key as the first epoch. That is the account-genesis ceremony's roster
stage, run after did:webvh provisioning because the log's entry proofs
anchor in the published account document. Login makes one direct read
(`initSessionFromSeed`, before the storage clients are built), gated on a
promoted (did:webvh) account pointer: it confirms the cached user key
current, or, on an epoch mismatch from another client's rotation, unwraps
the fresh key with this client's own key, adopts it, and persists it into
the client-key record. A failed persist (the record write or the epoch-pin
advance) does not fail the login. The adopted key authenticated against the
verified roster, so the session proceeds on it and the login page shows
"this browser could not be remembered" (`session.userKeyPersistFailed`); the
next login re-fetches the key. A failed persist must not masquerade as an
offline start, so wallet-core propagates the adoption callback's throw
instead of swallowing it into the warn-and-null path, and the login wrapper
catches it.

Three client-side guards are load-bearing against a tampering host.

First, the resource log. Roster state is adopted only from a verified head.
Its entry proofs must be signed by keys the independently verified did:webvh
document lists under `assertionMethod` at the anchored version
(`ResourceLogIntegrityError`). Its chain-head pin refuses rollbacks, forks,
and SCID or method switches within the visit (`ResourceLogContinuityError`).
That rule, and the prefix a fresh visit cannot detect, are stated under "Log
continuity within a session". At login the chain-head `rollback` reason is
the carve-out, matching the account-log pin's: wallet-core's login policy
degrades it to the transport class instead of locking the user out of a
healthy account. The session keeps the cached user key, adopts nothing
rolled back, and the pin never regresses. `fork` and the SCID/method
switches stay session-refusing.

Second, the visit's latest-seen roster epoch (`memoryEpochPinStore` in
`src/session/persistence.ts`). A served roster behind that pin is refused
(`UserKeyRosterContinuityError`), with no rollback carve-out: a chainless
epoch pin cannot tell a rollback from a fork. It guards separately because
the log pin does not cover a chainless value.

Third, at rotation time, a recipient resolver backed by the locally verified
did:webvh document. It drops any roster entry with no `keyAgreement`
verification method marked for that client, so a server-injected entry never
receives a wrap and sits ignored.

## The client enrollment ceremony (`@interop/wallet-core/enrollment`)

Connecting a second wallet client (a fresh browser profile) to an existing
account, with no secret leaving either side. A fresh browser holding a
standing unlock credential can self-enroll at login on its own (see "Session
& auth flow"). This two-party ceremony remains the path for records without
standing authority, for onboarding another wallet app over the rendezvous
transport, and as the future opt-in step-up approval policy.

The new client mints its whole key set locally (client seed, did:webvh
update-key seeds). Only PUBLIC halves travel, as a compact **connect code**
(`freewallet-connect:<base64url(JSON)>`) carried point-to-point: pasted
between two browsers, or sent over the rendezvous transport below. Nothing
travels back over the channel. The account pointer comes out of the keyring
(the enrollee holds the passphrase), and the user key comes back through the
wrap-set roster. Both screens show the new client's did:key fingerprint,
compared by the person running the ceremony before approving; the roster
wrap and the document VM inherit that point-to-point verification.

The flow, quorum-of-one (any single enrolled client can enroll):

1. **Enrollee** (login page, from the not-enrolled state): "Connect this
   browser" mints the key set (`mintEnrollmentRequest`) and shows the code.
   Nothing is written yet.
2. **Enrolling client** (Settings > Connect another wallet): pastes the
   code, compares the fingerprint, approves (`approveEnrollment`). Writes
   push rather than pull, in the recovery-anchor order of decryption
   material before authorization. The user key wraps to the new client's
   key-agreement key in `key-map/user-key.jsonl` FIRST
   (`addUserKeyRosterRecipient`, escrow semantics: every epoch, so
   pre-enrollment history decrypts). Then two did:webvh log entries
   (`enrollWebvhClient`): a sparse commit entry extending `nextKeyHashes`
   with the new client's update- and staged-key hashes, since prerotation
   demands the commitment land one entry early; then the add entry
   publishing its two verification methods and update key. No
   authorized-but-blind window exists at any point.
3. **Enrollee** ("finish connecting"): verifies the enrollment from the
   world-readable log (resolved locally, checked against the pointer's DID),
   makes its first roster read signed with its just-published
   `<did:webvh>#<multibase>` key, unwraps the user key, persists the key set
   into the local client-key record under the passphrase's unlock layer
   (stamping the account controller, so the login-time identity check binds
   the record to it), and logs in as an ordinary enrolled client.

**The connect code's keys must be canonical.** The enrolling client refuses
a code whose key-agreement key is not the canonical X25519 twin of its
signing key (`assertCanonicalEnrollmentKeys`, run inside the connect-code
parse, so the refusal lands before anything publishes). A client's
key-agreement method publishes under `controller: did:key:<its signing
multibase>`, and every reader pairs the two by that claim; without the check
an enrollee could publish a key-agreement key nobody can pair. The refusal
reaches both approval surfaces: the paste dialog under the code field, and a
scanned onboarding response, which ends the invite with the
generate-a-fresh-code copy.

Every stage is idempotent and the ceremony resumes from durable state alone;
re-running with the same code converges. A tear after the roster write
leaves an orphan wrap, invisible to authorization and harmless. A tear
between the log entries is detected from the standing `nextKeyHashes`
commitments, so the add entry alone is appended and no fork is written.

**The rendezvous transport (onboarding another wallet).** When the enrollee
is a camera-holding wallet rather than a browser with a paste box, the same
ceremony runs over the WAS server's ephemeral-exchanges facet
(`/workflows/ephemeral/exchanges`). That facet is unauthenticated: the
unguessable exchange URL is the only access control, and it travels
point-to-point in the QR. Settings > Connected wallets > "Connect another
wallet" opens one card offering both halves of the ceremony, the QR invite
and the paste-a-connect-code form.

The invite side creates an exchange whose stored request is a
`WalletOnboardingQuery` VPR carrying the account pointer and controller
(`composeWalletOnboardingRequest`), renders the interaction URL
(`.../protocols?iuv=1`) as a QR code, and polls (`OnboardInviteCard`). The
other wallet scans it, begins the exchange, mints its key set, and posts
back an onboarding-response envelope: the ordinary `freewallet-connect:`
code verbatim plus a suggested display label, nothing else
(`encodeOnboardingResponse` / `parseOnboardingResponse` in
`@interop/wallet-core/enrollment`). An oversize or malformed envelope is
refused whole, surfaced as "generate a new code and try again".

Poll completion swaps the card to a consent panel (`OnboardConsentPanel`)
that must state four things: the fingerprint comparison, leading, since
anyone holding the exchange URL could inject a response; the full-peer
consequence (an enrolled wallet reads and changes everything in the Space,
connects apps, onboards or disconnects other wallets, issues and revokes
recovery codes); the disconnect limitation; and an editable label prefilled
from the envelope's suggestion. Approval drives the same `approveEnrollment`
+ `setClientLabel` path as the paste dialog, and the enrollee completes the
ceremony off the world-readable log. The channel carries only the four
public key multibases and the label; the account pointer rides inside the
stored request, bounded in confidentiality by the exchange URL.

## Recovery codes (`@interop/wallet-core/recovery`)

The "lost my only client" answer: a 16-byte base58 **recovery code**, shown
exactly once at issuance, that restores the whole account from a fresh
browser with nothing else in hand. On the roster model a code is a minimal
wallet client that stands permanently in the user key roster but is never an
enrolled client, since its key publishes `keyAgreement`-only. Its whole key
set derives deterministically from its bytes: an unlock identity under a
distinct single-expansion HKDF (so a code and a passphrase that stringify
alike cannot reach the same unlock Space), a client seed, one did:webvh
update key, and a binding MAC key. The material exists nowhere until the
code is typed.

Its inventory is split. Decryption stands: the code's `keyAgreement`
verification method publishes in the did:webvh document as an ordinary,
unmarked Multikey entry, and its user key wrap stands in the
`key-map/user-key.jsonl` roster; rotation fan-out maintains both for free.
Being keyAgreement-only, it never shows in client listings keyed on
`capabilityInvocation`, and the document does not label which keyAgreement
key is the recovery one. Authority stays latent: the update key joins
`updateKeys` nowhere, only its hash is committed in `nextKeyHashes`, and the
one bridge into the zcap profile is a pre-minted PUT-on-`did.jsonl`
delegation inside the code's unlock record beside the account pointer. The
record holds no seed and no key wrap; it stays a pure pointer. That narrow
scope keeps recovery loud: any use of a code, legitimate or stolen, must
extend the world-readable, hash-chained log before it can read a byte.

The record splits into a code-authenticated core and a re-mintable shell.
The core is the account binding `{ controller, pointer }`, MAC'd at issuance
under a code-derived key the host never holds. The tag rides the frame in
the clear, and recovery verifies it BEFORE trusting the pointer. That closes
the host-forgery redirect. The record's JWE recipient is the code's unlock
KAK, whose public half sits in the stored frame, so a malicious host could
otherwise seal its own record naming an attacker-controlled account and sign
it with that account's genuinely enrolled key. Every signature-side check
passes on it; only the binding, which needs the code bytes, refuses.

The shell is the plaintext frame (controller, pointer, timestamp) plus the
sealed `bridge` member under the frame proof, the delegation wrapped alone
so a re-mint can replace it. The proof's signer is mixed: issuance signs
with the code-derived unlock key, verified before decrypt; the revocation
cascade's re-mint signs with the re-minting client's account verification
method, verified after decrypt against the did:webvh document the
code-authenticated pointer names. The re-mint reads the standing record
through its management zcap and preserves the binding tag verbatim (it
cannot recompute it), so it can never move the record to another account.
The tag covers the pointer's host, so codes need re-issuing when the account
migrates hosts.

The record carries no email and the locate step shows none: a self-declared
display string is the deception payload a forged record could show as "this
is your wallet". `/recover` confirms only that the code located an account.
The module's error discipline holds there. An account-log network failure
rethrows unchanged and surfaces as "could not check", and a continuity
refusal keeps its own identity rather than reading as a forged record. A
`rollback` (possibly replication lag) reads as could-not-check; a fork or
identity switch surfaces as its own continuity refusal.

Issuance (Settings > Recovery codes, `issueRecoveryCode` in
`src/session/recovery.ts`) runs in the recovery-anchor order: roster wrap
first (escrow into every epoch, so recovery decrypts pre-issuance history),
then the document entry (VM + commitment), then the delegation and unlock
record, then a registry entry of public halves only. Nothing binds until the
confirm-once dialog's "I saved this code". The confirm gates the writes
rather than the tears: an issuance torn after its document entry leaves a
saved code that locates no account (its unlock record never landed), plus a
document `keyAgreement` entry and roster wrap nothing names. The login sweep
rotates the orphan wrap away, but the registry-driven health check cannot
see the code, so the saved code stays silently dead. The retire-and-reissue
mender for that orphaned entry is not built yet, and the last-client
transition refuses while it stands.

Recovery (`/recover`, `recoverAccountWithCode`): the typed code decrypts its
unlock record, the log is fetched and locally verified against the pointer,
and the delegation writes the self-enrolling continuation. That is a
**reveal-and-commit** entry signed by the code's pre-committed update key
(prerotation is what lets a committed key reveal itself), then an
**add-and-retire** entry. The continuation enrolls what the login's routing
decision would.

With `rememberBrowser` (the programmatic remember entry) a fresh ordinary
client key set is minted. The continuation's required `onCommitted` seam,
between the two entries, writes the successors: the new passphrase's unlock
record in the standing LAYOUT (bridge, ladder seed, its standing property
completing post-pivot), the browser-local PENDING client-key record (seeds,
controller, `pointerDid`, the pending group of built-on head, unwrap key and
replacement-code bytes; no user key), and the replacement code's record and
bridge. A colliding unlock record (another credential's) refuses up front.
The add-and-retire entry then brings in the new client, retires the spent
code's inventory, and adds the replacement code's. The tail then makes the
passphrase standing: roster wrap, then commitment and rung-0 entry, before
the rotation. The user key unwraps from the code's wrap and mandatorily
rotates off it. The registry mutation (spent entry out, successors in) runs
between the re-seal and the cascade. The replacement code is pushed hard,
its save confirm completing the local record and clearing the carrier. The
spent code's unlock Space is deleted, so a spent code thereafter fails
distinctly. An ordinary enrolled login follows. A post-entry tab death
leaves the pending record for the next login's spend resume: escrows
re-derived from the unwrap key, standing and registry backfilled, the code
re-displayed until confirmed saved, the sweep completing rotation and
cascade.

The DEFAULT on a non-remembered browser is the **transient recovery
variant** (wallet-core's `recoverWebvhLadderAnchored`): no enrolled client
is minted anywhere. The add-and-retire entry publishes the fresh
credential's ladder VM in the new client's place (`assertionMethod` and
`capabilityDelegation` only), beside the new passphrase's `keyAgreement`
commitment and the replacement code's inventory, and retires every standing
ladder VM (the stale-third-party retirement no other ceremony performs). The
account lands client-less and ladder-anchored.

The continuation's persist-before-publish seam runs after the reveal entry
validates the code and before the ladder VM publishes. It mints a fresh
annex generation under the new ladder's bootstrap did:key; a recovery record
carries no annex sibling, so the old generation is unreachable and falls to
orphan discovery. It durably writes the new passphrase's unlock record
(ladder seed inside, bridge and sibling ladder-VM-signed) and the
replacement code's record, so a tab death can never publish an anchor nobody
can derive. It also loudly enrolls the per-visit transient client into the
fresh generation, controller-tier while the auxiliary Space still answers to
the bootstrap key. That client exercises no authority there: the generation
delegation it invokes under is signed by a ladder VM the document does not
list yet.

The seam names the fresh generation back to the ceremony, so the
`#DelegatedClients` pointer moves to it inside the SAME add-and-retire
entry. A pointer written after that entry would leave a window in which
neither credential could enroll.

Enrolling in the seam buys the window after the entry: the mandatory
rotation is the first request past it, with no enrollment and no pre-read
between the typed code dying in the document and the new credential gaining
its wrap. That rotation is the ONE ladder-signed roster append the
ceremony-tail license admits (`replaceUserKeyRosterRecipients`: spent code
retired, fresh credential and replacement code escrowed, fresh epoch minted,
one write anchored at the add-and-retire entry). The pre-rotation user key
the registry update needs is unwrapped afterwards, from the superseded
epoch's escrow to the fresh credential. The epoch cascade and the
unlock-methods registry update (spent entry out, replacement and
new-passphrase entries in, re-sealed to the rotated user key) ride the
generation delegation. The visit then enters through the ordinary transient
composition with zero local residue.

Two residues remain. A tear inside the append leaves the spent code dead
(its key left the document, so a re-run refuses it as spent) and the current
epoch wrapped to the removed code alone. No login sweep runs on a
client-less account, so the mender is a repair holding both the spent code
(to unwrap the epoch) and the new passphrase (its record's ladder seed and
sibling). It would run the same append under the ceremony-tail license's
still-unused shot, and is not built yet. A rotation torn mid-fan-out on a
client-less account has no repair either, and a stranded collection stays
keyed to the spent code until the next remembered login or a spend re-run.

Revoking a code from Settings is the issuance reversal and is REAL, since
the secret was only ever a pointer to the record: document entry out, the
user key rotated off the code's wrap and the collections re-epoch'd by the
same cascade, unlock Space deleted, registry entry dropped. The live session
adopts the rotated user key in place.

A login-time health check watches for delegation rot and delegation expiry.
A stored delegation stops chaining the moment its signing client's
verification method leaves the document, bricking recovery when it is
needed. Its TTL is one year (NIST SP 800-57 cryptoperiod guidance), so the
registry entry records its `expires`, and a delegation expired or inside the
30-day renewal window is flagged the same way. The check nudges
regeneration; a client revocation re-mints the affected delegations in its
cascade, and the same expiry predicate refreshes a near-lapse delegation
too. The passes skip a pending-shaped entry (one whose record is sealed to a
credential other than the one its identity members name, the residue of a
passphrase change torn before its retirement) rather than sealing a fresh
bridge into a half-retired credential's record. The re-mint core (staleness
checks, skip policy, binding-carried-forward re-wrap) and the delegation
builder live in `@interop/wallet-core/recovery`; `src/session/recovery.ts`
binds them to the session's signers, the storage URL, and the registry.

Two standing boundary rules. First, the hash-commitment rule: **a
low-entropy-derived public key is never published in the world-readable
document**. The document carries a hash commitment of the key
(`MultikeyCommitment`); the real key rides in the capability-gated roster
entry, and the recipient resolver verifies it against the commitment (the
oracle argument is in "Session & auth flow"). A high-entropy credential's
key (a passkey PRF output, a recovery code) may publish verbatim. Second,
the unlock-methods registry's additive `method` enum is the explicit seam
for a later quorum recovery method, rejected for v1 as presupposing a
contact roster most accounts lack. The re-mint machinery above also covers
the standing passphrase and passkey credentials' bridge delegations: the
cascade walks every registry entry recording one, and a standing
credential's own login refreshes its bridge inside the renewal window or
when its signing key has left the account document (the signer-rot axis a
self-enrollment's ladder-VM removal makes routine).

## Client revocation and the epoch cascade

Disconnecting an enrolled wallet client from the account. The cascade is
`revokeAccountClient` in `@interop/wallet-core/clients`, one orchestrator
for every wallet; `revokeEnrolledClient` in `src/session/revocation.ts`
supplies the freewallet-shaped stages around it (session preconditions, the
collections source, the recovery re-mint, the adoption side effects). The
Settings "Connected wallets" panel drives it (see "The Settings clients
surface" below). It runs in the revoking client, synchronously, in
dependency order:

1. **The document edit** (`revokeWebvhClient` in
   `@interop/wallet-core/webvh`): one log entry removes the revoked client's
   two verification methods (the key-agreement one found by its controller
   marker rather than re-derived), its update key, and both standing
   `nextKeyHashes` commitments: the carry-over hash, and the staged hash
   recovered by log attribution (an opaque committed hash left behind would
   be a re-seizure credential via the reveal mechanism). Under the
   current-key-set rule this one edit pulls the client's whole authority at
   once: its invocations, and every delegation and app grant it ever signed,
   stop verifying. The cascade makes no per-collection revoke calls; apps it
   had connected reconnect through the ordinary App Connect flow.
2. **The user key rotation** in the `key-map/user-key.jsonl` roster
   (`rotateUserKeyRoster`), recipients resolved from the just-updated
   verified document; the roster delivers key material rather than sourcing
   authority, so the revoked client's entry drops even before the retire
   filter. An account with no roster yet stops here: the document edit
   landed, so the wallet IS disconnected. Before any roster-side work the
   orchestrator sets the store's controller floor (`setControllerFloor`)
   from the edit's own post-edit log, so a stale cached controller view (the
   session's verified-log memo) can anchor neither the rotation nor the
   sealing append at a head predating the removal. The session hands
   wallet-core's sealable store over unwrapped, keeping that contract
   reachable.
3. **The epoch cascade**, driven by wallet-core over the collections
   `src/session/userKeyCascade.ts` enumerates: every encrypted collection
   (standard, plus any remotely listed collection whose Description carries
   an encryption descriptor) is re-epoch'd onto the fresh user key in
   parallel via was-client's `replaceRecipient`, about 2 requests each. The
   revoked user key generations retire from the epoch rosters and the fresh
   key escrows into every prior epoch, so every other replica keeps
   decrypting across the rotation. A collection is stale exactly when its
   current epoch names a non-current user key generation (durable state
   alone); a never-epoch'd one gets the newest prior generation as its first
   epoch, since the user key is the epoch construction and pre-epoch
   envelopes ARE epoch-`oldUserKey` envelopes. A descriptor whose
   `currentEpoch` names no epoch in its own `epochs` list is refused
   fail-closed, matching the roster read's integrity refusal. Failures
   collect per collection into the fan-out's `failed` report; the rest still
   rotate.
4. **The recovery re-PUTs** (`remintRecoveryDelegations`): recovery
   delegations the revoked client had signed stopped chaining at step 1, so
   the revoking client re-mints them and re-PUTs the unlock records.
5. **The generation-delegation re-mint** (the `remintGenerationDelegation`
   closure, module-level in `src/session/revocation.ts`): an embedded
   generation delegation the revoked client had signed also stopped chaining
   at step 1. The closure runs `ensureGenerationDelegationCurrent` against
   the post-edit document (the stale-signer axis beside expiry) and replaces
   the delegation in place: same fragment, no revocation POST, since the
   rotted chain no longer verifies. It signs with the login credential's
   ladder seed (`profile.ladderSeed`, in-memory) and skips with a report
   (`outcome.generation`) when that seed or a promoted pointer is absent.
   The mid-generation grant death that remains is a stated consequence of an
   ordinary disconnect. The closure runs in the no-roster early return too.

The revoking session then adopts the fresh user key in place: vault keys
swapped, storage ciphers rebuilt via `adoptRotatedVaultKeys`, the
unlock-methods registry re-wrapped. It keeps operating without a re-login,
and a wallet-activity record is written under the fresh epoch.
Self-revocation is refused up front (use another enrolled client, or a
recovery code). The cascade converges under a naive full re-run: the log
entry is idempotent, the roster no-ops once the entry is off the current
epoch, and the staleness rule finds exactly the stranded collections, so a
mid-cascade crash strands nothing permanently. The limitation: ciphertext
the revoked client already fetched stays readable to it, and old epochs open
to keys it already held.

One key survives every rotation: a collection's blinded-index HMAC key.
Minted with epoch[0] at provisioning and wrapped to each recipient on the
`encryption` descriptor, it never rotates, because blinded index tokens must
compare across the collection's whole history and a fresh key would orphan
every existing `indexed` entry. Recipient removal only drops the leaver's
wrap, so a removed recipient keeps the blinding key and, colluding with the
server, could confirm guessed attribute values indefinitely. That is a
guessing oracle rather than a read path: the server still gates the query
endpoint on the pull grant, and the content keys rotate above.

The standing backstop is the **cascade-completion sweep**: session creation
re-runs stages 2 and 3 on every login whose roster read succeeded, chained
behind collection provisioning as the first stage of the login-time chain
exposed as `session.registryReady` (best-effort: a failed sweep is logged
and skipped rather than failing the login). That chain runs after the
dashboard has rendered (see "Session & auth flow"), so a write in the
navigation window before the sweep finishes (a Login activity, an import)
can seal under an epoch a disconnect's rotation has not caught up to,
readable by a client the revoke already removed. Whether to hold such writes
until the sweep completes is an open decision, tracked separately.

The roster stage runs first (`convergeUserKeyRosterToDocument`). A cascade
torn between its document edit and its rotation leaves the roster wrapping
the CURRENT key to a recipient the locally verified document no longer keys,
durably and silently, since the revoked client's document edit will never be
re-run. Such a recipient is rotated away here, and the fresh key adopted
(client-key record, epoch pin, live session vault keys and ciphers) before
the collection fan-out runs against it. Because staleness is
durable-state-only, the fan-out completes a cascade another client crashed
partway through; on a healthy account both stages read descriptors and write
nothing. Together they are the standing invariant check that the roster keys
exactly the document's clients and that no collection's current epoch names
a retired user key generation.

Recovery-code spend and revocation drive stages 2 and 3 of the same cascade,
which closes the "writes still land under readable epochs" residue in both
flows. Their document edits are their own, and a spent code's replacement
delegation is minted by its own ceremony rather than the re-mint stage.

## The Settings clients surface ("Connected wallets")

The management surface over the enrolled-client roster
(`src/components/EnrolledClientsSection.tsx`, glue in
`src/session/clients.ts`): where "disconnect this phone" lives. Apps are
grantees rather than enrolled clients and stay on the sibling Applications
page.

The listing is wallet-core's `listAccountClients`, which
`src/session/clients.ts` supplies with the log location, this browser's key,
and the label store. It reads the locally verified did:webvh log (the
`verifyAccountLog` step every ceremony runs), then runs
`listEnrolledWebvhClients`, keyed on `capabilityInvocation`. That keying
excludes structurally rather than by filter: a recovery code's key publishes
under `keyAgreement` only (unmarked), the KMS-held convenience under
`authentication`.

Two members are not readable off the current document and come from log
attribution. One is each client's ACTIVE update key: the flat `updateKeys`
set has no per-client grouping. The entry that published a client's
verification methods revealed its initial key. Each later entry retiring the
attributed key while revealing exactly one replacement is that client's
self-rotation. An ambiguous attribution disables disconnect for the row. The
other member is the enrollment moment, the `versionTime` of the publishing
entry.

A row with both key members (signing key and active update key) is exactly a
`RevokedClientKeys` (`revokedClientKeysFor`), so Disconnect drives the
client-revocation epoch cascade verbatim. Eligibility is the shared
`disconnectEligibility` policy (self, last-wallet, and
unattributed-update-key refusals) rather than UI state. A partial collection
fan-out is reported through `cascadeCompletion` as a resumable success.

**Labels** live beside the keys rather than in the document, which carries
key material only: `key-map/client-labels.json`, over wallet-core's
`readClientLabels` / `setClientLabel` two-method store seam. They are
plaintext in the private, capability-gated `key-map` collection, since the
host already serves the world-readable log naming every client key and a
label adds only the display name. A label is chosen at enrollment approval
(a field in the enroll dialog, written best-effort after the ceremony lands)
and editable inline. A "This browser" chip marks the current client, matched
on the session's own signing key rather than on stored state.

Disconnect confirms the limitation (re-keying stops future reads;
already-fetched ciphertext stays readable) and runs the cascade with
keep-this-tab-open progress copy. Both failure modes surface as resumable
("try again -- it picks up where it stopped"), a partial fan-out pointing at
the login-time sweep. The cascade never disconnects the last enrolled
client: that client is always the current one from its own session, and
self-revocation is refused. Its row offers the last-client transition
instead (see "The forget affordance"), which lands the account client-less
and ladder-anchored, the shape every credential-anchored signup produces,
still reached by the standing credentials through transient logins. The
connect-another-wallet entry point lives here too: the enrollment ceremony's
approving half, one card offering both the QR onboarding invite and the
pasted connect code.

**The Applications sibling** knows the current-key-set rule. That page
(`src/lib/connectedApps.ts`) holds app grantees where this panel holds
wallet clients, with a cross-pointer in each. Its listing checks each
recorded App Connect grant's delegation signer against the same verified
document; the full zcap, proof included, is recorded on the Login activity.
It uses `currentAccountSigningKeys` (wallet-core's, wrapped in
`src/session/clients.ts` so a guest degrades rather than throws) plus
`deriveAppGrantsState`, matched on the key-multibase fragment so a key's
did:key and promoted did:webvh forms agree. An app whose recorded signers
have all left the document shows as orphaned; its grants stopped verifying
at that client's revocation, and reconnecting through the ordinary App
Connect flow is the recovery path. The marker does not gate the revocation.
Revoking an app POSTs every recorded revocation, rotates the
app-provisioned collections' epochs, and deletes the app key. "Signer gone"
does not mean "chain dead": a grant minted in a transient session is signed
by an annex key the account document never lists, so it derives as orphaned
while its chain stays alive under the generation delegation. A genuinely
dead chain comes back as a skipped revocation. The check is best-effort:
with no verified document this session (a guest, or the log unreachable) the
page lists without the marker rather than failing.

The panel's agent rows (see "The interaction-URL request page" above) run
the identical signer check against `currentAccountSigningKeys`, over the
recorded grant's `controller` instead of an app-key subject, so an agent
whose signing client was disconnected shows as orphaned too. The marker is
display-only on both row kinds, for the reason above: revoking an agent
always POSTs the recorded revocations, and a dead chain comes back as a
skipped one.

## Storage model (local-first)

Every credential, public-link, and history read/write goes through one
`SyncedCollectionStore` backend, chosen once at session construction by the
session's storage tier (see "Replica-less, capability-bound storage" under
"Session persistence"). A session with a local replica (a remembered login,
a guest, a no-WAS session) serves them from the local `BrowserStore` (RxDB
over Dexie/IndexedDB), online or offline. Two shapes serve them
remote-direct over the remote WAS collections instead. A transient session
is replica-less: it constructs no `BrowserStore` at all. A remembered CHAPI
popup does construct one, being on the browser-local strategy, but routes
every synced-collection operation past it (see "Remote-direct popup
storage"). One local database per user holds every standard collection
(`private-credentials`, `public-credentials`, `wallet-activity`, `contacts`,
`contacts-history`, `app-connections`) on the generic synced-doc schema (`{
id, updatedAt, version, data }`, `src/lib/sync/syncedDocSchema.ts`).

The encrypted collections, all of the above except `public-credentials`,
store **EDV envelopes**: encrypted at rest locally and opaque to the server.
A per-collection document cipher (`createEdvDocCipher` from
`@interop/was-client/edv`, built from the session's vault KAK) encrypts at
write time and decrypts at read time. The row id is a hash of the JWE
ciphertext, so it is identical on every replica. Page-facing identity stays
the credential `cid` or activity `id`, recovered by decrypting at read time.
JWE encryption is nondeterministic, so dedupe keys on that content identity
rather than on the row id. `public-credentials` is plaintext (public data)
and keyed directly by `cid`.

When `VITE_WAS_SERVER_URL` is set and the session is not a guest, a remote
WAS Space is attached as a **sync target**. `SyncController`
(`src/stores/syncController.ts`) replicates every synced local collection to
its remote WAS Collection counterpart in the background, through the
collection-agnostic adapter in `src/lib/sync/`, which ships stored bodies
(plaintext or envelope) verbatim and never touches keys. Every replication,
and every `WASRemoteStore` request, is signed with the session's root key.

`WASRemoteStore` does not serve credential reads and writes. It keeps the
Space lifecycle (create/exists/wipe), the storage-browser read-through
(`/storage/**` pages work directly over remote collections), export/import,
and quotas. `StorageManager` is the facade; pages and components always talk
to it rather than to a backend class.

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
`publicCredentialUrl`) is built with was-client's paths helpers (`spacePath`
/ `resourcePath` / `toUrl`), which join onto the storage server's base path.
On a sub-path deployment (a server URL like `https://host/was`) the link
addresses exactly the resource replication wrote, with per-segment encoding.
A root-anchored form was drift, corrected in wallet-core 0.39.1.

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
   CHAPI mediator (`authn.io`), through the credential-handler-polyfill's
   `installHandler()`.
2. A third-party site's `navigator.credentials.get/store()` opens
   `/wallet/get` or `/wallet/store` in a CHAPI-managed popup iframe, outside
   the normal app shell and `ProtectedRoute`.
3. The popup page intercepts the CHAPI event with
   `receiveCredentialEvent()`, shows a minimal login form, initialises a
   full `Session` in-popup, then returns the result to the site with
   `chapiEvent.respondWith(...)`.

The CHAPI pages (`src/pages/chapi/`) are not wrapped in `ProtectedRoute` and
do not use the main app layout.

**The popup follows the browser's ratchet state.** The popup does not choose
between the remembered and transient entries. It runs the same post-KDF
routing every login runs (`routeUnlockLogin`, see "Session persistence"),
with the Storage Access API handle threaded in as the record probe's `idb`
factory. A granted handle probes the FIRST-PARTY client-key record, so a
remembered browser proceeds as that enrolled client. A denied handle probes
the partitioned bucket instead, finds no record, and routes transient,
exactly as a non-remembered browser does. So does every engine that offers
no unpartitioned-IndexedDB request at all, which is Safari's and Firefox's
steady state. That one uniform fallback is
`decisions/0009-popup-denied-storage-access-goes-transient.md`, reached by
construction rather than by a popup arm of the routing. A transient popup
session composes like any other: the client-annex enrollment, the standing
roster wrap, the replica-less storage variant. Its App Connect response VP
holds and signs as the visit key's bare did:key. The annex verification
method form (`<clientAnnexDid>#<vm>`) covers two things: the visit's WAS
invocations, and the grants the visit delegates.

The popup marker is a `popup` option on `loginWithPassphrase`,
`loginWithPasskey`, `sessionFromKeyringHit`, and `initSessionFromSeed`. It
gates only what the partitioning implies, and only in the remembered arm:
remote-direct storage (below), suppressed localStorage caches, and that
arm's popup refusals. Those refusals are the record-less branch's
self-enrollment, the pending-enrollment resume, and the six login-time chain
passes that already carried the guard. The Storage Access handle
unpartitions IndexedDB and does not reach localStorage, so a persisted
descriptor or meta cache would be partitioned residue no top-level wipe can
reach; the popup's cache pair is in-memory for the visit. The suppression is
scoped to a WAS deployment, where that pair is genuinely a cache: the
descriptors are served, and the local copy is the offline fallback. On a
no-WAS deployment the same store is the only record of the locally minted
key epochs, so suppressing it would mint fresh ones and orphan everything
already encrypted; a local-mode popup keeps its persistent pair. Three chain
passes carry no popup guard today: the standing-delegation self-refresh, the
ladder-rung refresh, and the did:webvh pointer heal. Whether they should is
an open decision, tracked separately.

Handler registration is not on the persistence axis. `registerWallet()` runs
at mount on the login page, before the routing decides, so a transient login
registers the handler too. It writes nothing to the wallet origin, since the
registration bit lives on the mediator's, so a transient visit stays
residue-free here. The mediator-origin bit remains the stated limit no
top-level wipe reaches.

**Remote-direct popup storage.** The popup runs in a third-party iframe, so
its own IndexedDB is a partitioned bucket no `SyncController` ever drives: a
credential stored there would be stranded and a credential list would always
come back empty. A remembered popup session therefore routes every
synced-collection operation to a `RemoteDirectStore`
(`src/stores/remoteDirectStore.ts`, selected via `remoteDirect`, threaded
from the `popup` option) rather than to the local `BrowserStore`. It is on
the browser-local strategy, so it still constructs that `BrowserStore`, and
the partitioned RxDB database is created even though nothing is ever routed
to it. A transient session is replica-less and reaches the same backend that
way, so a transient popup visit provisions nothing in the partitioned
bucket.

That backend serves credential, history, and public-link reads and writes
straight over the remote WAS collections
(`WASRemoteStore.listSyncedResources` / `getSyncedResource` /
`putSyncedResource` / `deleteSyncedResource`), with the same per-collection
ciphers the local store uses, so the envelope, id, and key-epoch logic lives
once. A write reproduces verbatim what background replication would have
pushed: the raw EDV envelope under its content-derived envelope-hash id,
created with `If-None-Match: *`, stamped with the same `Key-Epoch`. The main
app's replication then pulls it cleanly. An unknown-epoch read (a rekey by
another client) drives the same one-time descriptor refresh the local
backend uses, so a fresh-epoch credential is never dropped.

Contacts are reachable in the popup over the same remote-direct path. Head
rows are mutable and updated in place under `If-Match` compare-and-swap
rather than created once and left alone. Their ids and epoch stamps still
match what background replication would have pushed, so a local replica
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
  default port, percent-encoding case, or dot-segments do not name distinct
  applications.
- `capabilityQuery: [...]` -- the usual capability descriptors minus
  `controller` (the wallet fills it) and `reason` (the consent screen
  supersedes per-grant reasons).

An `AppConnectQuery` is one mental model per popup. Mixing it with
`QueryByExample` or standalone capability queries is rejected at
classification time (the shared `appConnectRequestOf`); wallets predating it
fail closed with an "update Freewallet" error rather than degrading into a
partial generic flow.

The wire contract is normative in the **App Connect companion spec**
(<https://github.com/interop-alliance/app-connect-spec>; local checkout
`../app-connect-spec`, read `spec.md` there): the `AppConnectQuery`, the
app-key credential, the descriptor vocabulary and action limitations, and
the response presentation. The app-key module lives in
`@interop/wallet-core/request` (`appKey.ts`), shared with DCW: wire
constants, match and mint paths, store-time refusal policy, and the
`appConnectRequestOf` validation in `classify.ts`. Freewallet's half is
consent UI, credential storage, and delegation machinery.

The key design move: **the wallet mints the app-key seed**, a client secret
that must not transit a server. It exists only in the wallet and the app,
over the browser-direct CHAPI channel. On first run the wallet generates 32
random bytes, derives the did:key via `CapabilityAgent.fromSeed({ seed,
keyName: 'app-key' })` (the `keyName` string must match was-react's
derivation exactly), self-issues the credential (issuer == subject ==
seed-derived DID, seed base64url-no-pad in `credentialSubject.seed`), and
saves it to the dedicated `app-connections` collection under the same
consent. No second popup.

On a returning visit a stored credential matches on three equalities: the
`AppKeyCredential` marker type, `credentialSubject.appUrl` against the
request's serialized `appUrl`, and `credentialSubject.origin` against the
CHAPI requesting origin. A phishing origin can neither recover another
origin's key nor be handed one, and two applications sharing an origin stay
apart by their `appUrl`s. was-react's `parseSeedCredential` repeats the
origin check app-side as defense in depth.

A match also requires the subject DID to re-derive from the seed the
credential carries (`appKeySeedBindsSubject`). Self-issuance is a weak
signal, and candidates rank on a self-stated `issuanceDate`, so without the
binding a credential planted by import or injected into the Space would win
the match and its DID would become the delegation `controller`. The check is
local and deterministic (the same `CapabilityAgent.fromSeed` call that
minted it), failing closed on an absent, non-base64url, or wrong-length
seed. It proves internal consistency, not provenance: an attacker's own
credential, carrying a fresh seed and the victim app's `origin` and
`appUrl`, binds perfectly. The store-time refusal is what keeps plants out.
Ranking uses the instant each `issuanceDate` denotes rather than its text,
so a numeric offset or differing fractional-second precision cannot reopen
the planted-credential path; an absent or unparseable date sorts last.

**App keys live in their own collection.** `app-connections` is synced,
EDV-encrypted and content-addressed like the credential replica, but
structurally separate: the credential-wide surfaces (dashboard list,
credential detail, public-link creation, credential delete, collection
shares) are scoped to `private-credentials` and can never reach a seed, with
no filtering code. The collection is never shareable (`shareable: false` on
its roster spec), and a capability descriptor or URL naming it is
unsatisfiable in grant resolution rather than merely read-only. A
whole-Space read grant covers its ciphertext, as for every private
collection, but the grantee is not an epoch recipient and decrypts nothing.

Match and consent-preview candidates come from
`StorageManager.listAppKeys()`, so ordinary credentials never enter the
match. It reports what the scan skipped: rows whose key epoch is still
unknown after the one descriptor refresh, rows in a known epoch this session
holds no wrap for, and envelopes that will not decrypt at all. A scan that
found nothing but skipped such rows refuses to mint: "no match" does not
mean "never connected", and a fresh mint would orphan the app's prior
identity. The refresh is spent at most once per collection per session and
swallows a failed fetch, so an unknown-epoch row can still reach the match
path; hence the report rather than an assumption. Undecryptable rows are
purgeable from the Applications page; the other two kinds are real data and
stay unpurged.

There is no migration from the old in-`private-credentials` placement and no
legacy (pre-`appUrl`) re-issue path. An idempotent login-time sweep deletes
stranded app-key rows from `private-credentials`, marker-typed or matching
the old self-issued-with-origin shape; the affected app reconnects through
the ordinary flow as a first run, orphaning its prior identity and whatever
it encrypted under it (the greenfield re-provision rule). The same sweep
retracts app-key public copies left with no private row behind them (a
pre-upgrade app key kept through "keep public copy"), through the
remote-aware retraction path under "Storage model".

**Externally arriving app keys are refused at store time, unconditionally.**
Every minted app key carries the marker type `AppKeyCredential`
(`https://w3id.org/byoe#AppKeyCredential`, one stable IRI for every app, in
the static inline `@context`), so "presents as an app key" is a term check
rather than a shape heuristic. The marker is a self-declaration: a plant
controls its own `type` array, and binds just as well, so the rule cannot be
"binds, so it stores". `StorageManager.addCredential`, the one door for
externally supplied credentials (the CHAPI store popup, the URL / QR /
manual-paste import, the credentials half of a space import), refuses every
marked credential, binding or not (`assertStorableAppKey`,
`AppKeyRefusedError`). Refusing beats storing-and-ignoring: match consumers
need not each re-check provenance, and the wallet shows no credential it
will never act on. The marker is required at match time, so a credential
reaches the delegation path only by carrying it, exactly what this refusal
screens. The mint path has its own door, `StorageManager.addMintedAppKey`
(called only by `processAppConnect`, writing into `app-connections`), which
asserts the mint invariants so it cannot store a foreign key.

Two ingest paths sit outside the door. The background sync pull writes
pulled rows into the local replica directly, but it replicates the account's
own remote collections, writable only by the account's enrolled wallet
clients (`app-connections` is never grantable; `private-credentials` is
protected, so RP and share grants on it are read-only), each enforcing the
same refusal at its own door. The space half of an import writes opaque
resources into the user's own Space server-side. For both, the match-time
binding is the backstop.

Every app key has the same shape: the fixed two-entry `type` array
`["VerifiableCredential", "AppKeyCredential"]`, and an inline `@context` of
one static object mapping `appUrl`, `seed`, and `origin` to their
`https://w3id.org/byoe#` IRIs. Which application a credential belongs to is
the `credentialSubject.appUrl` claim, not a type.

The wallet delegates to the subject DID of the credential it just matched or
minted, so the request never names a controller DID; that is what makes the
flow single-round. Delegation reuses `resolveGrants` / `processZcaps`
verbatim: descriptor resolution, provisioning, per-target-class action
limitations, TTLs, protected-collection rules. Requested actions are
normalized against the closed WAS action vocabulary and intersected with the
limitation for the target's class (read-only for a whole Space, a protected
collection, and a share; the full vocabulary for public collections and
app-provisioned private collections), and the consent screen shows exactly
what `resolveGrants` resolved. A grant left with no permitted action is
unsatisfiable rather than delegated empty. So is a whole-Space target asked
for by a session whose grants chain under a generation delegation. That
delegation is scoped to the Space's items subtree, so it can parent no
whole-Space grant, and minting one anyway would produce a capability that
verifies nowhere. The consent screen words that refusal for itself instead
of showing the generic one. Resolution also consults a snapshot of the
existing collections' state, fetched once for the consent preview and again
at delegation time, then kept current as the delegation loop provisions, so
duplicate names in one request resolve against what the request itself
created.

The response VP embeds the credential, the `zcap` array, and a
wallet-provided `appConnect: { firstRun }` member (a JSON-literal term in
the VP `@context`), all before signing so the DIDAuth proof covers them
(`processAppConnect` in `src/lib/walletRequest/appConnect.ts`).
`WalletGetPage` renders an app-centric consent panel ("Connect {app}?") in
place of the three generic sections, and approval records an app-connect
Login activity.

**App-provisioned collection encryption (day-one policy).** A private
(non-public) collection provisioned by an App Connect `capabilityQuery` is
declared EDV-encrypted, with a multi-recipient key-epoch roster holding the
user's vault KAK as recipient zero alongside the app's identity KAK: the
X25519 (Montgomery) twin of the `did:key` being delegated to, derived with
the same `x25519RecipientFromDidKey` a share uses. One recipient-derivation
rule covers app and person alike, and the app seed never enters the grant
path. The wallet derives the app's recipient key from a public identifier it
already has; the app derives the private half from its own controller key.
Both read the collection, and the WAS server only ever stores ciphertext.

Provisioning is idempotent. The collection gets epoch[0] wrapped to the
owner create-if-absent (`ensureIndexedFirstEpoch` from
`@interop/wallet-core/keys`, which adopts an existing roster rather than
overwriting it); a first connect or a reconnect after revoke then escrows
the app into every epoch (`addRecipient(app)`), and an app already present
is a no-op. Epoch[0] is minted together with the collection's blinded-index
HMAC key, wrapped to the same roster, so the app can declare searchable
attributes and query the collection (was-client's `declareIndex` / `find`).
That key is installed at provisioning or never: a collection provisioned
before blind-index support is adopted as-is and stays unindexable.

The wallet's own writes carry the same blinded `indexed` entries a
Collection-handle write does. Each encrypted collection's doc cipher
installs the persisted index schema from the collection's stored `/meta`, an
opaque encrypted envelope fetched without keys and decrypted by the cipher.
The schema is cached beside the encryption descriptors and refetched on the
same unknown-epoch refresh, so an index declared mid-session reaches the
ciphers at the next refresh or login. The wallet ensures the collection
exists without clobbering an existing `encryption` descriptor, so an
established epoch roster is never dropped.

Public (`https://w3id.org/byoe#public-collection`) grants stay plaintext and
world-readable; only private app collections are encrypted. A public grant
can only ever CREATE its collection, and one naming an existing non-public
collection is unsatisfiable, so no consent approval can flip an established
collection world-readable. An idempotent re-grant on an already-public
collection delegates without re-provisioning, and any target naming one is
classed public-collection and skips provisioning, whether it arrives as a
`#public-collection` descriptor, a `#private-collection` descriptor, or a
plain URL string. The policy: the user is always a recipient of an encrypted
collection in their own Space, and any future exception needs its own
explicit consent surface rather than a silent default.

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

A grant minted in a transient session carries a lifetime limitation of its
own. It ends at its own expiry or when its annex generation is collected,
whichever comes first, and revocation is available for the whole window in
which the grant is usable. Collection runs from the remembered-login chain
alone, so on an account that never remembers a browser it never runs. The
real bound there is the earlier of the grant's own `expires` and the
generation delegation's, and the consent screen shows the clamped figure
rather than the configured TTL.

Two security properties of App Connect are worth stating on their own:

- **Challenge/domain**: was-react verifies the DIDAuth challenge and domain
  app-side.
- **Per-user app identity**: an app key is minted from 32 fresh random bytes
  inside the connecting user's own wallet and stored in that user's own
  `app-connections` collection, so the app's DID, and the X25519 recipient
  key derived from it, is scoped to the **(user, origin, `appUrl`)** triple.
  The same app connected by two users gets two unrelated DIDs: independent
  randomness per user, not a derivation over (app, user), so there is no
  cross-user linkability and compromising one user's app key reveals nothing
  about another's, where a shared-root KDF would break every user at once.
  "Encrypted to the app's key" throughout this document therefore means
  _that user's_ instance of the app.

  This holds on the App Connect path, where the wallet mints the key and
  fills `controller` itself. A standalone `AuthorizationCapabilityQuery`
  names its own `controller`, so an app taking that route could supply one
  static DID for every user, wrapping each user's (still distinct) epoch
  secret to one app-held key. The wallet cannot detect this (it sees only
  one user's view), so it is an ecosystem expectation of app authors, not an
  enforced invariant: **a grantee DID SHOULD NOT be shared across users.**
  Either way the recipient key derives from the named controller, so a
  request can never pair controller DID A with recipient key B.

## The interaction-URL request page (`/external/request`)

A request can also arrive from outside the app, with no CHAPI popup and no
attested requesting origin. An agent's `di was request-grant` prints an
interaction URL (`<exchange>/protocols?iuv=1`) plus the wallet deep link
`/external/request?url=<percent-encoded interaction URL>`. The same URL can
be pasted into Add Credential or scanned from a terminal QR;
`resolveWalletInput` returns it as a typed `interaction-url` outcome and
both callers route to the page.

The page (`src/pages/external/ExternalRequestPage.tsx`) is the
`WalletGetPage` shape minus CHAPI: it opens the exchange with wallet-core's
`openInteractionRequest`, classifies the VPR with the shared
`classifyRequest`, renders the storage-access consent panel, delegates
through the ordinary grant engine, and POSTs the unsigned zcap-only
presentation back through `composeAndDeliverResponse` with the exchange URL.
A live app session is used directly; otherwise the page runs the ordinary
login in place (the same routing decision `/login` makes) and adopts it
app-wide. The Login activity records the grant under the fixed origin marker
`n/a (API request)`, which the Applications page keys agent rows on.

A request may name its requester through the VPR's root `agent: { name }`
member, the parallel of App Connect's `app.name`, sent by `di was
request-grant --name`. The consent panel renders it as "an agent calling
itself ..." beside the grantee key, marked self-declared, and the activity
records it as `object.actor` (the ActivityStreams member; the activity's own
`actor` stays the user). The shared classifier enforces the limits (trimmed,
1 to 64 characters, no control characters); a name outside them is refused
as malformed.

The entry point is stricter than the popup, because the only requester
signals are the grantee DID and request-supplied text (the `reason` and the
agent name), all chosen by whoever wrote the link. Every refusal is decided
before consent renders, in the pure module
`src/lib/walletRequest/externalRequest.ts`, each with its own copy:

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
a link, plain collection URLs resolving to those classes included: a share
would hand the grantee decryption of the user's own encrypted collections,
and a whole-Space or protected-collection read covers the plaintext
`public-credentials` (`barredGrants`, run once the grants are resolved, the
first point a target's class is known). Widening the allowlist is a
documented decision, not a code change. A failed exchange POST-back leaves
the grant recorded and offers the composed response for manual delivery; a
decline abandons the exchange, which expires on its own.

Grants answered here are listed and revocable from the Applications page as
agent rows, keyed by the grant's `controller` did:key (`listConnectedAgents`
in `src/lib/connectedApps.ts`) and titled by the request's `agent.name`, or
by the grantee key's fingerprint when no name was sent. A row's grants are
the union over every agent Login for that controller newer than the latest
matching Revoke activity (same origin marker, no `appConnect`, the
controller in `object.controller`), since a later request can add a grant
without retiring an earlier one; a row whose grants have all expired is
dropped. Revoking a row POSTs every recorded capability's revocation
regardless of the orphaned marker, and stamps the Revoke's `created` at
least one millisecond past the latest Login, so a fast-clocked terminal
cannot leave the row standing. There is no app key to delete and no
collection epoch to rotate: an agent is never a key-epoch recipient.

A grant delegated from a transient session chains under the session's
generation delegation (`profile.invocationCapability`) rather than the Space
root, which would be signed by an annex key the account document never
lists, and its `expires` is clamped to the parent's. A generation delegation
that is expired or inside its renewal window runs the blocking renewal stage
first (`renewTransientGenerationDelegation`): a fresh ladder-signed
delegation, minted through the credential's sibling delegation, is installed
in place and adopted by the live session, the profile stamp, the persistence
strategy, and the `WASRemoteStore`'s bound capability swapping together, so
the collection-state listing and the grant mint that follow ride the fresh
parent. The approval refuses (`GenerationDelegationStaleError`) only when
the renewal cannot run at all (the account document does not anchor this
credential's ladder VM) or when it fails, rather than minting a silently
short grant.

## Sharing a wallet collection (`https://w3id.org/byoe#shared-wallet-collection`)

The collections above are ones an app created. **Sharing** is the other
direction: letting a grantee read and decrypt one of the wallet's own
encrypted collections. It is asked for with a distinct invocation-target
descriptor, `{ type: 'https://w3id.org/byoe#shared-wallet-collection', name
}`, in either channel (a standalone `AuthorizationCapabilityQuery`, or an
`AppConnectQuery.capabilityQuery`). A distinct `type` rather than a flag is
load-bearing: an unknown `type` already resolves to unsatisfiable, so a
wallet predating the feature refuses visibly instead of degrading to a
ciphertext-only read.

**The two axes stay fused.** Pull (a read-only Collection zcap) and read (an
epoch-key recipient entry) are granted together, by one call to
`StorageManager.shareCollection`, which returns the delegated zcap alongside
the refreshed descriptor so it rides back in the response VP's `zcap` array.
A share grant therefore bypasses the ordinary delegation loop in
`processZcaps`; no code path grants one axis without the other.

**The recipient key is derived, not transmitted.** `name` must be one of the
shareable standard collections: every `WALLET_STANDARD_COLLECTIONS` entry
whose roster spec carries `shareable: true`, so today `private-credentials`,
`wallet-activity`, `contacts`, and `contacts-history`. Sharing is
meaningless without an epoch roster, and `app-connections` is encrypted but
never shareable (its rows carry app seeds). The grantee's X25519 key is
derived from the `did:key` the request already names as `controller`
(`x25519RecipientFromDidKey` from `@interop/was-client/edv`, the same
Ed25519-to-Montgomery conversion the wallet applies to its own vault KAK),
so a request can never pair controller DID A with recipient key B. A
controller with no Ed25519 twin (a did:web, an X25519 did:key) makes the
grant unsatisfiable.

**Consent states the limitations before approval.** The share row on the
consent screen is visually distinct from every other grant and says three
things: the grant is read and decrypt; it covers the collection's contents
from the moment of approval, not only future writes; and removing access
later stops future reads but cannot take back what has already been read.
The second holds without a hedge because every encrypted collection carries
epoch[0] from provisioning (wrapped to the user key, recipient zero), so a
share is always an `addRecipient` that escrows the grantee into every
existing epoch: no rotation, and no envelope outside an epoch the grantee
now holds. An epoch-less descriptor is refused fail-closed rather than
seeded lazily at share time (it can only mean an unprovisioned or torn
collection), so no single-recipient residue exists that a reader could fetch
but not decrypt.

Removal is the shares dialog behind a collection row's "Shared" chip in the
Storage collection list (`unshareCollection`), not expiry: the share TTL
(`SHARE_ZCAP_TTL_MS`) is long, because expiry would end the pull axis while
leaving the grantee in the key roster. A share also escrows the grantee into
the collection's blinded-index HMAC key when the descriptor carries one;
removal drops that wrap but never rotates the key (see "Client revocation
and the epoch cascade" for why, and what a removed grantee keeps).

**The grantee's half lives in `@interop/was-react`.** An app declares the
wallet-owned collections it wants in `WasAppConfig.sharedCollections`, which
adds the `https://w3id.org/byoe#shared-wallet-collection` descriptors to its
App Connect request. On approval a `SharedCollectionReader` fetches the
Collection Description through the delegated read zcap, builds the
epoch-aware cipher from the descriptor, and decrypts the raw envelopes
locally with the app's identity key-agreement key: the X25519 twin of its
own controller DID, exactly what `x25519RecipientFromDidKey` derived
wallet-side, so both sides land on the same `kid` with nothing on the wire.
It is the same key an app-provisioned collection admits the app with: one
recipient identity per app, whoever owns the collection.

## Route map

Every row below `/external/request` is protected. `DocsPage` renders
`public/docs/*.md`.

| Path                                                    | Component                |
| ------------------------------------------------------- | ------------------------ |
| `/`                                                     | `LandingPage`            |
| `/login`                                                | `LoginPage`              |
| `/signup`                                               | `SignupPage`             |
| `/recover`                                              | `RecoverPage`            |
| `/guest-login`                                          | `GuestLoginPage`         |
| `/logout`                                               | `LogoutPage`             |
| `/wallet/get`                                           | `WalletGetPage`          |
| `/wallet/store`                                         | `WalletStorePage`        |
| `/external/request`                                     | `ExternalRequestPage`    |
| `/dashboard`                                            | `DashboardPage`          |
| `/credential/:cid`                                      | `CredentialDetailPage`   |
| `/credential/:cid/issuer`                               | `IssuerDetailPage`       |
| `/add-credential`                                       | `AddCredentialPage`      |
| `/accept-credentials`                                   | `AcceptCredentialsPage`  |
| `/contacts`                                             | `ContactsPage`           |
| `/contacts/new`                                         | `ContactFormPage`        |
| `/contacts/:contactId`                                  | `ContactDetailPage`      |
| `/contacts/:contactId/edit`                             | `ContactFormPage`        |
| `/contacts/:contactId/history`                          | `ContactHistoryPage`     |
| `/applications`                                         | `ApplicationsPage`       |
| `/applications/:cid`                                    | `ApplicationDetailPage`  |
| `/storage`                                              | `StoragePage`            |
| `/storage/collections/:collectionId`                    | `CollectionContentsPage` |
| `/storage/collections/:collectionId/resources/:resourceId` | `CollectionResourcePage` |
| `/history`                                              | `HistoryPage`            |
| `/settings`                                             | `SettingsPage`           |
| `/docs/:fileName`                                       | `DocsPage`               |
| `*`                                                     | `NotFoundPage`           |

## Ceremony inventory

The account ceremonies in one place: the set AGENTS.md's design gate
governs. The shared stage orders are canonical in wallet-core's
ARCHITECTURE.md ("Ceremonies and cascades"); this table lists the
freewallet-side wrappers and the app-only ceremonies. The mender column
names how a torn run gets finished (see Tear mending in the Glossary): a
trigger a credential-only visit can fire, or a remembered-login sweep on a
ceremony only a remembered session runs. A residue left to that chain on an
account that may never run one is an open gap instead, listed below.

| Ceremony                      | Entry point                                | Module                                                            | Shared half                 | Mender                                                                                      |
| ----------------------------- | ------------------------------------------ | ----------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------- |
| Account genesis (plain)       | no-WAS signup; healed at every login       | `src/session/signup.ts`                                           | `/genesis`                  | re-run (every stage an ensure)                                                              |
| Credential-anchored genesis   | every WAS signup (the default entry, non-remembered) | `src/session/credentialAnchoredGenesis.ts`                        | `/clientAnnex`              | re-run; the transient login's heal branch                                                   |
| Self-enrollment at login      | remembered login on a fresh browser        | `src/session/initSession.ts` + `src/session/pendingEnrollment.ts` | `/clientAnnex`              | pending record pre-pivot; the next remembered login's resume                                |
| Client enrollment (two-party) | Settings > Connected wallets, login page   | `src/components/EnrolledClientsSection.tsx`                       | `/enrollment`               | re-run with the same connect code                                                           |
| Client revocation + epoch cascade | Settings > Connected wallets               | `src/session/revocation.ts`                                       | `/clients`                  | re-run; the cascade-completion sweep                                                        |
| Recovery-code issuance        | Settings > Recovery codes                  | `src/session/recovery.ts`                                         | `/recovery`                 | re-run before the confirm; a tear after the document entry has no mender                    |
| Recovery spend (remembered and transient) | `/recover`                                 | `src/session/recovery.ts`                                         | `/recovery`, `/clientAnnex` | remembered: pending record pre-pivot + spend resume; transient: re-run, open gaps (below)                    |
| Recovery-code revocation      | Settings > Recovery codes                  | `src/session/recovery.ts`                                         | `/recovery`                 | re-run; the cascade-completion sweep                                                        |
| Unlock-credential rotation    | Settings (passphrase change, passkey removal) | `src/session/credentialRotation.ts`                               | `/unlock`                   | torn-retirement repair at the next passphrase login; remembered-login sweep; re-seal repair |
| Forget ceremony               | Settings > Connected wallets, own row      | `src/session/forget.ts`                                           | `/clientAnnex`              | re-run (wipe last); forgotten-browser detector at the next remembered login                                            |
| Last-client transition        | same row, `lastClient` confirm             | `src/session/forget.ts`                                           | `/clientAnnex`              | re-run; the re-mint refusal is a retryable stop                                              |
| Update-key rotation           | Settings                                   | `src/session/accountSettings.ts`                                  | `/webvh`                    | re-run (persist-before-publish)                                                             |
| Account deletion              | Settings                                   | `src/session/accountSettings.ts` + `wipe.ts`                      | app-side phase order        | re-run; a wipe failure after the unlock-method walk is accepted                              |
| Shared wipe (executor, not user-facing) | consumed by the deletion-shaped ceremonies | `src/session/wipe.ts`                                             | app-side                    | re-probe verification; the `unverified` report                                              |
| Step-up ceremony              | designed, not built                        | ---                                                               | ---                         | ---                                                                                         |

Claims the cells cannot hold. A WAS signup's remembered and passkey flavors
continue into the self-enrollment row. The credential-anchored genesis heal
branch also mends a remembered signup torn before its self-enrollment, and
that signup's own resume entry triggers the self-enrollment resume. A
passphrase change whose establishment fails leaves the old credential intact
(establish-first), mended by a retry. The last-client transition refuses
outright on a pending passphrase entry or an unrecorded standing credential.

The open gaps come in two classes: a stated residue with no mender built,
and one whose only mender is a remembered login.

No mender built. Two are unbuilt repairs on client-less accounts, where no
remembered-login sweep ever runs: the transient recovery's roster-append
repair, and one for a user-key rotation torn mid-fan-out. A third is
KMS-specific: an establishment torn between the re-bind and the promotion
leaves the keystore's controller on the ladder's bare did:key, outside the
current-key-set rule. That mender is designed alongside the did:web-stage
collapse work. The fourth is recovery-code issuance: a run torn after its
document entry leaves a saved code that locates no account, plus a document
`keyAgreement` entry and a roster wrap nothing names. The login sweep
rotates the orphan wrap away, but the registry-driven health check cannot
see the code, so the retire-and-reissue mender for the orphaned document
entry is still unbuilt (see "Recovery codes").

Mender unreachable. A self-enrollment strikes every ladder VM in the entry
that publishes the new client. Three artifacts signed under it stop
verifying at once: the unlock record's bridge delegation, its
`delegatedClients` sibling, and the pointed generation's embedded generation
delegation. Replacements are attempted on the un-awaited login chain, so a
tab closed in that window leaves them dead. The strike is account-wide, so
it reaches the account's other standing credentials too. No credential-only
visit can mend this: the rotted bridge is the credential's one log-write
path, leaving only a remembered login on a browser that already holds a
client-key record. FW-354 moves the acting credential's reseal into an
awaited stage; FW-208 would let a credential-only visit mend the rest.

The annex generation GC is the same class: it runs from the remembered-login
chain only. On a client-less account the pointed generation's log grows by
one entry per transient visit with nothing collecting it, and every visit
resolves that log from genesis. A `gen-` collection orphaned by a crashed
first visit waits for the same sweep. An account-log pointer entry left by
one is append-only, superseded rather than removed. An auxiliary Space
stranded between its mint and its pointer entry has no deleter at all. The
constraint is authority rather than oversight: the swap re-points the
account log, the collect fan-out is controller-tier, and a ladder VM can
sign neither. FW-365 owns the bound.

## What lives elsewhere (do not reimplement here)

Every `@interop/*` package is in-house, checked out beside this repo (e.g.
`../wallet-core`). A change needed in one is an in-house change: export it
from the owning package and import it, rather than copying or re-deriving it
app-side. The shared wallet layer's map is
[`../wallet-core/ARCHITECTURE.md`](../wallet-core/ARCHITECTURE.md): module
layers and dependency direction, the key hierarchy, the ceremonies and
cascades, and the permanent wire-level constants.

- **`@interop/wallet-core`** -- the correctness-critical logic shared with
  the DCW mobile wallet, imported by subpath. The sections above name each
  subpath where it surfaces; the full set:
  - `/webvh` (the did:webvh log, the document halves of the ceremonies)
  - `/clientAnnex` (the ladder, the annex log and its GC, and the
    ladder-anchored ceremonies: credential-anchored genesis, self-enrollment,
    transient recovery). The verify-side halves stay in the base subpaths.
  - `/keys` (the user key, its wrap-set roster, the client-key record codec,
    client labels)
  - `/keyring` (the unlock layer), `/unlock` (standing unlock credentials,
    the credential rotation and retirement sequence)
  - `/genesis` (the account-genesis key mint and ceremony)
  - `/enrollment`, `/recovery`
  - `/clients` (listing, disconnect policy, the revocation cascade
    orchestrator, the login-time roster policy)
  - `/descriptors`, `/identity`
  - `/space` (collection layout, activity builders, `was-link`)
  - `/request` (classification, matching, VP composition, exchanges, the App
    Connect app-key credential)
  - `/resourceLog` (the wallet-domain residue of the resource-log client
    side:
    the did:webvh controller adapter `webvhResourceLogController` and the
    ceremony-tail license)
  - `/sync` (contacts head-conflict resolution only:
    `resolveContactHeadConflict`, over social-core's comparison). Freewallet
    keeps its own RxDB replication driver in `src/lib/sync/`, over the wire
    contract from `@interop/was-client/sync`.
- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic
  client side: chain verification, the chain-head pin port
  (`ResourceLogPinStore`, `ResourceLogHeadPin`, `memoryResourceLogPinStore`)
  with its host-free slot keys, and the continuity/integrity refusal
  classes. Freewallet imports the pin port and refusal classes directly; the
  did:webvh controller adapter stays on `@interop/wallet-core/resourceLog`.
- **`@interop/was-client`** (+ `/edv`, `/sync`, `/paths`) -- the WAS HTTP
  client, the sync wire contract the RxDB driver speaks, the EDV envelope
  cipher and key-epoch construction (`createEdvDocCipher`,
  `x25519RecipientFromDidKey`), and the descriptor-store seam.
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
  account's stable id is a `did:webvh` (see "The did:webvh identity");
  clients, apps, and agents are identified by `did:key`.
- **did:key** -- a DID method where the identifier encodes the public key
  directly. No blockchain or registry needed. A wallet client's did:key
  comes from its randomly minted 32-byte client seed (`agentsFromSeed`),
  never from the passphrase.
- **CID (Content-addressed Identifier)** -- a base64url-encoded SHA-256 hash
  of the canonicalized credential JSON (`cidFrom()` from
  `@interop/was-client/sync`). The primary key for stored credentials.
- **ZCap (Authorization Capability)** -- the authorization model for HTTP
  requests to the WAS server. Clients sign requests with their Ed25519 key;
  the server verifies the signature against the Space controller's DID. See
  the WAS server AGENTS.md for details.
- **CHAPI (Credential Handler API)** -- a browser standard that lets
  websites delegate credential operations to a registered wallet via a
  popup. The mediator is `authn.io`.
- **App Connect** -- the one-popup app login: a CHAPI `get` whose VPR
  carries an `AppConnectQuery`, answered in one signed presentation with an
  app-key credential plus capabilities delegated to its subject DID. The
  credential is matched by origin, `appUrl`, and seed-to-subject binding, or
  minted wallet-side on first run. See "App Connect".
- **App key** -- a self-issued credential holding a 32-byte seed in
  `credentialSubject.seed`, bound to a requesting origin
  (`credentialSubject.origin`) and to the application's canonical URL
  (`credentialSubject.appUrl`). Issuer and subject are the seed-derived
  did:key (`CapabilityAgent.fromSeed`, `keyName: 'app-key'`). It is how a
  BYOE app keeps its identity and encryption root in the user's wallet
  (`@interop/wallet-core/request`). Marked with the type `AppKeyCredential`
  (`https://w3id.org/byoe#AppKeyCredential`) and stored in the dedicated
  `app-connections` collection. See "App Connect".
- **Client / `clientId`** -- the keyed, custodied, revocable identity of an
  (app, user) pair: a keypair that can be a zcap grantee, a delegation
  `controller`, or an entry in a collection's key-epoch roster. For a BYOE
  app it is the app key's subject DID, scoped to `(user, origin, appUrl)`
  and stable across browsers because the wallet custodies the seed. Not a
  "device": one machine hosts many clients, and a client is not tied to
  hardware. "App session" is informal prose for one live session of a
  client; nothing named `appSessionId` is persisted. A client is a cache
  rather than the account's durable state, so state reconstructible from a
  client alone is a defect rather than a stated limitation. Avoid: device,
  device id, durable client.
- **Agent** -- a connected app whose key is agent-held rather than
  wallet-custodied: a CLI or LLM agent that mints its own did:key and asks
  for scoped, expiring, revocable grants through a standalone
  `AuthorizationCapabilityQuery`, naming itself as `controller`. It fills
  the grantee slot a BYOE app fills, holds neither the user key nor the
  unlock credential, and is not a wallet client. Its grants are listed and
  revoked on the Applications page. A future CLI-class wallet would be a
  wallet client rather than an agent. Avoid: transient client (the annex
  inventory), agent client, bot.
- **`writerId`** -- an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision. It attributes history and
  breaks last-write-wins ties. Minted locally (`src/lib/writerId.ts`, a
  `localStorage` key), derived from no secret, and lost on a wallet reset,
  so it is never an identity: unlike a `clientId` it can vanish and be
  re-minted with nothing carried over. Not a `replicaId` either, since it is
  minted per browser profile while the local database is per user. Avoid:
  replicaId, device id, session id.
- **Share** -- granting a third party read AND decrypt access to one of the
  wallet's own encrypted collections, asked for with a
  `https://w3id.org/byoe#shared-wallet-collection` invocation-target
  descriptor. One `shareCollection` call grants both axes: a read-only
  Collection zcap and an entry in every one of the collection's key epochs
  (`addRecipient`). Removed from the Storage page's collection list rather
  than by expiry. See "Sharing a wallet collection".
- **WAS (Wallet Attached Storage)** -- an HTTP protocol for storing
  arbitrary resources in user-owned Spaces. Requests are authorized via
  ZCap. See [the
  spec](https://w3c-ccg.github.io/wallet-attached-storage-spec/).
- **Space** -- a storage area on the WAS server, owned by one controller.
  The account Space's id is an independent random identifier minted at
  signup and carried in the account pointer; unlock Spaces are addressed by
  `spaceId = base64url(SHA-256(unlock did:key))` (a discovery convention).
- **Collection** -- a named grouping of Resources within a Space. Standard
  collections: `private-credentials`, `public-credentials`,
  `wallet-activity`, `contacts`, `contacts-history`, `app-connections`.
- **Resource** -- an individual stored item (JSON or binary) within a
  Collection.
- **Controller** -- the DID that owns a Space. An account Space is
  controlled by the account's `did:webvh` once promoted (see "Controller
  promotion by ordering"); before promotion, and on an unlock Space, it is a
  `did:key`.
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
  in the standing configuration. Beside locating the account through its
  unlock record, it holds a wrap of the user key in the roster and latent
  self-enrollment authority carried in that record: a bridge delegation, the
  `delegatedClients` sibling delegation into the client annex, and a random
  ladder seed. A fresh browser holding only the credential can self-enroll
  as an enrolled client (`rememberBrowser: true`) or enter a transient
  session. Its entropy bounds everything server-held that it alone decrypts,
  and rotation is the remedy when it leaks. See "Session & auth flow".
- **Bridge delegation** -- the pre-minted, narrowly scoped zcap carried
  inside an unlock or recovery record beside the account pointer: a
  PUT-on-`did.jsonl` capability, plus annex-log access where that applies.
  It is a credential's only bridge into the zcap profile, and all it can do
  is extend the world-readable log, which keeps credential use loud.
  Re-minted by the revocation cascade, refreshed near expiry by the
  credential's own login.
- **Unlock-local state** -- the browser-local artifacts one unlock method
  leaves on a browser, all keyed by its unlock Space id: today the keyring
  cache and the wrapped client-key record. It is the whole of what a
  credential owns locally, so an artifact joins or leaves this list rather
  than each retiring site. The term is count-free: the set was three
  artifacts while the keyring-freshness pin stood
  (`decisions/0012-no-durable-continuity-pins.md`). `deleteUnlockLocalState`
  in `src/lib/sessionKey.ts` is the one deleter (see "The shared wipe
  enumeration"). Avoid: unlock trio, local trio, unlock artifacts,
  credential residue.
- **Ladder (update-key ladder)** -- the chain of did:webvh update keys
  derived from a standing credential's random ladder seed. Each rung is
  committed ahead of use as a hash in `nextKeyHashes` (the method's
  prerotation) and reveals itself in a reveal-and-commit log entry signed by
  the current rung. That is how a credential extends the log with no
  enrolled-client key in hand. The **ladder VM** is the verification method
  derived from the ladder, published under `assertionMethod` and
  `capabilityDelegation` with no invocation relation. It anchors an account
  with zero enrolled clients and is struck from the document when its
  credential retires. Its bare did:key (`ladderVmAgent`) is the bootstrap
  identity the credential-anchored genesis creates the Space under.
- **Roster** -- three related uses. The **enrolled-client roster** is the
  did:webvh document itself. The **user key wrap-set roster**
  (`key-map/user-key.jsonl`) is the log-governed record whose current epoch
  IS the current user key, wrapped once per enrolled client's key-agreement
  key. A **key-epoch roster** is the per-collection recipient set on an
  encrypted collection's `encryption` descriptor. All three deliver key
  material or membership; none is a source of authority on its own.
- **Inventory** -- a credential's or client's set of durable entries in the
  account document, the annex log, or the ladder: its `keyAgreement` entry
  or commitment, its ladder VMs, its committed rung hashes, its annex rung
  hashes. Ceremonies install it; retirement sweeps it out (wallet-core's
  `removeUnlockKey`, the annex rung strike). An entry is inventory-changing
  iff the set differs from the previous version's (the ceremony-tail
  license's test). A named arrangement of an inventory takes a qualified
  "configuration" phrase (split, carry-over, standing), never bare. Avoid:
  posture, footprint.
- **Loudness** -- the design property that any exercise of
  credential-derived authority must first extend a hash-chained, auditable
  log (the account log, or the annex log) before it can read or grant
  anything. It enables detect-and-remediate rather than prevent: a takeover
  with a phished credential is visible in the log and remediable by
  rotation. The two logs grade differently. The account log is
  world-readable and append-only, so an exercise recorded there is publicly
  auditable and permanent. The annex log is capability-gated and
  garbage-collected, so an exercise recorded there is auditable by
  capability holders and mortal. A log append confers loudness only where it
  sits on the critical path of exercising the authority. A per-visit annex
  entry is loud that the key exists and may delegate; what that key later
  delegates, to whom, and for how long is minted offline and leaves no entry
  anywhere. A mechanism "fails loudness" when it lets a credential exercise
  authority with no logged record at all.
- **Continuity pin** -- remembered evidence of what this client last saw,
  checked against what the host now serves. Two kinds: a log's verified
  chain head (`persistence.logPins`, one slot per log) and the user key
  roster's current epoch (`persistence.epochPins`). A signature proves an
  artifact authentic but not current, so the pin is what catches the attack
  in which every signature verifies. A served log that is a rollback, a
  fork, or an SCID or method switch is refused, as is a roster behind the
  pinned epoch. Every pin store is in-memory
  (`decisions/0012-no-durable-continuity-pins.md`). See "Log continuity
  within a session". Avoid: continuity prior.
- **Ceremony** -- an ordered sequence of writes across the account's systems
  (the account log, the roster, the unlock records, collection epochs) and
  this browser's local state. Its stage order carries an invariant:
  persist-before-publish, document-edit-first,
  decryption-material-before-authorization. Every stage detects its own
  completion from stored state, and every tear point has a stated mender
  (see Tear mending). Every ceremony has a **pivot**: the first durable
  write past which backward recovery is impossible. The derivability rule
  governs both sides of it. A write either sits before the pivot and stays
  inert until it lands, or sits after it and is re-derivable from the pivot
  entry plus durable state alone (wallet-core's
  `decisions/0010-post-pivot-derivability-rule.md`, checked per-write at the
  design gate for every new or changed ceremony). A write before the pivot
  also names its storage tier: a browser-local one owes an answer for a
  cleared or evicted browser, not only for a tab death. See "Ceremony
  inventory" for the full list; wallet-core's ARCHITECTURE.md ("Ceremonies
  and cascades") owns the shared stage orders. Avoid: flow, workflow,
  wizard.
- **Tear mending** -- the umbrella for how a torn ceremony (one interrupted
  mid-run) gets finished. Three menders exist: a converging re-run, a
  standing sweep (the cascade-completion sweep on the remembered-login
  chain, or the generation-readiness stage every transient visit runs), and
  a repair (below). A remembered-login sweep is one running on
  `session.registryReady`. A mender counts only if a credential-only visit
  can fire it. The default session is transient, so a residue whose one
  trigger is the remembered-login chain may wait forever on an account that
  never remembers a browser; that is an open gap rather than a mended tear
  (`decisions/0010-remembered-login-is-not-a-mender-trigger.md`, checked per
  residue at the design gate). The derivability rule makes these menders
  sufficient: a post-pivot write is re-derivable by construction, so a
  re-run, sweep, or repair can roll it forward from durable state. A write
  that fails the rule is a defect rather than a documented limitation, and a
  stated residue with no mender is an open gap. A ceremony family may also
  expose one mend entry point spanning the taxonomy, its arms these menders,
  run by whatever context holds the needed authority
  (`mendCredentialAnchoredAccount`). Avoid: tear closure.
- **Repair** -- the mender of last resort: code waiting at the one entry
  point where the authority a torn state needs reassembles, detecting that
  state from stored state alone and finishing the ceremony. Used where
  neither a re-run nor a remembered-login sweep can fire, typically a
  client-less account. Always qualified by its torn state ("the
  torn-retirement repair", `repairTornPassphraseRetirement`), never bare.
  Avoid: completer, finisher, fixup.
- **Client annex** (`clientAnnex`) -- the transient-session counterpart of
  an enrolled client for the public-computer case: a did:webvh whose log
  lives in a capability-gated auxiliary Space beside the account Space,
  recording per-visit transient verification methods in GC'd **generations**
  rather than permanent account-log entries ("the annex" in prose). Enrolled
  clients live in the account document; delegated and transient clients live
  in the annex, which never appears in that document. Transient keys invoke
  and delegate as `<clientAnnexDid>#<vm>`. A per-visit transient VM
  publishes under `capabilityInvocation` and `capabilityDelegation`, and
  under no other relation: a transient session invokes WAS requests and also
  mints App Connect grants, and a delegation proof verifies against
  `capabilityDelegation` in the current annex document.
- **Generation delegation** -- the one Space-scoped zcap per annex
  generation, delegated to the annex DID by the enrolled client that mints
  the generation, or by the ladder VM on an account with no enrolled client.
  Transient keys invoke under it, and an App Connect grant from a transient
  session chains one deeper (root, generation delegation, app). That grant
  is signed by the visit key under its annex verification method, which is
  why the transient VM publishes under `capabilityDelegation` beside
  `capabilityInvocation`. Its `invocationTarget` is the Space's items
  subtree, so a whole-Space target under it is unsatisfiable, and every
  grant's `expires` is clamped to its own. Its TTL matches the generation's
  GC cycle.
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
- **Vault KAK** -- the X25519 key-agreement key that encrypts and decrypts
  the EDV envelopes: the user key's key-agreement key. A remembered login
  recovers it from the local client-key record and checks it against the
  user key wrap-set roster (`key-map/user-key.jsonl`); a transient session
  unwraps it from the credential's standing wrap in that roster. Never
  replicated in unwrapped form and never held by the KMS; present for the
  life of every session. Avoid: PUK.
- **Session** -- the in-memory object (`src/types/auth.ts`) holding the
  logged-in user, their `ControllerProfile` (keyAgent + zcapClient, and the
  persistence strategy at `profile.persistence`), and their `StorageManager`
  instance.
- **Durable** -- persisted server-side, on the WAS host: the account log,
  the user key roster, the unlock records, the Collection Descriptions and
  their key epochs. It survives a cleared browser, an evicted origin, and a
  lost machine, which is why a ceremony stage may detect its own completion
  from it. The word names this tier alone: browser-local state is not
  durable, and neither a session nor a client is ever called durable
  (`decisions/0011-durable-names-server-storage-only.md`). Avoid: durable
  session, durable client, durable login, durable pin.
- **Browser-local** -- persisted in this browser's IndexedDB or
  localStorage: the client-key record, the keyring cache, the Space-to-DID
  mapping, the descriptor and meta caches, the `writerId`, and the replica
  database. Semi-durable: it survives a reload but not an eviction, a
  cleared profile, or a lost machine. It is a cache of what the host holds,
  and never the only home of anything the account needs. Avoid: durable
  local state, disk, persistent storage.
- **In-memory** -- held in tab memory and gone when the tab closes: a
  transient session's whole store family, every session's continuity pin
  stores and unlocked key material, and the prefs overlay. The third storage
  tier.
- **Session persistence** -- the axis deciding which storage tier a session
  may write to, fixed once at login by the typed persistence strategy (see
  the section of this name). Two variants, each named for the tier it
  reaches: browser-local (the `freewallet-session` database and the
  localStorage caches) and in-memory. A write site consults no flag. Not the
  remembered / transient axis: a guest session is browser-local and is not
  remembered. Avoid: durability, posture, mode.
- **Persistence strategy** -- the typed object at `profile.persistence`
  (FW-369 moves it onto the session) through which every tier-sensitive
  write travels. The variant IS the type, so a write site never branches: an
  in-memory strategy has no member reaching the session database
  (`decisions/0001-no-memory-overlay-storage-fork.md`). Both continuity pin
  stores ride it in memory whichever variant it is, so the strategy carries
  them without deciding them
  (`decisions/0012-no-durable-continuity-pins.md`). See "Session
  persistence". Avoid: persistence handle, durability handle ("handle" in
  this repo is the Storage Access API's).
- **Remembered browser** -- a browser holding a client-key record for an
  unlock credential, so a login on it proceeds as (or self-enrolls into) an
  enrolled client. Remembering is a deliberate opt-in (`rememberBrowser`),
  undone by the forget ceremony, and lost with a cleared profile:
  browser-local state rather than a durable property of the account. A login
  on one is a **remembered login**, its session a **remembered session**; a
  **non-remembered** browser defaults to the transient login. Avoid: durable
  browser, durable login, trusted browser, persistent login.
- **Enrolled client** -- a wallet client published in the account document,
  keyed on `capabilityInvocation` (see "The did:webvh identity"). It holds a
  client-key record, a wrap in the user key roster, and its own did:webvh
  update key. Contrast the **transient client**, a per-visit key recorded in
  a client annex generation. Both are caches (see Client): enrollment buys a
  local replica and root-tier authority, not permanence. Avoid: durable
  client, permanent client.
- **StorageManager** -- the facade class in `src/stores/storageManager.ts`.
  Routes all wallet reads and writes to the session's
  `SyncedCollectionStore` backend (the local `BrowserStore`, or the
  remote-direct store for a replica-less or popup session) and exposes the
  optional `WASRemoteStore` for background replication and remote-only
  features (storage browser, export/import, quotas).
- **BrowserStore** -- the local active replica of a session that has one,
  using RxDB / IndexedDB (Dexie). Holds every standard wallet collection on
  the generic synced-doc schema. A transient session is replica-less: it
  constructs none and reaches the same collections remote-direct. A
  remembered CHAPI popup constructs one but routes past it.
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

