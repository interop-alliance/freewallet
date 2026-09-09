<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Session & auth flow

There is no external identity provider, and nothing about the account
derives from the passphrase. The passphrase (or a passkey PRF output)
derives only an **unlock identity** (`src/session/keyring.ts`), which
locates the account's **unlock record** in its own minimal unlock Space. The
unlock record carries none of the account's content keys.

One post-KDF question decides the rest (`routeUnlockLogin` in
`src/session/transientLogin.ts`). Does this browser hold a client-key record
for this credential? A browser holding none takes the transient composition,
the default (see "The transient login" under "Session persistence" in session-persistence.md). A
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
high-entropy and publishes verbatim (see "Recovery codes" in recovery-codes.md).

The connect-another-wallet ceremony (see "The client enrollment ceremony" in client-enrollment.md)
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
the client revocation runs (see "Client revocation and the epoch cascade" in client-revocation.md).

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

Before the establishment starts, the change's enrolled branch stamps an
establishment marker on the old credential's registry entry, restated at
that credential's own unlock Space: `pendingEstablishment`, naming the NEW
credential's unlock Space and key-agreement multibase. The establishment
writes the new credential's standing record and roster wrap before its
document entry, and a tear between the two leaves that record with nothing
else naming it. The restatement comes from the fresh registry read the
compare-and-swap wrapper hands over, and the write is skipped when that
fresh entry names a credential other than the typed old passphrase (a change
that completed elsewhere in between), since stamping over it would drop that
credential's members. The change's final registry write drops the marker,
and so does any later write that names another credential or repoints the
entry. A write that keeps the entry on the same credential at the same Space
(a refresh, a backfill, a re-seal) carries it forward. The marker is an
index like the rest of the entry: the mend it arms re-derives everything
from the sealed record and the account document. Its write is best-effort,
its detector a retry of the same change, which re-runs it. An account whose
registry holds no passphrase entry yet gets no marker, that entry being the
backfill's to write.

The ladder branch stamps none. A transient session's passphrase change
leaves nothing browser-local, so no later login could hold the new
credential's client-key record and consume a marker. Its torn establishment
is mended by a retry of the same change.

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

**Establish-first arm.** An entry naming another credential while the login
credential is NOT in the account document is the change torn before its
document entry. The new credential's record and roster wrap stand, and the
entry still names the old credential at the old unlock Space. Registry and
document state alone cannot tell that state apart from two others: an old
passphrase logging in after a change that completed elsewhere, and an
abandoned torn passphrase after a later change succeeded. Establishing on
either of those readings would retire the account's current passphrase, the
forbidden direction. The gate is therefore the establishment marker naming
the credential logging in, at its own unlock Space. The address gate it
replaces asked whether the entry sat at the login credential's own unlock
Space, which the torn change does not satisfy, so nothing detected that
residue.

The arm carries a second gate. The entry's OWN credential must still be
listed in the account document, which the marker-armed state holds by
construction, the change tearing before its retirement. A marker over an
entry whose credential a later ceremony retired (a recovery spend whose
registry write tore, say) is stale, and firing there would reinstate an
abandoned passphrase over the account's current one.

The arm establishes the login credential from the record the torn change
sealed. `establishStandingUnlock` reads the ladder seed back from that
record, so the document entry names the rung the record already holds. The
live profile is then swapped onto the re-bound record, the retirement above
runs, and the entry is rewritten, which drops the marker. A bare entry
carrying the marker takes the same arm, on an account whose registry named
no passphrase members: establish first, then record the entry from that
establishment. The old credential in the bare case stays standing with
nothing naming it, the pre-existing bare-entry residue.

**A credential the document does not list.** A transient login verifies the
account log and then checks the credential's own inventory. A document
listing no `keyAgreement` member of this credential's (a passphrase's
commitment, a passkey's verbatim key) anchors nothing of its record, so the
bridge, the sibling delegation, and the ladder-signed mend would each refuse
at the server. The login raises the typed `credential-not-standing` refusal
there instead, before any ladder-signed request is tried, and the page
renders `auth.errors.transientCredentialNotStanding`. That is the state a
standing establishment torn before its document entry leaves for a browser
holding no client-key record for the new credential.

Two variants of that tear have a converging re-run as their only mender: a
passphrase change run from a transient session, which stamps no marker, and
an add-a-passphrase run torn at the same point, which stamps none either
since no entry names anything to mark. A retry of the same change with the
same secret converges, the sealed ladder seed being read back from the
record.

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
and a stale seal would make each warn and skip. The backfill carries the
refresh write's identity guard: it does not repoint the passphrase entry to
the login credential's unlock Space while that entry names another
credential's standing members or carries an establishment marker, so a
backfill running after a failed repair in the same chain cannot drop them.
The sweep is early because its roster convergence may rotate the key and
re-seal the registry, and a read-modify-write racing that re-seal would undo
it within one login.

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
document publishes (see "The KMS stage" in account-genesis.md). Provisioning failure is logged and
non-fatal. Only a remembered login provisions and binds the keystore, a
transient visit holding no key the keystore's controller document lists; the
ladder-signed delegation that would let it in is not built yet. Settings
shows whether the account document records the KMS-held key rather than
whether this session bound the keystore.
