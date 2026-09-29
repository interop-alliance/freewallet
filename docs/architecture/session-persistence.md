<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Session persistence

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
mender block runs afterward, settling `session.registryReady` and then
`session.mends`.

**The persistence strategy** (`src/session/persistence.ts`). Which storage
tier a session may write to is decided once at login, by the typed
`SessionPersistence` object at `session.persistence`. The tier is a property
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
database must hold it. Its `writerId` is the one label declared on the
wire. The sync controller sends it on every replication push as the WAS
`Writer-Id` header. The in-memory variant cannot reach that label. It holds
a per-visit one minted in tab memory, and declares none today, since it runs
no replication and remote-direct writes send no `Writer-Id` on any session
kind. A remembered session's own remote-direct writes (the CHAPI popup, the
app-key sweep's public-copy retraction) go unlabeled too.

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
popup is this same shape (see "Remote-direct popup storage" in chapi.md).

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
the probe's factory (see "The popup follows the browser's routing" in chapi.md).

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

**The login-time mender block.** The visit runs the user key sweep's
collection fan-out and four of the login-time registry passes as its own
block after navigation, in registration order: the fan-out, then
the stale-seal repair, the torn-retirement repair, the bare-passkey rebuild,
and the registry backfill, with the management-zcap refresh above as the
last registration (the ordering is under "Session & auth flow" in session-and-auth.md). Each rides
the visit's generation delegation and unwraps with the credential's standing
key, each failure is logged and reported, and the block is not awaited.
`session.registryReady` and `session.mends` settle together here, every
registration settling the first. In a CHAPI popup the registry passes
declare themselves off the route, so the fan-out runs alone. The sweep's
roster convergence and the annex generation GC do not run here. Nothing in the registry's write protocol turns on the session tier.

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
stranded collections are named in a warn, the only trace on a
credential-anchored account, which no login sweep revisits.

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
session may still remove its own login passkey. Removing the backup
credential a transient session entered on refuses the same way.

A passphrase change on the ladder branch replaces the generation delegation
before its strike entry lands, and adopts the replacement into the live
session (the profile stamp, the persistence strategy, the remote store). The
old credential's ladder VM may be what signed the delegation the visit's
every request rides, and the strike takes that VM out of the document. The
replacement is minted by the new credential's ladder VM and installed
through that credential's sibling delegation. Every App Connect grant the
visit chained under the old delegation ends with it.

**The backup export's stage order** (`src/session/backupExport.ts`). The
export packs a backup credential into the bundle. That is a standing unlock
credential (`src/session/backupCredential.ts`) whose secret is 32 random
bytes, derived under wallet-core's `BACKUP_CREDENTIAL_KDF`. The bundle
carries the secret as `backup-credential.json`, sealed under an export
passphrase or in the clear. A restore is a transient login on the
credential's record, which is not built yet: no login form accepts a backup
credential today. Nothing is retired and no key is rotated.

The ceremony waits out `session.registryReady` and `session.mends` and
resolves the account-ceremony context once. The pre-flight runs next, before
anything is minted, so a refusal there leaves no "Backup <date>" row behind.
It checks the account Space's, the client-annex Space's, and every registry
entry's capability for `POST`. The client-annex Space is resolved from the
account document's `#DelegatedClients` pointer on both session kinds, and a
named annex Space this session cannot reach refuses the run there. One more
condition rides the annex. The establishment must commit the new
credential's rung into the pointed generation, signed by this session's own
ladder rung. A session holding no ladder seed cannot. On an account naming
an annex Space, such a session refuses here with `BackupAnnexCommitError`. The new credential's own entry is minted with
the full verb set, so the pre-flight does not check it.

Four stages follow in order. First the establishment, which is the pivot.
Then the Space listing, read back from the server after it: the account
Space, the client-annex Space, and one unlock Space per unlock-methods
registry entry. A registry that carries no entry for the new credential's
unlock Space refuses the run (`BackupCredentialNotListedError`), since a
bundle missing that Space does not restore the account. Then one export per
Space, started in listing order. The bundle stream is handed back once the
listing is done, and the exports run as the picked file is written, up to
three at a time. The account Space's archive is checked against this
visit's pinned chain head for the account log before its entry is written,
and a mismatch refuses the run. A visit holding no pin for that log skips
the check. Then the packing. Once every archive is in hand, and before the
bundle's last entry is written, the registry is read once more. A set of
unlock Spaces that differs from the listed one refuses the run
(`BackupRegistryChangedError`). A refusal after the listing errors the
stream, so the save fails and does not finish the file.

The establishment (`establishBackupCredential`) is entry-first, in the
passkey's shape with one difference. A passkey writes a bare entry and
completes it afterwards, because that passkey's own next login rebuilds a
bare row. A backup credential has no next login until a restore runs it, and
its secret exists only in memory until the file is written. So its first
write carries everything Settings needs to remove it with no secret in hand.
That is the standing fields derivable in memory (the unlock Space id, the
roster kid, the key-agreement multibase, rung 0's update key, the client
DID) and a pre-minted management zcap. Then `establishStandingUnlock` runs
with its annex rung commit required: the roster wrap, the delegations, the
record, the annex rung commit, and the document entry, in that order. The
commit sits before the document entry, so a commit that cannot land throws
over inert writes alone. It must land before the annex Space is exported,
because a restore login on an uncommitted rung mints a fresh generation and
loses every restored grant. Last, the completion write adds the delegation
fields and swaps in the establishment's own management zcap.

A failure inside the establishment runs the verify-then-act cleanup the
passkey add runs, shared through `src/session/standingEstablishment.ts`. The
record is re-fetched first. A standing record the document lists is a lost
response to a success, and completes the entry. Otherwise anything published
is retired first, and then the unlock Space is deleted and the row dropped. The run then fails with `BackupAnnexCommitError` when the
annex rung commit was what failed, and with
`BackupCredentialNotEstablishedError` otherwise.

The secret reaches only the establishment and the packing. Nothing stores
it, returns it elsewhere, or logs it.

| Tear point                                  | What it leaves                                                                  | Mender                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Pre-flight refusal                          | nothing                                                                         | re-run                                                                                    |
| After the entry-first write                 | a row naming a Space that does not exist and a key no document lists            | Remove under Settings > Backup credentials, which deletes nothing and drops the row       |
| Inside the establishment, cleanup ran       | nothing, or the row and whatever the cleanup could not clear                    | the cleanup itself; a remaining row's Remove                                              |
| Inside the establishment, cleanup never ran | the entry-first row and whatever the establishment reached                      | the row's Remove, which converges it (strike, roster rotation, Space delete, entry drop)  |
| At the completion write                     | a standing credential under the entry-first row, recording no delegation expiry | none needed: the bundle restores through it, and a login with it refreshes the delegation |
| After the establishment completed           | an ordinary labeled backup credential                                           | re-run; the row is listed and removable like any other                                    |

The Remove tolerates every one of those states. The strike tolerates a
verification method the document never listed, and the Space delete
tolerates a 404.

Which capability each export rides depends on the kind. An enrolled session
root-invokes the account and annex Spaces and invokes each entry's stored
management zcap directly. A ladder-anchored session rides the generation
delegation on the account Space, the record's `delegatedClients` delegation
on the annex (sent by the credential's standing client, since the annex
Space answers to the account did:webvh), and a freshly minted POST-only
child of each management zcap on the siblings, signed by the ladder VM and
sent by its bare did:key. Both kinds run the same pre-flight over the stored
zcap: an entry whose zcap allows no `POST`, has expired, or names a
delegatee this session cannot act through is refused before the request, so
the report names the entry rather than a server refusal. What refreshes such
a zcap differs by entry. A passphrase's and a passkey's are re-minted by a
login with that credential. A recovery code's and a backup credential's
have no refresh path from Settings. Only the entry's own unlock identity can
re-delegate them, so the remedy is to remove the entry and issue or export
again, which is what the refusal says.

The export is a walk rather than a snapshot. Each Space is read at its own
moment and nothing on the server holds the set still, so the bundle is only
as consistent as the run was quiet. The one bound the ceremony can state it
does: the registry is re-read once every archive is in hand, and a set of
unlock Spaces that differs from the listed one fails the run, since a
credential added mid-run would be missing from the bundle and one removed
would be in it after its Space was gone. Because the bundle is buffered
whole before it is handed back (wallet-backup's writer finalizes the pack
with no consumer attached), that check still runs before the caller sees a
single byte.

The rule is fail-whole: one Space that cannot be exported fails the run, so
no bundle is written that reads as complete and is not. The export
passphrase seals the packed secret and nothing else. The bundle carries
every unlock Space archive and the account Space's user key roster, so a
holder can guess the wallet passphrase offline, and the file's bound is the
weaker of the two secrets.

The save is asked first. The dialog opens the browser's save picker before
the ceremony starts where the browser has one, so a dismissed picker
establishes no credential. It pipes the bundle into the chosen file
afterwards. A browser without the File System Access API buffers the
finished bundle into a Blob instead. A cancelled run renders the cancelled
message, which says any backup credential it already established is listed
under Settings > Backup credentials.

**Content migration's app collections** (`src/session/contentMigration.ts`).
Beside the standard collections, the walk hands the sink every app
collection in the bundle's account archive, one at a time: an
`ensureCollection` call, then its Resources. The sink carries that member only
when `StorageManager.canProvisionAppCollections` holds (remote storage and
descriptor logs), so a guest or a no-WAS session leaves app collections in
the report's not-migrated counts. `ensureImportedAppCollection` reads the
collection's standing state and checks a standing collection before it
writes anything. It then runs was-client's guarded ensure, whose `created`
report decides whether this run made the collection. The earlier read only
feeds the checks. A create lost to a rival reads the rival's collection
back and checks it the same way. An encrypted collection is ensured bare
and then gets its first epoch owner-only, the second half of
`provisionEncryptedCollection` with no grantee. On a collection the run
creates, it declares the archived index schema through was-client's
add-only `declareIndexes`. It then builds the row cipher from the
descriptor and the collection metadata as it then stands. A standing
collection that predates the blinded index has no key to declare under, and
its rows land without index entries. A plaintext collection is ensured
private with its archived attribution. When the run creates it and the
archive says public, the world-read grant follows.

A collection the account already holds keeps its own settings: its public
read, its index schema, and its attribution are left as they are. The one
exception is this migration's own torn create. A standing collection that
holds no rows and whose `generator` equals the archived one is finished as
if the run had created it. A plaintext one gets the archived public read,
and an encrypted one gets its first epoch and, when it declares none yet,
the archived index schema. An archive with no `generator` never qualifies,
since an interaction-URL grant also leaves an unattributed collection. So a
run torn between the create and the public read, or between the first epoch
and the schema, converges on its re-run.

Every other standing collection runs the refusal matrix. It is refused with
`AppCollectionMismatchError`, and its rows are not written, in these cases.
An archived plaintext collection is refused over one that stands encrypted.
Any archive is refused over a collection encrypted under a client-written
descriptor, which no governing log can take over. An archived encrypted
collection is refused over a plaintext one holding rows, and finishes an
empty one. A plaintext archive is refused when its public read differs from
the standing one. It is also refused over an empty collection with no
`encryption` member and no public read. That empty state is also what an
App Connect encrypted provision torn before its first epoch leaves, and
plaintext rows landed there would keep the app's provision refused. An
encrypted archive's public read is ignored, on the create and in the
checks.

The row cipher rides the same once-per-session unknown-epoch refresh the
storage browser's app-collection reads use: a snapshot row sealed under an
epoch the cipher does not know drops the cipher, and the rebuilt one reads
the verified log head. The server takes a write's `Key-Epoch` as advisory,
so the write path checks too. Before each row is sealed, the collection's
served metadata is read and its current epoch compared with the cipher's.
When they differ, the verified log head is read, and the cipher is rebuilt
with its schema when that head has moved. A row is therefore sealed under
the current epoch as of its own write, even after a rotation in another
tab. `snapshotAppCollection` reads the collection's held rows once per
run, at its first Resource, and `importAppCollectionResource` decides each Resource
against that snapshot: `skipped` for the same identity and content,
`conflicting` for the same identity under other content, and otherwise a
write. A plaintext Resource keeps its archived content type. A non-JSON one
arrives as raw bytes and is not in the snapshot, so an id already taken is
read back and compared by its bytes.

An encrypted Resource arrives by what it decrypted to. A JSON one takes the
route above. One that decrypted to bytes, a chunked Resource or a small
binary or text one, arrives as raw bytes under its sealed content type. Its
identity is its archived resource id. `WASRemoteStore.putEncryptedResourceBytes`
writes it at that id through was-client's `Resource.put` with
`ifNoneMatch`, on a handle carrying the verified descriptor and the vault
keys as a per-handle encryption override, since the store's client holds no
keystore. A payload over the codec's blob limit is written as a chunked
document. A `412` reads the held copy back, reassembling a chunked one, and
compares bytes: the same bytes are `skipped`, and other bytes (or a held
JSON copy) are `conflicting`, with the held copy untouched. When that read
fails with `EncryptionError`, the raw envelope is read, and a pending stub a
killed chunked write left is deleted with its chunks through
`resource.delete()`. The write then runs again. A stub is reaped only at an
id the run is importing. The snapshot decrypts each held envelope with a
chunk source that holds nothing, so a complete chunked Resource stops at its
first chunk with `NotFoundError` and is recorded by id, as a small bytes
Resource is. No held Resource is reassembled for the snapshot, and a pending
stub is left out of it. A `507` during a chunked write surfaces as
`QuotaExceededError`, which ends the walk. `migrateContent` refuses a second
run while one is going in the same tab (`ContentMigrationInProgressError`),
since that run could reap a stub the first is still filling. Runs in two tabs
are not held apart.

App collections are remote-only, so these writes go remote-direct
on a remembered session too. The app's own recipient entry and grants do
not travel; the app is admitted again when it reconnects.

**Removing a backup credential.** Settings > Backup credentials lists one
"Backup <date>" row per entry of the `backup-credential` kind. Its Remove
runs `removeAccountBackupCredential`, the passkey removal minus the
authenticator: the ordinary revoke, with no secret in hand. It strikes the
credential's ladder VM and key agreement from the account document, rotates
the user key off its roster wrap, deletes its unlock Space through the
entry's management zcap, and drops the entry. On the ladder kind the
generation delegation this visit rides is replaced first, best-effort, in
case the credential's ladder VM signed it. A transient session refuses to
remove the backup credential it entered on (`ActingCredentialRemovalError`),
since every stage would act through the VM being struck. An entry recording
no management zcap refuses with `BackupCredentialNotRemovableError`. After
the removal the bundle no longer signs in to the live account. It still
opens every row it carries offline, so removal bounds the live account and
not a file already written.

Contacts are reachable in a transient session. The remote-direct backend
serves all seven contact operations against the remote `contacts` and
`contacts-history` collections. Head rows are read and written in place
under compare-and-swap on the served ETag, and a lost race re-reads the
fresh head and re-applies the edit, bounded to a few attempts. Revisions
append content-addressed to `contacts-history`, the shape a local replica's
own writes take, and the tie-break `writerId` they carry is the visit's
in-memory one.
