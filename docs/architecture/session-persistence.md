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

**The login-time mender block.** The visit runs four of the login-time
registry passes as its own block after navigation, in registration order:
the stale-seal repair, the torn-retirement repair, the bare-passkey rebuild,
and the registry backfill, with the management-zcap refresh above as the
last registration (the ordering is under "Session & auth flow" in session-and-auth.md). Each rides
the visit's generation delegation and unwraps with the credential's standing
key, each failure is logged and reported, and the block is not awaited.
`session.registryReady` and `session.mends` settle together here, every
registration being registry-writing. In a CHAPI popup every one of them
declares itself off the route, so the block runs empty and both promises
settle at once. The user key sweep and the annex generation GC do not run
here. Nothing in the registry's write protocol turns on the session tier.

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
