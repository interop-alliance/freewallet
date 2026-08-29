# History

## 0.43.0 - TBD

### Changed

- ARCHITECTURE.md teaches the transient login and the credential-anchored
  establishment as the defaults. Session and auth flow, Session persistence,
  Account genesis, Recovery codes, CHAPI integration, and the Ceremony
  inventory each lead with them. The Glossary gains entries for the transient
  session and the credential-anchored account, and definitions no longer name
  a physical setting such as "public computer". Documentation only.
- A transient visit's readiness stage renews the unlock record's bridge
  delegation, through `@interop/wallet-core` 0.62.0's
  `ensureCredentialClientAnnexGeneration`: the same expiry-or-signer-rot
  predicate the sibling delegation uses, signed by the ladder VM, re-sealed
  into the record beside the sibling. A credential-anchored account's one
  log-write path used to lapse at its own one-year expiry, since no
  remembered login runs there to refresh it.
- The standing-delegation refresh, the generation-delegation heals, and the
  recovery health check report signer rot when the signing key has left
  `capabilityDelegation`, through `@interop/wallet-core` 0.61.0. The shared
  predicate matched the key anywhere in the account document, so a key kept
  under another relation and dropped from `capabilityDelegation` read as
  healthy while the server refused everything it signed.
- A signup provisions the account Space once instead of once per collection,
  through `@interop/wallet-core` 0.59.0 and `@interop/was-client` 0.45.0. The
  nine-collection fan-out each ensured the same Space through its own handle,
  so a fresh signup issued eighteen Space reads and nine racing Space
  Description writes where one read and one write do. Every login reached the
  same provisioning and inherits the fix.
- The credential-anchored establishment's stage timings measure the stages
  they name. Two marks previously covered nine stages between them, so both
  reported figures named one operation while measuring everything since the
  last mark. Every boundary is marked now: wallet-core reports the stages it
  runs through a new optional `onStage` notifier, and the three stages whose
  body is a closure this app supplies -- the KMS/did:web thunk, the
  pre-promotion registry write, the keystore promotion -- mark themselves.
  The mend entry point reports per arm the same way. Development-only
  telemetry; nothing about the ceremony changed.

## 0.42.0 - 2026-08-28

### Fixed

- App Connect and agent grants minted in a transient session now verify at
  the storage server. The per-visit annex verification method signs the grant
  delegation, and `@interop/wallet-core` 0.58.0 publishes that method under
  `capabilityDelegation` beside `capabilityInvocation`, so the delegation
  proof settles against the annex document. Before this, every request the
  grantee made under such a grant was refused, surfacing as a 404. The fix
  has effect only against a storage server that threads the webvh context on
  the WAS routes; against an older deployment the symptom is byte-identical
  to the bug.
- Revoking a connected app POSTs its recorded revocations in every case, as
  an agent row already did, in place of skipping them on the orphaned marker.
  A grant minted in a transient session derives as orphaned while its chain
  is still alive, so the skip reported success and left the capability
  working. The revocation outcome now also reports the collections the epoch
  rotation re-keyed, so an app whose only grant was withdrawn no longer reads
  as nothing revoked.

### Changed

- A whole-Space target is refused as unsatisfiable when the session's grants
  chain under a generation delegation. That delegation is scoped to the
  Space's items subtree and can parent no whole-Space grant, so the wallet
  would otherwise consent to and deliver a capability that verifies nowhere.
  The refusal has its own consent copy in `en` and `es`; individual
  collections are still grantable.
- The consent panel derives each grant's shown expiry from the clamped
  `expires` rather than from the configured TTL constants. Under a generation
  delegation a grant is clamped to its parent, which for the 365-day share
  row is essentially always shorter than the constant.

### Changed

- The session persistence seam is named for the storage tier each variant
  reaches. `durableSessionPersistence` is now `browserLocalSessionPersistence`
  and `transientSessionPersistence` is `inMemorySessionPersistence`, with the
  types, the `isBrowserLocalSession` predicate, the
  `assertBrowserLocalSession` refusal, and `BrowserLocalSessionRequiredError`
  following the axis. The discriminant is `persistence.storage`
  (`STORAGE_INDEXEDDB` / `STORAGE_IN_MEMORY`); the stored values are
  unchanged.
- `routeUnlockLogin` reports its decision as
  `{ login: 'remembered' | 'transient' }` in place of a `durability` member.
- `isRememberedSession({ persistence, isGuest })` replaces the three
  hand-written predicates in the login path: KMS keystore provisioning, the
  login-time roster read, and the client-seed stamp.
- Comments and JSDoc across `src/` now say `durable` only of server-backed
  storage. The browser-local, in-memory, remembered, transient, and enrolled
  uses take their own words, and the persistence object is the persistence
  strategy rather than a seam or a handle.
- The same triage runs over `tests/`, test titles included: a failing run no
  longer prints "durable client" or "durable session". The surviving
  `durable` uses in the suites all name server-backed state.
- `decisions/0010` is renamed to
  `0010-remembered-login-is-not-a-mender-trigger.md`, the axis its own rule
  is stated on. The record number is unchanged and every citation moved
  with it. AGENTS.md follows the same triage: a design's approval extracts
  its binding decisions, and the App Connect spec entry says action
  limitations.
- Comments that `decisions/0012-no-durable-continuity-pins.md` falsified are
  corrected as claims: none says a continuity pin survives a visit, that the
  two strategies differ in their pin members, or that a remembered browser
  gets stronger continuity than a transient one.
- The forget call sites follow wallet-core's renamed surface:
  `forgetEnrolledClient`, `forgetLastEnrolledClient`,
  `EnrolledClientForgetResult`, `LastEnrolledClientForgetResult`, and the
  name-stable `LastEnrolledClientForgetError` the Settings dialog routes the
  last-client transition on. Requires `@interop/wallet-core` 0.58.0.

### Changed

- Continuity is now checked within a session and not across sessions
  (`decisions/0012-no-durable-continuity-pins.md`). Both persistence
  strategies build the same in-memory pin stores the transient one already
  built, so a remembered browser and a public-terminal visit have identical
  continuity properties. A per-visit pin still catches a host serving
  inconsistent versions across one login's many log reads.
- Two bounds are now stated rather than defended. A host serving a valid
  prefix of the account log is not detected, and a rotation run against that
  view can re-wrap the fresh user key to a revoked client. A replayed unlock
  record is not detected, so a login can land in an account the user has
  moved off; it is visible on arrival and reversible by logging in again once
  the host serves the current record.
- `deleteUnlockLocalTrio` is now `deleteUnlockLocalState`, and deletes an
  unlock method's keyring cache and client-key record.

### Removed

- The four browser-local continuity pins in the `freewallet-session`
  database: the keyed chain-head store (the account log's and the roster
  log's slots), the user key roster-epoch pin, and the unlock record's
  freshness pin. `src/lib/sessionKey.ts` exports no pin function.
- `KeyringRecordRolledBackError` and its login-page copy. The other
  authenticity and continuity refusals still reach the login page's forget
  affordance.
- The `freshnessPinFloor` parameter threaded through signup, the
  credential-anchored genesis, and the unlock-secret bind, along with the
  stale-pin refusal it existed to prevent. A bind still advances its record
  stamp past the served record's stamp.
- The wipe enumeration's epoch-pin and log-pin stages with their now-dead
  targets, and the annex GC's pin-slot deletion. The Space-to-DID mapping
  stays: the pre-promotion heal login needs it to state an `expectedDid`.

### Changed

- The CHAPI popup no longer forces a remembered login. It runs the same
  post-KDF routing every login runs, with the Storage Access API handle as
  the client-key record probe's factory. A granted handle finds the
  first-party record, so a remembered browser logs in as that enrolled
  client. A denied handle finds none in the partitioned bucket and routes
  transient, as does every engine offering no unpartitioned-IndexedDB
  request at all.
- A transient popup session is replica-less by construction: no local
  replica is built, and provisioning and the login-time sweeps are skipped,
  so nothing provisions the popup's partitioned bucket.
- `remoteDirectStorage` is retired as the popup marker. The login entry
  points take a `popup` option instead, which gates only what the
  partitioning implies: remote-direct storage in the remembered arm, and
  the remembered arm's popup refusals (no self-enrollment, no
  pending-enrollment resume, and the login-time chain passes that already
  carried the guard).
- A remembered popup session on a WAS deployment no longer persists its
  descriptor and meta caches to localStorage. The Storage Access handle
  unpartitions IndexedDB and does not reach localStorage, so a persisted
  cache would be partitioned residue no top-level wipe can reach; the
  popup's pair is in-memory for the visit. A no-WAS popup keeps the
  persistent pair, which is the only record of its minted key epochs.
- A popup login that cannot compose a transient session now reports the
  shared per-reason refusal copy in place of a generic login failure. The
  popup's not-enrolled copy is reachable only on a no-WAS deployment now,
  and was trimmed accordingly.

### Removed

- The `remote-direct` transient-login refusal reason, along with its arm in
  the shared refusal-copy mapping.
- The non-production `__E2E_MINT_CLIENT_ANNEX_GENERATION__` seam, whose last
  caller went away when the remembered signup started minting the annex
  generation itself. A non-production waiter for the login-time pass chain
  (`__E2E_LOGIN_CHAIN_SETTLED__`) replaces the wait it had been providing
  incidentally, so an e2e fixture can let that chain finish instead of
  tearing its context down mid-pass.

### Changed

- The torn credential-anchored-signup heals moved out of the login paths
  into wallet-core's shared mend ceremony
  (`mendCredentialAnchoredAccount`): the transient composition and the
  remembered-signup resume now call one entry point whose arms converge
  every tear state (the establishment re-run, the record re-bind, the
  Space-promotion completion, the roster-and-epochs completion, the
  registry re-fire). The epoch mint policy now has one home in
  wallet-core.
- An establishment failure inside the login-time heal no longer escapes as
  a raw error: it rides the mend report and surfaces as the typed
  unpromoted-account refusal, with the failure as its cause. A
  transport-class failure still rethrows unchanged, so an offline start
  keeps its own copy.
- The remembered-signup resume now rethrows when the mend leaves the
  pointer naming no did:webvh, instead of continuing into a
  self-enrollment that would fail on it.
- A registry hook re-fired by the mend now carries the standing entry's
  management zcap forward instead of clearing it (the synthesized
  establishment context supplies none).
- The remembered-signup resume now supplies the read-first registry hook
  (a resume can record the passphrase entry the torn signup lost) and the
  local keyring-freshness-pin floor (a resume re-bind can no longer land
  behind this browser's own pin and be refused as a rollback).

### Added

- A new transient-login refusal for a user-key roster that carries no wrap
  for the logging-in credential (`no-user-key-wrap`), with its own copy in
  both locales; previously the state was folded into the absent-roster
  refusal, or escaped as a raw unwrap error.
- A new transient-login refusal for a roster mint the mend's preconditions
  refused (`roster-mint-refused`), with its own copy in both locales: a
  retry re-runs the same refusal, so the copy points at a connected
  wallet.
- The mend's partial collection fan-out is now logged with the collections
  it left behind.

- The seven contact operations (list, load, add, update, delete, add
  revision, list revisions) are now served remote-direct, reaching contacts
  from a transient session and the CHAPI popup. Head rows are read and
  written in place under compare-and-swap on the served ETag; revisions
  append content-addressed to `contacts-history`.
- The credential-anchored signup now seeds the two default contacts
  (the Interop Alliance Team, and a self-contact) through the same
  remote-direct path. Accounts created before this release keep no backfill.

## 0.41.0 - 2026-08-26

### Added

- A transient login now heals its client-annex generation on every visit:
  it mints a missing generation, renews an expiring or expired generation
  delegation, and re-mints a missing or misaimed sibling delegation, all
  signed by the credential's ladder. An account with enrolled durable
  clients (no ladder VM of this credential's) falls back to the existing
  record-sibling-plus-embedded-delegation path, and the transient login's
  refusals now stand only when that fallback path also fails.
- The App Connect / interaction-URL grant path renews a stale generation
  delegation in place before minting any grant, instead of refusing
  outright. The refusal now stands only when the account document does
  not anchor the credential's ladder VM or the renewal itself fails.
- Add the typed ceremony vocabulary: wallet-core's `CEREMONY_IDS` extended
  with the app-only ids, with a counterpart test keeping ARCHITECTURE.md's
  Ceremony inventory table and the id set equal.

### Changed

- The transient session's client-annex identity and generation
  delegation now ride the typed persistence handle instead of a
  separate `initSessionFromSeed` option, so a session's durability is
  declared exactly once.
- The transient session profile now carries the login credential's ladder
  seed and standing members, so mid-session ceremonies can sign as the
  ladder without a durable signer in hand.
- The credential-anchored establishment's stage sequence moved into
  wallet-core's shared orchestrator; `src/session/credentialAnchoredGenesis.ts`
  is now a thin binding supplying only the unlock-record codec, the
  roster store builder, the KMS/did:web thunk, and the registry-write hook.
- The add/change-method client-annex fold now runs through wallet-core's
  shared generation primitive, embedding the generation delegation before
  flipping the auxiliary Space's controller.

### Fixed

- The transient session's roster-epoch pin now refuses a served descriptor
  that omits the pinned epoch, matching the durable pin's refusal, so a
  host cannot roll a public-terminal visit back onto an older user-key
  generation. Both pin variants now decide through one shared predicate
  (`epochPinWriteAllowed`) instead of parallel comparisons.

## 0.40.0 - 2026-08-25

### Changed

- Every WAS signup (passphrase or passkey, remembered or not) now runs the
  credential-anchored establishment first, so the standing-layout unlock
  record is durably written before the account's Space exists. A
  remembered signup then runs the ordinary durable login, whose
  self-enrollment makes the browser a durable client; a torn remembered
  signup resumes at the next `rememberBrowser: true` login. Only a no-WAS
  deployment keeps the old plain durable signup.
- The credential-anchored establishment gained a KMS stage: when a KMS
  server is configured, it creates the keystore under the ladder VM's
  bare identity, mints the did:web keys, and promotes the keystore
  controller alongside the Space's. Best-effort with a timeout; a failed
  or hung stage leaves the account keystore-less.
- `addAccountPasskey` and `changeAccountPassphrase` are standing-or-fail:
  a failed standing establishment no longer leaves an unlock method
  silently plain. `changeAccountPassphrase` runs establish-first on a WAS
  account: the new passphrase's standing establishment is the ceremony's
  first write, and a failure fails the change with the old passphrase
  fully intact (record, Space, and standing configuration unchanged), so
  no plain record is ever written for the new passphrase and a retry of
  the same change converges.
- The durable recovery spend's outcome now reports `standing: 'established'
| 'pending'`, surfaced as a pending notice when the standing upgrade did
  not complete inline.
- The unlock-methods registry record's `userHandle` member is renamed
  `webAuthnUserId`.
- The `no-standing` transient-login refusal reason is removed; a record
  without a ladder seed is now an invariant violation rather than a
  user-facing refusal, since every WAS signup produces a standing record.

### Changed

- The durable recovery spend is persist-before-publish end to end: the
  required `onCommitted` seam fires between the reveal entry and the
  add-and-retire entry and durably writes the new passphrase's
  STANDING-layout unlock record, the local PENDING client-key record (the
  pending group now carrying the spent code's unwrap key and the
  replacement code's bytes beside the discriminator and built-on head),
  and the replacement code's record and bridge. Both entry builds run over
  the durable chain-head pin, and a hook-less wallet-core run is refused
  (`RecoverySpendSkewError`).
- The spend's registry mutation (spent entry out, replacement and
  new-passphrase entries in) moved from the post-login update into the
  ceremony tail, between the registry re-seal and the collection cascade.
  The new passphrase's standing establishment (its roster wrap, then its
  document commitment + rung-0 entry, before the mandatory rotation) runs
  in the same tail; the post-login half reduces to a best-effort registry
  backfill, and the spend resume backfills a torn establishment from
  durable state. A failed establishment writes the registry's passphrase
  entry BARE (no standing fields) rather than claiming a standing
  configuration the account does not back; the resume upgrades the entry
  once its backfill makes the establishment real. The record completion is confirm-gated: the "I saved this
  code" confirm fills the user key, clears the pending carrier, and only
  then writes the epoch pin, so the show-once replacement code stays
  re-displayable from the persisted bytes until confirmed saved (a failed
  confirm surfaces a retryable error instead of marking the code saved).
  The completion write is the one enrolling path: a userKey persist against a
  still-pending client-key record is dropped unless the same change clears
  the pending group.
- The pending-enrollment router's spend branches: a spend-written record
  whose client stands in the document completes through the new spend
  resume (`resumeRecoverySpend` -- the roster escrows re-derived from the
  persisted unwrap key at every kill point, the registry backfill, and the
  show-once prompt re-displayed on the login page until the confirm); a
  never-published spend record refuses toward `/recover` while the code is
  genuinely unspent, surfaces the transport state when the served log has
  not reached the record's built-on head, and is discarded when the code
  was spent elsewhere. The replacement code is minted once per
  ceremony: a re-run after a pre-entry tear reuses the persisted bytes, so
  the same replacement unlock Space address is written on every attempt.
- The bind gained the read-first collision refusal and the fetch-and-advance
  stamp: the recovery spend's pre-entry bind (and its pre-flight probe)
  refuses to overwrite an unlock record naming another account or a
  standing credential's record this ceremony cannot account for
  (`UnlockSpaceCollisionError`, surfaced under the new-passphrase field on
  `/recover`), and advances its `createdAt` past the served record's beside
  the local pin. The own-rewrite license requires the served stamp to be
  covered by the local freshness pin (a re-establishment from another
  browser is strictly newer and refuses); a served standing record whose
  credential inventory the verified account document does not publish is
  licensed as this ceremony's own inert residue -- the transient spend's
  only license (it holds no pin), and the durable spend's backstop for a
  tab death between its bind's remote record PUT and the local persists.
- The standing establishment's document entry (`publishUnlockKey`) reads
  the account log under the session's chain-head pin at all three call
  sites (the add/change-method establishment, the recovery-spend tail, and
  the spend resume's backfill), so a served prefix of the log is refused
  instead of getting a commitment entry built on it.
- The credential-anchored (default) signup now seeds the welcome credential
  and the two new-account history records, attributed to the account's
  did:webvh. The seeding runs off the signup's critical path: the visit
  lands on the dashboard immediately, which shows a "Generating welcome
  credentials..." indicator until the seed settles (best-effort and
  time-bounded -- a failed or timed-out seed is logged, never fails the
  signup, and leaves the empty state). A replica-less session now binds the
  remote collection map at storage-client construction, since the
  account-genesis ceremony already provisioned the Space.
- The dashboard shows a "No credentials yet." empty state when the
  credential list is empty, instead of an empty grid.

### Fixed

- A durable login no longer misreads a stale client-key record from a prior
  account (a reused passphrase whose old account is gone server-side) as a
  forgotten browser. The record's stamped `pointerDid` is now cross-checked
  against the unlock record's pointer before the forgotten-browser detector
  runs; a mismatch wipes the stale record's residue (the dead account's
  replica, caches, and pins, and the credential's local trio) and re-routes
  the login once as a not-remembered browser, instead of wiping the pointed
  account's state and throwing `BrowserForgottenError`.

### Removed

- The `VITE_SERVER_URL` and `VITE_DEPLOY_URL` environment variables. Both
  denoted the app's own public URL; CHAPI wallet registration now uses the
  page's own origin (registration is same-origin, and an unset
  `VITE_DEPLOY_URL` used to register the literal mediator URL
  `...?origin=undefined`), and the docs page fetches its markdown relative
  to the serving origin.

### Changed

- Self-enrollment at login is now persist-before-publish end to end: the
  required `onCommitted` seam writes a PENDING-shape client-key record
  (seeds, controller, `pointerDid`, and a `pending` group carrying the
  ceremony discriminator and built-on head) before the add entry publishes
  the client, and the completion fills the user key and clears `pending`
  before the epoch pin. A tab death after the add entry no longer strands
  a phantom client removable only through Disconnect.
- Login routing over the client-key record is three-way, keyed on `userKey`
  presence: a record holding a user key runs the detector and the ordinary
  login, a pending record (`userKey` absent) runs the new
  pending-enrollment resume (`src/session/pendingEnrollment.ts` --
  complete, seeded re-run, forgotten-browser wipe, or discard, decided
  from the verified log history with discard last), and a record-less
  browser self-enrolls as before. The pending arm is fail-closed with its
  own login copy; a served log behind the recorded head, or one the resume
  could not fetch, surfaces as the storage-unreachable state; a build-skew
  refusal (a stale wallet-core body that cannot state its persist hook
  fired) persists the key set first and gets its own copy.
- The forgotten-browser detector's trigger narrows to userKey-holding
  records; pending records are the resume's, whose published-then-removed
  branch hands the genuine removal back to the same wipe. The binds now
  record the account's `pointerDid` in the client-key record as the
  resume's record-to-account cross-check.
- Each transient-login refusal now gets its own login-page copy instead of
  the interim not-enrolled guidance: a failed heal says setup did not
  finish and a retry re-runs it; the annex-generation family states the
  refusal honestly and offers no remedy. No refusal names a second client
  as the way out: the connect-this-browser card no longer opens for any
  transient refusal, only for the durable path's own two-client states.
  `loginErrorKey` returns a typed outcome (the key plus the transient
  reason) so the page gates the card on it.
- The connect-this-browser card renders full-width above the passphrase
  and passkey cards, and its finish-connecting button sizes to its label
  instead of overflowing.
- Adding a passphrase from Settings no longer falls back to a plain pointer
  bind when the standing-credential establishment fails; the ceremony fails
  instead. A plain bind left a passphrase with no roster wrap and no
  self-enrollment authority, surfaced only by a fresh browser's refused
  login.
- Docs: the Glossary's Ceremony and Tear-mending entries name the
  derivability rule (canonical in wallet-core's
  `decisions/0010-post-pivot-derivability-rule.md`): every ceremony write
  sits before the pivot and stays inert until it lands, or after it and is
  re-derivable from the pivot entry plus durable state. New or changed
  ceremonies are checked against the rule per write at the design gate.

## 0.39.0 - 2026-08-24

### Added

- Adopted `@interop/logger` for structured, namespaced, leveled logging.
  Every `console.warn`/`console.error`/`console.log` call site in the app
  now goes through a namespaced logger (`fw:session:*`, `fw:storage:*`,
  `fw:sync:*`, `fw:chapi:*`, `fw:request:*`, `fw:ui:*`, and so on), and
  wallet-core's own logger is wired to the same sink at app bootstrap.
- Dev builds post log records as NDJSON to a dev-server endpoint, which
  writes them to a gitignored `.dev-logs/app.ndjson` (rotated to
  `app.prev.ndjson` on server start) and exposes a ring buffer at
  `window.__fwLog` (`snapshot`, `setFilter`, `clear`) for interactive
  filtering. Production builds make no request to the endpoint.
- The debug-level filter is read once, lazily, from the `interop:logger`
  localStorage key; nothing in the app writes that key.

### Changed

- Login now navigates to the dashboard as soon as storage provisioning is
  ready, instead of waiting on the full login-time registry pass chain (the
  user key sweep, the re-seal and torn-retirement repairs, the bare-passkey
  rebuild, the registry backfill, the standing-delegation and ladder-rung
  self-refreshes, the did:webvh pointer heal, and the generation-delegation
  self-heal). That chain now runs in the same order after navigation,
  tracked by a new `session.registryReady` promise that never rejects.
- Settings ceremonies that write the unlock-methods registry (passphrase
  change, passphrase/passkey add, rename, and remove, account deletion,
  client disconnect, the forget ceremony, recovery-code issuance and
  revocation) and the update-key rotation now await `session.registryReady`
  at entry, so they wait out the login-time passes instead of racing them.
  The Settings registry load and recovery-codes health check do the same.
- Measured effect at 100ms of per-request server latency: login-to-dashboard
  time drops from about 4.4s to about 3.4s.

### Changed

- Every unlock-methods registry write is now a compare-and-swap: the PUT
  carries `If-Match` on the ETag of the fresh read it was based on (or
  `If-None-Match` for the first materialization), and a lost race re-reads
  and re-applies the change on the fresh record, up to three attempts. This
  closes the seal-downgrade race (a stale tab's registry write can no longer
  undo another tab's rotation re-seal) and the lost-update window between
  two concurrent registry writers. The bare last-write-wins registry write
  is gone; all writers go through the shared read-modify-write wrapper.

### Added

- The interaction-URL request page shows the requester's self-declared name
  when the VPR carries one (the root `agent: { name }` member wallet-core
  0.53.0 classifies, sent by `di was request-grant --name`): "An agent
  calling itself ..." beside the grantee key, with copy marking the name as
  unverified. The name is recorded as `object.actor` on the Login activity
  for the Applications listing to show. A name outside the limits (trimmed,
  1 to 64 characters, no control characters) refuses the request as
  malformed before consent, as does any other classification failure on
  this entry point (previously a generic processing failure). en + es.
- The Applications page now lists and revokes standalone agent grants: the
  storage access answered from the interaction-URL request page, keyed by
  the grantee's did:key, titled by its self-declared name when it sent one
  or by its key fingerprint otherwise, and marked with an "Agent" chip. An
  agent row whose signing client has since been disconnected shows as
  orphaned, the same as an app row, but its revocation still POSTs every
  recorded capability's revocation (a transient session's grant chains
  under a live generation delegation). The Revoke activity is stamped no
  earlier than the grant's Login plus one millisecond, so clock skew cannot
  leave the row standing; there is no app key to delete and no collection
  epoch to rotate, since an agent is never an epoch recipient. A row's
  grants are the union of its Logins since the last Revoke, and it is
  dropped once every grant has expired. en + es.

### Fixed

- The login-time repair now also rebuilds a bare or absent passphrase
  registry entry from the login credential's own record, but only when the
  entry names no credential or names the login credential itself with no
  recorded update key. An entry naming another credential with no recorded
  update key is left alone, since rebuilding it could un-name a credential
  that is still standing. A passkey login runs the same rebuild for its own
  bare-but-present entry, restoring it from the account document's verbatim
  key-agreement key; an entry that was never written is not created, since
  that needs the WebAuthn credential id a login does not carry. Both are
  also the full migration for accounts an earlier defect left with bare
  entries; no separate migration step is needed.
- A passphrase change over a bare entry whose old credential still stands
  in the document (or whose document could not be read) no longer reports
  a clean run: it reports that the old passphrase was NOT retired. When
  the new credential's own standing setup ran, the change records the old
  credential's members on the new entry -- minting the registry first if
  none existed -- so the next passphrase login's repair can retire it.
  When that setup did not run, the entry instead names only the new
  credential, and the old one is left unnamed and still standing (en +
  es).
- The last-client transition now refuses up front, with the name-stable
  `UnrecordedCredentialForgetError` (en + es copy on the transition
  dialog), when the account document lists a sign-in credential the
  unlock-methods registry does not name -- every walk after the transition
  is registry-driven, and such a credential's bridge would otherwise rot
  un-re-minted.
- The last-client transition refuses up front on a pending-shaped passphrase
  registry entry -- one whose recorded unlock key-agreement key does not
  match the credential the record at its unlock Space is sealed to, the
  state a passphrase change torn before its retirement leaves. Only a
  durable enrolled login can finish that change, and the transition ends
  durable logins on the account forever, so it stops with the name-stable
  `PendingRetirementForgetError` before any write (en + es copy on the
  transition dialog). A record the check cannot read refuses the same way.
  With wallet-core's matching skip, the re-mint passes now leave such an
  entry alone instead of sealing the old credential a fresh bridge into the
  new credential's record, and the transition's own re-mint stage treats
  that skip as blocking -- so an entry the up-front check does not cover (a
  passkey or recovery-code entry) still withholds the removal entry.
- The Settings registry writes are read-first. `addAccountPasskey`,
  `addAccountPassphrase`, and `renameAccountPasskey` re-read the
  unlock-methods registry immediately before their PUT and merge the change
  into that fresh record, instead of writing a read-modify-write off the
  page-held record loaded at mount -- so an entry written since (another
  tab, another client, a login-time refresh) is no longer reverted. The
  passphrase add is an upsert (`upsertPassphraseUnlockMethod`), so two runs
  leave one passphrase entry rather than duplicates naming different
  credentials. The page-held record now seeds only the WebAuthn user handle
  and the exclude list of the passkey ceremony; a rename whose fresh read no
  longer lists the passkey writes nothing rather than re-adding a retired
  entry.
- Both signup registry writes are read-first. The credential-anchored
  signup's pre-promotion hook reads the unlock-methods registry
  (`getUnlockMethodsWithClient`) and upserts the passphrase entry into it,
  starting from an empty registry only on a true absent; a thrown read
  skips the write with a warning rather than failing the establishment or
  clobbering from an empty base (the transient login's heal branch re-runs
  the establishment end to end, and the re-fired hook used to re-mint the
  user handle and drop every other entry). The passkey signup's registry
  mint gets the same shape through the new `upsertPasskeyUnlockMethod`: an
  existing registry keeps its user handle and entries.
- A grant delegated from a transient session chains under the session's
  generation delegation (`profile.invocationCapability`) instead of the
  Space root, so the grantee receives a capability the server verifies
  (root, generation delegation, grantee); each such grant's `expires` is
  clamped to the parent's with wallet-core's `clampGrantExpires`. A
  generation delegation that is expired or inside the renewal window refuses
  the approval with the new `GenerationDelegationStaleError` rather than
  minting a silently short grant; the blocking renewal stage is a follow-up
  once the transient profile carries its ladder members. Durable sessions
  delegate from the root as before. The share delegation in
  `StorageManager.shareCollection` gets the same parent and clamp.
- The shared wipe enumeration (`snapshotWipeTargets`) now always includes
  the session's own login credential's unlock Space (`profile.unlockMethod`
  and `profile.standingUnlock`) beside the unlock-methods registry's
  entries. A registry read that failed (a transient server error) used to
  yield an empty list, so a forget or account deletion left this browser's
  client-key record, keyring cache, and freshness pin in place while
  reporting a clean wipe. The failed read is now passed as `registryUnread`
  and reported as the `unlock-methods-registry` stage on the wipe outcome.
- `forgetBrowserWalletData` and `executeLocalWipe` no longer require
  `indexedDB.databases()` to run their deletes: the session database and
  replica databases are removed by known name (replica prefixes recovered
  from localStorage traces when they are not), and what could not be
  discovered or confirmed is reported on a new `unverified` result array
  instead of read as a clean wipe. `hasForgettableBrowserData` returns true
  rather than "nothing to delete" when IndexedDB exists but cannot be
  enumerated, and `sessionDatabaseExists` (behind `hasClientKeyRecord` and
  the wipe's trio gate) falls back to a create-nothing versionless open
  when `databases()` is absent, so a login on such a browser routes
  correctly instead of throwing. The unverified outcome is surfaced on the
  login page's forget toast, on `ForgetOutcome.wipeUnverified` and
  `BrowserForgottenError.wipeUnverified`, and as account deletion's new
  `'deleted-unverified'` result with its own settings-page alert.
- A transient session now makes no unlock-methods registry call at all --
  `backfillPassphraseUnlockMethod` and `loadUnlockRegistry` return `null`
  immediately, before even a read, instead of issuing one the server was
  only ever going to refuse. The login backfill, the external-request
  page's post-login adoption, and the Settings passkeys load all gate on
  `isDurableSession`.

### Added

- An agent-grant e2e (`tests/e2e-was/agent-grant.spec.ts`): a fresh did:key
  agent, played by was-client, stores a zcap-only VPR (one
  `#public-collection` descriptor named `web`) on an ephemeral exchange,
  the interaction-URL request page is driven through approval from a live
  session and again from its own login in place, and the agent then invokes
  the returned zcap to PUT `index.html` as `text/html` and reads it back
  with an unauthenticated fetch.
- A request page for interaction URLs, `/external/request?url=<interaction
url>` (`src/pages/external/ExternalRequestPage.tsx`): a request arriving
  from outside the app (a CLI agent's `di was request-grant` link by deep
  link, or the same URL pasted into Add Credential or scanned from a
  terminal QR) is answered without a CHAPI popup. The page opens the
  exchange behind the URL with wallet-core's `openInteractionRequest`,
  classifies the VPR with the existing `classifyRequest`, renders the
  storage-access consent panel (the grantee DID as the requester, the
  `reason` strings, and the host the answer will be sent to), delegates
  through the existing grant engine, and POSTs the unsigned zcap-only
  presentation back through `composeAndDeliverResponse`. A live session is
  used directly; otherwise the page runs the ordinary login in place. The
  Login activity records the grant under the fixed origin marker
  `n/a (API request)`.
- The pure half of that entry point, `src/lib/walletRequest/externalRequest.ts`,
  carries the refusal matrix, each cell with its own copy: an invalid deep
  link; an exchange that is gone (a 404 on either fetch, worded as
  expired-or-wrong-link), unreachable, or answering with no readable VPR; a request with no capability query; a
  `DIDAuthentication` query in either spelling, a `domain`, or an
  `AppConnectQuery` (no attested origin exists here); a VPR-named
  presentation endpoint on another origin than the exchange (the consent
  panel names the resolved delivery host); and any grant class outside the
  allowlist -- only `#public-collection` and `#private-collection` targets
  (plain collection URLs resolving to those classes included) are granted
  from a link, so a share, a whole-Space read, or a protected-collection
  read is refused before consent. A failed exchange POST-back keeps the
  composed response on `WalletResponseFailure.response`, which the page
  offers for manual delivery (the activity is already recorded).
- `resolveWalletInput` returns a typed outcome (`{ kind: 'credentials' }`
  or `{ kind: 'interaction-url' }`) instead of a credential array, and the
  Add Credential box and the QR scanner route an interaction URL to the
  request page; a bare exchange URL still falls to the credential fetch and
  fails with the URL-fetch message (the CLI prints the `?iuv=1` form).
- `ZcapGrantsPanel` takes a `revokeNote` override, which the request page
  uses to state that a grant answered from a link cannot yet be revoked
  from the wallet and expires on its own.
- `loginErrorKey` moves out of `LoginPage` into `src/session/loginErrorKey.ts`,
  shared with the request page's in-page login.
- Decision record `decisions/0004-agents-are-grantees.md`: an agent is a
  zcap grantee holding its own did:key, never a wallet client.

- A local sign-in (passphrase, passkey, completing the connect-this-browser
  flow, or the login that ends a recovery) records a `wallet-activity` Login
  entry built by wallet-core's `addHistoryWalletLogin` ("Logged in to
  wallet."), through the new `StorageManager.addHistoryWalletLogin` wrapper
  and the shared `recordWalletLogin` helper (`src/session/walletLoginActivity.ts`).
  The write is best-effort and never blocks the login. The relying-party `addHistoryLogin` path is
  unchanged.

### Changed

- ARCHITECTURE.md defines the ceremony vocabulary: Glossary entries for
  Ceremony, Tear mending (the umbrella: re-run, sweep, repair), and Repair,
  plus a Ceremony inventory table listing every ceremony, its entry point,
  module, shared half, and mender. `finishPendingPassphraseRetirement` is
  renamed `repairTornPassphraseRetirement` to match, and prose "completer"
  becomes "repair" throughout.
- The `json-canonicalize` resolution override (pinning 2.0.0 around the broken
  2.0.1 publish) is lifted now that 3.0.0 ships intact. 2.0.0 stays in the
  lockfile only through `@interop/did-method-webvh` until its 5.5.1 publish.
- Bump @interop/vh-resource-log to ^0.4.0

### Added

- Both forget ceremonies run under the session's account-log chain-head
  pin: `forgetThisBrowser` passes `profile.persistence.logPins` and the
  account log's slot into wallet-core's `forgetDurableClient` and
  `forgetLastDurableClient`, so a host serving a truncated prefix of the log
  is refused before any roster append or log publish instead of having the
  removal (and install) entries published on top of it.
- The last-client forget transition re-seals every OTHER unlock method's
  record before the removal entry: the standing passphrase and passkey
  credentials' and the recovery codes' bridge delegations (and
  `delegatedClients` siblings) are re-signed by the ladder VM through
  wallet-core's `unlockMethods` reach, so they no longer rot with the client
  that signed them. A registry the transition cannot read refuses up front.
  The confirm copy no longer states the re-establish residue, and the
  last-client e2e walk issues a recovery code from the forgotten browser and
  recovers with it afterwards.
- Unlock and recovery record proofs are settled against wallet-core's
  `currentAccountRecordSigners` (the enrolled clients' signing keys plus the
  ladder VMs) instead of the enrolled-client set alone, so a ladder-VM-signed
  re-mint on a client-less account is accepted.
- The forget-this-browser dialog handles wallet-core's name-stable
  `RecordRemintFailedError` from the last-client transition: the removal entry
  was withheld because another sign-in method's record could not be re-sealed,
  so the dialog shows a retryable stop naming those methods (the browser stays
  connected; a re-click resumes) instead of the generic failure copy.

### Changed

- Public-copy retraction (`StorageManager.retractPublicCopy`, formerly
  private) can consult the remote `public-credentials` collection when one
  is configured (`consultRemote`, also on `deleteCredential`), deleting a
  present remote copy before the local row: the local replica cannot prove a
  remote copy's absence on a fresh enrollment or while replication sits in
  retry backoff, and a remote that cannot be reached refuses the delete. The
  login-time app-key sweep turns it on; the interactive delete keeps deciding
  on the local replica, so an offline delete of a credential with no local
  public copy still works. New `StorageManager.listPublicCredentials` unions the local
  and remote `public-credentials` rows (`BrowserStore.listPublicCredentials`
  and the remote-direct backend gained the same method).
- The login-time stranded app-key sweep also retracts orphaned public
  copies -- app keys kept as a public copy with no private row through the
  delete dialog's "keep public copy" choice. The affected app's grants are
  revoked first when the copy states a revocable identity. The sweep now
  returns `{ deleted, retracted }`.

- The generic resource-log names (`ResourceLogPinStore`, `ResourceLogHeadPin`,
  `memoryResourceLogPinStore`) are imported from `@interop/vh-resource-log`,
  now a direct dependency; `webvhResourceLogController` stays on
  `@interop/wallet-core/resourceLog`, and the bare-parts roster store's
  controller memo re-types against wallet-core's extended
  `WebvhResourceLogController`. `@interop/was-client` raised to 0.44.0 to
  match wallet-core's floor.
- Retired the "posture" terminology: the session axis is now durability (the
  durable and transient variants), a credential's durable entries in the
  account document, annex log, and ladder are its inventory, and named
  arrangements use qualified configuration phrases (the split configuration,
  the standing configuration). Glossary entries added; wallet-core's renamed
  inventory exports adopted.

### Fixed

- A standing unlock credential's management zcap keeps its PUT action across
  logins. The per-login mint (`buildFetchResult`) now delegates
  `GET/PUT/DELETE` for a record in the standing layout, matching the bind,
  instead of the `GET/DELETE` default; the registry's near-expiry refresh
  (`backfillPassphraseUnlockMethod`, passphrase and passkey entries alike)
  no longer narrows a stored capability that is not expiring, writes a
  strictly wider fresh one even before expiry (so an entry a past login
  narrowed heals at the next login), and on expiry writes the fresh one
  regardless, logging an error if it narrows (a dead capability would lose
  DELETE too). A passphrase change records the wide capability the standing
  establishment minted rather than the bind's narrow one. Without this the
  revocation cascade's record re-PUT (`remintRecoveryDelegations`) failed
  unauthorized once the refresh had run.
- Retiring the unlock credential a session logged in with no longer swaps
  the client annex generation onto that credential's own ladder.
  `rotateOffUnlockCredential` settles its ladder seeds against a fresh,
  pinned read of the pre-edit account log (the session memo is dropped
  first, since a login-time memo can predate a self-enrollment elsewhere)
  before the ceremony: with no retired seed in hand, the
  session's login seed is identified as the retired ladder when the entry's
  recorded update key is one of its rungs up to the attributed one (it then
  also feeds the document edit's attribution), stands in as the surviving
  seed only when it provably is not, and fills neither role when the log
  attributes it nothing or cannot be read. The tap-free removal of the login passkey now
  reports `{ action: 'skipped', reason: 'no-ladder-seed' }` instead of
  re-establishing the retired ladder's annex authority as `swapped`.
- App Connect no longer mints a second app key when the app-key scan could
  not read every row. `BrowserStore` and `RemoteDirectStore` (the popup's
  backend) now record what a `listAppKeys` scan skipped, and
  `StorageManager.listAppKeys` returns those counts beside the listing,
  captured from the same scan: rows whose key epoch is still unknown after
  the one descriptor refresh the facade spends per collection per session,
  rows in a known epoch this session holds no wrap for, and envelopes that
  will not decrypt at all. With no match and anything skipped,
  `processAppConnect` throws `AppKeysUnreadableError` (surfaced in the popup
  as the `appKeysUnreadable` block, set at consent-preview time), instead of
  minting a fresh seed and DID that would orphan whatever the app encrypted
  under its first identity. The undecryptable rows are purgeable from the
  Applications page; the other two kinds are never purged.
- Retiring a passphrase or a tap-confirmed passkey now removes the
  credential's ladder VM from the account document when one stands (the
  residue of a last-client forget torn after its install entry), so the
  retired seed no longer signs log appends or account delegations. Through
  wallet-core's `removeUnlockKey`; the seedless removals (management
  capability, the pending-retirement repair) leave it.
- A passphrase change whose retirement fails at its document edit can now be
  finished. The registry's passphrase entry is written after the retirement
  reports, so an edit that never landed leaves the entry naming the new
  unlock Space but the old credential's whole standing configuration, and the next
  passphrase login retires it (`finishPendingPassphraseRetirement`) and
  records its own standing configuration -- or, when that credential is already out of the
  document, records the standing configuration without re-running the retirement.
  Previously the entry named the new credential immediately, leaving the old
  one standing with nothing able to name it, and the Settings copy promised a
  resumption that could not happen.
- A passphrase change over an entry that still names an earlier passphrase is
  refused before anything is written (`PendingPassphraseRetirementError`,
  shown in Settings as "log out and log in again with your passphrase, then
  try again"). Running it would have removed one credential's document
  inventory while striking the other credential's ladder, leaving the second
  one standing and unnamed.
- The login-time delegation and ladder-rung refreshes no longer write onto a
  registry entry that records another credential's standing configuration: they match on the
  acting credential's key-agreement multibase beside the unlock Space id. A
  rung stamped next to a pending credential's key would have made the next
  completion run strike the current passphrase's ladder.
- The passphrase-change ceremony no longer strips its own standing configuration or
  misreads a failed registry read. A change whose new passphrase is the
  current one (the same derived credential) is refused up front
  (`SamePassphraseError`, rendered as its own Settings message): retiring it
  would strip the standing configuration just re-published, and skipping the retirement
  would orphan the old ladder's committed rung. An unlock-methods registry
  that cannot be read refuses the change before anything is written instead
  of overwriting the old entry's multibases and reporting the retirement as
  skipped.
- The self-enrollment completion now persists the freshly minted client key
  set into the local client-key record before writing the user key roster
  epoch pin, not after. A rejecting pin write (quota, a blocked IndexedDB
  upgrade) previously threw out of the login with the account document
  already listing the new client, but its seeds unpersisted -- a phantom
  client that a re-run would accrete another of and that
  `listAccountClients` still counted. The pin write is now best-effort: a
  failure is logged and the login proceeds, and the next login's roster read
  establishes the pin.
- The enrollment completion's unlock-record rebind (the connect-code
  ceremony's last step) re-states every standing member the fetched record
  carried, the `delegatedClients` sibling included. It previously forwarded
  only the bridge delegation and ladder seed, so the rewritten record lost the
  annex-Space sibling and the credential's public-terminal login refused from
  then on with `TransientLoginUnavailableError`.
- A credential-anchored establishment re-run over a roster an earlier run
  keyed no longer leaves a collection epoch'd under the throwaway candidate
  key. Wallet-core's ceremony now skips its epochs stage when the adopted
  roster's current epoch is not the key it was handed (reported as
  `epochsSkipped`), so the establishment's heal branch, which completes the
  epochs under the roster's real key, is the one installer.
- The transient login's empty-roster heal installs the collection epochs
  under the key the roster delivers after its ensure, not the candidate it
  minted, so two visits healing the same account concurrently can no longer
  key a collection to the losing tab's throwaway key.
- Transient recovery's mandatory rotation is now the first request after
  the add-and-retire entry. The per-visit transient client is enrolled into
  the fresh annex generation inside the persist-before-publish seam
  (controller-tier, before the auxiliary Space's controller flips) and the
  pre-rotation roster read is gone (the superseded epoch's user key is
  unwrapped from the rotated roster afterwards), so the window in which the
  typed code is dead and the new credential holds no wrap is the append
  alone. A tear inside it remains a stated residue. The transient-recovery
  e2e cell pins the write order under an aborted append.
- Transient recovery no longer strands the account when a flap follows the
  add-and-retire entry. The `#DelegatedClients` pointer now rides into that
  entry (the persist-before-publish seam names the fresh annex generation
  back to wallet-core's `recoverWebvhLadderAnchored`) instead of being
  written by a separate log entry afterwards, so the document can never name
  a generation the surviving record's sibling delegation cannot reach while
  the pre-recovery credential's ladder VM is already retired.
- The forget ceremony re-seals the unlock-methods registry to the rotated
  user key while this client still invokes; before, the registry stayed
  sealed to the retired key after a forget, so the surviving clients and
  transient logins could no longer read it.
- The login-time standing-delegation refresh now replaces the refreshed
  bridge and sibling on the live session's standing members, so a forget run
  later in the same session signs through the delegation that verifies.
- Retiring an unlock credential that had self-enrolled a browser no longer
  leaves its live ladder commitment standing in the account document (a
  latent re-seizure credential). The ceremony resolves the ladder's current
  inventory from the log (wallet-core's `attributeLadderInventory`) instead of
  trusting the registry's recorded bind-time rung, and the ceremonies that
  hold the credential's secret pass its ladder seed through to strengthen the
  attribution: a passphrase change captures the old record's seed before the
  old unlock Space is deleted, and the tapped-passkey removal reads it off
  the tapped credential's record (`standingLadderSeed`). The tap-free
  removal of a lost passkey relies on the seed-less log attribution.
- The credential-anchored establishment now refuses to continue when the
  genesis ceremony reports a failed roster or epochs stage, before the annex
  generation is minted and before the record re-bind. Previously such a
  failure was carried past silently: signup continued on a user key held
  only in the tab's memory, the unlock-methods registry was sealed under it,
  and every later registry read (recovery-code issuance, passkey add and
  remove, the standing upsert) failed forever. Refusing before the re-bind
  leaves the unlock record DID-less, so the next login routes into the
  establishment re-run and converges. The heal branch's own epoch fan-out
  result is checked the same way. A regression test covers a genesis whose
  roster stage failed.

### Added

- The last-client forget transition: forgetting the account's only connected
  browser runs wallet-core's `forgetLastDurableClient` instead of refusing,
  landing the account client-less and anchored by its sign-in credentials
  alone (the state a credential-anchored signup produces). Settings >
  Connected wallets confirms it against transition-stating copy (chosen from
  the listing; a stale listing's refusal flips the dialog to that copy for a
  second confirm). The ceremony's stages on this side: a ladder-VM-signed
  roster store over the post-install log for the rotation, the annex reach
  (generation log store and revocation POST under this client's authority)
  for the forced generation-delegation replacement and the revocation of
  every ladder-signed delegation the annex history embedded, and the login
  credential's record re-bind before the removal entry (bridge and sibling
  re-signed by the ladder VM through the keyring hit's re-bind closure, now
  stamped on the profile's standing members beside the unlock Space id, the
  registry pair refreshed). The wipe runs last. Other unlock methods' records
  (recovery codes included) may rot at the removal entry and are re-established
  from a logged-in session; the confirm copy says so.
- The forget affordance, in two grades over the shared wipe enumeration.
  From a live session, Settings > Connected wallets gains "Forget this
  browser" on the current client's row: wallet-core's `forgetDurableClient`
  ceremony (the user-key rotation off this client's wrap and the collection
  fan-out under its still-standing authority, then one atomic ladder-signed
  removal entry through the login credential's bridge), followed by the
  local wipe with the writer id cleared; the wipe runs last, so a torn run
  reads as "not forgotten" and a re-click resumes. From the login
  page, the keyring authenticity/replay and continuity refusals now offer
  "Forget wallet data on this browser" -- the no-unlock-material grade: a
  whole-database, browser-scoped wipe (every replica database, the session
  database, the per-account localStorage families), with the cross-account
  blast radius and the standing-document-client residue stated in the
  confirm dialog; nothing is signed or flagged. The affordance is reachable
  from passkey refusals without a typed passphrase, resets between login
  attempts, and says so when the browser holds nothing to delete.
- The login-time forgotten-browser detector: a durable login whose keyring
  hit still carries this browser's client keys, while the cleanly verified
  account document no longer lists its verification method (a forget torn
  before its wipe, or a disconnect run from another client), finishes the
  wipe from what the hit alone derives and surfaces "this browser's access
  was removed" instead of raw authorization errors. Nothing about the
  detection is persisted; it recomputes from durable state each login.
- The session profile carries the login credential's standing members
  (`profile.standingUnlock`: the bridge delegation, the annex sibling, and
  the credential-derived client identity) beside the existing ladder seed,
  so the forget ceremony signs through the bridge without re-prompting for
  the secret.
- The transient recovery variant is the `/recover` default on a
  non-remembered browser (wallet-core's `recoverWebvhLadderAnchored`): the
  add-and-retire entry publishes the fresh credential's ladder VM in place
  of a durable client, so the account lands client-less and ladder-anchored,
  with zero local residue. Inside the continuation's persist-before-publish
  seam, a fresh client-annex generation is minted under the new ladder (a
  recovery record carries no annex sibling, so the old generation falls
  to orphan discovery) and the new passphrase's and replacement code's
  records are durably written before the ladder VM publishes; after the
  entry, the `#DelegatedClients` pointer is re-pointed through the new
  credential's bridge (log-only), the mandatory user-key rotation runs as
  the one ladder-signed roster append the ceremony-tail license admits
  (`replaceUserKeyRosterRecipients`: retire, escrow, and fresh epoch in a
  single write), and the epoch cascade and unlock-methods registry update
  ride the generation delegation as the enrolled per-visit annex VM.
  The durable continuation stays reachable through the remember entry, and
  the recover page's locate step now pins the account log in memory unless
  the browser is being remembered. Both durability cells are pinned by e2e
  (`recovery.spec.ts` durable, `recovery-transient.spec.ts` transient).
- The bind ceremonies close the mid-generation annex lockout: making a
  credential standing (passkey add, passphrase add or change, the signup
  tail) appends one atomic hash-restating annex commit entry adding the
  new credential's rung-0 hash, signed by the login credential's committed
  rung (wallet-core's `commitClientAnnexRung`). Without it a freshly bound
  credential could not enter the transient session until the next
  generation swap. Best-effort: an acting rung the generation does not
  commit is the honest skip.
- The existing account ceremonies reach the client-annex artifacts. Client
  revocation gains a generation-delegation re-mint stage (wallet-core's
  `remintGenerationDelegation` closure): revoking the durable client that
  signed the current generation delegation replaces the delegation in place
  on the post-edit document, so the transient entry path survives the
  disconnect; the login credential's ladder seed rides the session in memory
  (`profile.ladderSeed`) to sign it, and the stage skips with a report when
  it is absent. The credential-rotation ceremony retires the retired
  credential's annex inventory beside its account-side one
  (`src/session/credentialRotation.ts`): a strike entry drops its revealed
  annex rung and standing hash when a distinct surviving credential's
  rung can sign it, and otherwise the generation is swapped onto a surviving
  credential's ladder (`swapClientAnnexGeneration`), the old one left to
  orphan discovery; a passphrase change signs with the new credential's
  seed. Login's bridge-refresh predicate widens from expiry-only to expiry
  or signer rot (the delegation's proof key gone from the account document),
  which is also the first durable self-enrollment's window close: the add
  entry removes the ladder VM, and the same login re-signs the bridge and
  the `delegatedClients` sibling and reseals the record; a durable login
  additionally self-heals a rotted embedded generation delegation
  (`ensureGenerationDelegationCurrent` with the account-document axis).

- Account deletion tears down every unlock method's server-side artifacts
  and the auxiliary annex Space. `deleteAccount` walks the
  unlock-methods registry before the account Space dies and deletes each
  entry's unlock Space and local trio best-effort
  (`deleteUnlockMethodArtifacts` in `src/session/unlockMethods.ts`), then
  deletes the auxiliary Space -- all before the fatal wipe, since resolving
  the auxiliary Space's controller reads the account log out of the account
  Space.

- The shared wipe enumeration (`src/session/wipe.ts`): one snapshot-first
  list of the durable local state an account leaves on a browser, with one
  best-effort executor, consumed by account deletion and the guest wipe
  (the forget affordance and the orphan-client heal land on the same seam).
  It covers every unlock method's local trio across the registry, the
  roster-epoch pin, the chain-head pin slots by Space-scoped prefix
  (annex generation slots included, via the new
  `deleteSessionKeysByPrefix` / `deleteLogPinsForSpace` primitives), the
  Space-to-DID mapping, the unlock-methods registry cache and the
  passkey-safety notice (keyed by this browser's client did:key), the
  replica databases by this client's prefix, and the per-account
  localStorage families (descriptor and meta caches under both scope
  schemes, migration markers) -- the cache and marker families had no
  deletion path at all before. Account deletion threads a popup-begun
  session's Storage Access factory through every local delete, and the
  global `writerId` is cleared only by the forget grade
  (`clearWriterId`). The honest limits are documented in ARCHITECTURE.md:
  forensic recoverability of deleted IndexedDB, the popup's partitioned
  buckets, and the mediator-origin registration bit stay out of reach.

- Replica wipes are cross-tab safe and verified. Wiping the local replica
  first broadcasts a teardown on a `BroadcastChannel`, so a sibling tab
  closes its open database handles instead of blocking the deletion
  forever, and the wipe re-probes `indexedDB.databases()` at the end,
  failing honestly when a prefixed database survived rather than reporting
  success on a deletion that is merely queued (`BrowserStore.wipeStorage`;
  `StorageManager` splits into `wipeRemoteStorage` / `wipeLocalStorage`).

- Credential-anchored signup. On a non-remembered browser with a WAS server
  configured, the passphrase signup mints no durable client: the account's
  genesis is anchored on the passphrase's ladder (wallet-core's
  `ensureCredentialAnchoredAccountGenesis`), the Space is bootstrapped and
  promoted under the ladder VM's did:key, the roster's epoch[0] wraps the
  user key to the credential's standing key-agreement key with a
  ladder-signed entry proof, the annex generation is minted and pointed
  at inside the same establishment (`establishCredentialAnchoredAccount` in
  `src/session/credentialAnchoredGenesis.ts`), and the visit ends in an
  ordinary transient session with zero local residue. The unlock record
  carrying the ladder seed is durably written before the Space exists and
  before rung 0 publishes; a torn signup converges on re-run by adopting the
  published log (rung-attributed as this credential's ladder). An explicit
  `rememberBrowser: true` (the e2e seam) and no-WAS deployments keep the
  durable signup; passkey signup stays durable. The transient login gains
  the matching heals: a ladder-seeded record with no did:webvh pointer
  re-runs the establishment, and a promoted account with no roster -- the
  genesis-to-epoch[0] tear -- mints a fresh user key and lands epoch[0]
  under the generation delegation (the carve-out from the sweeps-skipped
  rule). The signup durability cell is pinned by
  `tests/e2e-was/credential-anchored-signup.spec.ts` (residue-zero signup
  plus a cold-terminal re-entry on the passphrase alone).

- Client-annex GC. Keyring logins fire a best-effort background sweep
  (`session.clientAnnexGcSweep`, `src/session/clientAnnexGc.ts` over
  wallet-core's `runClientAnnexGc`): the quarterly generation swap when the
  pointed generation is quiet, and at every durable login the collection of
  every non-pointed `gen-` collection -- delegation revoked, a
  `GenerationCollect` digest written to `wallet-activity` before the delete,
  the collection deleted, the local annex pin slot dropped. Durable
  sessions only, resumable from durable state.

- The residue-zero e2e. A WAS e2e spec
  (`tests/e2e-was/transient-login.spec.ts`) runs the full default transient
  login through the real login form in a fresh browser context, stores a
  credential, and asserts zero storage residue after both a logout and a
  simulated crash (the page closed with no logout): no IndexedDB database
  (checked via CDP), no localStorage key gained over a before/after delta,
  and an empty sessionStorage. The assertions are a reusable helper
  (`tests/shared/storageResidue.ts`) shared by later transient-session
  specs. The account fixture drives a new non-production
  `window.__E2E_MINT_CLIENT_ANNEX_GENERATION__` seam over
  `establishClientAnnexGeneration` (`src/session/standingUnlock.ts`), which
  ensures a annex generation exists and is pointed at (created under
  this client's did:key and promoted to the account DID, with the
  credential-signed genesis from wallet-core's
  `mintCredentialClientAnnexGeneration` and the embedded generation
  delegation installed), then mints the annex-Space sibling delegation
  and re-seals it into the credential's unlock record, preserving the
  ladder seed.

- The transient login. On a browser holding no client-key record for the
  typed credential (and with a WAS server configured), login now defaults to
  a transient session that persists nothing locally: the unlock record is
  fetched transiently, a per-visit key enrolls into the account's annex
  generation through the record's sibling delegation, the session invokes as
  `<clientAnnexDid>#<vm>` under the embedded generation delegation on the
  replica-less remote-direct storage variant, and the user key comes from
  the credential's standing roster wrap (never escrowed to the transient
  client). A browser already holding the credential's client-key record
  proceeds durable as before (checked without creating the session
  database); `rememberBrowser: true` on the login functions is the
  programmatic durable entry (the standing self-enrollment), used by the
  signup probe, the recovery tail, and tests until the login form grows the
  choice, and `rememberBrowser: false` on a remembered browser refuses with
  `AlreadyRememberedError`. Transient sessions skip the KMS keystore, the
  login-time roster read, provisioning, and every login-time sweep;
  unavailable states (a record without standing authority or the
  `delegatedClients` sibling, an unpromoted account, no live annex
  generation or embedded delegation, no roster) refuse with a typed
  `TransientLoginUnavailableError` before any ceremony byte is written, and
  the login page maps the refusal onto the existing not-enrolled guidance
  for now.

- Capability-bound, replica-less remote storage. `WASRemoteStore` accepts an
  optional invocation capability (a delegated Space-subtree zcap) that every
  request it makes rides -- the navigational handles through one private
  Space-handle helper, the raw request sites directly -- threaded from the
  profile's `invocationCapability`; absent, behavior is unchanged (root
  invocations). In a transient session `StorageManager.initStorageClients`
  constructs no local `BrowserStore` at all (opening one durably creates the
  per-user database): the remote-direct backend serves every
  synced-collection operation, and the sync controller never starts for a
  session with no local replica.

- A transient unlock-record fetch (`fetchTransientKeyring`) beside
  `fetchKeyring`. Remote-only, it fetches the record, verifies the proof and
  the account-binding MAC, and settles a pending proof against the account
  log under a caller-supplied (in-memory) chain-head pin store, performing no
  durable operation: no keyring cache, no freshness pin, no client-key
  record, no management zcap. `settlePendingRecordProof` now takes its pin
  store as a parameter, with the durable session-database store staying the
  default for existing callers.

- The session durability seam. Every durability-sensitive local write
  (the chain-head and roster-epoch pins, the unlock-methods registry cache,
  the passkey-safety notice, the descriptor/meta cache pair, the `writerId`
  mint) now rides one typed `SessionPersistence` handle chosen at login and
  carried on the profile: the durable variant keeps today's behavior, the
  transient variant is in-memory throughout and never creates the session
  database. A transient session skips storage provisioning, the login-time
  sweeps, and the `userExists` probe; update-key rotation refuses there with
  a typed durable-session error, and the account-management ceremonies
  (passphrase and passkey changes, client revocation, enrollment approval,
  recovery-code issuance and revocation, account deletion, Space export and
  import) refuse with a typed step-up-required error. UI prefs (theme,
  language) get a sibling seam: while a transient session is live, pref
  writes land in an in-memory overlay instead of localStorage.

- Standing unlock credentials with self-enrolling login. Every passphrase and
  passkey bound on a promoted account now holds the recovery-code configuration
  minus spend-on-use: a user-key roster wrap escrowed into every epoch, a
  document `keyAgreement` entry (a hash commitment for a passphrase, the key
  verbatim for a passkey PRF output), a committed update-key ladder, and an
  unlock record carrying a bridge delegation and the ladder seed under a
  credential-authenticated binding MAC. A fresh browser holding the
  credential self-enrolls at login as an ordinary full client (two loud
  entries on the world-readable account log, then the first roster read
  through the credential's standing wrap) -- the not-enrolled dead end
  remains only for records without standing authority, where the
  connect-another-wallet ceremony still applies. The revocation cascade
  re-mints standing bridge delegations beside the recovery ones, a standing
  credential's own login refreshes its bridge inside the renewal window, and
  a self-enrolled login refreshes the registry's recorded ladder rung.
  Passphrase/passkey registry entries record the standing configuration
  (`rosterKid`, key multibases, delegation key id and expiry,
  `unlockClientDid`, unlock-KAK members). Existing accounts are not
  migrated in place: re-provision to adopt the standing configuration (the plain
  record keeps logging in via the connect ceremony).

- The unlock record's `delegatedClients` member and registry pair. A standing
  credential's unlock record can now carry a second sealed member beside the
  bridge: a pre-minted GET+PUT delegation over the auxiliary annex
  Space's items subtree, additive within record version 2 and absent on
  recovery codes. The bind ceremony mints it when the account document
  points at a annex generation (the auxiliary Space id is read off the
  delegated-clients service entry); the unlock-methods registry tracks its
  staleness as a second scalar pair (`delegatedClientsKeyId` /
  `delegatedClientsExpires`); and the delegation refreshes atomically beside
  the bridge -- in the revocation cascade's re-mint pass and in the standing
  credential's own login-time expiry refresh, each resealing both members
  with one registry rewrite.

- Unlock-credential rotation ceremony. Changing the passphrase and removing
  a passkey now retire the old credential for real instead of only
  rebinding the unlock record: its document inventory (keyAgreement entry and
  committed ladder-rung hash) leaves the account log, the user key rotates
  off its roster wrap, every encrypted collection re-epochs onto the fresh
  key, the unlock-methods registry is re-sealed, and the live session
  adopts the rotated key in place. The shared ceremony is wallet-core's
  `retireUnlockCredential`, wrapped by `src/session/credentialRotation.ts`;
  a torn run converges at the login-time completion sweep. Settings
  documents the ceremony as the remedy for a suspected passphrase leak,
  with honest copy about already-fetched ciphertext.

### Changed

- The ladder-seed comparison in the unlock-credential retirement uses
  `equalBytes` from `@noble/ciphers` (a direct dependency now) instead of a
  local early-exit byte loop.
- The transient-client subsystem formerly called the companion is renamed
  the client annex (`clientAnnex` symbols), across code and docs.
- Enrollment now refuses a connect code whose key-agreement key is not the
  canonical X25519 twin of its signing key, before anything is published.
  The refusal is surfaced on both approval surfaces: its own copy under the
  paste dialog's code field, and the generate-a-fresh-code state on the QR
  onboarding flow.
- The revocation cascade's roster appends now anchor at the post-edit
  document head through the shared orchestrator's controller floor, set from
  the document edit's own post-edit log, instead of relying on the session's
  verified-log memo being invalidated first. The roster store builders in
  `src/session/rosterStore.ts` declare the sealable store type so the
  contract cannot be stripped by a wrapper.
- A collection descriptor whose current epoch is missing from its own epoch
  list is now refused fail-closed during the user key cascade and reported
  per collection, instead of being evaluated against the last epoch.
- The recovery delegation's lifetime drops from ten years to one year
  (NIST SP 800-57 cryptoperiod guidance), with a 30-day renewal window.
  Registry entries record the delegation's expiry (`delegationExpires`,
  stamped at issuance and re-mint), and the login-time recovery health
  check flags an expired or expiring delegation the same way it flags rot
  (wallet-core 0.42.0's shared `zcapExpiring` predicate; the revocation
  cascade's re-mint refreshes such delegations automatically).
- The unlock-Space management zcap's lifetime (`UNLOCK_MANAGE_ZCAP_TTL_MS`)
  drops from ten years to one year under the same policy. Every passphrase
  or passkey login already mints a fresh delegation; the registry backfill
  now replaces a stored copy that is expired or inside the renewal window,
  for the passphrase entry and for a passkey login's own entry. A recovery
  code's management zcap cannot be re-delegated without the code and runs
  out on the same annual clock as its `did.jsonl` delegation, whose expiry
  nudge drives regeneration of both.

- The recovery-delegation builder and the revocation cascade's delegation
  re-mint core moved to `@interop/wallet-core/recovery`
  (`delegateLogWrite`, `delegationProofKeyId`, `remintRecoveryDelegations`);
  `src/session/recovery.ts` keeps only the session/config binding (storage
  URL, signers, management-zcap client, unlock-methods registry seams). The
  delegation TTL now comes from the shared `RECOVERY_DELEGATION_TTL_MS`;
  `RECOVERY_ZCAP_TTL_MS` is removed from `app.config.ts` (same ten-year
  value).

- Keyring and recovery records are now signed (record v2): an embedded
  `eddsa-jcs-2022` data-integrity proof by the unlock key, verified before
  decrypting, so the storage host can no longer forge a record it encrypted
  itself. Old unsigned records are refused as unusable; accounts are
  re-provisioned, not migrated.
- Account-pointer equality pinning is replaced by signed freshness pinning:
  the newest signed record timestamp seen is pinned per unlock credential,
  an older served record is refused as a rollback, and a newer validly
  signed record is followed wherever its pointer leads. A new account
  reusing a since-deleted account's passphrase now logs in cleanly on every
  machine.
- Recovery records verify under two signer classes: the code-derived unlock
  key at issuance (checked before decrypt), or an enrolled client's account
  key for revocation-cascade re-mints (checked after decrypt against the
  locally verified account document; recovery refuses an unverifiable
  record).
- A recovery record's account binding (`pointer`, `controller`) is MAC'd
  under a key derived from the code bytes at issuance and verified before
  the pointer is trusted, so a storage host can no longer redirect recovery
  into an attacker-controlled account by re-encrypting and re-signing a
  record of its own. The delegation re-mint preserves the binding verbatim
  (it reads the standing record through the management zcap), so a re-mint
  can never change the pointer; codes must be re-issued when the account
  moves hosts. A record whose tag does not verify, or that carries none, is
  refused as forged.
- The recovery record no longer carries the account email, and the recover
  page's locate step no longer shows one (a self-declared display string
  was exactly what a forged record could present as "this is your wallet");
  the post-recovery keyring record starts without an email. The signup
  email hint now describes the email as a settings label rather than a
  recovery aid.
- The two chain-head pins (account log, roster log) now live in one keyed
  pin store (`sessionLogPinStore`), with per-log slot keys derived by
  wallet-core from the Space id (`accountLogPinId` / `userKeyRosterPinId`,
  host-free so a claimed host move hits the held slot instead of a fresh
  trust-on-first-use slate). The user-key epoch pin stays keyed by the
  account DID. Standing pins under the old per-DID keys are not migrated;
  they re-establish at the next login.
- New login error states for a forged or tampered keyring record and for a
  rolled-back record, in both locales.
- Keyring-freshness pin writes are transactional and forward-only, and every
  record write site stamps its bind timestamp above both the record it
  replaces and the local pin. A client whose clock lags another's can no
  longer write a record every other client then refuses as a rollback.
- The account-genesis log read now carries a chain-head pin on every login,
  including the pre-promotion window: the Space-keyed slot serves the log
  from true first contact on (no bridging pin needed), and the locally
  recorded published DID supplies `expectedDid` on later heal logins whose
  pointer backfill never landed. A signup torn between log publication and
  the pointer backfill no longer heals against an unpinned log.
- The recovery locate step no longer reports an unreachable storage server
  or an account-log continuity refusal as a forged record: a network
  failure surfaces as "could not check", a continuity rollback (possibly
  replication lag) does too, and a fork or identity switch gets its own
  error message in both locales.
- `@interop/wallet-core` bumped to `^0.43.0` (with `@interop/was-client`
  `^0.39.1`). The recovery record codec is the shared unlock record codec
  now (`wrapUnlockRecord` / `unwrapUnlockRecord`; the delegation rides a
  sealed `bridge` member the re-mint replaces on its own), and already
  issued recovery codes are re-issued rather than migrated.
- A login no longer hard-fails when the served roster log sits behind this
  browser's chain-head pin (`rollback` -- possibly nothing worse than a
  lagging replica): the session degrades to the cached user key, nothing
  rolled back is adopted, and the pin never regresses. Forks and
  SCID/method switches still refuse the session.
- A roster read whose local persist fails (the client-key record write or
  the epoch-pin advance) no longer masquerades as an offline start: the
  session proceeds on the adopted key and the login page shows a "this
  browser could not be remembered" warning, in both locales.
- AGENTS.md and CONTRIBUTING.md gain pointers to the ecosystem-wide
  conventions: the shared learnings file and decision-record convention in
  the byoe-ecosystem and isomorphic-lib-template repos, and the
  contributor-tier note (PRs need tests plus a summary only).

### Fixed

- The self-enrollment log store's delegated `did.jsonl` PUT now maps a
  failed precondition (HTTP 412) to the conditional-publish conflict the
  ceremonies rebase on: the raw signed request applies no error mapping, so
  a lost compare-and-swap race previously surfaced as a bare HTTP error
  instead of re-running on the new head. Its log fetch is also built with
  the was-client paths helpers, so a sub-path deployment fetches the
  resource the bridge delegation's target names.
- The revocation cascade's recovery-delegation re-mint now actually
  re-wraps the unlock records: the record wrap path seals through an
  encrypt-only cipher built from the recipient's public half alone, where
  it previously needed a key-agreement secret the re-mint does not hold
  and silently skipped every entry. The wrap calls drop the now-dead key
  resolver argument.
- Every user-key rotation ceremony now re-seals the unlock-methods registry
  inside its roster tail, before the rotated key is persisted into the
  client-key record and before the collection fan-out runs
  (`adoptRotatedUserKeyInBand`). A tab death mid-ceremony no longer strands
  the registry sealed to a key no durable copy holds. The login-time
  convergence rotation gained the same duty; it previously skipped the
  re-seal outright. A failed re-seal leaves the session on the pre-rotation
  vault keys rather than moving it onto a key the stored record is not
  sealed to; the ceremony's post-run `adoptRotatedUserKey` retries the
  re-seal from those keys.
- A login-time repair mends a registry left sealed to a superseded user key
  generation: on a login whose roster read succeeded, a registry that fails
  to decrypt under the current vault keys is re-opened with a prior
  generation unwrapped from the roster escrow and re-sealed to the current
  key (`repairStaleUnlockRegistrySeal`).
- The login-time registry passes -- the re-seal repair, the torn-retirement
  repair, the backfill, the standing-delegation refresh, and the rung
  refresh -- now run in that order on one promise chain behind storage
  provisioning and the login's user key sweep, instead of the backfill
  firing separately from the login pages and the sweep's own re-seal racing
  them.
- Settings names a registry left sealed to a superseded key with its own
  copy instead of the generic "could not load" message
  (`UnlockRegistryStaleSealError`). en + es.

## 0.38.0 - 2026-08-14

### Changed

- Store app-key credentials in a dedicated `app-connections` collection
  (synced, encrypted) instead of `private-credentials`. App keys no longer
  appear on the credentials dashboard, credential detail, public links, or
  credential delete, and no "credential created" activity row is written for
  them. The new collection can never be shared or granted to an app or
  relying party, so a collection share can no longer expose an app's seed.
  Existing app-key rows in `private-credentials` are deleted by a login-time
  sweep rather than migrated; affected apps reconnect as a first run. The
  legacy pre-`appUrl` app-key re-issue path is removed.
- The login-time app-key sweep now retires a stranded app's live authority
  before deleting its row: the app's recorded storage grants are revoked and
  it is rotated out of its app-provisioned collections' key-epoch rosters
  (the same path revoking a connected app uses). A row whose revocation
  fails is left in place and retried at the next login instead of being
  deleted with its grants still live.
- Move the Applications and Storage links out of the Settings group in the
  left nav; they now sit at the top level beside Dashboard and Contacts.
- Rename the Storage page's display label to "Your Data" ("Tus datos" in
  Spanish). Routes and identifiers are unchanged.

## 0.37.0 - 2026-08-13

### Added

- Background sync now polls for remote changes on a timer (default every
  30 seconds, `VITE_WAS_SYNC_POLL_MS`; `0` disables), so rows another wallet
  pushes mid-session appear without a re-login. The timer skips ticks while
  offline and is torn down on logout.
- The Contact Detail page carries a back link to the Contacts list.
- The Contacts page carries a Sync button (matching the Dashboard's) that
  kicks an immediate replication cycle and reloads the contact list.

### Changed

- Merge the Settings "Enroll another wallet" and "Onboard another wallet"
  entry points into a single "Connect another wallet" button. It opens one
  card offering both paths at once: the QR onboarding invite (with its
  copyable link) and the paste-a-connect-code form. The paste form stays
  available when the invite fails or expires.
- Fix the Connected wallets action button labels overflowing the button
  bounds (the row now wraps and the buttons no longer flex-shrink below
  their label width).
- Label the first enrolled client "Freewallet" at signup, so a fresh
  account's Connected wallets panel no longer shows "Unnamed wallet".
- Move the sync status display from Settings to the Storage page: each
  synced collection's entry now carries its status chip (left of the
  storage usage column), and the standalone Settings "Sync" section is
  removed.
- Move the shared-collections management from Settings to the Storage page:
  a shared collection's entry now carries a "Shared" chip that opens a
  dialog listing its readers and removing their access, and the standalone
  Settings "Shared collections" section is removed.

### Fixed

- Updated to `@interop/wallet-core` 0.38.0, which stores wallet onboarding
  invitations on the ephemeral exchange in their VC-API shape (wrapped in
  `verifiablePresentationRequest`). Invitations minted before this were
  stored unwrapped, so the joining wallet could not recognize them and gave
  up without joining; only the corrected shape is supported.

## 0.36.0 - 2026-08-13

### Changed

- Update to `@interop/wallet-core@0.37.0` and consume its onboarding-invite
  transport: `createOnboardingExchange`, `pollOnboardingExchange`,
  `OnboardingExchangeGoneError`, and the poll/TTL constants now come from
  `@interop/wallet-core/enrollment`, and the local
  `src/lib/onboardingInvite.ts` copy (with its unit test, whose coverage
  lives in wallet-core's own suite) is removed. No behavior change.

- Update to `@interop/wallet-core@0.36.0` and consume its shared
  account-genesis ceremony (`@interop/wallet-core/genesis`). Signup's key
  mint is now `mintAccountKeySet`, `mintSpaceId` re-exports the shared mint,
  and login-time remote provisioning calls `ensureAccountGenesis` once for
  the Space provisioning, did:web key map, did:webvh genesis, user key roster,
  and collection key epochs. The keyring bind, the `userExists` probe, the
  pointer backfill, and controller promotion stay in freewallet's own flow
  (the ceremony is called with `promoteController: false`). Sessions with no
  did:webvh -- the flag off, no keystore agent, or no client update keys /
  user key -- keep the reduced path (Space provisioning, key epochs,
  did:web), and a failed Space provisioning stays fatal.

### Added

- Wallet-written envelopes now carry blinded `indexed` entries on collections
  with a declared index schema, matching Collection-handle writes -- so a
  credential the wallet stores is findable by an app's `find()` without a
  rewrite. Each encrypted collection's doc cipher installs the persisted
  index schema from the collection's stored `/meta` (via
  `@interop/was-client@0.36.0`'s `createEdvDocCipher` `meta` input /
  `applyMeta`), acquired keyless and cached beside the encryption
  descriptors, refetched on the unknown-epoch descriptor refresh, and applied
  to the lazily built app-collection ciphers too. A metadata value the cipher
  cannot decode degrades to a schema-less cipher (writes stay encrypted,
  without `indexed` entries) rather than failing the build.
- Encrypted collections are indexable from birth: provisioning now mints a
  blinded-index HMAC key alongside epoch[0] and installs it on the
  `encryption` descriptor, wrapped to each recipient's key-agreement key --
  the standard collections via `@interop/wallet-core@0.35.0`'s
  `ensureIndexedFirstEpoch`, and App Connect app-provisioned private
  collections through the same helper. `addRecipient` (app connect, shares)
  escrows the new recipient into the key; `removeRecipient` (app revocation,
  unshare) drops the leaver's wrap without rotating the key, since blinded
  tokens must compare across the collection's whole history. Collections
  provisioned before blind-index support are adopted as-is and stay
  unindexable. The resulting revocation asymmetry (a removed recipient keeps
  the blinding key) is documented in ARCHITECTURE.md.

### Changed

- Update to `@interop/was-client@0.36.0` and `@interop/storage-core@0.8.0`.

### Fixed

- Classify a `KeyUnwrapError` decrypt failure (the row's key epoch is on the
  collection's descriptor, but this wallet holds no key for it) on its own
  axis in `BrowserStore` and `RemoteDirectStore`, rather than as undecryptable
  garbage. Such rows are skipped and counted as `noEpochKeyCredentials`, never
  cached, and never removed by "Remove undecryptable" -- which in the
  remote-direct backend deletes from the WAS server. They also drive no
  descriptor refresh, since a refresh cannot grant a key.

## 0.34.0 - TBD

### Changed

- Lift the `#public-collection` grant action ceiling from add-only
  (`GET`/`HEAD`/`POST`) to the full WAS action vocabulary, matching the App
  Connect spec: published content is still the app's own data, and
  un-publishing or revising it is data management like any other write. The
  create-only rule (a public grant never converts an existing non-public
  collection) is unchanged.

### Fixed

- Match wallet-core's security refusals (`ResourceLogContinuityError`,
  `UserKeyRosterContinuityError`, `UserKeyRosterIntegrityError`,
  `UserKeyRosterUnwrapError`) on `err.name` rather than `instanceof`, at the
  login-page error classifier and the login-time did:webvh provisioning. Those
  errors are raised inside app-injected seams, so a linked or duplicated copy
  of `@interop/wallet-core` could otherwise make the check miss and show a
  generic setup-failure message instead of the specific refusal.

## 0.33.0 - TBD

### Changed

- Update to `@interop/wallet-core@0.33.0`: the did:webvh provisioning
  (`ensureDidWebvh`, at login) and the settings-page update-key rotation
  (`rotateWebvhUpdateKey`) now read `did.jsonl` under this browser's
  account-log chain-head pin and the expected account DID, so a truncated or
  substituted log is refused before an entry is built on it. Provisioning
  stays non-fatal, logging a non-`rollback` continuity refusal as an error.

## 0.32.0 - TBD

### Changed

- Update to `@interop/wallet-core@0.32.0`: the account's did:webvh log now
  carries a durable chain-head pin (`accountLogPinStore` in the session
  database, keyed by the data Space id beside the roster-log pin), so a
  served `did.jsonl` that is a rollback, a fork, or an SCID/method switch
  against the pinned head is refused rather than adopted. The pin rides the
  verified-log memo, the roster store's controller resolution, the recovery
  flows, and enrollment completion (first contact establishes it,
  trust-on-first-use); the login page renders the refusal. Ceremony-path
  `did.jsonl` reads (the revocation cascade, recovery-code issuance /
  revocation / continuation) now also check the resolved DID against the
  account pointer via `expectedDid`.
- Update to `@interop/wallet-core@0.31.0`: every did:webvh ceremony now
  publishes `did.jsonl` as a compare-and-swap on the read its entry was built
  on, so two clients extending the log concurrently can never silently erase
  each other's entries; a lost race re-runs the ceremony on the new head. The
  shared `wasWebvhIdStore` carries this with no app change; the recovery
  continuation's delegated log store now returns the log's ETag on read and
  forwards the `ifMatch` / `ifNoneMatch` preconditions on its delegated PUT.
- Loading a single contact is now a `findOne` point read (at most one
  decrypt) instead of decrypting every `contacts` row; a contact delete's
  pre-delete snapshot stops paying that full scan too.
- A contact's revision history is read through a new local-only `contactId`
  projection index over `contacts-history` (never replicated; the wire body
  stays an opaque EDV envelope, matching the mobile wallet's local design),
  so other contacts' revisions are skipped without decryption. The index is
  populated at write time and lazily backfilled on read, so each history row
  is decrypted at most once per browser.
- The Dashboard, Contacts, and History search boxes share one `SearchField`
  component and a page-neutral style constant.
- AGENTS.md cross-references the standing measures for cross-repo changes
  (blast-radius enumeration, the spec repos' parties-to-the-contract tables,
  the breaking-release doc audit, counterpart tests).
- Code-style sweep over the contact pages and `writerId.ts`: positional
  helpers moved to options objects, single-letter callback parameters
  renamed, and a module header added. No behavior change.
- The share row on the App Connect consent screen no longer hedges its
  coverage: a share escrows the reader into every existing key epoch, so it
  covers everything already stored, and the "items stored before this
  wallet's first share may not be included" sentence is dropped (en and es).

### Added

- Settings > Connected wallets gained an "Onboard another wallet" invite
  card: it creates an ephemeral exchange on the configured WAS server (the
  exchanger URL is derived from it; no new environment variable) with a
  `WalletOnboardingQuery` VPR as the stored request, renders the exchange's
  interaction URL (`.../protocols?iuv=1`) as a QR code and as copyable text,
  counts the invite down (~5 minutes, inside the server's exchange TTL), and
  polls the exchange (~3s, per-instance with an AbortController, cleaned up
  on cancel/unmount); expiry surfaces as "code expired -- generate a new
  one". The create/poll module lives in `src/lib/onboardingInvite.ts`
  (`@interop/wallet-core` 0.29.0, which carries the account pointer and
  controller in the query).
- When the other wallet responds, the invite card swaps to an onboarding
  consent panel ("Onboard this wallet?"): the enrollee's did:key fingerprint
  with the compare-with-the-other-screen instruction leading, a full-peer
  warning and the honest disconnect ceiling, and an editable label prefilled
  from the response envelope's suggestion. Approve drives the existing
  `approveEnrollment` + `setClientLabel` path; a malformed or invalid
  response envelope (bad connect code, oversize label) surfaces as
  "generate a new code and try again".
- New dependency `qrcode.react` for QR rendering (the wallet could only
  decode QR codes before).
- Contact history rows expand (one at a time) to a per-field snapshot view
  and a "Restore this version" action, which rewrites the contact with that
  snapshot through the ordinary update path and appends a `restore` revision
  -- the previously dead `restore` action gains its producer. Each row also
  shows a writer-attribution line (the first 8 characters of the revision's
  `writerId`), matching the mobile wallet.
- Contact revision history is now ordered by the logical `timestamp` each
  revision payload carries (`writerId` breaks ties), not local row insertion
  order, so a history replicated from another wallet reads chronologically
  on every replica.
- The contact delete confirmation names the contact being deleted.

## 0.31.0 - TBD

### Changed

- The `unlock-methods` registry is now a protected collection: a capability
  query naming it (as a `#private-collection` descriptor or a plain URL) is
  capped read-only instead of getting the full app-collection action
  vocabulary, is never treated as needing provisioning, and a
  `#public-collection` grant naming it is refused outright. App revocation
  likewise no longer treats it as app-provisioned.
- The protected-collection set, the app-revocation exclusion, and the storage
  browser's system grouping all derive from one list of the account's system
  collections (`SYSTEM_COLLECTIONS` in `src/app.config.ts`) rather than three
  local enumerations. That list is now wallet-core's shared Space layout:
  `unlock-methods` joins `WALLET_SPACE_SYSTEM_SPECS`
  (`@interop/wallet-core` 0.27.0), which `SYSTEM_COLLECTIONS` maps directly,
  so every wallet provisioning an account's Space agrees on it. The local
  `UNLOCK_METHODS_COLLECTION` / `UNLOCK_METHODS_RESOURCE` definitions are
  re-exported from `@interop/wallet-core/space` instead.

## 0.30.0 - TBD

### Changed

- App Connect Login activities record the connected app's `appUrl` alongside
  the display name and first-run flag (`@interop/wallet-core` 0.26.0).
- `listConnectedApps` joins app-key credentials to Login activities on
  `appUrl` when both carry one, so several apps on one origin get their own
  name, grants, and last-connected timestamp; activities written without an
  `appUrl` still join by origin.

## 0.29.0 - TBD

### Changed

- **BREAKING**: App Connect is now on the spec's `appUrl` model. An
  `AppConnectQuery`'s `app` block is `{ name, appUrl }` -- the
  `credentialType` / `vocabBase` pair is gone -- and the `appUrl` must be an
  absolute URL, carry no fragment, and be same-origin with the attested
  requesting origin (any violation is a malformed request). App-key
  credentials carry the fixed two-entry type array
  `["VerifiableCredential", "AppKeyCredential"]`, a static inline `@context`,
  and a `credentialSubject.appUrl` claim; matching is on that claim plus the
  origin, so the app identity is scoped to (user, origin, `appUrl`). No
  dual-read: old-shape requests are no longer recognized.
- A connect that finds no current-shape app key re-issues a legacy
  (pre-`appUrl`) key for the origin in place under the same seed, preserving
  the app's identity and its access to already-encrypted data; the superseded
  record is retired. Two distinct legacy identities on one origin are treated
  as a first run rather than guessed at.
- `src/lib/appKey.ts` is removed: the app-key constants, matching, minting,
  legacy re-issue, and store-time refusal policy now come from
  `@interop/wallet-core/request`, as does the `AppConnectQuery` validation
  that replaced the local `appConnectRequestOf`. `classifyRequest` now takes
  `{ request, origin }` -- the origin the `appUrl` is validated against.
- `ConnectedApp` entries carry the app key's `appUrl` when it has one.

## 0.28.0 - TBD

### Changed

- **BREAKING**: The user key wrap-set roster is now log-governed
  (`@interop/wallet-core` 0.24.0, `@interop/was-client` 0.32.1): the roster
  lives as the `key-map/user-key.jsonl` resource log, reads resolve only to
  the log's verified head (entry proofs checked against the locally verified
  did:webvh document, a durable chain-head pin -- new `userKeyLogPinStore` in
  the session database -- refusing rollbacks and forks), and writes are
  signed log appends. The new `src/session/rosterStore.ts` builders
  (`sessionRosterStore` / `accountRosterStore`) replace
  `WASRemoteStore.userKeyRosterStore()` and the retired point-state
  `key-map/user-key.json` resource; the retired detached epoch-configuration
  signature (`signEpochs` / `userKeyRosterEpochsSigner`) and the `epochsMac`
  MAC are gone with them (their tamper checks are subsumed by log
  verification). Roster provisioning now runs after did:webvh provisioning,
  since the log genesis anchors in the published account document, and the
  login-time roster read is gated on a promoted (did:webvh) account pointer.
- Renamed the two App Connect collection-descriptor type IRIs, following the
  spec: `https://w3id.org/byoe#collection` is now
  `https://w3id.org/byoe#private-collection`, and
  `https://w3id.org/byoe#shared-collection` is now
  `https://w3id.org/byoe#shared-wallet-collection` (the request-processing
  branches in `walletRequest/processZcaps.ts`, the consent panels, and the
  tests). No dual-read: old-IRI requests are no longer recognized.
- Renamed the key-epoch write header to `Key-Epoch`
  (`@interop/was-client` 0.32.0's `KEY_EPOCH_HEADER`); requires a WAS server
  release that reads the new spelling.

- The wallet now builds its own JSON-LD document loader (in
  `walletRequest/composeVP.ts`) and registers the BYOE App Connect context
  (`byoe-context@^0.3.0`, adds the `appUrl` term) on it directly, passing the
  loader into the shared VP compose path; update to
  `@interop/security-document-loader@10` (which no longer bundles that
  context).

- Wallet Space provisioning now runs through the shared one-shot
  `provisionWalletSpace` from `@interop/wallet-core/space`, and
  `WALLET_STANDARD_COLLECTIONS` is derived from the shared
  `WALLET_SPACE_SYNCED_SPECS` roster (collection ids, display names,
  encryption, public flags, id derivation) -- the RxDB collection key is the
  only app-local binding left. The `id` / `key-map` system-collection config
  and the epoch-refusal name-only retry moved into the shared provisioner, so
  a Space provisioned by either wallet app has an identical layout.
- Provisioning is now the shared two-step (`@interop/wallet-core` 0.22.0,
  `@interop/was-client` 0.29.1): after the container ensure, key epoch[0] is
  installed on every encrypted roster collection (`ensureWalletSpaceEpochs`),
  wrapped to the account's user key -- create-if-absent, adopting whatever an
  earlier provisioner landed, and run before login completes so no encrypted
  collection's first content push precedes its descriptor. Every encrypted
  collection carries its key epochs from birth.
- The init-vs-add forks in `shareCollection` and `provisionAppCollection`
  collapse to always-`addRecipient`: first-epoch minting runs only at
  provisioning (`ensureFirstEpoch` for an app-provisioned collection, the
  wallet-Space epoch install for the standard set), a share escrows the
  reader into the existing epochs, and an epoch-less descriptor is refused
  fail-closed rather than seeded lazily.
- Encrypted-collection ciphers are fail-closed: a collection whose descriptor
  is missing or epoch-less gets a refusing cipher rather than none, so a read
  or write errors instead of falling through to the cipher-less plaintext
  path -- nothing can silently store or push plaintext into an encrypted
  collection.
- The locally stored records that sealed directly to a key-agreement key --
  the client-key record and the unlock-methods registry -- now seal under a
  record-own key epoch, stored as `{ version, encryption, wrapped }`: the
  same self-contained frame the keyring record uses, built from the same
  construction (`mintRecordEncryption` / `recordCipher` / `parseRecordFrame`,
  exported by `@interop/wallet-core/keyring` 0.22.1;
  `session/recordEnvelope.ts` adds only the frame stamp and the cipher
  rebuild, with the frame validation imported rather than re-derived).
  Records in the retired
  direct-to-KAK form are refused as unusable (greenfield: re-provision /
  re-enroll), matching wallet-core's keyring-record reset.
- A session with no remote store (a guest, or no WAS server configured) mints
  its encrypted collections' descriptors locally: a one-epoch descriptor per
  collection wrapped to the session's vault KAK alone, persisted in the
  localStorage descriptor cache scoped by the user's DID (guests are minted
  fresh, never persisted) -- so the epoch-from-birth model holds without a
  server instead of every local read/write hitting the refusing cipher.
- The did:web provisioning no longer mints a KMS-held assertion key
  (`@interop/wallet-core` 0.23.0: the account document's `assertionMethod`
  relation lists client keys only, since membership there authorizes appends
  to co-managed resource logs). `keys.json` carries no `assertionMethod`
  member at all (greenfield: accounts are re-provisioned), and a served map
  that does carry one is ignored rather than republished -- a tampered
  `keys.json` can no longer reintroduce a server-held key into the
  document's `assertionMethod` relation.
- Adopted the `@interop/was-client` 0.29.x sync-port contract: an absent or
  tombstoned resource surfaces as `get` resolving `null`, simplifying the
  push-conflict assembly and the
  delete-retry path. The rotation-only user-key cascade means the login
  sweep refreshes ciphers only on a `rotated` outcome (the `installed`
  outcome is gone -- provisioning, not the cascade, installs epochs).

### Fixed

- A fresh signup now refreshes its encrypted-collection descriptors and
  rebuilds the session ciphers once epoch[0] is installed: the ciphers were
  built before the Space existed, so under the fail-closed rule every
  encrypted read/write refused until the next login. An ordinary login (whose
  descriptors were fetched at session init) adds no requests.

### Security

- Externally arriving app-key credentials are refused at store time
  unconditionally: any credential carrying the `AppKeyCredential` marker is
  refused at every ingest door (CHAPI store popup, URL / QR / manual-paste
  import), whether or not its subject DID binds to its own seed -- a fully
  attacker-generated credential binds, so binding proves nothing about
  provenance. Only the wallet's own App Connect mint path stores one, through
  its own `StorageManager.addMintedAppKey` door. App-key matching also drops
  candidates whose `issuanceDate` is missing, unparseable, or more than a day
  in the future (fail-closed), so a planted credential cannot durably win the
  latest-first ranking. Batch imports that contain app keys (e.g. a wallet
  archive) skip them and store the rest, reporting the skipped count.
- A `https://w3id.org/byoe#public-collection` grant can no longer convert an
  existing collection to world-readable: grant resolution now consults the
  Space's existing collections, refuses a public grant naming an existing
  non-public collection as unsatisfiable, and no longer re-applies the
  `PublicCanRead` policy when re-granting an already-public collection. Any
  target naming an already-public collection is capped to the add-only
  public-collection ceiling (`GET`/`HEAD`/`POST`) whether it arrives as a
  descriptor or a plain URL string, and is never re-provisioned. Both rules
  hold within a single request: delegation tracks the collections the request
  itself provisions, so duplicate names in one consent approval cannot
  convert or escalate.
- App Connect capability queries are rebuilt from an allowlist of the
  declared fields at classification time, so undeclared wire-level fields (a
  smuggled per-grant `reason`, an attacker-chosen `controller`) never reach
  the consent screen or the delegation path (the type-level omission alone
  did not bind actual request bodies). The consent screen also no longer
  hides the recipient-identity row: on first run the mint marking stands
  alone, and the returning-visit copy states custody ("stored in your
  wallet"), not provenance, which the app-key match cannot prove.
- Requester-supplied free text on the consent screen -- per-grant `reason`
  lines, the generic request's top-level reason, and the app-manifest
  description -- now renders under an explicit "The site says:" attribution
  label, italicized, line-clamped, and textually truncated (a CSS-only clamp
  would leave the full text for a screen reader to read out ahead of the
  trusted rows). A non-string wire `reason` renders nothing instead of
  crashing the consent popup, and the requester-supplied app name is bounded
  before it is interpolated into the consent copy.
- An App Connect approval delegates to exactly the app-key DID the consent
  screen displayed: the approve-time re-match fails closed when the matched
  credential changed between preview and approval.
- A capability request that names no `controller` resolves unsatisfiable
  ("cannot fulfill") instead of rendering a recipient-less consent row and
  delegating to nobody.

### Changed

- A Space provisioned by this wallet is now named "Wallet Space" instead of
  "Freewallet Space". Both wallets now use the same app-neutral name, so a
  shared Space keeps one name no matter which wallet provisions it.

## 0.27.0 - 2026-08-06

### Changed

- The local writer-attribution id is now spelled `writerId` end to end,
  matching the `@interop/social-core` 0.8.0 wire rename: `src/lib/deviceId.ts`
  is `src/lib/writerId.ts` (`getOrCreateWriterId`, `localStorage` key
  `freewallet:writerId`), and the store/manager parameters follow. Greenfield
  rename: the old `freewallet:deviceId` key is not carried over, so a fresh id
  is minted on first write.
- The "PUK" abbreviation is retired: the concept is unchanged (the
  account-wide key that is recipient zero of every encrypted collection,
  delivered through the wrap-set roster), but identifiers are now `userKey` /
  `UserKey` / `USER_KEY` and prose says "user key". `Session.pukSweep` is
  `Session.userKeySweep` and `profile.puk` is `profile.userKey`.
  User-facing copy is unchanged.
- Upgraded `@interop/wallet-core` (0.18.0), whose matching rename moves the
  roster resource to `key-map/user-key.json` and the client-key record's key
  member to `userKey`. No read fallback onto the former names: accounts
  provisioned before the rename must be re-provisioned.
- The local roster-epoch pin moved from the `puk-epoch/<spaceId>` key to
  `user-key-epoch/<spaceId>`. No carry-over from the former key: a
  pre-rename profile re-establishes its pin on the next roster read.
- Updated dependencies to latest (MUI 9.3.1, React 19.2.8, Vite 8.2.1,
  RxDB 17.4.0, and others). TypeScript moves to 6.0.3, the last
  JS-compiler line; the 7.x native compiler is deferred until its stable
  API lands (7.1) and typescript-eslint supports it.

## 0.26.1 - 2026-08-06

### Added

- Add search bar and tabs to History page.

## 0.26.0 - 2026-08-06

### Changed

- Upgraded `@interop/wallet-core` (0.17.1), `@interop/was-client` (0.27.0),
  `@interop/storage-core` (0.3.13), and `@interop/social-core` (0.8.0): the
  PUK roster's epoch configuration is now signed by an enrolled client and
  verified at login against the locally verified did:webvh document -- a
  fabricated, spliced, or unsigned epoch configuration is refused instead of
  adopted. Every roster write (provisioning, the login read, client and
  recovery-code revocation, recovery) signs its epoch configuration with the
  client's enrolled signing key, and the login roster read requires an
  account pointer naming the account DID. The enrolled-client ceremonies'
  shared preconditions now include the session's signing key.
- Contact head and revision payloads carry `writerId` (renamed from
  `deviceId`, following the shared contact-payload types).
- Upgraded `@interop/verifier-core` to 3.5.3.

## 0.25.0 - 2026-08-04

### Changed

- **Deleting a credential now retracts its public copy first.** The
  world-readable copy is retracted before the private credential is removed
  (matching the mobile wallet's order): once the private credential is gone
  there is nothing left to retract the public copy with, so the old order
  could leave a credential the user believes is deleted still readable at its
  public link. Retraction of a live public copy is blocking, not best-effort
  -- a public copy that cannot be retracted (offline while a remote server is
  configured, say) refuses the delete with a clear message instead of stranding
  an orphan, and the delete can be retried once it can land. A credential with
  no public copy still deletes normally offline, and the delete dialog's
  deliberate "keep the public link" choice is unchanged.
- **Ceremony orchestration moved out of the React components.** The ordered
  sequences the pages drive -- the two signup provisioning paths, the Settings
  ceremonies (passphrase change and bind, passkey add / rename / remove, the
  did:webvh update-key rotation, and account deletion's verify-wipe-retire
  phase order), the post-recovery registry updates, the connected-app and
  shared-collection listings and revocations, and the CHAPI `get` approval
  sequence -- now live in `src/session/` and `src/lib/walletRequest/`, with
  each function's JSDoc stating the ordering it must keep. Behavior is
  unchanged; the components keep rendering, form state, and confirmation
  callbacks only, and the orderings are now testable without a DOM (new unit
  tests cover the account-deletion phases and the
  persist-before-deliver rule).
- The account's key log is fetched and fully verified once per session
  instead of once per screen that reads it. Signing in and opening Settings
  used to re-verify it three or four times over, and renaming a connected
  wallet re-verified the whole log again; the result is now reused for the
  session and re-read after any ceremony that changes it (connecting or
  disconnecting a wallet, issuing or revoking a recovery code, rotating this
  browser's update key).
- Finishing "connect this browser" is faster: the ceremony derived the
  passphrase's unlock key three times over (looking the account up, saving the
  key set, and logging in). It now derives it once and ends in the logged-in
  session directly, removing two of the deliberately slow key derivations from
  the flow.
- Unified the two CORS-proxy paths into a single module and a single config
  key: `corsProxyFetch` and `fetchFromURL` both build their proxied URL
  through one helper over `VITE_CORS_PROXY_URL`, so the known-registries fetch
  and the pasted-credential-URL fetch are configured the same way.
- **Code the two wallets had grown separate copies of now lives once, in the
  shared packages, and freewallet consumes it.** Divergence in any of these
  was a correctness risk rather than a tidiness one -- both wallets read and
  write the same account, so a rule one implements differently is a rule that
  breaks the other's data:
  - The **client-key record** contents codec and its strict validation (the
    client seed, the cached per-user key, this client's did:webvh update-key
    seeds, the account controller) come from `@interop/wallet-core/keys`.
    Freewallet keeps its own unlock-layer wrap and IndexedDB storage around
    them; the stored bytes are unchanged.
  - The **enrolled-client listing** and the **disconnect-eligibility policy**
    (self-disconnect refused, the last connected wallet refused, disconnect
    disabled on an ambiguous update-key attribution, a partial collection
    fan-out reported as the resumable success it is) come from
    `@interop/wallet-core/clients`. `src/session/clients.ts` is now a
    session-shaped adapter, and the Settings panel consumes the policy
    instead of re-deriving it as UI state.
  - The **revocation cascade** and the **login-time roster policy** are the
    shared orchestrators; freewallet supplies the stages only it knows (the
    collections source, the recovery-delegation re-mint, and the adoption
    side effects: epoch pin, client-key record, live vault keys and storage
    ciphers).
  - The **contacts conflict rule**, the **contact display helpers** (initials,
    secondary line, list order), the headless **contact form assembly**, and
    the generic **self-contact seed** come from `@interop/wallet-core/sync`
    and `@interop/social-core`, so a contact edited on either wallet
    serializes identically. The product's own seed contact stays in
    `src/fixtures/defaultContacts.ts`: the shared package is team-neutral, and
    the two wallets deliberately hold those display-name strings separately
    but byte-for-byte identically, since the pull path matches a pulled seed
    on its exact name.
  - The `did:key`-to-X25519 **recipient derivation** behind a share comes from
    `@interop/was-client/edv`.
- **Free-form input is classified before it is resolved.** The Add Credential
  paste box and the QR scanner now run text through the shared wallet-input
  classifier instead of assuming everything is a credential or a URL, so a
  pasted wallet connect code is recognized and pointed at Settings >
  Connected wallets rather than failing as malformed credential JSON.
- Freewallet's two conflicting initials implementations collapsed to the one
  shared rule (first + last name token); the unused first-two-tokens variant
  is deleted.
- Disconnecting a wallet client from an account that has no key roster yet
  now reports a completed cascade with nothing rotated instead of failing.
  The account-log edit lands first and is what disconnects the client, so
  there was never anything left to fail on -- an account whose collections
  are not encrypted simply has no roster to rotate.
- A contacts conflict between a valid local edit and a malformed remote copy
  now keeps the local edit (which then repairs the server copy), where the
  remote copy previously won and the local edit was lost. Validation of both
  sides is also stricter: a payload is checked in full rather than by two of
  its fields.
- The contact history now lists the DIDs each revision's snapshot carried,
  under the display name, so an edit that only added or removed a DID reads as
  a distinct revision instead of as a repeat of the one before it.

### Fixed

- A recovery code whose entry records no signing key for its stored
  authorization now gets the "regenerate this code" nudge. The login-time
  health check treated such an entry as fine while the client-disconnect
  cascade already treated the same entry as needing re-minting, so a code
  that could not be checked was silently reported healthy; both now ask one
  shared question about the account's current keys.

- Settings no longer offers "Disconnect" on a session that cannot complete it.
  The button was enabled whenever the account was promoted and a storage
  server was configured, so a browser whose stored key set predates the
  per-client update keys could start the disconnect and only then fail; the
  panel now enables it exactly when the ceremony's own preconditions are met.
- A contact's DID rows are now validated before the contact is saved: a row
  that is not a DID blocks the save and is flagged inline, instead of being
  stored and synced as an entry that every view then filters out -- leaving no
  way to see or correct it. Blank rows are still dropped, as before.
- Replicated deletes were being refused by the server with `412` whenever the
  local row's revision lagged the resource's ETag (a locally created row is
  pushed with the revision it was inserted with, while the server assigns its
  own), leaving deleted resources -- including retracted public credentials --
  live on the remote server. A refused delete whose remote body is unchanged is
  now re-issued against the current ETag.
- The issuer-registry loader no longer poisons its module cache: a failed
  registries fetch used to serve the local fallback list for the rest of the
  session. The fallback client is not cached and the rejected load is evicted,
  so the next lookup retries.

## 0.24.0 - 2026-08-03

### Changed

- The UI language is auto-detected from the browser locale on first visit;
  an explicit choice in the language selector is persisted and wins on later
  visits.
- Timestamp formatting (`formatDate` / `formatDateTime`) is locale-aware:
  dates render in the active UI language instead of a fixed locale.
- **Contacts rows are now keyed by the cipher-minted EDV id.** The encrypted
  collections' ciphers are built with each collection spec's `idDerivation`
  (`'random'` for the mutable `contacts` head, `'content'` for the
  content-addressed collections) instead of all defaulting to `'content'`,
  and `addContact` adopts the cipher-minted random EDV id as the row id --
  so the server resource id a new contact replicates under is a spec-format
  EDV id, like every other replica's, instead of an app-minted uuidv7.
  Fixes the cross-replica defect where the mobile wallet could not in-place
  edit a web-authored contact (its client rejected the uuid resource id on
  the update path). Existing uuid-keyed rows are untouched and stay fully
  editable everywhere -- `@interop/was-client` >= 0.25.0 accepts a
  pre-existing resource id verbatim on updates -- so no migration runs.
- `updateContact` re-encrypts through the cipher's in-place update path
  (`encryptUpdate`) when the stored head is an envelope: the rewritten
  envelope stays bound to the row's real resource id and its EDV `sequence`
  advances from the prior envelope instead of resetting to 0 on every save.
  (A plaintext prior row keeps the fresh-encrypt fallback.)
- The cross-replica conformance exercise's pinned-defect test now exercises
  the full edit round trip, plus a legacy-row test proving uuid-keyed,
  sequence-0 contacts authored by the pre-fix write path remain readable and
  editable from both replicas.

## 0.23.0 - 2026-08-03

### Added

- **Cross-replica sync conformance exercise** (`tests/conformance/`,
  `pnpm run test:conformance`): drives both wallets' replication engines --
  this wallet's RxDB adapter and the mobile wallet's
  `@interop/wallet-core/sync` `SyncEngine` -- against a real in-process
  `was-teaching-server` on one shared Space, round-tripping create / edit /
  delete both ways across all three collection models, including LWW
  edit-collision convergence. Needs the sibling `was-teaching-server`
  checkout built (`WAS_SERVER_DIR` overrides). Findings are the
  compatibility contract in
  `wallet-core/docs/cross-replica-sync-compatibility.md`; one open defect
  is pinned (the mobile wallet cannot in-place edit a web-authored,
  uuid-keyed contact).

- **Applications reconciliation with per-client keys**: the Applications
  surface now checks each connected app's recorded storage grants against
  the account's current key set (from the locally verified account log). An
  app whose grants were all signed by a since-disconnected wallet is shown
  as needing a reconnect instead of listing as live, and revoking it skips
  the pointless per-grant server revocations while still rotating the
  collection encryption keys and removing its app key. The Applications
  page and the Connected wallets panel now cross-reference each other.

- **Connected wallets** (Settings > "Connected wallets"): the management
  surface over the account's enrolled wallet clients, listed from the
  locally verified account log -- so a recovery code (decryption-only key)
  and connected apps (never enrolled) can never appear in it. The current
  browser is marked; each wallet gets a human-readable name, chosen at
  enrollment approval and editable inline (names live in the private
  key-map, never the public document). "Disconnect" runs the full
  client-revocation cascade with resumable-failure messaging; the last
  enrolled wallet cannot be disconnected (that would abandon the account's
  update authority) -- the panel points at recovery-code issuance instead.
  The "Enroll another wallet" entry point moved here from the DID section.

- **Recovery codes** (`/recover`, Settings > "Recovery codes"): a 16-byte
  base58 code, shown exactly once, that restores the whole account from a
  fresh browser when the passphrase and every connected browser are lost. A
  code is a minimal always-enrolled wallet client derived entirely from its
  bytes: its decryption standing is maintained for free by rotation, while
  its authority stays latent -- any use of a code must first extend the
  world-readable account log. Recovering enrolls a brand-new ordinary
  client, retires the spent code (presumed compromised), rotates the
  per-user key off it, re-epochs every encrypted collection onto the fresh
  key (the same cascade client revocation runs), and pushes a replacement
  code that must be confirmed saved, ending in an ordinary enrolled login
  under a fresh passphrase. Entry points: "Forgot your passphrase?" on the
  login page and a signup pointer. Revoking a code from Settings is a real
  revocation and runs the same re-epoch, adopting the rotated key into the
  live session; a login-time health check warns when a stored recovery
  delegation has rotted. Details in ARCHITECTURE.md ("Recovery codes").

- **Client revocation** (`revokeEnrolledClient` in
  `src/session/revocation.ts`): disconnecting an enrolled wallet client,
  run in the revoking client as one synchronous cascade in dependency
  order. One log entry removes the revoked client's keys from the account's
  DID document -- under the current-key-set rule that single edit stops its
  requests, and every delegation and app grant it ever signed, from
  verifying anywhere. The per-user key then rotates off its roster wrap,
  every encrypted collection re-epochs onto the fresh key in parallel
  (revoked generations retired, history escrowed, so other replicas keep
  decrypting), and the recovery delegations it had signed are re-minted.
  The revoking session adopts the fresh key in place (no re-login), and the
  cascade converges under a naive full re-run, so a mid-cascade crash
  strands nothing. The honest ceiling is unchanged: ciphertext the revoked
  client already fetched stays readable to it.

- **The cascade-completion sweep**: every login re-checks, in the
  background, that the per-user key is wrapped to exactly the wallets the
  account document keys and that each encrypted collection's current epoch
  names the current per-user key -- completing any disconnect, revocation,
  or recovery cascade another client crashed partway through. Both checks
  read durable state alone (no checkpoint resource), so on a healthy
  account the sweep writes nothing; best-effort, a failed sweep never fails
  the login.

- A **per-user key (PUK)** is now minted at wallet provisioning:
  client-side, never server-held, replacing the passphrase-seed-derived
  vault KAK as "recipient zero" of every encrypted collection. Cached
  locally under the unlock layer (every unlock method recovers it; a
  passphrase change preserves it), with one remote home: a **wrap-set
  roster** (`key-map/puk.json`) whose current key epoch IS the current PUK,
  wrapped once per enrolled client -- login confirms the cached copy
  current or adopts a rotated one. Client-side guards (`epochsMac`, a
  pinned latest-seen epoch, rotation recipients resolved only from the
  locally verified did:webvh document) defend the roster against a
  tampering host. Pre-PUK accounts keep the seed-derived key until
  re-provisioned. See ARCHITECTURE.md ("The PUK wrap-set roster").

- **A second browser can now be connected to an existing account** -- the
  client enrollment ceremony. The new browser's "not enrolled" login offers
  "Connect this browser": it mints its key set locally and displays a
  compact **connect code** carrying only public halves (QR-renderable
  unchanged); an already-connected browser approves it from Settings, both
  screens showing the new client's did:key fingerprint for comparison. Any
  single enrolled client can enroll, no secret ever transits a server or
  the code, there is no authorized-but-blind window, and every stage is
  idempotent -- re-running the same code after an interruption converges
  without forking the account log. See ARCHITECTURE.md ("The client
  enrollment ceremony").
- The CHAPI popup pages now ask for unpartitioned IndexedDB through the
  Storage Access API's handle extension (inside the login submit gesture),
  so an enrolled browser's key record is reachable from the popup and it
  can sign in normally. Browsers without the extension fall back to the
  partitioned bucket and the popup's not-enrolled state, as before.
- On signup, pre-seed the user's Contacts collection with default records
  (InteropAlliance.org and the user themselves) and their DIDs.
- A capability request can now ask to **share** one of the wallet's own
  encrypted collections: a `https://w3id.org/byoe#shared-collection`
  invocation-target descriptor grants read _and decrypt_ access, where the
  ordinary collection grant only ever hands over ciphertext. Approval makes
  the grantee a key-epoch recipient and delegates a read-only capability in
  one indivisible step. Only the encrypted standard collections can be
  shared (`private-credentials`, `wallet-activity`, `contacts`,
  `contacts-history`); anything else is refused. The decryption key is
  never carried in the request -- it is derived locally from the `did:key`
  the request already names as controller, so a request cannot pair one
  entity's DID with another's key (a DID with no derivable key is
  unsatisfiable).
- The CHAPI consent screen renders a share request unmistakably differently
  from an ordinary storage grant: a heavier border and a filled callout
  saying the grant covers reading _and_ decrypting, covers the collection's
  contents from the moment of approval, and -- stated before approval --
  that removing access later stops future reads but cannot take back
  anything already read. The expiry line says the _fetch_ permission
  expires, since the ability to decrypt does not lapse on its own. Both the
  generic and App Connect consent panels get it (English and Spanish).
- A share granted through App Connect records the app's name and origin, so
  Settings > Shared collections lists "Text Editor (app.example)" above the
  reader's DID instead of the DID alone.
- `VITE_SHARE_ZCAP_TTL_HOURS` (default 365 days) sets a share capability's
  lifetime. Deliberately long: expiry is the wrong removal mechanism for a
  share (it would end the fetch axis while leaving the grantee in the key
  roster), so the Settings panel's "Remove access" -- rotating the epoch
  and revoking the capability together -- is the way a share ends.

### Changed

- The account-log verification step, the WAS-backed stores behind the
  did:webvh log and the connected-wallet names, and the roster kid a
  wallet's key wrap is filed under now come from `@interop/wallet-core`
  instead of this app's own copies, so every wallet on an account agrees on
  them by construction. No behavior change.

- **BREAKING**: All BYOE-layer wire vocabulary moves from the retired
  `urn:was:` / `urn:freewallet:vocab#` schemes to the shared
  `https://w3id.org/byoe#` namespace: the app-key credential's marker type
  and claim terms (`#AppKeyCredential` / `#seed` / `#origin`, now imported
  from the published `byoe-context` package), the capability-descriptor
  types matched by `processZcaps` (`#collection` / `#public-collection` /
  `#shared-collection` / `#space`), and the response VP's embedded `#zcap`
  / `#appConnect` terms. Token spellings and JSON keys are unchanged;
  matching is literal string equality on both sides, so this lands in
  lockstep with the `@interop/was-react` release carrying the app-side
  renames. Pre-release, no migration path: test accounts re-provision.

- The Collection Description's `encryption` member is now called an
  **encryption descriptor** throughout (previously "marker"), following the
  spec wording -- identifiers, prose, and the consumed
  `@interop/wallet-core` `/descriptors` and `@interop/was-client` `/edv`
  exports. The app-key credential marker type, the App Connect response
  marker, and the local one-time-migration markers are unrelated senses and
  keep their names; the `freewallet:collection-encryption:` localStorage
  keys are unchanged.

- **The account identity, unlock, and enrollment machinery now comes from
  `@interop/wallet-core`**: did:webvh hosting and its ZCap signing
  identities (`/webvh`), the per-user key, wrap-set roster, and rotation
  fan-out (`/keys`), the unlock derivation and unlock Space lifecycle
  (`/keyring`), the enrollment ceremony (`/enrollment`), recovery codes
  (`/recovery`), descriptor acquisition and the unknown-epoch refresh
  policy (`/descriptors`), and the shared system-collection names
  (`/space`). Behavior, wire formats, and stored records are unchanged --
  they are shared contracts now, so a second wallet reading the same
  account agrees with this one by construction. The freewallet-specific
  glue (the `freewallet-session` IndexedDB layer, the unlock-methods
  registry, the KMS-driven did:web provisioning) stays here.

- **The shared account data seed is retired; each client now holds its own
  key set**, minted locally on first run, private halves never leaving the
  client. The keyring record in each unlock Space now carries only an
  encrypted **account pointer** `{ did, spaceId, host }`; the unlock layer
  (shape unchanged) protects the local client-key record instead. Logging
  in therefore stops being sufficient to BE the account: a passphrase on a
  fresh browser locates the account but surfaces a distinct "this browser
  does not hold the account's keys" state offering the enrollment ceremony
  (a storage-partitioned CHAPI popup stays degraded). Each client pins the
  account pointer it has seen and refuses a substituted one. Records
  written under the old seed-carrying shape are refused as unusable
  (accounts are re-provisioned, not migrated).

- **The account's stable identity is now a `did:webvh`, and its DID
  document is the roster of the account's enrolled wallet clients** -- a
  hash-chained log, world-readable in the `id` collection, that anyone can
  fetch and fully verify. Update keys are client-held (one per enrolled
  client, prerotation on), so the storage server can never extend the
  account's own history, and no server-held key is ever a recipient of an
  encrypted collection. The Space's controller -- and the KMS keystore's,
  non-fatally -- is promoted to the did:webvh at signup (an interrupted
  promotion heals on the next login), after which the server authorizes by
  verifying the published log against the keys the document lists _now_ --
  dropping a client from the roster stops everything it signed from
  verifying. Sessions on a promoted account sign under the did:webvh
  verification-method id; the user id shown to connecting apps, and the
  unlock layer, stay `did:key`. See ARCHITECTURE.md ("The did:webvh
  identity").
- One rule now decides who a key-epoch recipient is: the X25519 twin of a
  controller `did:key`, for an app and a person alike. An App
  Connect-provisioned private collection now admits the app with its
  identity key, derived from the subject DID the wallet is already
  delegating to, instead of a per-collection key derived from the app-key
  seed -- the seed no longer enters the grant path at all. Apps must be on
  `@interop/was-react` with the matching change; collections encrypted
  under the old per-collection keys are not migrated.
- What a delegated capability may be granted is now a per-target-class
  table rather than a single read-only/pass-through switch: the whole
  Space, a protected wallet collection (the standard collections plus `id`
  and `key-map`), and a share stay read-only; an app-provisioned **public**
  collection is now add-only (`GET`/`HEAD`/`POST`); an app-provisioned
  private collection keeps the full vocabulary. The public cap is the
  user-visible change: a world-readable plaintext collection is a
  publication surface, and a write there is irreversible in practice, so an
  app may add to what it published but can no longer be granted `PUT` or
  `DELETE` to rewrite or retract it.
- Requested actions are now intersected against the closed action
  vocabulary the WAS spec fixes (`GET`, `POST`, `PUT`, `DELETE`, plus
  `HEAD` as a tolerated read alias). Previously anything a site put in
  `allowedAction` became the `allowedAction` of a capability the user's
  root key signs -- including every action a server might grow support for
  later. Unknown verbs and non-string entries are now dropped (the same
  fail-closed treatment an unknown descriptor type already got); the
  surviving actions are uppercased, deduplicated, and emitted in a stable
  order, so an equivalent request always yields the same grant.
- A request asking only for actions its target forbids is now refused
  visibly instead of being silently downgraded to a read grant nobody asked
  for: the consent screen shows "cannot fulfill" and nothing is delegated.
  Also necessary, since an empty `allowedAction` array means "every action"
  in the capability model and must never be signed.
- The wallet now refuses to store a credential that claims to be an app key
  but is not one. Every minted app key carries a shared `AppKeyCredential`
  marker type, and a credential carrying the marker is stored only when its
  subject DID derives from the seed the credential itself carries -- a
  planted app key is turned away at the door rather than stored and quietly
  ignored. The refusal covers every outside arrival path (the CHAPI store
  popup, the URL / QR / manual-paste import); the marker is also required
  at match time, so a credential can only reach the delegation path by
  carrying it. An ordinary credential with a `seed` or `origin` claim
  carries no marker and is never caught; a genuine app key still stores.
- An app-key credential's `seed` and `origin` claims now carry shared IRIs
  instead of ones namespaced under each app's `vocabBase`: they mean the
  same thing in every app. The JSON shape is unchanged; `vocabBase` now
  namespaces only the app's own type term.
- An App Connect request now only matches a stored app-key credential whose
  subject DID is the one its own seed derives. Previously any self-issued
  credential with the right type and origin qualified, ranked newest-first
  on a self-stated issuance date -- so a planted credential could win the
  match and have its DID become the identity the wallet delegates to. The
  check is local (re-derive from the carried seed and compare) and fails
  closed: an absent, malformed, or wrong-length seed does not match.
- Aligned with the current `@interop/social-core` contact model: a postal
  address spells its fields `postalCode` and `poBox`, and carries the
  administrative subdivision as `region` only (a separate `state` folds
  into `region` when `region` is absent). Stored contact documents are
  upgraded to the current shape as they are read, so contacts written by an
  earlier version compare cleanly against a fresh write and last-write-wins
  sees no spurious edit.
- Editing a contact no longer strips the extra phone/email fields an
  importer recorded (`digits`, `countryCode`, entry ids): they are carried
  through a save, and the number-derived `digits` / `countryCode` are
  dropped only when the number itself is edited.
- Updated `@interop/did-method-webvh` to 5.0.0. Newly created did:webvh
  documents no longer carry empty verification-relationship arrays, so a
  freshly provisioned Space gets a different SCID than an earlier version
  would have minted for the same keys. Already published logs keep
  resolving, and a Space whose log is published adopts that log's DID
  rather than re-creating it.

### Fixed

- A capability request naming a plain URL is now parsed and normalized
  against the user's Space instead of being matched by string prefix. The
  prefix test could be walked past:
  `<space URL>/private-credentials?x=1` starts with the Space URL and so
  classified as the requesting site's own collection, earning the full
  write ceiling on the user's own credentials collection. A target must now
  parse as a URL on the Space's origin, resolve to a path inside the Space
  (escaping dot segments refused), carry no query string or fragment, and
  name a valid collection in its first path segment; the Space URL itself
  is a whole-Space grant. A target with a query or fragment is refused
  outright rather than quietly rewritten, since showing the user one target
  and delegating another would defeat the point of asking.

## 0.22.0 - 2026-07-23

### Added

- Collections an app provisions through App Connect are now end-to-end
  encrypted with the user as a recipient: a private collection an app requests
  is set up multi-recipient, with the user's vault key alongside the app's own
  per-collection key, so both can read it while the storage server only ever
  holds ciphertext. The storage browser decrypts these collections and shows a
  generic JSON view (with a decrypted/envelope toggle) for any non-credential
  resource, in addition to the credential view.

### Changed

- Revoking a connected app now rotates the encryption key of every collection
  it provisioned before withdrawing its access, so a revoked app cannot decrypt
  anything written afterward. The revoke confirmation says so: the app may still
  hold copies of data it already fetched.

## 0.21.0 - 2026-07-23

### Changed

- The private key-id map `keys.json` moved out of the `id` collection into its
  own plaintext, capability-only `key-map` system collection. Spaces
  provisioned by earlier versions are not migrated; re-provision (wipe and log
  in again) to adopt the new layout.
- The `Identity` (`id`) collection is now provisioned with a collection-level
  `PublicCanRead` policy -- it holds only world-readable DID artifacts
  (`did.json`, `did.jsonl`) -- replacing the previous per-resource publication.

## 0.20.0 - 2026-07-23

### Fixed

- Provisioned collections carry their friendly display names again
  ("Verifiable Credentials", "Wallet Activity Log", etc.) via
  `@interop/was-client@0.20.0`'s new `collectionName` option, instead of
  falling back to the raw collection id.
- CHAPI share flow now records the Login history entry (including granted
  capability records) before delivering the presentation to a VC API exchange,
  so a relying party can never end up holding delegated capabilities that are
  missing from the sharing panel and unrevocable.
- Credentials whose `type` is a plain string (spec-legal) are no longer
  silently dropped by the import flow.
- CHAPI popup sessions now recover credentials encrypted under a fresh key
  epoch (after a rekey on another device) instead of silently omitting them,
  and popup writes stamp the `WAS-Key-Epoch` header exactly like background
  replication does.
- The storage browser now refreshes key-epoch markers and retries when a
  resource was encrypted under a newer epoch, instead of rendering the raw
  encrypted envelope until re-login.
- A VPR carrying a mismatched `domain` without a DIDAuthentication query now
  fails preflight with the specific domain-mismatch message instead of a
  generic processing error.
- Logging in over an existing session (without visiting `/logout` first) now
  closes the previous session's storage, preventing a leaked IndexedDB
  connection that could block later database deletion.
- Contact writes now stamp the key epoch on stored rows, so replicated contact
  resources carry the correct `WAS-Key-Epoch` header.
- Conflict documents assembled from a 412 response without a `/meta` document
  no longer carry an empty `updatedAt` timestamp.

### Changed

- The storage browser's collection listing now reads each collection's
  public/`PublicCanRead` status from the inline `public` flag on the List
  Collections result (`@interop/storage-core@0.3.9`), dropping the
  per-collection policy probe; a server that predates the flag still gets the
  old probe as a fallback.
- The data-identity derivation (`agentsFromSeed`) and the one-key resolver
  factory (`singleKeyResolver`, deleted from `src/lib/keyResolver.ts`) now come
  from `@interop/wallet-core/identity`. The derivation is byte-identical --
  same bootstrap handle / key name, same did:key, ZcapClient, and X25519
  key-agreement-key wiring -- so existing accounts derive the same identity;
  the library pins it with fixture tests shared with the mobile wallet. The
  keyring's unlock-identity derivation (distinct `'unlock'` handle) stays
  app-side and keeps using the shared `singleKeyResolver`.
- The wallet-request / exchange-protocol logic now comes from
  `@interop/wallet-core` (its `./request` subpath) instead of local copies:
  VPR classification, cryptosuite negotiation, the VC API exchange client, the
  QueryByExample matcher, and the VP compose / process pipeline. `composeVP` and
  `processRequest` shrink to thin Freewallet wrappers -- `composeVP` resolves the
  KMS did:web-vs-root signer and holder and enforces Freewallet's stricter
  "domain required for DID Auth" rule; `processRequest` injects Freewallet's
  `processZcaps` / App Connect processors. Signed presentation output is
  unchanged (the shared compose path defaults its embedded-grant vocabulary base
  IRI to `urn:freewallet:vocab#`). The App Connect protocol extension
  (`AppConnectQuery` and its classification) stays app-side. The VPR message
  vocabulary and the loose-shape helpers (`typeArray` / `issuerId` / `subjectId`)
  now come from `@interop/data-integrity-core` (its `./vpr` and `./guards`
  subpaths).
- The VC display helpers now come from `@interop/wallet-core` (its `./display`
  subpath) instead of local copies: credential title, issuer details, subject /
  issued-to extraction, validity periods, OBv3 achievement / skill / alignment
  helpers, the aggregate display projection, the verification-to-UI checklist,
  and credential-input parsing. Date formatting, i18n, and the CORS-proxy fetch
  stay app-side as thin wrappers (`formatDate` keeps `Intl`;
  `mapVerificationToUi` builds the library's `labels` map from its `TFunction`;
  `resolveCredentialsInput` injects `fetchFromURL`). As part of reconciling with
  the mobile wallet's implementation, credential titles now emit type-specific
  prefixes for a few credential types (e.g. `Employment: ...`,
  `Volunteer: ...`, `Recommendation From ...`), and the resume-credential check
  matches the subject `type` by case-insensitive substring rather than an exact
  `'Resume'` match.
- The wallet Space layout pieces now come from `@interop/wallet-core` (its
  `./space` subpath) instead of local copies, so the browser wallet and
  Freewallet mobile share one source of truth: the `private-credentials`,
  `public-credentials`, and `wallet-activity` collection ids and their
  public/encryption config are sourced from the library specs in
  `WALLET_STANDARD_COLLECTIONS` (the RxDB `key` and friendly display `name`
  stay app-side); the `WalletActivity` wire shape and the eight `addHistory*`
  activity-payload builders are the library's, with `StorageManager` keeping
  thin wrappers that preserve their signatures; and `publicCredentialUrl` is
  derived by the library. The contacts collections still come from
  `@interop/social-core`.
- The WAS sync port, content-id derivation, EDV document cipher, space-id
  derivation, and space/collection provisioning now come from
  `@interop/was-client` (its `./sync` and `./edv` subpaths) instead of local
  copies, removing `src/stores/wasSyncPort.ts`, `src/stores/edvDocCipher.ts`,
  and the `cidFrom` derivation from `src/lib/cidFrom.ts` (its `digestHash` /
  `bufferToBase64Url` byte helpers remain). `WASRemoteStore.ensureUserCollections`
  now provisions each collection through the generic `ensureSpaceAndCollection`
  helper, keeping the wallet's collection roster app-side. `contentCid` is now
  synchronous, so the public-link and storage-browser cid derivations moved from
  effects into `useMemo`.
  from `@interop/verifier-core` (via its `expirationSuite` and
  `createIssuerDetailsSuite` exports) instead of local copies, removing
  `src/lib/verifierSuites/`. The expired-credential problem type is now the
  standard `EXPIRED_PROBLEM_TYPE` URI from the same package.
- Replaced the CHAPI popup's remote-direct boolean fork in `StorageManager`
  with a `SyncedCollectionStore` backend seam: a local-replica backend and a
  remote-direct WAS backend selected once at construction, sharing the same
  cipher, envelope-id, and epoch logic. All synced-collection operations
  (including delete and public-link operations) now route uniformly through
  the active backend, and pages await a uniform `ready()` contract instead of
  branching on backend mode.
- `addCredential` is now idempotent by content cid via an in-memory cid index,
  removing the per-insert full-collection dedupe scan and making batch imports
  safe without call-site pre-deduplication.
- Login-path performance: per-collection epoch markers are fetched
  concurrently, the public-credentials cid migration runs once per database
  instead of on every login, and contact reads now use the shared decrypt
  cache and distinguish unknown-epoch rows.

### Removed

- Removed refresh-surviving delegated sessions and the vault-lock mechanism;
  reloading the browser now requires logging in again. Dropped the
  `VITE_SESSION_ZCAP_TTL_HOURS`, `VITE_SESSION_VAULT_TTL_HOURS`, and
  `VITE_REQUIRE_PASSPHRASE_FOR_VAULT` environment variables.

## 0.19.0 - 2026-07-21

### Added

- Add Contacts management, based on Freewallet Mobile's contacts sync.

## 0.18.1 - 2026-07-21

### Changed

- Storage screen: moved per-collection usage out of the Storage usage card and
  onto the Collection cards themselves (shown next to each resource count). The
  usage card now shows only the overall backend usage, the measured timestamp,
  and the max upload size.
- Storage screen: collection cards now show the collection id (in code style)
  next to the display name, each collection category sorts alphabetically by
  display name, and the redundant "Default (WAS)" backend line is gone (also
  from the collection contents page subtitle).
- Renamed the public credentials collection to "Verifiable Credentials
  (Publicly Shared)"; wallet-provisioned collections now display their
  canonical name even on spaces provisioned under an older name, and those
  names are now localized (en/es).
- Storage screen: the Export button now comes first, and the import/export
  actions are relabeled "Export (Backup) Space Contents" and "Import (Load)
  from Backup".

### Fixed

- Fix Application revocation action (await behavior).

## 0.18.0 - 2026-07-20

### Added

- **Applications settings section.** A new Applications page lists the apps
  connected through App Connect, one per stored app-key credential, with each
  app's origin and connected date. An App Details view shows the app's identity
  DID and the storage access it was granted (targets, allowed actions, and
  expiry). Both offer a Revoke App Access action that revokes the app's storage
  grants on the server (via the Space-scoped revocation endpoint), then removes
  the app key and records the revocation; revoking requires a full (passphrase)
  session with an unlocked vault. Grants are revoked before the key is deleted,
  so a network failure leaves the connection intact to retry. App Connect
  approvals now persist the full delegated capabilities (not just a display
  summary) so they can be revoked later; connections made before this change
  have no revocable grant and lapse on their own expiry.

## 0.17.1 - 2026-07-20

### Changed

- **App Connect consent screen refresh.** The CHAPI "Connect {app}?" panel now
  reads "Connect {app} to storage?", attempts to fetch Web App Manifest,
  emphasizes relevant fields.
- **Storage page collections grouped by category.** The collections overview
  now renders three sections instead of one flat list: "Wallet Contents" (the
  private and publicly shared credential collections), "Application
  Collections" (anything registered by connected applications and sites;
  hidden when empty), and "Wallet System Collections" (activity log, identity,
  unlock methods).

## 0.17.0 - 2026-07-20

### Changed

- Background WAS replication now pulls its change feed through the storage
  client's `Collection.changes()` API instead of a hand-rolled query request.
  The signed request is unchanged; only the pull path moved onto the typed
  client. Writes continue to move stored bodies verbatim through the raw,
  codec-bypassing request path.

### Added

- **App Connect: one-popup app login.** A relying party can now connect to the
  wallet in a single CHAPI popup via the new `AppConnectQuery` request type
  (alongside DID Authentication). The wallet finds the app-key credential for
  the app and requesting origin -- or, on first run, mints one itself (32-byte
  seed, seed-derived did:key, self-issued) and saves it to the credential
  store under the same consent -- then delegates the requested collection
  capabilities to the app key's DID and returns credential, grants, and a
  wallet-provided first-run marker in one signed presentation. The consent
  screen is a dedicated app-centric panel ("Connect {app}?") with the
  collections-and-access preview; the origin binding is enforced wallet-side,
  so a phishing origin can neither recover nor be handed another origin's
  key. Approval records an app-connect Login entry in the wallet activity
  log. Wallets that predate `AppConnectQuery` fail closed rather than
  degrading into a partial generic flow. Pairs with the
  `@interop/was-react` 0.2.0 release, whose one-popup Login With Wallet flow
  requires this App Connect support.

- Synced documents now carry the server-managed `createdBy` creator DID from the
  change feed onto the local replica (present on live documents and tombstones,
  absent when the server recorded no creator). The local synced-doc schema bumps
  to version 1 to persist it, with a migration that leaves existing documents'
  `createdBy` unset. The 412-conflict re-read path carries `createdBy` too, so
  a document assembled from a push conflict keeps its attribution.

- **Multi-recipient sharing of encrypted collections.** An encrypted collection
  (`private-credentials`, `wallet-activity`) can now be readable by additional
  readers besides its owner, without exposing the vault key. Each collection
  carries per-collection key epochs, with the owner's vault key always a
  standing recipient; reads tolerate resources written before the first epoch
  indefinitely, so nothing already stored is stranded. Removing a reader is one
  action with two halves: it revokes that reader's storage authorization (the
  server stops serving it the collection) and rotates the collection's key epoch
  so resources written afterwards are unreadable to it. Data the reader already
  fetched is not clawed back -- it may still hold copies of what it read before
  removal.

- The background-sync layer now carries each resource's key-epoch stamp so a
  replica encrypts and decrypts under the right epoch. The synced-doc schema
  bumps to version 2 to persist the stamp, with a migration that leaves existing
  documents' stamp unset.

- A "Shared collections" panel on the Settings page lists, per encrypted
  collection, the readers it is currently shared with (their controller DID or
  key id, and the grant's expiry) with a "Remove access" action behind a
  confirmation dialog. Removing access requires a passphrase (full) session; a
  restored session sees the list read-only with a re-login prompt.

### Fixed

- The replication push handler now compares bodies by JCS-canonicalized JSON,
  so a key-order-only difference between structurally identical bodies is no
  longer misread as a change (which could trigger a spurious conditional
  write).

## 0.16.0 - 2026-07-19

### Added

- **Public-collection grants in "Login with Wallet"
  (`urn:was:public-collection`).** A relying party can now request a
  world-readable collection. On approval the wallet provisions the collection
  plaintext (public implies plaintext -- no encryption marker), sets a
  collection-level `PublicCanRead` policy at provisioning time (the wallet
  holds the space root; policy endpoints are capability-only, so an app can
  never escalate a private collection to public on its own), and delegates the
  usual collection-scoped read/write zcap to the app's DID -- public covers
  only unauthenticated reads; writes stay capability-only, with the existing
  write-grant TTL. The consent screen renders such a grant with a dedicated
  warning banner stating that anyone on the web will be able to read the
  collection (and no ciphertext note, which does not apply). A public grant on
  the wallet's protected collections (`private-credentials`,
  `public-credentials`, `wallet-activity`, `id`) is refused unconditionally,
  and genuinely unknown descriptor types still render as "cannot fulfill".

- **Passkey unlock (sign up and log in with a passkey).** An account can now be
  unlocked with a passkey in addition to a passphrase. Signup offers a passkey
  path (create the wallet, register a passkey, land on the dashboard), and login
  offers a one-tap passkey option that reconstitutes a full session. A passkey
  is a peer unlock method with full account control, not a second factor; it is
  phishing-resistant because it is bound to the app's origin. There is no login
  server: the passkey's WebAuthn PRF-extension output feeds a key derivation
  that unlocks the wallet locally, with no server-side WebAuthn verification and
  nothing about the passkey stored remotely. User verification (biometric or
  PIN) is required on every ceremony. Passkey unlock depends on the WebAuthn PRF
  extension, which some browsers and platforms do not provide; the passphrase
  option is always available as a fallback, and PRF failures surface a clear
  message with a link to the passkeys documentation. A new
  `public/docs/passkeys.md` page covers capabilities, platform compatibility,
  and the recovery story.

- **Passkey management in Settings.** A new Passkeys section lets you add a
  passkey, rename it, and remove it. Each passkey shows a sync badge -- Synced,
  Sync available, or Not synced -- read from the authenticator's backup flags at
  registration, so you can see whether a passkey is backed up to your platform
  account (and would survive a lost device) or lives only in that one
  authenticator. Removing a passkey genuinely retires it, and a lost passkey can
  be removed without the device it lives on. Settings refuses to remove the last
  remaining unlock method, which would leave the wallet unrecoverable. An account
  created with a passkey only gains an "Add a passphrase" option so it can have a
  second way in, and a post-signup prompt encourages adding a second unlock
  method (more urgently when the only passkey is not backed up).

- **Decrypted / encrypted-envelope views in the storage browser.** Opening a
  resource from an encrypted collection (`private-credentials`,
  `wallet-activity`) used to show only the raw EDV envelope (the JWE). With an
  unlocked vault, the storage browser now decrypts the envelope and offers a
  two-button toggle between "Decrypted contents" and "Encrypted envelope" --
  in the resource preview dialog and on the resource detail page. An encrypted
  credential now also gets the full credential detail treatment (title,
  description, View details / Download / Delete), same as a plaintext one.
  Copy and Download follow whichever view is active. With a locked vault (or a
  foreign envelope), the raw envelope is shown as before.

- **Toast notifications for wallet actions.** Actions that previously succeeded
  silently now confirm themselves: deleting a credential ("Credential deleted."),
  creating or removing its public link, saving accepted credentials, and
  removing undecryptable rows. Messages are posted to a small global store
  (`src/stores/toastStore.ts`) and rendered as a MUI Snackbar by
  `DashboardLayout`, so a message posted just before a redirect -- as delete does
  -- still shows on the page the user lands on. Existing error `Alert`s are
  unchanged; they stay in place on the page rather than auto-dismissing.

## 0.15.5 - 2026-07-12

### Added

- **Recognize the CHAPI `interact` protocol in credential requests.** The newer
  single-call CHAPI entry point (`chapi.interact()`) hands the wallet an
  exchange URL under `protocols.interact` rather than the classic
  `protocols.vcapi`, with an empty presentation/store body, and does not depend
  on `navigator.credentials` (which browsers are expected to freeze). The get
  and store popups now read either handle -- preferring `interact` when both are
  present -- so requests from sites that adopt the new API open the exchange
  instead of being rejected as unreadable. The exchange itself is handled by the
  existing VC API machinery, since the `interact` URL is an opaque HTTP exchange
  endpoint like `vcapi`.

### Fixed

- **CHAPI popup store and share now use the remote storage directly.** A CHAPI
  popup runs in a third-party partitioned iframe, so its local IndexedDB is an
  isolated bucket no background sync reaches. Credentials stored through the
  store popup were stranded in that bucket (invisible to the main app and the
  remote storage), and the get popup always saw an empty wallet, so sharing and
  the "Login with Wallet" credential flow could not find anything to offer. A
  popup session now reads and writes the standard remote collections directly,
  writing exactly what background replication would have pushed so the main app
  picks it up cleanly. Guest and no-server sessions are unaffected.
- **Credential-added history entries are now recorded uniformly.** Logging a
  credential-created activity moved into the shared storage call, gated on an
  actual insert, so every entry point records it once (and re-adding a stored
  credential logs nothing). The welcome credential written at sign-up and guest
  login now gets a history entry too.
- **A zcap query with no `capabilityQuery` is now reported as a malformed
  request.** A `ZcapQuery` / `AuthorizationCapabilityQuery` missing its
  `capabilityQuery` detail used to slip an `undefined` descriptor into the
  request profile, which blew up during grant resolution after login and
  showed the misleading generic "login failed" message. Classification now
  rejects such queries up front, so the share popup shows the accurate
  "this site didn't send a request this wallet can read" blocked state
  before the user is ever asked to log in.

- **A corrupt keyring record now surfaces its own login error.** When the
  passphrase located a keyring record on the storage server but the record
  failed to unwrap or validate (a genuinely corrupt/malformed record -- a wrong
  passphrase never reaches this point), the failure bubbled out as the generic
  "could not finish setting up your wallet" message. The remote unwrap is now
  guarded like the cached one, throwing a dedicated `KeyringRecordUnusableError`
  (also used for the unwrapped-controller sanity check), and the login page
  shows a distinct message with recovery guidance -- separate from a server
  outage. An unusable record no longer refreshes the local keyring cache.

- **Deleting the account now fully retires the identity.** The delete flow
  wiped the data but never ended the persisted browser session, so the next
  visit silently restored a live session for the just-deleted identity, and it
  left the passphrase keyring behind, so the wrapped data seed outlived the
  account. Deleting now also ends the persisted session (its session key,
  zcaps, and vault envelope) and retires the passphrase keyring -- deleting the
  unlock Space on the storage server and its local cached copy. The confirmation
  is now an in-app dialog that asks for the passphrase and verifies it before
  wiping anything, so a wrong passphrase can never destroy data; guest sessions
  have no passphrase and skip that step.

- **The Delete Account button is now disabled in a restored session.** Deleting
  the account requires the passphrase-derived root key (only the Space
  controller may delete the Space), so in a restored session the delete always
  failed server-side and surfaced only a generic error with no hint at the
  cause. The button is now disabled there, with a note to log in with the
  passphrase first -- matching the other passphrase-gated Settings controls.

- **A generic credential request no longer pre-checks your Login Credential.**
  The share popup pre-selected the newest self-issued Login Credential for
  every request, so a verifier asking for "any VC" -- one that never mentioned
  a Login Credential -- arrived with the row already checked, and a single
  Continue click would disclose the account's username. The Login Credential is
  now pre-selected only when the request explicitly asks for that type (the
  DID Authentication / login flows); a generic request starts with nothing
  checked, so sharing the username is always a deliberate choice.

- **The share popup no longer lets an empty share leave a verifier's exchange
  hanging.** With no DID Authentication in the request, nothing selected, and
  no satisfiable storage grant, Continue composed an empty response: the
  exchange endpoint (the verifier's system of record for a VC API request)
  never received anything and sat waiting until its own expiry, while the
  CHAPI channel got a bare `null`. Continue is now disabled when there is
  nothing to share, so the only way out of an empty consent screen is Cancel.
  Cancel itself (and any blocked-state exit) still answers only the CHAPI
  channel by design: the exchange protocol defines no holder decline message,
  so an abandoned exchange expiring on the verifier's side is the correct
  outcome, now documented as such rather than left as an accident.

- **Background sync no longer silently stops after a re-login.** Re-entering
  the passphrase over a restored session (or logging into a second account
  without logging out first) reopened the local database -- which cancelled the
  running replication -- but the sync controller's start call no-oped on its
  already-running guard, so nothing replicated for the rest of the session,
  with no error shown. The login path now restarts the controller (a serialized
  stop-then-start; overlapping lifecycle transitions queue rather than
  interleave), so replication always tracks the current session and an
  account switch tears down the previous account's replication.

- **A storage-server outage during first-login provisioning now shows the
  right error.** The unreachable-server detection only recognized a raw
  storage-client error, but the space/collection provisioning steps rethrow
  that error wrapped in a plain `Error` -- so an outage striking during
  provisioning (rather than the initial probe) surfaced as the generic
  "could not finish setting up your wallet" message instead of the
  "storage unreachable" state with its guest-mode fallback. The check now
  unwraps the error `cause` chain (with depth and cycle guards) before
  classifying.

- **Wiping local storage now actually waits for the databases to be deleted.**
  The wipe issued the IndexedDB delete requests and returned immediately,
  so account deletion and re-signup could proceed while the wallet databases
  still existed -- letting a prompt re-signup see remnants of the old account.
  Each deletion is now awaited to completion; when another open tab blocks a
  deletion, a warning is logged and the wipe proceeds rather than hanging
  (the queued deletion completes once that tab closes).

- **A passphrase change now takes effect on other devices.** Passphrase login
  answered from the locally cached keyring record before consulting the WAS
  server, and the cache never expired -- so a passphrase retired via "Change
  passphrase" on one device kept unlocking the account indefinitely on every
  other device that had cached it, defeating rotation after a compromise. The
  keyring lookup is now remote-first whenever a WAS server is configured: the
  remote copy is the source of truth, a missing remote record drops the local
  cache and reports "no account", and the cache only answers as an offline
  fallback within a bounded window (`VITE_KEYRING_CACHE_TTL_HOURS`, default 7
  days; cache entries are now stamped with their write time). The
  old-passphrase check inside "Change passphrase" follows the same
  remote-first rule. Cache entries written before this change carry no
  timestamp and fail closed on the offline path -- one online login refreshes
  them. No-WAS deployments are unchanged: there the cache is the keyring's
  only copy and remains authoritative with no TTL.

- **"Allow Wallet" CHAPI prompt reappeared on every visit to Login/Signup.**
  `registerWallet()` runs from a mount effect on the Login, Signup, and Guest
  login pages, and it unconditionally called `installHandler()`, whose only
  action is the mediator's `permissions.request()` -- the prompting call, which
  always shows the "Allow Wallet" popup regardless of prior grants. Registration
  now first queries the existing `credentialhandler` permission state (a
  non-prompting call) and only installs the handler when the origin has not
  already been granted, so the prompt appears at most once per browser.

- **"Login with Wallet" storage grants are hardened against write abuse.** A
  relying party could request write actions (PUT/POST/DELETE) on the user's own
  protected collections -- the standard `private-credentials`,
  `public-credentials`, and `wallet-activity` collections, and the `id`
  collection holding the published DID document -- and, by naming a plain
  resource URL under the Space rather than a collection descriptor, sidestep
  the checks entirely. Grants on any protected collection are now capped to
  read-only (GET/HEAD), matching the existing whole-Space cap, and the cap is
  applied by deriving the collection from the target URL as well as the
  descriptor object, so a string target cannot bypass it; only an
  RP-provisioned collection may still receive writes. Those write grants are delegated for a shorter lifetime than
  read-only grants (`VITE_RP_ZCAP_WRITE_TTL_HOURS`, default 7 days, versus the
  read-only `VITE_RP_ZCAP_TTL_HOURS`, default 30 days), and the consent screen
  now shows the recipient DID on every grant -- rendered distinctly from the
  relying party's own free-text reason so it cannot be spoofed -- plus an
  explicit warning on any grant that carries write access.

- **Credential ids now hash the canonical JSON bytes as documented.** The CID
  formula ran an extra `JSON.stringify` over the already-canonical JCS string,
  so it hashed the JSON-escaped, re-quoted text rather than the canonical bytes
  -- diverging from `base64url(sha256(utf8(JCS(doc))))` and from what external
  tools compute for the same credential. The wrapper is gone, so stored
  credential ids change. Public-credential rows (the only rows keyed directly by
  cid) are re-keyed automatically at the next login, locally and on the remote
  storage: each is re-inserted under its correct cid and its old-cid row is
  tombstoned. As a result, any public-link URL copied before this change stops
  resolving and the credential must be re-shared to mint a fresh link.

## 0.15.4 - 2026-07-10

### Fixed

- **CHAPI popup showed a "Use saved login" button that failed off Chromium.**
  The saved-login recognition in the store and get popups relies on the Storage
  Access API "beyond cookies" handle, which only Chromium browsers implement;
  on Firefox and Safari the button always ended in "Saved login is not available
  in this browser." The popup now detects the browser engine and hides the
  saved-login notice entirely off Chromium, leaving just the passphrase form.
- **CHAPI store popup reported a false "not saved" to exchange issuers.** When an
  issuer delivers a credential through a VC API exchange, it receives the
  credential out of band and expects the wallet to acknowledge with an
  `OutOfBand` response so it can advance to its own status page; the store popup
  was returning the stored presentation (`VerifiablePresentation`) instead, which
  such an issuer reads as a failed store (vcplayground.org's issuer then toasts
  "VC not saved to wallet."). The popup now answers an exchange offer with
  `OutOfBand` and keeps echoing the presentation back only for inline offers.

## 0.15.3 - 2026-07-10

### Added

- **DID Authentication holder binding on the store popup.** An issuance exchange
  may answer the wallet's opening message with a `DIDAuthentication` request
  rather than the credentials, binding what it issues to the holder's DID
  (vcplayground.org's issuer does this whenever DID Auth is checked). The store
  popup previously reported such exchanges as unsupported. It now defers the
  exchange until the user logs in, signs a presentation over the exchange's
  challenge (falling back to the exchange origin when it states no `domain`),
  and collects the offered credentials from the reply.

### Fixed

- The CHAPI store popup left a spinner on screen when it could not read the
  incoming offer, hiding the error it had already recorded. The failure and a
  Cancel button are now shown.

## 0.15.2 - 2026-07-10

### Added

- **VC API exchange offers on the store popup (CHAPI `protocols.vcapi`).** An
  issuer may offer an empty credential payload and name a VC API exchange URL
  under `credential.options.protocols.vcapi` instead, keeping the credentials it
  is issuing on its exchange server (vcplayground.org's issuer always does
  this). The store popup previously read the empty payload, found no credential,
  and refused to store. It now opens the exchange and collects the offered
  presentation from it, the same way the share popup already retrieves a
  presentation request. An exchange that demands a presentation before offering
  a credential is reported as unsupported.

### Changed

- The CHAPI store popup now stores **every** credential an offer carries, rather
  than only the first. All of them are summarized on the confirmation screen;
  each is written independently, and a failure part-way through reports how many
  were stored rather than claiming a clean success or a clean failure.

### Fixed

- The CHAPI store popup logged the incoming offer at `console.debug`, which
  browsers hide by default. It now logs at the default level, and reports the
  protocols the issuer offered and the presentation fetched from an exchange.

## 0.15.1 - 2026-07-10

### Added

- **VC API exchange requests (CHAPI `protocols.vcapi`).** A verifier may hand
  the wallet an empty `VerifiablePresentation` request body and name a VC API
  exchange URL under `credentialRequestOptions.web.protocols.vcapi` instead,
  keeping the real Verifiable Presentation Request on its exchange server
  (vcplayground.org's verifier always does this). The share popup now opens the
  exchange, retrieves the request, runs it through the usual consent screen, and
  POSTs the composed presentation back to the exchange as well as returning it
  over the CHAPI channel. A failed delivery is reported rather than silently
  handing the site a presentation it never received, and a multi-step exchange
  (one that answers with a further request) is reported as unsupported.

### Fixed

- **CHAPI share requests hung on a spinner.** A request whose Verifiable
  Presentation Request carried no `query` -- what every `protocols`-bearing
  request sends -- made query normalization yield a one-element array holding
  `undefined`, and classification then threw on reading its `type`. The popup's
  initialization rejected into a bare `console.error`, leaving the page spinning
  forever. Query normalization now drops entries that are not typed query
  objects, an empty request body classifies cleanly, and any initialization
  failure surfaces on the page.
- **Array-shaped `credentialQuery` in a `QueryByExample`.** The VP Request
  spec allows `credentialQuery` to be a single object or an array of them, and
  verifiers send both (vcplayground.org sends the array). Only the object form
  was read, so an array-shaped query showed no reason string and then threw
  while matching stored credentials against its example. Both forms are now
  normalized, as `capabilityQuery` already was.
- **Bare-string `acceptedCryptosuites`.** Cryptosuite negotiation only read the
  `{ cryptosuite }` object form, so a verifier listing plain cryptosuite name
  strings got the wallet's legacy `Ed25519Signature2020` default instead of the
  `eddsa-rdfc-2022` proof it asked for. Both forms are now accepted.

- **CHAPI store of a bare credential.** Issuers may offer a bare
  `VerifiableCredential` over `navigator.credentials.store()` rather than
  wrapping it in a `VerifiablePresentation` (vcplayground.org does this). The
  store popup only read `verifiableCredential` off the offered payload, so no
  credential was found, the confirmation screen rendered without its summary,
  and the Store button silently did nothing. The classifier now inspects the
  event's `dataType` (and the payload `type`) and wraps a bare credential in an
  unsigned presentation, matching the credential's VC data model version.
- The CHAPI store popup now reports failures instead of failing silently: the
  incoming offer is logged, and an unreadable offer, a missing credential, or a
  storage write error surfaces on the page and in the console.

## 0.15.0 - 2026-07-09

### Added

- **Session vault envelope.** At full login the vault KAK (the X25519 key
  that encrypts/decrypts the wallet's private collections) is now wrapped
  (AES-GCM) under a fresh non-extractable WebCrypto key and persisted in the
  `freewallet-session` IndexedDB database with its own TTL (default 24h,
  `VITE_SESSION_VAULT_TTL_HOURS`) -- so a refresh-restored (`delegated` tier)
  session unlocks the vault without a passphrase re-prompt, in the main app
  and in the CHAPI popup's saved-session recognition alike. Only the KAK is
  ever wrapped -- never the data seed or the root signing key -- and the pair
  is deleted on logout. Fail closed: an absent, expired, tampered, or
  wrong-identity envelope leaves the vault locked exactly as before (and a
  bad envelope is deleted so it is not retried). Setting the new
  `VITE_REQUIRE_PASSPHRASE_FOR_VAULT=true` disables the envelope entirely:
  nothing is persisted and vault access always requires a fresh passphrase
  login (`src/session/vault.ts`).
- **Hosted did:web DID (Phase 1).** Each full login now provisions and
  publishes a multi-key `did:web` DID in the user's WAS Space, backed by
  three KMS-held keys (`authentication` and `assertionMethod` Ed25519,
  `keyAgreement` X25519). The DID document is an ordinary world-readable WAS
  Resource -- `did:web:<host>:space:<spaceId>:id` resolves to
  `https://<host>/space/<spaceId>/id/did.json` -- so hosting needs no server
  changes. The verification-method-to-KMS-key map is stored (non-public) as
  `keys.json` in the same new `id` collection (the recovery anchor, written
  before the DID document), and cached in the delegated session record.
  Provisioning is idempotent and non-fatal: the steady-state path is a single
  read, a torn run resumes on the next login, and failure leaves login
  unaffected. The Settings page shows the published DID and its resolution
  URL.
- **KMS-signed DIDAuth.** CHAPI DID Authentication (and the "Login with
  Wallet" DID Auth VP) now presents the `did:web` DID and signs with the
  KMS-held `authentication` key. In a refresh-restored (`delegated` tier)
  session the browser session key invokes a persisted `sign` capability
  (delegated at login, scoped to the `authentication` key), and the CHAPI
  popup completes a DID-Auth-only request straight from the recognized saved
  session -- so DIDAuth completes **without a passphrase re-prompt**. Guests,
  no-KMS deployments, and not-yet-provisioned sessions keep the previous
  root-key `did:key` DIDAuth.
- **Hosted did:webvh DID log (Phase 2).** Each full login now also publishes a
  hash-chained, self-certifying `did:webvh` DID log (`did.jsonl`) alongside the
  `did:web` document, in the same `id` collection and served world-readable as
  `text/jsonl` -- `did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to
  `https://<host>/space/<spaceId>/id/did.jsonl`, so hosting needs no server
  changes. The log becomes the single source of truth: `did.json` is now its
  `did:web` projection (verification methods flipped to `Multikey`, an
  `alsoKnownAs` cross-link between the two ids), and the log's three
  verification methods reuse the Phase 1 KMS keys. A dedicated KMS-held update
  key (never the root `did:key`, never a document verification method) is the
  log's write authority, with prerotation committed from the first entry; the
  `keys.json` map gains a non-public `webvh` block recording the active,
  staged, and retired update keys (the anchor that prevents a frozen log).
  Provisioning is idempotent, crash-resumable, and non-fatal, runs directly
  after the `did:web` provisioning, and is gated on the new
  `VITE_ENABLE_DID_WEBVH` flag (default `true`; opt out with `false`). The
  Settings page shows the published `did:webvh` id, its log URL, and a
  full-tier **Rotate update key** action that reveals the staged key and
  appends a fresh entry to the public log. CHAPI DIDAuth and "Login with
  Wallet" still present the `did:web` holder for now, since few verifiers
  resolve `did:webvh` yet (the `alsoKnownAs` cross-link correlates the two).
  Adds the `@interop/did-method-webvh` dependency.
- **`keys.json` repair path.** `repairKeyBindings` (`src/lib/didWebvh.ts`)
  rebuilds a lost or rolled-back `keys.json` from the published artifacts plus
  one WebKMS List Keys call: `did.json`'s verification methods and the log's
  authorized `updateKeys` are matched back to their KMS key URLs by
  `publicKeyMultibase`, and the staged prerotation key by hashing every listed
  key against the log's committed `nextKeyHashes` (its only public trace);
  what matched is rewritten as the new anchor, and an unmatchable binding
  throws. The provisioning flow's frozen-log row (`did.jsonl` present, `webvh`
  block lost) now runs this repair instead of failing -- losing `keys.json` no
  longer permanently freezes the published DID log. Relies on the List Keys
  `keyUrl` projection (was-teaching-server's K5 fix, typed in
  `@interop/webkms-client` 14.7.1).
- **Keyring v2: the wallet identity is decoupled from the passphrase.** The
  passphrase now derives an _unlock identity_ (PBKDF2-stretched, 600k
  iterations of SHA-256 with a fixed app salt -- a slow KDF the old chain
  never had) that locates and unwraps the real _data identity_ from a
  **keyring record**: the data seed wrapped (JWE, via the wallet's existing
  EDV cipher stack) to the unlock key, stored in the unlock identity's own
  minimal WAS Space (`keyring/keyring.json`) and cached locally in the
  `freewallet-session` database (so offline and no-WAS logins keep working;
  the remote copy is the source of truth and makes the passphrase portable
  across devices). The data seed is **random 32 bytes** -- never derivable
  from any passphrase -- generated at signup and bound to the passphrase
  before the data Space is created (a failed keyring publish aborts the
  signup rather than minting an unrecoverable account). Login is unified
  behind `loginWithPassphrase` (keyring hit, or no account) across the login
  page, signup probe, and both CHAPI popup pages (which thread the
  first-party Storage Access API IndexedDB handle into the keyring cache).
  Everything downstream of the data seed -- session tiers, vault KAK, KMS
  keystore, did:web/did:webvh, sync -- is untouched, and guests never touch
  the keyring. **Breaking (fresh start):** the keyring is the only login
  path; accounts created before it (whose identity was derived directly from
  the passphrase) no longer resolve and get "profile does not exist" at
  login. There is no compatibility flag.
- **Passphrase change.** A new full-tier Settings action re-wraps the data
  seed under the new passphrase's unlock identity and deletes the old unlock
  Space, which **retires the old passphrase**: since data seeds are random,
  nothing about the wallet is derivable from a retired passphrase.

### Changed

- **Adopt `@interop/did-method-webvh` 3.6.0.** Dropped the freewallet
  workarounds the library now subsumes: the `webvhLogVerifier` normalizing
  wrapper (the library's realm-safe default verifier now works under
  vitest + jsdom, and the create/update/resolve calls default it, so the
  explicit `verifier:` option is gone everywhere); the hand-rolled
  `logToJsonl` / `parseJsonlLog` serializers (now the library's
  `logToJsonlString` / `readLogFromString`); the `didWebvhLogUrl` mapping (the
  Settings log URL is now derived from the published did via the library's
  `getFileUrl`); and the hand-built `proofValue`/multibase logic inside the
  KMS update-key signer (now the library's `signerFromExternalKey`, with only
  a thin `sign({ data })` shape adapter kept). The `{SCID}` placeholder is now
  the library's exported `SCID_PLACEHOLDER`. Net behavior is unchanged.
- **Adopt `@interop/webkms-client` 14.7.0** (adds `KeystoreAgent.listKeys()`).
- **Adopt `@interop/was-client` 0.13.1.** Collection provisioning passes the
  new `force: true` to `configure()` where a fresh collection is created
  through a handle: the client now fails closed when the pre-merge
  `describe()` is masked (404), and these upserts run with the root
  capability, where a 404 genuinely means the collection is absent.
- **Test coverage for critical paths.** New unit suites for the login/identity
  bootstrap (`initSession`), CHAPI wallet registration (`registerWallet`),
  credential JSON parsing (`credentialsFromJSON`), and the ten previously
  untested `viewMappers` modules; plus a new offline-deterministic e2e spec
  (`tests/e2e/credential-flows.spec.ts`) covering the add, accept, delete, and
  verify credential flows.
- **Cleanup.** Moved the duplicated `AuthLocationState` type to
  `src/types/auth.ts`; removed leftover debug `console.log` calls from the
  landing, login, and signup pages and the auth store; removed the
  commented-out `WALLET_LOCATION` constant from `app.config.ts`; `getBackends`
  is now a named function declaration.

## 0.14.0 - 2026-07-04

### Added

- **Login with Wallet.** A relying party can now send one CHAPI Verifiable
  Presentation Request that asks for DID Authentication, a self-issued **Login
  Credential** (a username, set on the Settings page), and one or more
  **WAS storage capabilities** described abstractly (a named collection or the
  whole Space). The `/wallet/get` popup shows a single consent screen with up
  to three sections (identity, credential selection, storage grants) and
  responds with a signed VP whose `verifiableCredential` carries the Login
  Credential and whose `zcap` array carries the delegated capabilities
  (embedded before signing, so the authentication proof covers them). Grants
  are rooted at the user's own Space, whole-Space grants are capped to
  read-only, and each grant expires after `VITE_RP_ZCAP_TTL_HOURS` (default 30
  days). A zcap-only request returns an unsigned VP (the grants are
  individually signed and bound to the relying party's DID). See
  `public/docs/login-with-wallet.md` for the relying-party response format.

### Changed

- The dashboard Sync button now triggers an immediate replication cycle on
  all synced collections (via a new public `SyncController.reSync()`) in
  addition to reloading the credential list from the local replica.

- **Slimmer entry bundle** (450 kB to 130 kB minified, 140 kB to 42 kB
  gzipped). Two eager imports moved to on-demand loading: `InfoBoxProvider`
  now lazy-loads `DocContent` (keeping the react-markdown/remark stack out of
  the entry chunk), and the sync controller loads the RxDB replication
  adapter dynamically when replication actually starts (keeping rxdb, rxjs,
  and broadcast-channel out of the eager auth-store path).

## 0.13.0 - 2026-07-02

### Changed

- **Local-first storage model.** The local
  RxDB/Dexie `BrowserStore` is now the always-on ACTIVE replica: every
  credential, public-link, and history read/write targets it unconditionally
  (online or offline, guest or not), and the remote WAS Space is demoted from
  a primary store to a background sync target. One local database per user
  now holds all three standard collections (`private-credentials`,
  `public-credentials`, `wallet-activity`) on the generic synced-doc schema,
  and the sync controller replicates those same collections (no separate
  sync db). Concretely:
  - `StorageManager` loses the `remoteOnly` mutual-exclusion branch that
    forked every method; `WASRemoteStore` keeps only the Space lifecycle,
    the storage-browser read-through (`/storage/**` pages), export/import,
    and quotas -- its direct credential/history/public-link methods are gone.
  - Sharing writes the public copy to the local `public-credentials`
    collection and background replication mirrors it to the remote
    Collection, where the returned public URL resolves (sharing still
    requires a configured remote).
  - History (`wallet-activity`) is now recorded for all sessions, including
    guest / local-only ones (the "skip history for local storage" caveats are
    gone), and the History page reads it locally.

### Added

- **Refresh-surviving sessions via delegated zcaps.** A full
  (passphrase) login now mints a browser session key -- a non-extractable
  WebCrypto Ed25519 key pair in its own IndexedDB database
  (`src/lib/sessionKey.ts`) -- and the root key delegates session zcaps to
  its did:key (`src/session/delegatedSession.ts`): a read-only capability on
  the WAS Space, a read/write capability per standard collection (rooted at
  the Space, target-attenuated at delegation time -- the session key can
  sync and share but can never rewrite the Space Description), and a `sign`
  capability on the WebKMS keystore (inert for now). Lifetime defaults
  to 24h (`VITE_SESSION_ZCAP_TTL_HOURS`). On the next page load,
  `ProtectedRoute` restores a restricted **delegated-tier** session
  (`Session.tier: 'full' | 'delegated'`): the zcap client signs with the
  session key, the storage browser and background envelope replication work
  through the delegated capabilities, but the vault stays **locked** -- the
  KAK is passphrase-derived and never persisted, so encrypted collections
  are unreadable (and fail closed on writes) until the user logs back in;
  a dashboard banner says so and links to login. Logout revokes the
  keystore session zcap on the KMS (best-effort) and
  always deletes the persisted records and session key. The CHAPI popup
  half remains gated on the storage-partitioning experiment.
- **CHAPI popup saved-login on Chrome (the popup half).** The
  `/wallet/get` and `/wallet/store` popups -- third-party iframes whose
  IndexedDB is a partitioned bucket -- can now reach the first-party
  session persisted by the first-party login, via Chrome's Storage Access API
  beyond-cookies handle: a new `SavedSessionNotice` above the popup login
  form silently restores the delegated session when the `storage-access`
  permission was granted before (zero clicks for returning users), or
  offers a "Use saved login" button (the user gesture Chrome's first
  prompt requires), then shows who is signed in. A successful passphrase
  login in the popup also _persists through the handle_, so a popup-first
  user gets main-app refresh-survival and next-popup auto-recognition too.
  Plumbing: `src/lib/storageAccess.ts` (first-party storage acquisition),
  `src/lib/sessionKey.ts` parametrized over an injectable `IDBFactory`,
  threaded through restore/persist. Popup _operations_ stay
  passphrase-gated for now (the vault KAK never leaves the
  passphrase); Firefox/Safari grant cookies only, so they keep the
  passphrase-login popup unchanged. E2e:
  `tests/e2e-was/chapi-saved-session.spec.ts` drives the real flow inside
  a cross-site iframe (`public/embed-harness.html`).
- **The CHAPI storage-partitioning experiment (popup-half gate).**
  `public/storage-probe.html` (wallet-origin probe reporting which
  pre-seeded localStorage / IndexedDB / cookie markers a document can see,
  plus Storage Access API attempts) + `public/partitioning-harness.html`
  (cross-site embedder reproducing the authn.io mediator-popup shape),
  automated across Chromium/Firefox/WebKit at both Playwright-permissive
  and release-default protection levels by
  `tests/experiments/storage-partitioning.spec.ts`
  (`playwright.partitioning.config.ts`; not part of the regular suites).
  Outcome: all engines
  partition third-party-iframe IndexedDB at release defaults; Chrome's
  `requestStorageAccess({ indexedDB, localStorage })` handle restores
  first-party access (popup half buildable there), Firefox/Safari are
  cookies-only (popup re-login until support improves).
- **WebKMS keystore provisioning.** Non-guest logins now ensure a
  WebKMS keystore exists for the user's did:key controller on the configured
  KMS server (list-by-controller, create on first login) and bind a
  `KeystoreAgent` to it on the session profile
  (`profile.keystoreAgent`). The KMS defaults to the WAS server's `/kms`
  facet; a separately hosted KMS can be set via the new
  `VITE_KMS_SERVER_URL` env var. Provisioning failure is non-fatal (no
  wallet feature depends on the keystore yet); the settings page's new
  "Key management" section reports the keystore state. No keys are
  generated yet -- the first KMS-held keys arrive with the did:web work.
- **Encrypted-collection sync.** `private-credentials` and
  `wallet-activity` now replicate through the same collection-agnostic
  adapter as `public-credentials`, end-to-end encrypted. The local store
  holds EDV envelopes for these collections (encrypted-at-rest in IndexedDB):
  a new per-collection document cipher (`src/stores/edvDocCipher.ts`, built on
  `@interop/was-client@0.12.0`'s content-derived EDV ids) encrypts at write
  time -- minting the envelope-hash id that keys the row identically on every
  replica -- and decrypts at read time; the sync layer ships the envelopes
  verbatim and never touches keys. Because JWE encryption is
  nondeterministic, write idempotence and read collapsing are keyed by the
  document's content identity (credential `cid` / activity `id`) rather than
  by row id, and deleting a credential removes every row carrying it.
  `wallet-activity` is now encrypted like `private-credentials` (its
  Collection declares the `edv` marker; the server permits the late
  declaration on existing Spaces). A one-time local migration re-keys
  never-synced plaintext rows into envelopes at login, before replication
  starts (the server rejects plaintext pushes to a marked collection);
  legacy plaintext rows replicated from pre-marker Spaces stay readable
  through tolerant read paths. Guest sessions encrypt locally too.

- **Background WAS replication.** A new
  collection-agnostic replication adapter (`src/lib/sync/`) drives an RxDB
  `replicateRxCollection` state machine against a remote WAS Collection's
  `changes`-feed (`POST .../query`) + conditional-write (`PUT`/`DELETE`/`PUT
.../meta`) endpoints. The core (`wasReplication`, `changesQuery`, `pushWrites`,
  `syncedDocSchema`) has no React or `@interop/was-client` imports -- all WAS
  access is injected through a small `WasSyncPort` seam (
  `src/stores/wasSyncPort.ts`),
  so it can later be extracted to a standalone `was-rxdb-replication` library.
  The port drives the raw signed `was.request()` escape hatch, moving stored
  bodies **verbatim** (codec-bypassing). The generic synced-doc schema carries
  both a content revision (`version`/`data`) and an independently-versioned
  metadata
  sub-resource (`metaVersion`/`custom`), matching the server's V2
  encrypted-metadata change-feed contract.
- **SyncController + per-collection status.** `src/stores/syncController.ts`
  starts replication on login (skipped for guests / when no remote replica is
  configured), cancels on logout, and re-syncs on `window` `online`; a Zustand
  `syncStatusStore` surfaces per-collection status
  (`idle`/`syncing`/`synced`/`error`) driven off the replication `active$` /
  `error$` streams, shown on the Settings page. Reachability is inferred from
  replication itself (no health poll). Syncs `public-credentials`;
  `VITE_WAS_SERVER_URL` is re-interpreted as "a remote replica is available."
  New optional env knobs `VITE_WAS_SYNC_RETRY_MS` and
  `VITE_WAS_SYNC_BATCH_SIZE`.

## 0.12.0 - 2026-07-01

### Added

- Support **DID Authentication** in the CHAPI `/wallet/get` popup. Incoming VC
  API messages are now classified and dispatched by a new framework-agnostic
  `src/lib/walletRequest/` module (message types, `classify`, `processRequest`,
  `composeVp`, `presentationSuite`), so a request can be a plain VC share, a
  DID-Auth-only proof, or a combined VC-share + DID-Auth. DID-Auth responses are
  **signed** Verifiable Presentations proving control of the user's `did:key`
  over the request's `challenge`/`domain`, honoring the verifier's
  `acceptedCryptosuites` (`eddsa-rdfc-2022` / VC 2.0) and falling back to the
  wallet default `Ed25519Signature2020` (VC 1.0). The wallet enforces the VCALM
  domain-binding advisement (the request `domain` must match the channel origin)
  and only satisfies requests whose `acceptedMethods` allow `key`. Adds
  dependencies `@interop/vc`, `@interop/data-integrity-proof`, and
  `@interop/security-document-loader`.

- End-to-end encrypt the remote `private-credentials` collection using the new
  EDV-over-WAS capability in `@interop/was-client` (`0.9.x`, opt-in `/edv`
  subpath). The WAS server now only ever stores opaque JWE envelopes for private
  credentials, while the Dashboard transparently decrypts and lists them. A
  deterministic X25519 key agreement key (added dependency
  `@interop/x25519-key-agreement-key`) is derived from the passphrase -- the
  Montgomery form of the existing Ed25519 signing key -- and threaded onto
  `Session.profile`, so a returning user re-derives the same key and can decrypt
  their vault. Encryption is supplied via a per-handle override at the one site
  that opens the private collection (`WASRemoteStore._collection()`), and the
  collection is also declared with a server-side `encryption` marker at creation
  so it is self-describing (a future client/delegate can discover it is
  encrypted and supply its own keys); other collections stay plaintext.
  Credentials in encrypted mode are now keyed by the
  EDV-minted (opaque) id rather than the content cid; public sharing remains
  plaintext and content-addressed (keyed by the cid computed from the decrypted
  VC).
- Show an on-screen error on the login page when the remote WAS storage server
  is unreachable, instead of silently failing (the login spinner used to just
  stop). The message offers a link to guest mode as a fallback
  (`auth.errors.storageUnreachable`, detected via the new
  `isStorageUnreachable()` helper in `src/lib/storageErrors.ts`). Other login
  failures now surface the generic `auth.errors.setupFailed` message rather than
  throwing uncaught.
- Extend the same unreachable-storage handling to the signup page (offers the
  guest-mode fallback) and to the CHAPI `wallet/get` and `wallet/store` popups
  (which now show `chapi.storageUnreachable` / `chapi.loginFailed` instead of
  hanging on a stuck spinner).

### Fixed

- Guest mode now always uses local browser storage and never contacts the remote
  WAS server, matching its documented design. Previously, when
  `VITE_WAS_SERVER_URL` was set, guest login would also fail if that server was
  unreachable -- making it useless as a fallback.
  `StorageManager.initStorageClients`
  now skips the remote backend for guest sessions.

### Changed

- Upgrade the `@interop/*` forks to their latest published versions.
  The app's import contract is unchanged.
- Upgrade `@zxcvbn-ts/*` to 4.x (`core` `^3.0.4` -> `^4.1.1`, `language-common`
  `^3.0.4` -> `^4.1.1`, `language-en` and `language-es-es` `^3.0.2` ->
  `^4.1.0`). 4.x replaces the `zxcvbn()` / `zxcvbnOptions.setOptions()`
  singleton
  API with a `ZxcvbnFactory` class, so `PasswordStrengthMeter` is rewired to
  construct a factory and call `.check(password).score`.

## 0.11.0 - 2026-06-15

### Performance

- Speed up initial page load and eliminate the blank-screen wait. `index.html`
  now renders a lightweight, theme-aware CSS spinner shell that paints instantly
  before any application JavaScript parses (`main.tsx` removes it once React has
  mounted). All routes except the lightweight `LandingPage` are now
  `React.lazy()` code-split (wrapped in a single `<Suspense>` with a new
  `RouteFallback` spinner), so heavy dependencies (`rxdb`, `jsonld`,
  `verifier-core`, `qr-scanner`) no longer load on first paint. `vite.config.ts`
  adds `manualChunks` to split `react`/`react-dom`/`react-router` and
  `@mui`/`@emotion` into stable, separately-cacheable vendor chunks. The
  critical-path bundle for `/` drops from a single ~1.8 MB chunk to ~250 KB
  gzipped.

### Changed

- Replace the unmaintained `react-password-strength-bar` dependency with a
  `PasswordStrengthMeter` component backed by the maintained `@zxcvbn-ts`
  packages. The zxcvbn dictionaries are loaded on demand via dynamic `import()`
  so they are code-split out of the initial bundle and only fetched when the
  signup page's meter mounts; the matching Spanish dictionary is loaded when the
  active locale is Spanish. See the README Deployment section for the Nginx
  `try_files` configuration recommended for code-split chunks.
- Refactor `WASRemoteStore` to perform all remote Wallet Attached Storage
  operations through `@interop/was-client`'s `WasClient` and its lazy
  navigational handles (`space` / `collection` / `resource`) instead of
  hand-built `@interop/ezcap` `ZcapClient.request` calls. The store now wraps
  the user's `ZcapClient` in a `WasClient` and addresses spaces, collections,
  and resources via the handle model (`describe`/`configure`/`list`/`get`/
  `put`/`delete`), relying on the client's built-in 404-to-`null` read
  semantics and typed errors. Space and collection creation use the idempotent
  `configure()` upsert.
- `wipeStorage()` no longer takes a `profile` argument -- the signer is carried
  by the wrapped client. Space export keeps streaming the tar archive straight
  to disk: rather than `space.export()` (which buffers the whole archive into
  memory), `exportSpace()` uses the WAS client's raw-request escape hatch and
  returns the response `body` `ReadableStream`, preserving the prior behavior.
- Replace the unmaintained `microlight` dependency (last published at `0.0.7`)
  with `prism-react-renderer` via a new shared `JsonHighlight` component. The
  raw-JSON source views (`CredentialDetail`, `ResumeCredentialCard`,
  `CollectionResourcePage`, `CollectionContentsPage`) now render highlighted
  tokens as React nodes, removing the imperative `microlightReset()` /
  `requestAnimationFrame` DOM-scanning pattern.

## 0.10.0 - 2026-06-06

### Fixed

- Stop silently swallowing remote-storage failures in `WASRemoteStore`. The
  catch blocks in `addCollectionResource`, `listCollectionItems`,
  `deleteCredential`, and `wipeStorage` now rethrow after logging instead of
  masking the error (or, in `listCollectionItems`, crashing on an `undefined`
  response). `fetchDocument` still treats a `404` as "not found" (returns
  `undefined`) but rethrows network/auth/server errors so they are no longer
  mistaken for a missing document. Removed the unconditional
  `"Remote space deleted."` success log on wipe failure.
- Surface those failures in the UI: `AcceptCredentialsPage`, `SettingsPage`,
  `CredentialDetailPage`, `IssuerDetailPage`, `SignupPage`, and `GuestLoginPage`
  now show an error message instead of leaving the user hanging. In particular,
  `SettingsPage` no longer logs the user out as if the wipe succeeded when the
  remote deletion failed.

### Changed

- Replace `@digitalcredentials/verifier-core` with the TypeScript fork
  `@interop/verifier-core`. The fork un-bundled the convenience checks into a
  composable suite pipeline, so the removed expiration check and the rich
  issuer-registry lookup are re-added as custom suites
  (`src/lib/verifierSuites/`); `verify.ts` now adapts the fork's
  `CredentialVerificationResult` back into the wallet's internal verification
  payload so the view layer is unchanged. Rich issuer metadata is sourced from
  `@digitalcredentials/issuer-registry-client`.

## 0.9.0 - 2026-06-04

### Added

- Add a separate WAS-integration e2e project (`pnpm run test:e2e:was`) that
  boots
  a local `was-teaching-server` and exercises the remote (WAS) storage path.

### Changed

- Replace `@digitalcredentials/ssi` with `@interop/data-integrity-core` and
  `@digitalcredentials/ed25519-signature-2020` with
  `@interop/ed25519-signature`.
- Replace `@digitalcredentials/ezcap`, `@digitalcredentials/http-client`, and
  `@digitalcredentials/security-document-loader` with their TypeScript
  `@interop/` forks.
- Run the local-mode e2e suite on a dedicated port with a fresh server and
  local (IndexedDB) storage pinned, so a separately-running dev server can no
  longer be reused and cause failures.

### Fixed

- Fix the logout page firing redundant, deferred redirects (from a React
  StrictMode double-invoke and an effect re-run when the session cleared), where
  a late redirect could navigate away from a page the user had already moved to.
  Logout now runs once and redirects once.
- Fix a flaky login e2e test where the freshly-navigated login form could
  remount and clear the typed passphrase before submit.

### Removed

- Remove support for VPQR decoding.

## 0.8.0 - 2026-05-20

### Added

- Add issuer detail functionality and enhance credential verification
- Add credential JSON upload functionality, including error handling and
  localization updates for English and Spanish. Introduce a maximum file size
  limit for uploads and refactor error messaging in the AddCredentialPage and
  ScanCredentialQrDialog components.

## 0.7.0 - 2026-05-18

### Added

- Add QR code scanner.

## 0.6.1 - 2026-05-16

### Added

- Add routing to VC viewer for resource browser.

## 0.5.0 - 2026-05-14

### Added

- Add storage browser UI (refactor Collections view, add resource listing
  view).

## 0.4.0/0.4.2 - 2026-05-14

### Added

- Add Internationalization/Translation (i18n) support.
- Add support for English and Spanish.

## 0.3.0 - 2026-05-13

### Added

- Add Export Wallet button on the Storage page.
- Add List Collections functionality to Storage page.
- Add Light and Dark mode styles.

## 0.2.0 - 2026-05-11

### Changed

- **BREAKING**: Update data structure in fetchAll method to use 'items' instead
  of 'rows' in storageManager.

## 0.1.2 - 2026-04-29

### Added

- Add getContacts() placeholder function and routes
- Add StoragePage route and update DashboardLayout navigation structure

## 0.0.1 - 2026-03-16

### Added

- Initial commits
