# History

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
