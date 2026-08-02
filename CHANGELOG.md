# History

## Unreleased - TBD

### Added

- **Recovery codes** (`/recover`, Settings > "Recovery codes"): a 16-byte
  base58 code, shown exactly once at issuance, that restores the whole
  account from a fresh browser when the passphrase and every connected
  browser are lost. A code is a minimal always-enrolled wallet client whose
  entire key set derives from its bytes: its decryption standing (a
  published key-agreement entry in the DID document plus a per-user-key
  wrap) is maintained for free by rotation, while its authority stays
  latent until the code is typed -- so any use of a code must first extend
  the world-readable account log. Recovering enrolls a brand-new ordinary
  client, retires the spent code (a typed code is a spent credential,
  presumed compromised), rotates the per-user key off it, and pushes a
  replacement code that must be confirmed saved -- ending in an ordinary
  enrolled login under a freshly chosen passphrase. Entry points: "Forgot
  your passphrase?" on the login page and a pointer on the signup page.
  Revoking a code from Settings is a real revocation -- the code resolves
  to nothing afterwards, everywhere -- and a login-time health check warns
  when a stored recovery delegation has rotted and would brick recovery.
  Spending or revoking a code re-epochs every encrypted collection onto
  the fresh per-user key (the same cascade client revocation runs), so
  writes stop landing under epochs the spent or revoked code could read;
  revoking from Settings also adopts the rotated key into the live session
  in place. Design details in ARCHITECTURE.md ("Recovery codes").

- **Client revocation** (`revokeEnrolledClient` in `src/session/revocation.ts`):
  disconnecting an enrolled wallet client from the account, run entirely in
  the revoking client as one synchronous cascade in dependency order. The
  revoked client's verification methods, update key, and standing
  commitments leave the account's DID document in a single log entry --
  under the current-key-set rule that one edit stops the revoked client's
  requests, and every delegation and app grant it ever signed, from
  verifying anywhere. The per-user key then rotates off the revoked
  client's wrap in the roster, every encrypted collection re-epochs onto
  the fresh key in parallel (revoked key generations retired, history
  escrowed, so every other replica keeps decrypting across the rotation),
  and the recovery delegations the revoked client had signed -- which
  stopped chaining at the document edit -- are re-minted by the revoking
  client. The revoking session adopts the fresh key in place (no re-login),
  a wallet-activity record is written, and the cascade converges under a
  naive full re-run: every stage detects completion from durable state
  alone, so a mid-cascade crash strands nothing. The Settings surface for
  it ships separately; the honest ceiling is unchanged -- ciphertext the
  revoked client already fetched stays readable to it.

- A **per-user key (PUK)** is now minted at wallet provisioning:
  client-side, never server-held, replacing the passphrase-seed-derived
  vault KAK as "recipient zero" of every encrypted collection. It is cached
  locally under the unlock layer, so every unlock method recovers it at
  login and a passphrase change preserves it. Its one remote home is a
  **wrap-set roster** (`key-map/puk.json`, outside the synced collections):
  the roster's current key epoch IS the current PUK, wrapped once per
  enrolled client, and login confirms the cached copy current or adopts a
  rotated one. Three client-side guards defend the roster against a
  tampering host: an authenticated epoch configuration (`epochsMac`), a
  locally pinned latest-seen epoch (a rolled-back roster is refused), and
  rotation recipients resolved only from the locally verified did:webvh
  document. Accounts provisioned before the PUK keep the seed-derived key
  until re-provisioned. See ARCHITECTURE.md ("The PUK wrap-set roster").

- **A second browser can now be connected to an existing account** -- the
  client enrollment ceremony. The new browser's "not enrolled" login offers
  "Connect this browser": it mints its whole key set locally and displays a
  compact **connect code** carrying only public halves (QR-renderable
  unchanged); an already-connected browser approves it from Settings >
  "Enroll another wallet", both screens showing the new client's did:key
  fingerprint for comparison first. Any single enrolled client can enroll,
  no secret ever transits a server or the code, there is no
  authorized-but-blind window, and every stage is idempotent -- re-running
  the same code after an interruption converges without forking the account
  log. See ARCHITECTURE.md ("The client enrollment ceremony").
- On signup, pre-seed the user's Contacts collection with default records
  (InteropAlliance.org and the user themselves) and their DIDs.
- A capability request can now ask to **share** one of the wallet's own
  encrypted collections: a `urn:was:shared-collection` invocation-target
  descriptor grants read _and decrypt_ access, where the ordinary
  collection grant only ever hands over ciphertext. Approving it makes the
  grantee a recipient of the collection's key epochs and delegates it a
  read-only capability in a single indivisible step, so the two halves can
  never come apart. Only the encrypted standard collections can be shared
  (today: `private-credentials`, `wallet-activity`, `contacts`, and
  `contacts-history`); a share of a plaintext collection, an app collection,
  or the whole Space is refused, as is a request whose grantee's DID has no
  key the wallet can derive a recipient key from. The grantee's
  decryption key is never carried in the request -- it is derived locally from
  the `did:key` the request already names as the capability's controller, so a
  request cannot pair one entity's DID with another's key.
- The CHAPI consent screen renders a share request unmistakably differently
  from an ordinary storage grant: a heavier border and a filled callout saying
  the grant covers reading _and_ decrypting, that it covers the collection's
  contents from the moment of approval rather than only future writes, and --
  stated before approval, not after -- that removing access later stops future
  reads but cannot take back anything already read. The expiry line is
  share-specific: it says the _fetch_ permission expires, since the ability to
  decrypt does not lapse on its own. Both the generic and the App Connect
  consent panels get it (English and Spanish).
- A share granted through App Connect records the app's name and origin, so
  Settings > Shared collections lists "Text Editor (app.example)" above the
  reader's DID instead of showing the DID alone.
- `VITE_SHARE_ZCAP_TTL_HOURS` (default 365 days) sets the lifetime of a share's
  capability. It is deliberately long: expiry is the wrong removal mechanism
  for a share (it would end the fetch axis while leaving the grantee in the key
  roster), so the Settings panel's "Remove access" -- which rotates the epoch
  and revokes the capability together -- is the way a share ends.

### Changed

- **BREAKING**: All BYOE-layer wire vocabulary moves from the retired
  `urn:was:` / `urn:freewallet:vocab#` schemes to the shared
  `https://w3id.org/byoe#` namespace: the app-key credential's marker type
  and claim terms (`#AppKeyCredential` / `#seed` / `#origin`, now imported
  from the published `byoe-context` package), the capability-descriptor
  types matched by `processZcaps` (`#collection` / `#public-collection` /
  `#shared-collection` / `#space`), and -- via the shared `composeVp`
  default -- the response VP's embedded `#zcap` / `#appConnect` terms.
  Token spellings and JSON keys are unchanged; matching is literal string
  equality on both sides, so this lands in lockstep with the
  `@interop/was-react` release carrying the app-side renames. Pre-release,
  no migration path: test accounts re-provision.

- The Collection Description's `encryption` member is now called an
  **encryption descriptor** throughout (previously "marker"), following the
  spec wording: identifiers (`localStorageDescriptorCache`,
  `#refreshDescriptors`, the `descriptors` constructor option, the
  `{ descriptor, zcap }` share return shape), prose, and the consumed
  `@interop/wallet-core` `/descriptors` subpath and
  `@interop/was-client` `/edv` descriptor-store exports. The app-key
  credential marker type, the App Connect response marker, and the local
  one-time-migration markers are unrelated senses and keep their names; the
  `freewallet:collection-encryption:` localStorage keys are term-neutral
  and unchanged.

- **The account identity, unlock, and enrollment machinery now comes from
  `@interop/wallet-core`** instead of being maintained here: did:webvh
  hosting and its ZCap signing identities (`/webvh`), the per-user key and
  its wrap-set roster (`/keys`), the unlock derivation and unlock Space
  lifecycle (`/keyring`), the enrollment ceremony (`/enrollment`), recovery
  codes (`/recovery`), the collection-encryption descriptor acquisition and
  its unknown-epoch refresh policy (`/descriptors`), and the shared
  system-collection and resource names (`/space`). Behavior, wire formats,
  and stored records are unchanged --
  they are shared contracts now, so a second wallet reading the same account
  agrees with this one by construction. The freewallet-specific glue (the
  `freewallet-session` IndexedDB layer, the unlock-methods registry, the
  KMS-driven did:web provisioning) stays here.

- **The shared account data seed is retired; each client now holds its own
  key set**, minted locally on first run, with private halves that never
  leave the client. The keyring record in each unlock Space now carries only
  an encrypted **account pointer** `{ did, spaceId, host }` in place of the
  retired wrapped seed; the unlock layer (whose shape is unchanged) protects
  the local client-key record instead. Logging in therefore stops being
  sufficient to BE the account: a passphrase on a fresh browser locates the
  account but surfaces a distinct "this browser does not hold the account's
  keys" state, from which the login page offers the enrollment ceremony (a
  storage-partitioned CHAPI popup stays degraded). Each client also pins the
  account pointer it has seen and refuses a substituted one. Records written
  under the old seed-carrying shape are refused as unusable (accounts are
  re-provisioned, not migrated).

- **The account's stable identity is now a `did:webvh`, and its DID document
  is the roster of that account's enrolled wallet clients** -- a
  hash-chained log, world-readable in the `id` collection, that anyone can
  fetch and fully verify. The log's update keys are client-held (one per
  enrolled client, prerotation on), so the storage server can never extend
  the account's own history, and no server-held key is ever a recipient of
  an encrypted collection. The Space's controller -- and the KMS keystore's,
  non-fatally -- is promoted to the did:webvh at signup (a signup
  interrupted mid-promotion heals on the next login), after which the server
  authorizes by verifying the published log: a capability verifies only
  against the keys the document lists _now_, so dropping a client from the
  roster stops everything it signed from verifying. Sessions on a promoted
  account sign with the client key under its did:webvh verification-method
  id; the user id shown to connecting apps stays the client's `did:key`, and
  the unlock layer stays `did:key` end to end. See ARCHITECTURE.md ("The
  did:webvh identity").
- One rule now decides who a key-epoch recipient is: the X25519 twin of a
  controller `did:key`, for an app and a person alike. An App
  Connect-provisioned private collection now admits the app with its identity
  key, derived from the subject DID the wallet is already delegating to,
  instead of a per-collection key derived from the app-key seed -- the seed no
  longer enters the grant path at all. Apps must be on `@interop/was-react`
  with the matching change; collections encrypted under the old
  per-collection keys are not migrated.
- What a delegated capability may be granted is now a per-target-class table
  rather than a single read-only/pass-through switch. Every target a request
  resolves onto falls into exactly one class, and each class has a ceiling the
  requested actions are intersected against: the whole Space, a protected
  wallet collection (the standard collections plus the `id` and `key-map`
  collections), and a share stay read-only, an app-provisioned **public**
  collection is now add-only (`GET`/`HEAD`/`POST`), and an app-provisioned
  private collection keeps the full vocabulary under the consent screen and
  the shorter write TTL. The public cap is the user-visible change: a
  world-readable plaintext collection is a publication surface, not a data
  store, and a write there is irreversible in practice (retracting removes the
  link, not the copies already fetched), so an app may add to what it
  published but can no longer be granted `PUT` or `DELETE` to rewrite or
  retract it.
- Requested actions are now intersected against the closed action vocabulary
  the WAS spec fixes (`GET`, `POST`, `PUT`, `DELETE`, plus `HEAD` kept as a
  tolerated read alias, since the spec authorizes a `HEAD` request as a `GET`
  and the wallet has always minted it alongside `GET` in every read grant).
  Previously a requested token was array-wrapped and stringified, so anything a
  site put in `allowedAction` became the `allowedAction` of a capability the
  user's root key signs -- including every action a server might grow support
  for later, retroactively and with no wallet-side review. Unknown verbs and
  non-string entries are now dropped, the same fail-closed treatment an unknown
  invocation-target descriptor type already got; the surviving actions are
  uppercased, deduplicated, and emitted in a stable order, so an equivalent
  request always yields the same grant.
- A request asking only for actions its target forbids is now refused visibly
  instead of being silently downgraded. Where such a request previously came
  back as a read grant nobody asked for, the consent screen now shows it as
  "cannot fulfill" and nothing is delegated -- which is both more honest to the
  user and necessary, since an empty `allowedAction` array means "every action"
  in the capability model and must never be signed.
- The wallet now refuses to store a credential that claims to be an app key
  but is not one. Every app key it mints carries a shared `AppKeyCredential`
  marker type (one stable IRI for every app), and a credential carrying that
  marker is stored only when its subject DID derives from the seed the
  credential itself carries -- so a planted app key is turned away at the door
  rather than sitting in the credential list, showing up in the storage
  browser, and replicating to the user's Space while being quietly ignored.
  The refusal applies to every path a credential can arrive on from outside:
  the CHAPI store popup, and the URL / QR / manual-paste import. The marker is
  also required at match time, so a credential can only reach the delegation
  path by carrying it. An ordinary credential that merely happens to have a
  `seed` or `origin` claim carries no marker and is never caught, and a
  genuine app key still stores.
- An app-key credential's `seed` and `origin` claims now carry shared
  `urn:was:seed` / `urn:was:origin` IRIs instead of ones namespaced under each
  app's `vocabBase`: they mean the same thing in every app, so two apps' keys
  no longer make semantically identical claims under different IRIs. The JSON
  shape is unchanged (`credentialSubject.seed` / `.origin` keep their keys);
  the app's `vocabBase` now namespaces only its own type term.
- An App Connect request now only matches a stored app-key credential whose
  subject DID is the one its own seed derives. Previously any self-issued
  credential carrying the right type and origin qualified, and candidates were
  ranked newest-first on an issuance date the credential itself states -- so a
  credential planted through the store popup or a manual import could win the
  match and have its DID become the identity the wallet delegates capabilities
  to. The check is local (the credential carries the seed, so the wallet
  re-derives and compares) and fails closed: an absent, malformed, or
  wrong-length seed simply does not match.
- Aligned with the current `@interop/social-core` contact model: a postal
  address spells its fields `postalCode` and `poBox`, and carries the
  administrative subdivision as `region` only (a separate `state` folds into
  `region` when `region` is absent). Stored contact head and revision
  documents are upgraded to the current shape as they are read, so contacts
  written by an earlier version compare cleanly against a fresh write and
  last-write-wins sees no spurious edit; writes always produce the current
  shape.
- Editing a contact no longer strips the extra phone/email fields an importer
  recorded (`digits`, `countryCode`, entry ids): they are carried through a
  save, and the number-derived `digits` / `countryCode` are dropped only when
  the number itself is edited.
- Updated `@interop/did-method-webvh` to 5.0.0. Newly created did:webvh DID
  documents no longer carry empty verification-relationship arrays, so a
  freshly provisioned Space gets a different self-certifying identifier (SCID)
  than an earlier version would have minted for the same keys. Already
  published logs are unaffected -- they keep resolving, and a Space whose log
  is already published adopts that log's DID rather than re-creating it.

### Fixed

- A capability request naming a plain URL is now parsed and normalized against
  the user's Space instead of being matched by string prefix. The prefix test
  could be walked past: `<space URL>/private-credentials?x=1` starts with the
  Space URL and so classified as the requesting site's own collection, earning
  the full write ceiling on the user's own credentials collection -- the exact
  target the read-only cap exists to protect. A target must now parse as a URL
  on the Space's origin, resolve to a path inside the Space (dot segments that
  escape it are refused), carry no query string or fragment, and name a valid
  collection in its first path segment; the Space URL itself, with or without a
  trailing slash, is a whole-Space grant. A target carrying a query or fragment
  is refused outright rather than quietly rewritten, since showing the user one
  target on the consent screen and delegating another would defeat the point of
  asking.

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
