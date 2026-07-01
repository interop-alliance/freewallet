# History

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
  unreachable -- making it useless as a fallback. `StorageManager.initStorageClients`
  now skips the remote backend for guest sessions.

### Changed

- Upgrade the `@interop/*` forks to their latest published versions.
  The app's import contract is unchanged.
- Upgrade `@zxcvbn-ts/*` to 4.x (`core` `^3.0.4` -> `^4.1.1`, `language-common`
  `^3.0.4` -> `^4.1.1`, `language-en` and `language-es-es` `^3.0.2` ->
  `^4.1.0`). 4.x replaces the `zxcvbn()` / `zxcvbnOptions.setOptions()` singleton
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

- Add a separate WAS-integration e2e project (`pnpm run test:e2e:was`) that boots
  a local `was-teaching-server` and exercises the remote (WAS) storage path.

### Changed

- Replace `@digitalcredentials/ssi` with `@interop/data-integrity-core` and
  `@digitalcredentials/ed25519-signature-2020` with `@interop/ed25519-signature`.
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
