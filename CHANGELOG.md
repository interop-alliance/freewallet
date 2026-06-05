# History

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
