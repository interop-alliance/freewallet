# Agent Guidelines

## Project Overview

Freewallet is a browser-based **W3C Verifiable Credentials (VC) wallet**. It
lets users store, view, verify, and share VCs. It integrates with the
[CHAPI](https://chapi.io) (Credential Handler API) browser standard so that
third-party websites can request or deliver credentials through a browser
popup without sharing the user's passphrase. All wallet data lives in local
IndexedDB (the active replica); optionally, a remote **Wallet Attached Storage
(WAS)** server is configured as a sync target that the wallet replicates to in
the background.

The companion WAS server lives at
<https://github.com/interop-alliance/was-teaching-server>. Its
[AGENTS.md](https://github.com/interop-alliance/was-teaching-server/blob/main/AGENTS.md)
has the
authoritative description of the WAS protocol, Space/Collection/Resource data
model, and ZCap authorization model.

## Tech Stack

- **React 19** with **TypeScript**, bundled by **Vite**
- **MUI (Material UI) v9** for UI components
- **React Router v7** for client-side routing
- **Zustand** for global session state (`src/stores/authStore.ts`)
- **RxDB + Dexie (IndexedDB)** for local wallet storage -- the always-active
  replica (`BrowserStore` in `src/stores/browserStore.ts`)
- **`@interop/webkms-client`** (`CapabilityAgent`, `KmsClient`,
  `KeystoreAgent`) for key derivation and WebKMS keystore access
- **`@interop/ezcap`** (`ZcapClient`) for ZCap-signed HTTP requests
- **`credential-handler-polyfill` / `web-credential-handler`** for CHAPI
- **`@digitalcredentials/verifier-core`** for credential verification
- **`react-i18next`** for internationalisation (locales: `en`, `es`)
- **`pnpm`** as the package manager; **`vitest`** for unit tests,
  **`playwright`** for e2e tests

## Architecture

The layer map, session and auth flow, storage model (local-first), CHAPI and
App Connect flows, route map, the shared-logic map (what lives in
`@interop/wallet-core` and the other `@interop/*` packages rather than
app-side), domain glossary (VC / VP / DID / Space / Collection / Resource),
and ZCap authorization structure live in @ARCHITECTURE.md -- read it before
making changes.

## Environment Variables

The authoritative table of environment variables (all optional; the app runs
without any set) lives in [README.md](README.md#environment-variables). Keep
that table up to date when adding or changing a variable.

## Roadmap & Task Conventions

Roadmap tracking lives in `_spec/ROADMAP.md` (a local, gitignored planning
dir): narrative context plus structured `### FW-N` work items, following the
item structure shared with the isomorphic-lib-template and dcw roadmaps.
Never create a parallel task list elsewhere. The full item schema lives in
that file's header; the rules that apply when working an item:

- Item ids are permanent and never reused; a new item takes the next unused
  number regardless of section.
- Statuses are edited in place; acceptance checkboxes are ticked as they are
  met.
- **Completing an item includes archiving it**: in the same pass that marks
  it `done`, move it verbatim (number, title, field block, prose, with its
  `done` date) from `_spec/ROADMAP.md` to
  `_spec/historical/archived-roadmap.md`, append-only at the bottom. A `done`
  item left in ROADMAP.md is an unfinished task. CHANGELOG.md remains the
  record of what landed; do not rewrite or summarize items on the way into
  the archive.
- Work discovered mid-implementation gets its own FW-N item immediately,
  noting `discovered-from: FW-N` in its prose.

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in
@CONTRIBUTING.md -- follow them.

## Reference material (read-only, outside this repo)

These are separate repositories. Use them to ground changes against the specs
and the shared libraries' actual source -- check with the user before editing
anything in them. (If a repo happens to be checked out beside this one, read
it locally instead of fetching.)

- [wallet-attached-storage-spec](https://github.com/w3c-ccg/wallet-attached-storage-spec)
  -- the WAS spec: the Space / Collection / Resource model, the HTTP API, and
  the zCap authorization profile.
- [app-connect-spec](https://github.com/interop-alliance/app-connect-spec)
  -- the App Connect companion spec: the `AppConnectQuery`, the app-key
  credential, descriptor vocabulary and action ceilings, and the response
  presentation. The normative wire contract for `src/lib/walletRequest/`.
- [encrypted-collections-spec](https://github.com/interop-alliance/encrypted-collections-spec)
  -- the WAS Encrypted Collections profile: envelope cryptography, key
  epochs, and recipient-key derivation.
- [wallet-core](https://github.com/interop-alliance/wallet-core) --
  `@interop/wallet-core`, the shared wallet layer (see "What lives elsewhere"
  in ARCHITECTURE.md); its own `ARCHITECTURE.md` maps the module layers, key
  hierarchy, and ceremonies.
- [was-client](https://github.com/interop-alliance/was-client) /
  [was-teaching-server](https://github.com/interop-alliance/was-teaching-server)
  -- the WAS HTTP client (plus the EDV cipher and sync wire contract) and the
  companion server; the server's AGENTS.md is the authoritative protocol
  description.
- [was-react](https://github.com/interop-alliance/was-react) -- the
  app-side half of App Connect and shared-collection reading; what a BYOE app
  runs against the capabilities this wallet grants.
- dcw (private repo) -- the sibling mobile wallet built on the same
  `@interop/wallet-core` ceremonies; the cross-wallet interop check.
- [zcap-developer-guide](https://github.com/interop-alliance/zcap-developer-guide)
  -- how zCaps (delegation, invocation, verification, root-of-trust) actually
  work. Consult before changing anything about authorization.
