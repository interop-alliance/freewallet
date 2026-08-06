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
`/home/dmitri/code/Interop/was-teaching-server`. Its AGENTS.md has the
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

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in
@CONTRIBUTING.md -- follow them.
