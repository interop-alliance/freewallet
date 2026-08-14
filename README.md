# Freewallet

[![Node.js CI](https://github.com/interop-alliance/freewallet/workflows/CI/badge.svg)](https://github.com/interop-alliance/freewallet/actions?query=workflow%3A%22CI%22)

> An open source, open standards web application for managing Verifiable
> Credentials, DIDs, and cryptographic keys.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Security](#security)
- [License](#license)

## Background

See:

- [Wallet Attached Storage Specification](https://w3c-ccg.github.io/wallet-attached-storage-spec/)
- [ARCHITECTURE.md](ARCHITECTURE.md) -- layer map, session/auth flow, storage model, CHAPI and App Connect flows, glossary
- [CONTRIBUTING.md](CONTRIBUTING.md) -- code style, JSDoc, comment, and error-handling conventions

### Supported Features

#### Passkey unlock

Alongside the passphrase, an account can be unlocked with a **passkey**
(WebAuthn). You can sign up with a passkey, log in with one, and add, rename,
or remove passkeys from Settings. A passkey is a peer unlock method with full
account control -- not a second factor -- and is phishing-resistant because it
is bound to the app's origin. There is no login server and no server-side
WebAuthn verification: the passkey's PRF-extension output feeds a key
derivation that unlocks the wallet locally, so nothing about the passkey is
stored or checked remotely. Passkey unlock needs the WebAuthn PRF extension,
which some browsers and platforms do not provide; the passphrase is always
offered as a fallback. Settings shows a Synced / Sync available / Not synced
badge per passkey, since a not-synced passkey lost with its device cannot
recover the wallet. See [`public/docs/passkeys.md`](public/docs/passkeys.md)
for the full compatibility and recovery story. Optionally set
`VITE_PASSKEY_RP_ID` to scope passkeys across subdomains (changing the origin
or RP ID orphans every registered passkey).

### Tech Stack

Development:

- Javascript/TypeScript, Node.js 22+
- React + ReactDOM 19
- React Router 7 (in library mode), using `HashRouter`
- `zustand` for state management
- Vite 8 bundler (so it can deploy as a static SPA)
- Prettier for code formatting, and React-aware eslint for linting

## Install

```
pnpm install
```

## Usage

### Starting the Server

```
npm start
```

### Environment Variables

All are optional; the app runs without any set (local storage, no remote server).

| Variable                       | Default                                    | Purpose                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`                         | _(Vite default)_                           | Used by Docker, Dokku, etc. Automatically handled by Vite.                                                                                                                                                                                                                                                                                                                                        |
| `VITE_WAS_SERVER_URL`          | _(none)_                                   | Remote [WAS](https://w3c-ccg.github.io/wallet-attached-storage-spec/) server URL. **Setting this attaches a remote replica: local collections replicate to it in the background.** If not provided, the app runs in a local-only mode (storing VCs in browser IndexedDB).                                                                                                                         |
| `VITE_KMS_SERVER_URL`          | `<WAS server>/kms`                         | WebKMS server URL. Set only when the KMS is hosted separately from the WAS server; no WAS server and no explicit value means no KMS.                                                                                                                                                                                                                                                              |
| `VITE_KEYRING_CACHE_TTL_HOURS` | `168`                                      | Offline-fallback lifetime of the locally cached keyring record when a WAS server is configured (the remote copy is consulted first on every login). No effect in no-WAS deployments, where the cache is the keyring's only copy.                                                                                                                                                                  |
| `VITE_PASSKEY_RP_ID`           | _(none)_                                   | WebAuthn Relying Party ID for passkey ceremonies. When unset, the page origin's registrable domain applies. **Changing the origin or the RP ID orphans every registered passkey.**                                                                                                                                                                                                                |
| `VITE_RP_ZCAP_TTL_HOURS`       | `720`                                      | Lifetime of a read-only capability delegated to a relying party on an approved "Login with Wallet" zcap request. Expiry is the sole limiter on RP grants (no Space-side revocation endpoint).                                                                                                                                                                                                     |
| `VITE_RP_ZCAP_WRITE_TTL_HOURS` | `168`                                      | Lifetime of a _write_ capability delegated to a relying party (a grant on an RP-provisioned collection whose actions go beyond GET/HEAD). Deliberately shorter than the read-only TTL.                                                                                                                                                                                                            |
| `VITE_SHARE_ZCAP_TTL_HOURS`    | `8760`                                     | Lifetime of the read-only capability delegated by a _share_ grant (a `https://w3id.org/byoe#shared-wallet-collection` request, which also adds the grantee to the collection's key-epoch roster). Deliberately long: the Storage page's shares dialog, not expiry, is the removal mechanism -- expiry would kill the fetch axis while leaving the grantee in the roster.                          |
| `VITE_SERVER_URL`              | `http://localhost:5173`                    | This app's own URL (used for CHAPI registration).                                                                                                                                                                                                                                                                                                                                                 |
| `VITE_DEPLOY_URL`              | _(none)_                                   | Public deploy URL registered with the CHAPI mediator.                                                                                                                                                                                                                                                                                                                                             |
| `VITE_CORS_PROXY_URL`          | `<WAS>/api/cors` or `https://corsproxy.io` | CORS proxy base URL for every cross-origin fetch the wallet makes on a user-supplied URL -- pasting a VC URL into the Add Credential box, and the known-issuer registries fetch used during verification. The target is appended as `?url=`. Defaults to the WAS server's `/api/cors` facet when a WAS server is configured, otherwise `https://corsproxy.io`; unset means the fetch goes direct. |
| `VITE_WAS_SYNC_RETRY_MS`       | _(RxDB default)_                           | Replication `retryTime` backoff between failed sync cycles.                                                                                                                                                                                                                                                                                                                                       |
| `VITE_WAS_SYNC_BATCH_SIZE`     | `100`                                      | Replication pull `limit` / push batch size.                                                                                                                                                                                                                                                                                                                                                       |
| `VITE_WAS_SYNC_POLL_MS`        | `30000`                                    | Interval between background pull polls, so rows another wallet pushes mid-session land without a re-login. `0` disables polling; skipped while offline.                                                                                                                                                                                                                                           |
| `VITE_ALLOWED_HOST`            | _(none)_                                   | Additional hostname that the dev server will accept requests from. Useful when testing CHAPI wallet functionality behind a reverse proxy such as Ngrok (`VITE_ALLOWED_HOST=example.ngrok.dev npm run dev`); without it, only localhost is accepted.                                                                                                                                               |

### Running Tests

Freewallet uses two frameworks for testing: Vitest for unit tests, and
Playwright for end-to-end browser tests.
If you want to run the e2e Playwright tests, you will need to install the
framework the first time:

```
npx playwright install
```

To run the Vitest unit tests:

```
npm test
```

To run the e2e Playwright tests:

```
npm run test:e2e
```

## Deployment

`npm run build` produces a static SPA in `dist/` that can be served by any
static file host (Nginx, Dokku buildpack, etc.).

The build is code-split: some chunks (for example the password-strength
dictionaries used on the signup page) are loaded on demand via dynamic
`import()` rather than in the initial bundle. When serving behind Nginx, scope
the SPA history fallback so that requests for hashed asset files return a real
404 instead of `index.html`. Otherwise, after a redeploy, a still-open tab that
requests an old (now-removed) chunk hash will receive `index.html` with a `200`
and fail with a "Failed to fetch dynamically imported module" error:

```nginx
# Hashed build assets: serve the file or 404 -- never fall back to index.html.
location /assets/ {
    try_files $uri =404;
}

# Client-side routes: fall back to the SPA entry point.
location / {
    try_files $uri $uri/ /index.html;
}
```

## Security

## License

Copyright 2026 Interop Alliance.
[GNU AFFERO GENERAL PUBLIC LICENSE v3](LICENSE)
