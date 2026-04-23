# Freewallet

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

* [Wallet Attached Storage Specification](https://digitalcredentials.github.io/wallet-attached-storage-spec/)

### Supported Features

### Tech Stack

Development:

* Javascript/TypeScript, Node.js 22+
* React + ReactDOM 19
* React Router 7 (in library mode), using `HashRouter`
* `zustand` for state management
* Vite 8 bundler (so it can deploy as a static SPA)
* Prettier for code formatting, and React-aware eslint for linting

## Install

```
pnpm install
```

## Usage

### Starting the Server

```
npm start
```

Optional env vars:

* `PORT` - Used by Docker, Dokku, etc. Automatically handled by Vite.
* `VITE_DEPLOY_URL` - URL to which the Freewallet app is deployed.
  Used for CHAPI wallet registration etc.
* `VITE_WAS_SERVER_URL` - URL to
  a [WAS](https://digitalcredentials.github.io/wallet-attached-storage-spec/)
  server instance. If not provided, the server will run in a local-only mode
  (storing VCs in browser IndexedDB).
* `VITE_CORS_PROXY_URL` - URL to a CORS proxy (used for fetching VCs when
  you paste their URLs into the Add Credential box).
* `VITE_ALLOWED_HOST` - Additional hostname that the server will accept
  requests from. This is useful when testing CHAPI wallet functionality behind
  a reverse proxy such as Ngrok. If not provided, the server will only accept
  requests from localhost. So, for example:
  `VITE_ALLOWED_HOST=example.ngrok.dev npm run dev`

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

## Security

## License

Copyright 2026 Interop Alliance.
[GNU AFFERO GENERAL PUBLIC LICENSE v3](LICENSE)
