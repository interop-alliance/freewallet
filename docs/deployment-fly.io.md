# Deployment

The production image serves the built SPA from nginx and proxies the WAS
server's routes on the same origin. The repo also carries an example Fly.io
configuration and deploy workflows for staging and production. The server side
is covered by the was-teaching-server repo's `docs/deployment-fly.io.md`.

## Why one origin

The wallet's WAS requests carry `Authorization`, `Capability-Invocation` and
`Digest` headers. Sent to another origin, each one needs a CORS preflight
first. Browsers cache a preflight per URL, and a signup touches many distinct
URLs, so the preflights add a round trip to most of signup's requests. With
the server's routes on the wallet's origin, the requests are same-origin and
no preflight is sent.

```
browser --> https://wallet.example.com --> TLS termination
                                              |
                                              v
                                      [this image: nginx]
                                              |  server routes
                                              v
                                         [WAS server]
```

The image listens on plain HTTP, port 8080. Something in front of it
terminates TLS: a platform edge, a load balancer, or a reverse proxy. That
front must pass `Host` through unchanged.

### Hosted pages on the wallet's origin

One origin has a cost. The server serves a Resource with the content type it
was stored with, so an HTML Resource opened in a browser is a working page.
Through this image, that page runs on the wallet's origin. Its scripts could
read the wallet's `localStorage` and IndexedDB, key material included, and
anyone who can write a Resource could plant one.

So the server sends a sandbox header on every Resource and chunk read, and
the proxy passes it through unchanged:

```
Content-Security-Policy: sandbox allow-scripts allow-forms allow-modals allow-downloads allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation
```

A hosted page then runs in an opaque origin. It keeps its scripts, the DOM,
WebCrypto and `fetch()` to CORS APIs, and gets no browser storage, cookies or
service workers. The header has no effect on the wallet's own `fetch()` calls.
It leaves out `allow-same-origin`, which would let a page lift the sandbox.

The CORS proxy at `/api/cors` relays a third-party URL's response with that
URL's content type, so a link to it could run anyone's HTML on the wallet's
origin. The proxy sends those responses with
`Content-Security-Policy: default-src 'none'; sandbox` and
`X-Content-Type-Options: nosniff`.

This is option 3 under "Choosing an origin layout" in the was-teaching-server
repo's `docs/deployment-fly.io.md`, which compares the other layouts. The server
sends the Resource and chunk header itself since its 0.39.0 release, so run
that version or later behind this image. It does not send the `/api/cors`
headers yet, so the proxy adds those. When the server sends them, remove them
from `deploy/nginx.conf.template`.

## Files

| File                                   | Purpose                                                                          |
| -------------------------------------- | -------------------------------------------------------------------------------- |
| `Dockerfile`                           | Builds `dist/` with pnpm, precompresses text assets, copies them into nginx.     |
| `.dockerignore`                        | Keeps `node_modules/`, `.git`, test output and local files out of the build.     |
| `deploy/nginx.conf.template`           | The nginx server block: SPA serving, cache headers, and the proxy to the server. |
| `fly.toml`                             | Example Fly.io app with placeholder values. See "Example: Fly.io" below.         |
| `.github/workflows/deploy.yml`         | Deploys to Fly.io when a GitHub release is published, or by hand.                |
| `.github/workflows/deploy-staging.yml` | Deploys to the staging app after CI passes on `main`, or by hand.                |

## Request routing

| Path                                                                                          | Served by                                |
| --------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `/spaces`, `/space/*`, `/kms/*`, `/workflows/*`, `/api/*`, `/common/*`, `/service`, `/health` | the WAS server, proxied                  |
| `/assets/*`                                                                                   | nginx: the file, or a 404                |
| anything else                                                                                 | nginx: a `public/` file, or `index.html` |

The proxied list is the server's full set of top-level routes. When the server
adds one, add it to the `location` regex in `deploy/nginx.conf.template`. The
server's welcome page at `/` is not reachable through this image, since the
wallet takes `/`.

Hashed files under `/assets/` get a one-year immutable cache and never fall
back to `index.html` (the README's Deployment section explains the stale-chunk
failure that fallback would cause). Everything else is sent with `no-cache`,
so browsers revalidate `index.html` and pick up a deploy on the next load.

### Rules the proxy block must keep

- It passes `Host` through unchanged (`proxy_set_header Host $http_host`).
  HTTP Signatures cover `host`, and nginx's default would replace it with the
  upstream's name, which fails every signed request.
- It leaves paths alone. The signature covers `(request-target)` too, and the
  server does not run under a sub-path.
- It does not gzip responses. nginx weakens an `ETag` when it compresses, and
  the wallet's conditional writes send `If-Match`, which needs the strong one.
- It sets no body size limit. The server applies `MAX_UPLOAD_BYTES` itself,
  and backup imports can be large.
- It adds the `/api/cors` headers and passes the server's Resource sandbox
  header through (see "Hosted pages on the wallet's origin" above). Without
  them, a hosted HTML page can read the wallet's keys.
- It keeps upstream connections alive (`keepalive` in the `upstream` block,
  HTTP/1.1, and an empty `Connection` header). Without that, every API request
  opens a new connection to the server.

## Configuration

Build-time settings are the `VITE_*` variables from the README's Environment
Variables table. Vite bakes them into the bundle, so each image serves one
domain, and changing a setting takes a rebuild. The `Dockerfile` declares an
`ARG` for each one (all but `VITE_ALLOWED_HOST`, which only affects the dev
server). Pass them with `docker build --build-arg`.

The build also needs `APP_VERSION`, the version shown in Settings. The
build context carries no `.git`, so pass the host's
`git describe --tags --always --dirty` output. Without it the build fails.

A same-origin deployment sets one:
`VITE_WAS_SERVER_URL=https://wallet.example.com/spaces/`. The CORS proxy
(`/api/cors`) and the KMS (`/kms`) default to that same server, so they are
same-origin too.

The one run-time setting is `WAS_UPSTREAM`, the server's `host:port` as nginx
reaches it. The nginx image writes it into the config when the container
starts. nginx resolves the name once, at startup, and refuses to start if it
does not resolve. So start the server first. If the server's address can
change while nginx runs (a recreated Docker Compose container, say), restart
nginx with it.

The server's `SERVER_URL` must be the wallet's public origin,
`https://wallet.example.com` in these examples. ZCap invocation targets are
built from it and must match the URLs the browser signs.

## Running the image locally

Start the server with `SERVER_URL` set to the proxy's origin, then build and
run this image in front of it:

```sh
# In the was-teaching-server checkout:
SERVER_URL=http://localhost:8080 PORT=3002 pnpm start

# Here:
docker build -t freewallet \
  --build-arg VITE_WAS_SERVER_URL=http://localhost:8080/spaces/ \
  --build-arg APP_VERSION="$(git describe --tags --always --dirty)" .
docker run --rm -p 8080:8080 \
  --add-host=host.docker.internal:host-gateway \
  -e WAS_UPSTREAM=host.docker.internal:3002 \
  freewallet
```

Then open `http://localhost:8080`.

## Example: Fly.io

`fly.toml` and the deploy workflows run the image as one Fly app per
environment, with the WAS server as a second app deployed from its own repo.
nginx reaches the server over Flycast, a private address inside the Fly
organization's network, so the server app needs no public IP. Each repo
deploys its own app.

The values in `fly.toml` are placeholders: the app name `freewallet`, the
domain `wallet.example.com`, and the upstream
`was-teaching-server.flycast:80`. Each workflow replaces them at deploy time.

### First-time setup

Set up the server app first (see the was-teaching-server repo's
`docs/deployment-fly.io.md`). Then, with your own app name, domain and server app:

```sh
fly apps create <app>
fly deploy --app <app> \
  --build-arg VITE_WAS_SERVER_URL=https://<domain>/spaces/ \
  --build-arg APP_VERSION="$(git describe --tags --always --dirty)" \
  --env WAS_UPSTREAM=<server-app>.flycast:80
fly scale count 2 --app <app>
fly certs add <domain> --app <app>
```

`fly ips list --app <app>` shows the public addresses. Point the domain's `A`
and `AAAA` records at them, and follow `fly certs show <domain>` until the
certificate is issued. If the domain's DNS goes through a proxying CDN, set
the records to DNS only so Fly terminates TLS.

The app runs two machines, so a deploy replaces one at a time and the site
stays up. Every API request goes through this app, so a single machine would
take the server offline during each deploy.

Use `primary_region` in `fly.toml` for the region closest to most users, and
put the server app in the same one.

### Deploying from CI

Two workflows deploy the same image to two Fly apps:

- `.github/workflows/deploy-staging.yml` deploys to a staging app each time the
  CI workflow passes on a push to `main`. It deploys the commit CI tested.
- `.github/workflows/deploy.yml` deploys to the production app when a GitHub
  release is published.

A change reaches production in three steps. Merge it to `main`, check it on
staging, then publish a release whose tag points at the commit staging runs.
Both workflows can also run by hand from the Actions tab (`workflow_dispatch`).

Each workflow reads its values from a GitHub environment of its own, so the two
apps never share a token. To set up production:

1. Create a deploy token scoped to the one app:
   `fly tokens create deploy --app <app>`.
2. In the GitHub repo settings, create an environment named `production`.
   Store the token there as the `FLY_API_TOKEN` secret.
3. On the same environment, add three variables:

   | Variable              | Example                              |
   | --------------------- | ------------------------------------ |
   | `FLY_APP`             | `freewallet`                         |
   | `VITE_WAS_SERVER_URL` | `https://wallet.example.com/spaces/` |
   | `WAS_UPSTREAM`        | `was-teaching-server.flycast:80`     |

   The workflow fails before deploying if any of them is missing.

4. Limit the environment's deployment branches and tags to `main` and `v*`. A
   release event runs on its tag, so a `main`-only rule would block it.

Staging is a second app on a domain of its own, set up as under "First-time
setup" above. It proxies to the staging server app, whose `SERVER_URL` is the
staging wallet's domain. Then:

1. Create a deploy token scoped to the staging app.
2. Create an environment named `staging`, with the token as its `FLY_API_TOKEN`
   secret. Add the same three variables, with the staging app's name, the
   staging domain's `/spaces/` URL, and the staging server's Flycast address.
3. Limit the environment's deployment branches to `main`.

Neither workflow runs on pull requests, so a pull request from a fork cannot
read the tokens or the variables. The staging workflow runs after every CI run,
but deploys only when the run passed and was triggered by a push.

A deploy from a workstation needs the same three values, passed as in the
first-time setup above. A plain `fly deploy` would deploy the placeholders.
