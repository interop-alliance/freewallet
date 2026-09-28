# syntax=docker/dockerfile:1

# Production image for Freewallet: the static build served by nginx, which
# also proxies the WAS server's routes on the same origin.
# docs/deployment-fly.io.md covers running it.

# Build stage: compile the SPA into dist/.
FROM node:24-slim AS build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Vite bakes these into the bundle at build time (see the README's
# Environment Variables table). VITE_ALLOWED_HOST is left out: it only
# affects the dev server.
ARG VITE_WAS_SERVER_URL
ARG VITE_KMS_SERVER_URL
ARG VITE_CORS_PROXY_URL
ARG VITE_PASSKEY_RP_ID
ARG VITE_KEYRING_CACHE_TTL_HOURS
ARG VITE_RP_ZCAP_TTL_HOURS
ARG VITE_RP_ZCAP_WRITE_TTL_HOURS
ARG VITE_SHARE_ZCAP_TTL_HOURS
ARG VITE_WAS_SYNC_BATCH_SIZE
ARG VITE_WAS_SYNC_POLL_MS
ARG VITE_WAS_SYNC_RETRY_MS
# The version shown in Settings. The build context carries no .git, so the
# host passes the output of `git describe --tags --always --dirty`.
ARG APP_VERSION

COPY . .
RUN pnpm run build

# Precompress text assets once, so nginx serves them with gzip_static instead
# of compressing on every request.
RUN find dist -type f -size +1k \
    \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \
    -o -name '*.json' -o -name '*.webmanifest' -o -name '*.md' -o -name '*.wasm' \) \
    -exec gzip -9 -k {} +

# Runtime stage: nginx serving dist/.
FROM nginx:stable-alpine

# The image renders /etc/nginx/templates/*.template into /etc/nginx/conf.d/
# at startup. The filter limits substitution to WAS_UPSTREAM, so nginx's own
# $variables are left alone.
ENV NGINX_ENVSUBST_FILTER=^WAS_UPSTREAM$
COPY deploy/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080
