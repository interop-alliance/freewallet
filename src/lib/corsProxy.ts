/**
 * The wallet's single CORS-proxy path. Every cross-origin fetch the app makes
 * on behalf of a user-supplied URL (a pasted credential URL, the `oidf`
 * issuer-registry lookups) goes through one proxy base -- `CORS_PROXY_URL`, which
 * defaults to the configured WAS server's `/api/cors` facet -- so there is one
 * config key and one URL-building rule to reason about.
 *
 * It also holds the one direct-first fallback (`fetchWithProxyFallback`):
 * a request goes direct, and a rejected fetch retries once through the
 * proxy. The registry client and credential verification (DID documents,
 * JSON-LD contexts, status lists) both ride it, since many hosts send no
 * `Access-Control-Allow-Origin` header.
 */
import { httpClient } from '@interop/http-client'
import { BuiltinHttpGetService } from '@interop/verifier-core'
import type { HttpGetService } from '@interop/verifier-core'
import { CORS_PROXY_URL } from '@/app.config'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:cors-proxy')

/**
 * How long an origin found blocked goes straight to the proxy before it is
 * tried direct again, so one transient network failure does not route an
 * origin through the proxy for the rest of the tab.
 */
const DIRECT_RETRY_AFTER_MS = 5 * 60 * 1000

/**
 * Origins whose direct fetch was rejected, each with the time it was
 * rejected, so requests to them go straight to the proxy until
 * `DIRECT_RETRY_AFTER_MS` has passed. In memory only, and cleared at logout.
 */
const directBlockedOrigins = new Map<string, number>()

/**
 * Builds the proxied URL for a target: the target is appended to the
 * configured proxy base as a `?url=` query parameter. A trailing slash on the
 * base is tolerated so that both `https://corsproxy.io` and `<WAS>/api/cors`
 * (with or without a trailing slash) produce a well-formed proxy URL. With no
 * proxy configured the target is returned unchanged, so the fetch goes direct.
 *
 * @param options {object}
 * @param options.url {string}   the target URL to fetch
 * @returns {string}
 */
export function corsProxyUrl({ url }: { url: string }): string {
  if (!CORS_PROXY_URL) {
    return url
  }
  return `${CORS_PROXY_URL.replace(/\/+$/, '')}?url=${encodeURIComponent(url)}`
}

/**
 * Fetches a URL through the CORS proxy, returning the raw `Response` for
 * callers that need the status or a non-JSON body.
 *
 * @param options {object}
 * @param options.url {string}   the target URL to fetch
 * @param [options.signal] {AbortSignal}   bounds a stalled proxy hop
 * @returns {Promise<Response>}
 */
export async function corsProxyFetch({
  url,
  signal
}: {
  url: string
  signal?: AbortSignal
}): Promise<Response> {
  return fetch(corsProxyUrl({ url }), { signal })
}

/**
 * Fetches a URL through the CORS proxy and returns its body as a string,
 * requesting JSON-LD. A JSON response is re-serialized so callers get the same
 * string shape either way; a text response is trimmed.
 *
 * @param url {string}   the target URL to fetch
 * @returns {Promise<string>}
 */
export async function fetchFromURL(url: string): Promise<string> {
  const response = await httpClient.get(corsProxyUrl({ url }), {
    headers: { Accept: 'application/ld+json, application/json' }
  })

  if (response.data) {
    return JSON.stringify(response.data)
  }

  return (await response.text()).trim()
}

/**
 * Runs a request direct first, and on a rejection retries it once through
 * the CORS proxy.
 *
 * A browser reports a CORS block as a rejected fetch (a `TypeError`), which
 * cannot be told apart from a network error, so any rejection counts. An
 * HTTP error status is a real answer from the host and is not retried: the
 * request resolves with it. An abort is not retried either, since the
 * caller's budget is spent. With no proxy configured there is nothing to
 * retry through, so the direct result stands.
 *
 * An origin whose direct fetch was rejected goes straight to the proxy for
 * `DIRECT_RETRY_AFTER_MS`, then is tried direct again. If the proxied
 * request itself rejects while an origin is marked blocked, the mark is
 * dropped and the request is tried direct once, so a refusing or unreachable
 * proxy cannot cut off an origin a direct fetch would reach. The fallback is
 * logged each time an origin is marked.
 *
 * @param options {object}
 * @param options.url {string}   the target URL
 * @param options.request {(target: string) => Promise<T>}   performs one
 *   request against the given URL (the target, or its proxied form)
 * @param [options.signal] {AbortSignal}   the request's abort signal, if any
 * @returns {Promise<T>}
 */
export async function fetchWithProxyFallback<T>({
  url,
  request,
  signal
}: {
  url: string
  request: (target: string) => Promise<T>
  signal?: AbortSignal
}): Promise<T> {
  const proxiedUrl = corsProxyUrl({ url })
  const origin = originOf(url)
  if (proxiedUrl === url || origin === undefined) {
    return request(url)
  }
  if (isDirectBlocked(origin)) {
    try {
      return await request(proxiedUrl)
    } catch (err) {
      if (signal?.aborted || isAbortError(err)) {
        throw err
      }
      directBlockedOrigins.delete(origin)
      log.warn('Proxied fetch failed, trying the origin direct', {
        origin,
        err
      })
      return request(url)
    }
  }
  try {
    return await request(url)
  } catch (err) {
    if (signal?.aborted || isAbortError(err)) {
      throw err
    }
    directBlockedOrigins.set(origin, Date.now())
    log.warn('Direct fetch failed, using the CORS proxy for this origin', {
      origin,
      err
    })
    return request(proxiedUrl)
  }
}

/**
 * Whether an origin's direct fetch was rejected within
 * `DIRECT_RETRY_AFTER_MS`. An expired mark is dropped.
 *
 * @param origin {string}
 * @returns {boolean}
 */
function isDirectBlocked(origin: string): boolean {
  const blockedAt = directBlockedOrigins.get(origin)
  if (blockedAt === undefined) {
    return false
  }
  if (Date.now() - blockedAt >= DIRECT_RETRY_AFTER_MS) {
    directBlockedOrigins.delete(origin)
    return false
  }
  return true
}

/**
 * Builds the `HttpGetService` credential verification fetches through:
 * verifier-core's built-in service, with each request run through
 * {@link fetchWithProxyFallback}. Construct it once and reuse it, since
 * verifier-core memoizes its document loader per service instance.
 *
 * @returns {HttpGetService}
 */
export function proxyFallbackHttpGetService(): HttpGetService {
  const builtin = BuiltinHttpGetService()
  return {
    get: url =>
      fetchWithProxyFallback({ url, request: target => builtin.get(target) })
  }
}

/**
 * Forgets which origins were found blocked for direct fetches. Run at logout
 * beside the registry caches.
 *
 * @returns {void}
 */
export function clearDirectFetchFailures(): void {
  directBlockedOrigins.clear()
}

/**
 * The origin of a URL, or `undefined` when it does not parse.
 *
 * @param url {string}
 * @returns {string | undefined}
 */
function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin
  } catch {
    return undefined
  }
}

/**
 * Whether a rejection is an abort.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isAbortError(err: unknown): boolean {
  return (
    (err instanceof Error || err instanceof DOMException) &&
    err.name === 'AbortError'
  )
}
