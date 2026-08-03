/**
 * The wallet's single CORS-proxy path. Every cross-origin fetch the app makes
 * on behalf of a user-supplied URL (a pasted credential URL, the known-issuer
 * registries list) goes through one proxy base -- `CORS_PROXY_URL`, which
 * defaults to the configured WAS server's `/api/cors` facet -- so there is one
 * config key and one URL-building rule to reason about.
 */
import { httpClient } from '@interop/http-client'
import { CORS_PROXY_URL } from '@/app.config'

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
 * @returns {Promise<Response>}
 */
export async function corsProxyFetch({
  url
}: {
  url: string
}): Promise<Response> {
  return fetch(corsProxyUrl({ url }))
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
