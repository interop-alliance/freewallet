import { httpClient } from '@interop/http-client'
import { CORS_PROXY_URL } from '@/app.config'

export async function fetchFromURL(url: string): Promise<string> {
  // Append the target as a `?url=` query parameter on the proxy base. A
  // trailing slash on the configured base is tolerated so that both
  // `https://corsproxy.io` and `<WAS>/api/cors` (with or without a trailing
  // slash) produce a well-formed proxy URL.
  const target = CORS_PROXY_URL
    ? `${CORS_PROXY_URL.replace(/\/+$/, '')}?url=${encodeURIComponent(url)}`
    : url

  const response = await httpClient.get(target, {
    headers: { Accept: 'application/ld+json, application/json' }
  })

  if (response.data) {
    return JSON.stringify(response.data)
  }

  return (await response.text()).trim()
}
