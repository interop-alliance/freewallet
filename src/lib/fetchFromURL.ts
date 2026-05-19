import { httpClient } from '@digitalcredentials/http-client'
import { CORS_PROXY_URL } from '@/app.config'

export async function fetchFromURL(url: string): Promise<string> {
  const target = CORS_PROXY_URL
    ? `${CORS_PROXY_URL}/?url=${encodeURIComponent(url)}`
    : url

  const response = await httpClient.get(target, {
    headers: { Accept: 'application/ld+json, application/json' }
  })

  if (response.data) {
    return JSON.stringify(response.data)
  }

  return (await response.text()).trim()
}
