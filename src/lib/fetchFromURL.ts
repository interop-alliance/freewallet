import { httpClient } from '@digitalcredentials/http-client'
import { CORS_PROXY_URL } from '@/app.config'

export async function fetchFromURL(url: string): Promise<string> {
  const target = CORS_PROXY_URL
    ? `${CORS_PROXY_URL}/?url=${encodeURIComponent(url)}`
    : url

  console.log('Fetching credential from URL:', url)
  if (CORS_PROXY_URL) {
    console.log('Using CORS proxy:', CORS_PROXY_URL)
  }

  const response = await httpClient.get(target, {
    headers: { Accept: 'application/ld+json, application/json' }
  })

  if (response.data) {
    console.log('Fetched credential JSON from URL')
    return JSON.stringify(response.data)
  }

  const text = await response.text()
  console.log('Fetched credential text, length:', text.length)
  return text.trim()
}
