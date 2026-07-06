import { WAS_SERVER_URL } from '@/app.config'

export function corsProxyFetch(url: string) {
  const target = WAS_SERVER_URL
    ? `${WAS_SERVER_URL}/api/cors?url=${encodeURIComponent(url)}`
    : url
  return fetch(target)
}
