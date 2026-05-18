/**
 * General app config
 */
const env = import.meta.env

export const SERVER_URL = env.VITE_SERVER_URL || 'http://localhost:5173'
export const DEPLOY_URL = env.VITE_DEPLOY_URL
export const WAS_SERVER_URL = env.VITE_WAS_SERVER_URL

export const CORS_PROXY_URL = env.VITE_CORS_PROXY_URL || 'https://corsproxy.io'

export const PASSWORD_RULES = {
  minlength: 16,
  minscore: 3
}

export const DATE_FMT: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'short',
  day: 'numeric'
}

export const MEDIATOR_BASE = 'https://authn.io/mediator?origin='

// export const WALLET_LOCATION = window.location.origin + '/'

export const KNOWN_REGISTRIES_URL =
  'https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json'

export const KNOWN_EXTENSIONS =
  /\.(json|jsonld|ldjson|txt|md|pdf|png|jpg|jpeg|webp|svg|csv|xml|yaml|yml)$/i

export const COMMON_CONTENT_TYPES: Record<string, string> = {
  'application/json': 'JSON',
  'application/ld+json': 'JSON-LD',
  'application/jsonld+json': 'JSON-LD',
  'application/pdf': 'PDF',
  'application/x-tar': 'TAR',
  'application/zip': 'ZIP',
  'application/xml': 'XML',
  'application/yaml': 'YAML',
  'application/x-yaml': 'YAML',
  'text/plain': 'TXT',
  'text/markdown': 'MD',
  'text/html': 'HTML',
  'text/css': 'CSS',
  'text/csv': 'CSV',
  'text/xml': 'XML',
  'image/png': 'PNG',
  'image/jpeg': 'JPEG',
  'image/gif': 'GIF',
  'image/svg+xml': 'SVG',
  'image/webp': 'WEBP'
}
