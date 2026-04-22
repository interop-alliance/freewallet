/**
 * General app config
 */
const env = import.meta.env

export const DEPLOY_URL = env.VITE_DEPLOY_URL
export const WAS_SERVER_URL = env.VITE_WAS_SERVER_URL
export const CORS_PROXY_URL = env.VITE_CORS_PROXY_URL || ''

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
