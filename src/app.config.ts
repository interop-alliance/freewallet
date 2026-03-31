/**
 * General app config
 */
const env = import.meta.env

export const BASE_URL = env.BASE_URL
export const WAS_SERVER_URL = env.WAS_SERVER_URL
export const CORS_PROXY_URL = env.CORS_PROXY_URL || ''

export const PASSWORD_RULES = {
  minlength: 16,
  minscore: 3
}

export const MEDIATOR =
  'https://authn.io/mediator?origin=' +
  encodeURIComponent(window.location.origin)

export const WALLET_LOCATION = window.location.origin + '/'
