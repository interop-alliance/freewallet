/**
 * The non-CHAPI request entry point: a request that arrives as an interaction
 * URL (a CLI agent's `di was request-grant` link, a pasted or scanned
 * `...?iuv=1` URL) instead of through a CHAPI popup. The page that renders it
 * (`src/pages/external/ExternalRequestPage.tsx`) is the `WalletGetPage` shape
 * minus CHAPI; everything that can be stated without a DOM lives here, so the
 * refusal matrix is exercisable as plain functions.
 *
 * Two things make this entry point stricter than the popup. There is no
 * attested requesting origin: the only requester signal is the grantee DID
 * and the request-supplied `reason` text, both chosen by whoever wrote the
 * link. And the VPR is wholly link-supplied, so it could name a delivery
 * endpoint on a third host. So the page refuses, before consent, everything
 * that needs an origin (`DIDAuthentication`, a `domain`, an
 * `AppConnectQuery`), every grant class beyond the two an agent may
 * legitimately ask for (`#public-collection` and `#private-collection`
 * descriptors, or plain collection URLs resolving to those classes), and a
 * `interact.service` endpoint on another origin than the exchange.
 */
import {
  EphemeralExchangeGoneError,
  isInteractionUrl,
  openInteractionRequest,
  presentationEndpointFor
} from '@interop/wallet-core/request'
import type {
  FetchLike,
  IVPRDetails as ISpecVPRDetails
} from '@interop/wallet-core/request'
import { classifyRequest, queriesOf } from './classify'
import type { ResolvedGrant } from './processZcaps'
import type { IVPRDetails, WalletRequestProfile } from './types'

/**
 * The deep-link route the CLI prints (`--wallet <url>`), and the query
 * parameter carrying the percent-encoded interaction URL. Both are published
 * conventions once a skill ships them.
 */
export const EXTERNAL_REQUEST_PATH = '/external/request'
export const EXTERNAL_REQUEST_URL_PARAM = 'url'

/**
 * The `origin` recorded on the Login activity for a grant answered through
 * this entry point, which has no requesting origin. A fixed marker rather
 * than the exchange host, so the Applications listing can key agent rows on
 * it beside the grant's `controller` DID.
 */
export const EXTERNAL_REQUEST_ORIGIN = 'n/a (API request)'

/**
 * The grant classes this entry point delegates. Everything else the grant
 * engine supports is refused before consent: a share hands the grantee
 * decryption of the user's own encrypted collections, and a whole-Space or
 * protected-collection read covers plaintext `public-credentials`. Widening
 * the list is a documented decision, not a code change.
 */
const ALLOWED_TARGET_CLASSES: readonly string[] = [
  'public-collection',
  'collection'
]

/**
 * Why a request cannot proceed, each with its own copy cell on the page.
 * `invalidLink` and the exchange-state reasons (`gone`, `unreachable`,
 * `malformedRequest`) come from opening the request; the rest come from the
 * pre-consent check over the VPR the exchange handed back.
 */
export type ExternalRequestRefusal =
  | 'invalidLink'
  | 'gone'
  | 'unreachable'
  | 'malformedRequest'
  | 'didAuth'
  | 'domain'
  | 'appConnect'
  | 'foreignDelivery'
  | 'barredGrant'

/**
 * A request this entry point refuses before anything is shown or written.
 */
export class ExternalRequestRefusedError extends Error {
  refusal: ExternalRequestRefusal

  constructor(refusal: ExternalRequestRefusal, options?: ErrorOptions) {
    super(`The external request was refused: ${refusal}`, options)
    this.name = 'ExternalRequestRefusedError'
    this.refusal = refusal
  }
}

/**
 * The in-app path for an interaction URL: the deep link the CLI prints, and
 * where the paste box and the QR scanner send one.
 *
 * @param options {object}
 * @param options.url {string}   the interaction URL
 * @returns {string}
 */
export function externalRequestPath({ url }: { url: string }): string {
  const params = new URLSearchParams({ [EXTERNAL_REQUEST_URL_PARAM]: url })
  return `${EXTERNAL_REQUEST_PATH}?${params.toString()}`
}

/**
 * Reads the interaction URL out of the route's query string. Strict: an
 * absolute http(s) URL carrying `iuv`, or an `interaction:` URL, and nothing
 * else -- a bare exchange URL, a relative path, or another scheme is refused.
 *
 * @param search {string}   the route's `location.search`
 * @returns {string | null}   the interaction URL, or null when absent or
 *   refused
 */
export function interactionUrlFromSearch(search: string): string | null {
  const raw = new URLSearchParams(search).get(EXTERNAL_REQUEST_URL_PARAM)
  if (!raw) {
    return null
  }
  const trimmed = raw.trim()
  if (!isInteractionUrl(trimmed)) {
    return null
  }
  if (trimmed.startsWith('interaction:')) {
    return trimmed
  }
  try {
    const parsed = new URL(trimmed)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:'
      ? trimmed
      : null
  } catch {
    return null
  }
}

/**
 * Opens the request behind an interaction URL -- the protocols fetch and the
 * exchange begin -- mapping each failure onto its refusal: a 404 on either
 * fetch is `gone` (the server answers the same for an expired and an unknown
 * exchange, so the copy must not assert expiry), a network failure is
 * `unreachable`, and anything else (no usable protocols map, a begin body
 * that is not a VPR) is `malformedRequest`.
 *
 * @param options {object}
 * @param options.url {string}   the interaction URL
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<{ exchangeUrl: string, request: IVPRDetails }>}
 * @throws {ExternalRequestRefusedError}
 */
export async function openExternalRequest({
  url,
  fetch
}: {
  url: string
  fetch?: FetchLike
}): Promise<{ exchangeUrl: string; request: IVPRDetails }> {
  try {
    const { exchangeUrl, request } = await openInteractionRequest({
      url,
      ...(fetch ? { fetch } : {})
    })
    return { exchangeUrl, request: request as IVPRDetails }
  } catch (err) {
    // Dispatch on the name: the class may come from a second copy of
    // wallet-core in a linked install.
    if (
      err instanceof EphemeralExchangeGoneError ||
      (err instanceof Error && err.name === 'EphemeralExchangeGoneError')
    ) {
      throw new ExternalRequestRefusedError('gone', { cause: err })
    }
    // `fetch` rejects with a TypeError on a network failure; every other
    // failure is the helper's own, over a reply it could not read.
    if (err instanceof TypeError) {
      throw new ExternalRequestRefusedError('unreachable', { cause: err })
    }
    throw new ExternalRequestRefusedError('malformedRequest', { cause: err })
  }
}

/**
 * The pre-consent check over the VPR the exchange handed back. Classifies
 * the request and refuses, in this order, everything this entry point cannot
 * answer: an empty query set, an `AppConnectQuery` (checked ahead of
 * classification, which would otherwise throw for the missing origin), a
 * `DIDAuthentication` query (freewallet requires a `domain` for DID Auth and
 * there is no origin to match one against), a `domain` on any request, and a
 * presentation endpoint on another origin than the exchange's. The delivery
 * host is resolved exactly the way delivery resolves it, so the consent
 * screen names where the response will actually go.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}
 * @param options.exchangeUrl {string}
 * @returns {{ profile: WalletRequestProfile, deliveryHost: string }}
 * @throws {ExternalRequestRefusedError}
 */
export function precheckExternalRequest({
  request,
  exchangeUrl
}: {
  request: IVPRDetails
  exchangeUrl: string
}): { profile: WalletRequestProfile; deliveryHost: string } {
  const queries = queriesOf(request)
  if (queries.length === 0) {
    throw new ExternalRequestRefusedError('malformedRequest')
  }
  if (queries.some(query => (query.type as string) === 'AppConnectQuery')) {
    throw new ExternalRequestRefusedError('appConnect')
  }
  const profile = classifyRequest({ request })
  if (profile.didAuth) {
    throw new ExternalRequestRefusedError('didAuth')
  }
  if (request.domain) {
    throw new ExternalRequestRefusedError('domain')
  }
  const endpoint = presentationEndpointFor({
    request: request as ISpecVPRDetails,
    exchangeUrl
  })
  let deliveryHost: string
  try {
    const resolved = new URL(endpoint)
    if (resolved.origin !== new URL(exchangeUrl).origin) {
      throw new ExternalRequestRefusedError('foreignDelivery')
    }
    deliveryHost = resolved.host
  } catch (err) {
    if (err instanceof ExternalRequestRefusedError) {
      throw err
    }
    throw new ExternalRequestRefusedError('foreignDelivery', { cause: err })
  }
  return { profile, deliveryHost }
}

/**
 * The grants a resolved request asks for outside this entry point's
 * allowlist. Run once the grants are resolved (the first point a target's
 * class is known); a non-empty result refuses the request before consent.
 * Unsatisfiable grants are not barred -- they delegate nothing and render as
 * "cannot fulfill", as on the popup.
 *
 * @param grants {ResolvedGrant[]}
 * @returns {ResolvedGrant[]}
 */
export function barredGrants(grants: ResolvedGrant[]): ResolvedGrant[] {
  return grants.filter(
    ({ target }) =>
      target.satisfiable &&
      !!target.targetClass &&
      !ALLOWED_TARGET_CLASSES.includes(target.targetClass)
  )
}
