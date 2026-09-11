/**
 * The pre-login check over an issuance exchange's DID-Auth step, for the CHAPI
 * store popup. The popup signs a presentation over a challenge and a domain
 * the exchange states, so a hostile site can relay a third-party verifier's
 * challenge and domain through its own store call and keep the replayable
 * proof. The answer is the get page's rule plus the external page's: the
 * stated `domain` must match the attested requesting origin, and the endpoint
 * the answer is POSTed to must sit on the exchange's own origin.
 */
import { presentationEndpointFor } from '@interop/wallet-request'
import type { IVPRDetails as ISpecVPRDetails } from '@interop/wallet-request'
import { classifyRequest } from './classify'
import { domainMatchesOrigin } from './processRequest'
import type { IVPRDetails } from './types'

/**
 * Why the popup cannot answer an exchange's opening request, each with its own
 * copy cell on the page.
 */
export type StoreRequestRefusal =
  'unsupportedRequest' | 'noDomain' | 'domainMismatch' | 'foreignDelivery'

/**
 * An issuance exchange's DID-Auth step the popup refuses before login.
 */
export class StoreRequestRefusedError extends Error {
  refusal: StoreRequestRefusal

  constructor(refusal: StoreRequestRefusal, options?: ErrorOptions) {
    super(`The store request was refused: ${refusal}`, options)
    this.name = 'StoreRequestRefusedError'
    this.refusal = refusal
  }
}

/**
 * Checks the request an issuance exchange opened with, before the passphrase
 * form is shown. Refuses, in order: anything other than a plain DID-Auth
 * request, a request stating no `domain` (the exchange origin is not a
 * substitute, since the relaying site chooses it), a `domain` that does not
 * match the attested requesting origin, and a delivery endpoint on another
 * origin than the exchange.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}   the VPR the exchange opened with
 * @param options.exchangeUrl {string}
 * @param [options.origin] {string}   the canonical requesting origin
 * @returns {{ exchangeHost: string }}   the host the answer will be sent to
 * @throws {StoreRequestRefusedError}
 */
export function checkStoreDIDAuthRequest({
  request,
  exchangeUrl,
  origin
}: {
  request: IVPRDetails
  exchangeUrl: string
  origin?: string
}): { exchangeHost: string } {
  const { didAuth, vcQueries, zcapRequests } = classifyRequest({ request })
  if (!didAuth || vcQueries.length > 0 || zcapRequests.length > 0) {
    throw new StoreRequestRefusedError('unsupportedRequest')
  }
  if (!request.domain) {
    throw new StoreRequestRefusedError('noDomain')
  }
  if (!domainMatchesOrigin({ domain: request.domain, origin })) {
    throw new StoreRequestRefusedError('domainMismatch')
  }
  const endpoint = presentationEndpointFor({
    request: request as ISpecVPRDetails,
    exchangeUrl
  })
  try {
    const resolved = new URL(endpoint)
    if (resolved.origin !== new URL(exchangeUrl).origin) {
      throw new StoreRequestRefusedError('foreignDelivery')
    }
    return { exchangeHost: new URL(exchangeUrl).host }
  } catch (err) {
    if (err instanceof StoreRequestRefusedError) {
      throw err
    }
    throw new StoreRequestRefusedError('foreignDelivery', { cause: err })
  }
}
