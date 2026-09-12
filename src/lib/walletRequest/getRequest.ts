/**
 * The pre-consent check over a CHAPI `get` request, for the credential-get
 * popup (`src/pages/chapi/WalletGetPage.tsx`). Everything the page can decide
 * before its login form renders lives here as plain functions, the way
 * `storeRequest.ts` carries the store popup's check and
 * `externalRequest.ts` the interaction-URL page's, so the refusal matrix is
 * exercisable without a DOM.
 *
 * The popup's one requester signal is the origin the CHAPI mediator attests
 * off the message event. A value that does not parse, or that parses to an
 * opaque origin, is no attestation at all: the consent screen would name
 * nobody and an approval would record a Login activity attributed to nobody,
 * so it is refused here rather than rendered as a blank label.
 */
import { didAuthMethodSupported } from '@interop/wallet-request'
import type { IVPRQuery as ISpecVPRQuery } from '@interop/wallet-request'
import { classifyRequest, queriesOf, requestingOriginOf } from './classify'
import { domainMatchesOrigin } from './processRequest'
import type { IVPRDetails, WalletRequestProfile } from './types'

/**
 * Why the popup cannot answer a `get` request, each a `BlockReason` the page
 * already has a `chapi.get.*` copy cell for.
 */
export type GetRequestRefusal =
  'unattributedOrigin' | 'malformedRequest' | 'unsupported' | 'domainMismatch'

/**
 * A `get` request the popup refuses before consent renders.
 */
export class GetRequestRefusedError extends Error {
  refusal: GetRequestRefusal

  constructor(refusal: GetRequestRefusal, options?: ErrorOptions) {
    super(`The CHAPI get request was refused: ${refusal}`, options)
    this.name = 'GetRequestRefusedError'
    this.refusal = refusal
  }
}

/**
 * The canonical requesting origin, or the refusal for a request this wallet
 * cannot attribute to a website. Checked first, ahead of the request body,
 * so an unattributable request is refused before the popup opens a VC API
 * exchange on its behalf.
 *
 * @param [credentialRequestOrigin] {string}   the origin as the CHAPI event
 *   carried it
 * @returns {string}   the canonical origin, never empty
 * @throws {GetRequestRefusedError}
 */
export function attestedRequestOrigin(
  credentialRequestOrigin?: string
): string {
  const origin = requestingOriginOf(credentialRequestOrigin)
  if (!origin) {
    throw new GetRequestRefusedError('unattributedOrigin')
  }
  return origin
}

/**
 * The pre-consent check over the VPR body, run once the request is in hand
 * (off the CHAPI event, or off the exchange the event named). Refuses, in
 * this order: an origin this wallet cannot attribute, a body carrying no
 * readable query, a body the classifier rejects, a `DIDAuthentication`
 * constrained to DID methods no session on this deployment could present,
 * and a `domain` that does not match the attested origin.
 *
 * The DID-method cell judges deployment capability alone; which holder form
 * THIS visit can present is the page's post-login gate, the routing between
 * the transient and remembered compositions being post-KDF. The domain cell
 * applies to any request carrying a `domain`, not only a DID-Auth one: a VPR
 * can pin a foreign domain with no `DIDAuthentication` query, and it
 * deserves the specific refusal rather than a processing failure surfaced
 * after consent.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}   the VPR body
 * @param [options.credentialRequestOrigin] {string}   the origin as the CHAPI
 *   event carried it
 * @param options.didMethods {readonly string[]}   the DID methods some
 *   session on this deployment could present a holder for
 * @returns {{ profile: WalletRequestProfile, queries: ISpecVPRQuery[],
 *   origin: string }}
 * @throws {GetRequestRefusedError}
 */
export function precheckGetRequest({
  request,
  credentialRequestOrigin,
  didMethods
}: {
  request: IVPRDetails
  credentialRequestOrigin?: string
  didMethods: readonly string[]
}): {
  profile: WalletRequestProfile
  queries: ISpecVPRQuery[]
  origin: string
} {
  const origin = attestedRequestOrigin(credentialRequestOrigin)
  const queries = queriesOf(request)
  if (queries.length === 0) {
    throw new GetRequestRefusedError('malformedRequest')
  }
  let profile: WalletRequestProfile
  try {
    profile = classifyRequest({ request, origin })
  } catch (err) {
    // A malformed App Connect query or `agent` member: nothing to consent to.
    throw new GetRequestRefusedError('malformedRequest', { cause: err })
  }
  if (profile.didAuth && !didAuthMethodSupported(queries, didMethods)) {
    throw new GetRequestRefusedError('unsupported')
  }
  if (
    request.domain &&
    !domainMatchesOrigin({ domain: request.domain, origin })
  ) {
    throw new GetRequestRefusedError('domainMismatch')
  }
  return { profile, queries, origin }
}
