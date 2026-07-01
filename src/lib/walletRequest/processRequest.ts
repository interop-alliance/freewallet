/**
 * Framework-agnostic request processing: turns a classified `IVprDetails` plus
 * the user's VC selection into a `WalletResponse` (a possibly-signed VP). The
 * response channel (CHAPI `respondWith`, a future exchange-URL POST) stays with
 * the caller -- this function only returns data. Trimmed from DCW's
 * `exchanges.ts#processRequest` (zcap and exchanger-POST branches dropped).
 */
import type { Session } from '@/types/auth'
import { isDIDAuthRequested, queriesOf } from './classify'
import { composeVP } from './composeVP'
import { negotiateCryptosuite } from './presentationSuite'
import type {
  IVerifiableCredential,
  IVPRDetails,
  WalletResponse
} from './types'

/**
 * Extracts the host (`host:port`) from a value that may be a full URL or a bare
 * host / host:port. Returns undefined if it cannot be parsed.
 */
function hostOf(value: string): string | undefined {
  try {
    const url = value.includes('://')
      ? new URL(value)
      : new URL(`https://${value}`)
    return url.host
  } catch (err) {
    console.warn(`Could not parse host from "${value}":`, err)
    return undefined
  }
}

/**
 * Domain-binding check (VCALM §3.4.3 advisement): a DID-Auth `domain` MUST match
 * the channel the request arrived on, otherwise a dishonest verifier could relay
 * the challenge from another origin and replay the response.
 *
 * @param options {object}
 * @param options.domain {string} - The `domain` from the request.
 * @param [options.origin] {string} - The channel origin (for CHAPI,
 *   `event.credentialRequestOrigin`).
 * @returns {boolean}
 */
export function domainMatchesOrigin({
  domain,
  origin
}: {
  domain: string
  origin?: string
}): boolean {
  if (!origin) {
    return false
  }
  const originHost = hostOf(origin)
  const domainHost = hostOf(domain)
  return !!originHost && originHost === domainHost
}

/**
 * Processes a Verifiable Presentation Request and composes the wallet's
 * response. Assumes the user has already consented and (for VC sharing) picked
 * which credentials to send.
 *
 * @param options {object}
 * @param options.request {IVPRDetails} - The classified VPR body.
 * @param options.session {Session} - The logged-in session.
 * @param [options.credentialRequestOrigin] {string} - Channel origin, used for
 *   the domain-binding check.
 * @param [options.selectedVCs] {IVerifiableCredential[]} - VCs the user chose to
 *   share (empty for a DID-Auth-only response).
 * @returns {Promise<WalletResponse>} The response VP, or `{}` when there is
 *   nothing to send.
 */
export async function processRequest({
  request,
  session,
  credentialRequestOrigin,
  selectedVCs = []
}: {
  request: IVPRDetails
  session: Session
  credentialRequestOrigin?: string
  selectedVCs?: IVerifiableCredential[]
}): Promise<WalletResponse> {
  const queries = queriesOf(request)
  const didAuthRequested = isDIDAuthRequested({ queries })
  const { challenge, domain } = request
  // Honor any cryptosuite the verifier asks for (VCALM `acceptedCryptosuites`).
  const cryptosuite = negotiateCryptosuite(queries)

  // Security: never sign an authentication proof bound to a domain the request
  // did not actually arrive from.
  if (
    domain &&
    !domainMatchesOrigin({ domain, origin: credentialRequestOrigin })
  ) {
    throw new Error(
      `DID Auth domain "${domain}" does not match request origin ` +
        `"${credentialRequestOrigin}".`
    )
  }

  if (!didAuthRequested && selectedVCs.length === 0) {
    // Neither VCs selected nor DID Auth requested -- nothing to send.
    return {}
  }

  const verifiablePresentation = await composeVP({
    session,
    selectedVCs: selectedVCs,
    challenge,
    domain,
    didAuthRequested,
    cryptosuite
  })
  return { verifiablePresentation }
}
