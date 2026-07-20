/**
 * Framework-agnostic request processing: turns a classified `IVprDetails` plus
 * the user's VC selection into a `WalletResponse` (a possibly-signed VP). The
 * response channel (CHAPI `respondWith`, a future exchange-URL POST) stays with
 * the caller -- this function only returns data. Trimmed from DCW's
 * `exchanges.ts#processRequest` (zcap and exchanger-POST branches dropped).
 */
import type { Session } from '@/types/auth'
import { processAppConnect } from './appConnect'
import { classifyRequest, queriesOf } from './classify'
import { composeVP } from './composeVP'
import { negotiateCryptosuite } from './presentationSuite'
import { processZcaps } from './processZcaps'
import type {
  IVerifiableCredential,
  IVPRDetails,
  IZcap,
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
  const { didAuth, zcapRequests, appConnect } = classifyRequest(request)
  const queries = queriesOf(request)
  const { challenge, domain } = request
  // Honor any cryptosuite the verifier asks for (VCALM `acceptedCryptosuites`).
  const cryptosuite = negotiateCryptosuite(queries)

  // Security: never sign an authentication proof bound to a domain the request
  // did not actually arrive from. Enforced whenever a `domain` is present,
  // including a zcap-only request whose (unsigned) VP still names an origin.
  if (
    domain &&
    !domainMatchesOrigin({ domain, origin: credentialRequestOrigin })
  ) {
    throw new Error(
      `DID Auth domain "${domain}" does not match request origin ` +
        `"${credentialRequestOrigin}".`
    )
  }

  // An App Connect request takes its own single-round branch: match-or-mint
  // the app key, delegate to its subject DID, one composed response. The
  // requesting origin is what the app key is bound to, so it is required.
  if (appConnect) {
    if (!credentialRequestOrigin) {
      throw new Error('An App Connect request requires a requesting origin.')
    }
    return processAppConnect({
      appConnect,
      session,
      origin: credentialRequestOrigin,
      challenge,
      domain,
      didAuthRequested: didAuth,
      cryptosuite
    })
  }

  // Delegate the approved capabilities first, then embed them in the VP.
  const zcaps: IZcap[] =
    zcapRequests.length > 0 ? await processZcaps({ zcapRequests, session }) : []

  if (!didAuth && selectedVCs.length === 0 && zcaps.length === 0) {
    // Nothing to send: no DID Auth, no VCs, and no satisfiable grants.
    return {}
  }

  const verifiablePresentation = await composeVP({
    session,
    selectedVCs,
    challenge,
    domain,
    didAuthRequested: didAuth,
    cryptosuite,
    zcaps
  })
  // Return the delegated capabilities alongside the VP so the caller can log
  // exactly what was granted from these objects, rather than reading them back
  // off the composed VP.
  return { verifiablePresentation, zcaps }
}
