/**
 * VC API exchange client. A verifier may hand the wallet a CHAPI request whose
 * `VerifiablePresentation` body is empty and whose `protocols.vcapi` names an
 * exchange URL instead: the real Verifiable Presentation Request lives on the
 * verifier's exchange endpoint, and the wallet POSTs its response back there
 * rather than (only) over the CHAPI channel. vcplayground.org's verifier does
 * exactly this whenever it mints an exchange, which is always.
 *
 * Two calls make up the wallet's side of the exchange: `startExchange` (POST an
 * empty body, receive the VPR) and `submitPresentation` (POST the composed VP
 * to the VPR's presentation service endpoint, defaulting to the exchange URL).
 *
 * @see https://w3c-ccg.github.io/vc-api/#exchange-examples
 */
import type { CHAPIProtocols } from './classify'
import type { IVerifiablePresentation, IVPRDetails } from './types'

/**
 * The `interact.service` type naming an endpoint that accepts a Verifiable
 * Presentation over plain HTTP POST, with no mediator in between.
 */
const PRESENTATION_SERVICE_TYPE = 'UnmediatedHttpPresentationService2021'

/**
 * The exchange's reply to either wallet call. A multi-step exchange answers a
 * submitted presentation with another `verifiablePresentationRequest`; a
 * finished one answers with nothing, or with credentials it issued, or with a
 * `redirectUrl` for the user to land on.
 */
export interface VCAPIExchangeResponse {
  verifiablePresentationRequest?: IVPRDetails
  verifiablePresentation?: IVerifiablePresentation
  redirectUrl?: string
}

/**
 * The exchange URL a CHAPI request defers to, if any. Present only when the
 * verifier chose the VC API protocol, in which case the request's VPR body is
 * empty and everything of substance lives behind this URL.
 *
 * @param options {object}
 * @param [options.protocols] {CHAPIProtocols}
 * @returns {string | undefined}
 */
export function vcApiExchangeUrl({
  protocols
}: {
  protocols?: CHAPIProtocols
}): string | undefined {
  const vcapi = protocols?.vcapi
  return typeof vcapi === 'string' && vcapi.length > 0 ? vcapi : undefined
}

/**
 * POSTs a JSON body to an exchange endpoint and parses the reply. A 2xx with an
 * empty body is normal (a completed exchange), and yields `{}`.
 *
 * @param options {object}
 * @param options.url {string}
 * @param options.body {object}
 * @returns {Promise<VCAPIExchangeResponse>}
 */
async function postToExchange({
  url,
  body
}: {
  url: string
  body: object
}): Promise<VCAPIExchangeResponse> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body)
  })
  if (!response.ok) {
    throw new Error(
      `The exchange at ${url} responded ${response.status} ` +
        `${response.statusText}.`
    )
  }
  const text = await response.text()
  if (!text) {
    return {}
  }
  try {
    return JSON.parse(text) as VCAPIExchangeResponse
  } catch (err) {
    throw new Error(`The exchange at ${url} returned malformed JSON.`, {
      cause: err
    })
  }
}

/**
 * Opens the exchange and retrieves the Verifiable Presentation Request the
 * verifier is actually asking for. The wallet begins an exchange by POSTing an
 * empty body; the reply carries the VPR.
 *
 * @param options {object}
 * @param options.exchangeUrl {string}
 * @returns {Promise<IVPRDetails>}
 */
export async function startExchange({
  exchangeUrl
}: {
  exchangeUrl: string
}): Promise<IVPRDetails> {
  const { verifiablePresentationRequest } = await postToExchange({
    url: exchangeUrl,
    body: {}
  })
  if (!verifiablePresentationRequest) {
    throw new Error(
      `The exchange at ${exchangeUrl} did not return a ` +
        'verifiablePresentationRequest.'
    )
  }
  return verifiablePresentationRequest
}

/**
 * Where to POST the composed presentation: the VPR's unmediated HTTP
 * presentation service, when it names one, else the exchange URL itself (which
 * every exchange accepts, and which is all vcplayground.org's VPR offers).
 *
 * @param options {object}
 * @param options.request {IVPRDetails}
 * @param options.exchangeUrl {string}
 * @returns {string}
 */
export function presentationEndpointFor({
  request,
  exchangeUrl
}: {
  request: IVPRDetails
  exchangeUrl: string
}): string {
  const services = request.interact?.service ?? []
  const unmediated = services.find(
    ({ type, serviceEndpoint }) =>
      type === PRESENTATION_SERVICE_TYPE && !!serviceEndpoint
  )
  return unmediated?.serviceEndpoint ?? exchangeUrl
}

/**
 * Delivers the wallet's composed presentation to the exchange. The exchange is
 * complete unless the reply carries a further `verifiablePresentationRequest`,
 * which a multi-step exchange uses to ask for more; this wallet answers a single
 * round, so the caller inspects the reply and reports an unfinished exchange
 * rather than pretending it closed.
 *
 * @param options {object}
 * @param options.request {IVPRDetails} - The VPR the exchange handed back.
 * @param options.exchangeUrl {string}
 * @param options.verifiablePresentation {IVerifiablePresentation}
 * @returns {Promise<VCAPIExchangeResponse>}
 */
export async function submitPresentation({
  request,
  exchangeUrl,
  verifiablePresentation
}: {
  request: IVPRDetails
  exchangeUrl: string
  verifiablePresentation: IVerifiablePresentation
}): Promise<VCAPIExchangeResponse> {
  return postToExchange({
    url: presentationEndpointFor({ request, exchangeUrl }),
    body: { verifiablePresentation }
  })
}
