/**
 * Classification of incoming VC API messages. Turns a raw CHAPI event (or, in a
 * later phase, a QR / pasted payload) into a typed `IVpRequest` / `IVpOffer`,
 * and provides the type guards used to dispatch on what was actually asked for
 * (VC sharing, DID Authentication, or both).
 */
import type {
  IDIDAuthenticationQuery,
  IVPOffer,
  IVPRequest,
  IVPRDetails,
  IVPRQuery,
  IVerifiablePresentation,
  WalletAPIMessage,
  WalletRequestKind
} from './types'

/**
 * Raw CHAPI credential-get event. The `VerifiablePresentation` object CHAPI
 * hands us *is* the VPR body (`query` / `challenge` / `domain`); classification
 * rewraps it as an `IVpRequest`.
 */
export interface CHAPIGetEvent {
  credentialRequestOrigin: string
  credentialRequestOptions?: {
    web?: {
      VerifiablePresentation?: IVPRDetails
    }
  }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

/**
 * Raw CHAPI credential-store event. `credential.data` is the offered VP.
 */
export interface CHAPIStoreEvent {
  credentialRequestOrigin?: string
  credential: { data: IVerifiablePresentation }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

/**
 * Wraps a CHAPI get event as an `IVpRequest`.
 *
 * @param event {CHAPIGetEvent}
 * @returns {IVPRequest}
 */
export function classifyCHAPIGetEvent(event: CHAPIGetEvent): IVPRequest {
  const verifiablePresentationRequest =
    event.credentialRequestOptions?.web?.VerifiablePresentation
  if (!verifiablePresentationRequest) {
    throw new Error(
      'CHAPI get event is missing a VerifiablePresentation request.'
    )
  }
  return {
    verifiablePresentationRequest,
    credentialRequestOrigin: event.credentialRequestOrigin
  }
}

/**
 * Wraps a CHAPI store event as an `IVpOffer`.
 *
 * @param event {CHAPIStoreEvent}
 * @returns {IVPOffer}
 */
export function classifyCHAPIStoreEvent(event: CHAPIStoreEvent): IVPOffer {
  return {
    verifiablePresentation: event.credential.data,
    credentialRequestOrigin: event.credentialRequestOrigin
  }
}

/**
 * Type guard: the message is an offer of a credential for storage.
 */
export function isVPOffer(message: WalletAPIMessage): message is IVPOffer {
  return 'verifiablePresentation' in message
}

/**
 * Type guard: the message is a request for credentials / DID Authentication.
 */
export function isVPRequest(message: WalletAPIMessage): message is IVPRequest {
  return 'verifiablePresentationRequest' in message
}

/**
 * Returns true if the query set contains a `DIDAuthentication` query. Throws if
 * more than one is present -- a single DID-Auth proof answers the request.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}
 * @returns {boolean}
 */
export function isDIDAuthRequested({
  queries
}: {
  queries: IVPRQuery[]
}): boolean {
  const didAuthRequests = queries.filter(q => q.type === 'DIDAuthentication')
  if (didAuthRequests.length > 1) {
    throw new Error('More than one DIDAuthentication request found, exiting.')
  }
  return didAuthRequests.length === 1
}

/**
 * Returns true if the message is a VPR whose queries are *all*
 * `DIDAuthentication` (i.e. no credential sharing is involved).
 *
 * @param message {WalletAPIMessage}
 * @returns {boolean}
 */
export function isDIDAuthOnlyRequest(message: WalletAPIMessage): boolean {
  if (!isVPRequest(message)) {
    return false
  }
  const queries = queriesOf(message.verifiablePresentationRequest)
  return (
    queries.length > 0 && queries.every(q => q.type === 'DIDAuthentication')
  )
}

/**
 * Normalizes a VPR's `query` (which may be a single object or an array) to an
 * array.
 *
 * @param request {IVPRDetails}
 * @returns {IVPRQuery[]}
 */
export function queriesOf(request: IVPRDetails): IVPRQuery[] {
  const { query } = request
  return Array.isArray(query) ? query : [query]
}

/**
 * Classifies a request into the workflow the page should dispatch to.
 *
 * @param request {IVPRequest}
 * @returns {WalletRequestKind}
 */
export function requestKindOf(request: IVPRequest): WalletRequestKind {
  if (isDIDAuthOnlyRequest(request)) {
    return 'didauth'
  }
  const queries = queriesOf(request.verifiablePresentationRequest)
  return isDIDAuthRequested({ queries }) ? 'vc+didauth' : 'vc'
}

/**
 * Returns true if the wallet can satisfy the DID method a `DIDAuthentication`
 * query constrains to. Freewallet only holds `did:key`, so a request is
 * satisfiable when it lists `key` among `acceptedMethods` or omits the
 * constraint entirely.
 *
 * @param queries {IVPRQuery[]}
 * @returns {boolean}
 */
export function didAuthMethodSupported(queries: IVPRQuery[]): boolean {
  const didAuth = queries.find(query => query.type === 'DIDAuthentication') as
    IDIDAuthenticationQuery | undefined
  const acceptedMethods = didAuth?.acceptedMethods
  if (!acceptedMethods || acceptedMethods.length === 0) {
    return true
  }
  return acceptedMethods.some(({ method }) => method === 'key')
}
