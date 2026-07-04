/**
 * Classification of incoming VC API messages. Turns a raw CHAPI event (or,
 * later, a QR / pasted payload) into a typed `IVpRequest` / `IVpOffer`,
 * and provides the type guards used to dispatch on what was actually asked for
 * (VC sharing, DID Authentication, or both).
 */
import type {
  ICapabilityQueryDetail,
  IDIDAuthenticationQuery,
  IQueryByExample,
  IVPOffer,
  IVPRequest,
  IVPRDetails,
  IVPRQuery,
  IVerifiablePresentation,
  IZcapQuery,
  WalletAPIMessage,
  WalletRequestProfile
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
 * Collects the requested capabilities from a query set: filters the two zcap
 * query type strings (`AuthorizationCapabilityQuery` canonical, `ZcapQuery`
 * legacy alias), normalizes each `capabilityQuery` (object or array) to an
 * array, and flattens.
 *
 * @param queries {IVPRQuery[]}
 * @returns {ICapabilityQueryDetail[]}
 */
export function zcapQueriesOf(queries: IVPRQuery[]): ICapabilityQueryDetail[] {
  return queries
    .filter(
      (query): query is IZcapQuery =>
        query.type === 'AuthorizationCapabilityQuery' ||
        query.type === 'ZcapQuery'
    )
    .flatMap(({ capabilityQuery }) =>
      Array.isArray(capabilityQuery) ? capabilityQuery : [capabilityQuery]
    )
}

/**
 * Classifies a VPR body onto the two independent axes the consent screen and
 * response assembly work from: whether DID Authentication is requested, and
 * separately the credential (`QueryByExample`) and capability
 * (`AuthorizationCapabilityQuery` / `ZcapQuery`) content asked for. Any
 * combination is valid, including zcap-only.
 *
 * @param request {IVPRDetails}
 * @returns {WalletRequestProfile}
 */
export function classifyRequest(request: IVPRDetails): WalletRequestProfile {
  const queries = queriesOf(request)
  return {
    didAuth: isDIDAuthRequested({ queries }),
    vcQueries: queries.filter(
      (query): query is IQueryByExample => query.type === 'QueryByExample'
    ),
    zcapRequests: zcapQueriesOf(queries)
  }
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
