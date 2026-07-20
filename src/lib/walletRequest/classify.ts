/**
 * Classification of incoming VC API messages. Turns a raw CHAPI event (or,
 * later, a QR / pasted payload) into a typed `IVpRequest` / `IVpOffer`,
 * and provides the type guards used to dispatch on what was actually asked for
 * (VC sharing, DID Authentication, or both).
 */
import type {
  IAppConnectCapabilityQuery,
  IAppConnectQuery,
  IAppConnectRequest,
  ICapabilityQueryDetail,
  ICredentialQuery,
  IDIDAuthenticationQuery,
  IQueryByExample,
  IVPOffer,
  IVPRequest,
  IVPRDetails,
  IVPRQuery,
  IVerifiableCredential,
  IVerifiablePresentation,
  IZcapQuery,
  WalletRequestProfile
} from './types'
import { typeArray } from '@/lib/vcShape'

/**
 * The protocol handles a verifier offers alongside a CHAPI request. Only
 * `vcapi` is acted on; `OID4VP` / `OID4VCI` and the `interact` URL (a QR /
 * redirect flow for a wallet on another device) are recognized but unused.
 */
export interface CHAPIProtocols {
  vcapi?: string
  interact?: string
  OID4VP?: string
  OID4VCI?: string
}

/**
 * Raw CHAPI credential-get event. The `VerifiablePresentation` object CHAPI
 * hands us *is* the VPR body (`query` / `challenge` / `domain`); classification
 * rewraps it as an `IVpRequest`. When the verifier names a `protocols` handle
 * it sends that body empty instead, and the VPR must be fetched from the
 * protocol exchange (see `vcApiExchange.ts`).
 */
export interface CHAPIGetEvent {
  credentialRequestOrigin: string
  credentialRequestOptions?: {
    web?: {
      VerifiablePresentation?: IVPRDetails
      protocols?: CHAPIProtocols
    }
  }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

/**
 * Raw CHAPI credential-store event. `credential.data` is the offered payload,
 * and `credential.dataType` names its shape: issuers may offer either a
 * `VerifiablePresentation` wrapping the credential(s), or a bare
 * `VerifiableCredential` (what vcplayground.org sends). An issuer that names a
 * `protocols` handle in `credential.options` sends `data` empty instead, and
 * the offered credentials must be fetched from the protocol exchange (see
 * `vcApiExchange.ts`).
 */
export interface CHAPIStoreEvent {
  credentialRequestOrigin?: string
  credential: {
    dataType?: string
    data: IVerifiablePresentation | IVerifiableCredential
    options?: {
      protocols?: CHAPIProtocols
      recommendedHandlerOrigins?: string[]
    }
  }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

const VC_1_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1'
const VC_2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2'

/**
 * Wraps a bare Verifiable Credential in an unsigned Verifiable Presentation,
 * matching the credential's VC data model version so the presentation's
 * `@context` stays coherent with the credential it carries.
 *
 * @param credential {IVerifiableCredential}
 * @returns {IVerifiablePresentation}
 */
function presentationWrapping(
  credential: IVerifiableCredential
): IVerifiablePresentation {
  const contexts = credential['@context']
  const contextArray = Array.isArray(contexts) ? contexts : [contexts]
  const isV2 = contextArray.includes(VC_2_CONTEXT_URL)
  return {
    '@context': [isV2 ? VC_2_CONTEXT_URL : VC_1_CONTEXT_URL],
    type: ['VerifiablePresentation'],
    verifiableCredential: [credential]
  } as IVerifiablePresentation
}

/**
 * The offered payload as a Verifiable Presentation: passed through when the
 * issuer already offered one, and wrapped when it offered a bare Verifiable
 * Credential.
 *
 * @param credential {CHAPIStoreEvent['credential']}
 * @returns {IVerifiablePresentation}
 */
function offeredPresentation({
  dataType,
  data
}: CHAPIStoreEvent['credential']): IVerifiablePresentation {
  const types = typeArray((data as { type?: unknown })?.type)
  const isPresentation =
    dataType === 'VerifiablePresentation' ||
    types.includes('VerifiablePresentation') ||
    'verifiableCredential' in (data ?? {})
  if (isPresentation) {
    return data as IVerifiablePresentation
  }
  if (
    dataType === 'VerifiableCredential' ||
    types.includes('VerifiableCredential')
  ) {
    return presentationWrapping(data as IVerifiableCredential)
  }
  throw new Error(
    `CHAPI store event offered an unrecognized payload (dataType: ${
      dataType ?? 'undefined'
    }, type: ${JSON.stringify(types)}).`
  )
}

/**
 * The Verifiable Credentials carried by a presentation, normalized to an array.
 *
 * @param presentation {IVerifiablePresentation}
 * @returns {IVerifiableCredential[]}
 */
export function credentialsOf(
  presentation: IVerifiablePresentation
): IVerifiableCredential[] {
  const { verifiableCredential } = presentation
  if (!verifiableCredential) {
    return []
  }
  return Array.isArray(verifiableCredential)
    ? verifiableCredential
    : [verifiableCredential]
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
 * Wraps a CHAPI store event as an `IVpOffer`. A bare offered credential is
 * wrapped in an unsigned presentation, so downstream code always sees a VP.
 *
 * @param event {CHAPIStoreEvent}
 * @returns {IVPOffer}
 */
export function classifyCHAPIStoreEvent(event: CHAPIStoreEvent): IVPOffer {
  return {
    verifiablePresentation: offeredPresentation(event.credential),
    credentialRequestOrigin: event.credentialRequestOrigin
  }
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
 * array, dropping anything that is not a typed query object. A VPR body can
 * legitimately carry no queries at all -- a CHAPI request that names a
 * `protocols` exchange sends an empty body -- so callers get an empty array
 * rather than an array holding `undefined`.
 *
 * @param request {IVPRDetails}
 * @returns {IVPRQuery[]}
 */
export function queriesOf(request: IVPRDetails): IVPRQuery[] {
  const { query } = request
  const queries = Array.isArray(query) ? query : [query]
  return queries.filter(
    (entry): entry is IVPRQuery =>
      !!entry &&
      typeof entry === 'object' &&
      typeof (entry as { type?: unknown }).type === 'string'
  )
}

/**
 * Normalizes a `QueryByExample`'s `credentialQuery` (a single detail object or
 * an array of them) to an array.
 *
 * @param query {IQueryByExample}
 * @returns {ICredentialQuery[]}
 */
export function credentialQueriesOf(
  query: IQueryByExample
): ICredentialQuery[] {
  const { credentialQuery } = query
  if (!credentialQuery) {
    return []
  }
  return Array.isArray(credentialQuery) ? credentialQuery : [credentialQuery]
}

/**
 * Collects the requested capabilities from a query set: filters the two zcap
 * query type strings (`AuthorizationCapabilityQuery` canonical, `ZcapQuery`
 * legacy alias), normalizes each `capabilityQuery` (object or array) to an
 * array, and flattens. A zcap query whose `capabilityQuery` is missing or not
 * an object is malformed -- there is nothing to ask consent for -- so it
 * throws rather than letting an `undefined` descriptor reach grant
 * resolution; classification-time callers surface the throw as a
 * malformed-request state.
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
    .flatMap(({ type, capabilityQuery }) => {
      const detailEntries = Array.isArray(capabilityQuery)
        ? capabilityQuery
        : [capabilityQuery]
      for (const detail of detailEntries) {
        if (!detail || typeof detail !== 'object') {
          throw new Error(
            `A "${type}" query is missing its capabilityQuery detail.`
          )
        }
      }
      return detailEntries
    })
}

/**
 * Extracts the App Connect request from a query set, when one is present. An
 * `AppConnectQuery` is one mental model per popup: the request must not also
 * carry `QueryByExample` or standalone zcap queries, at most one
 * `AppConnectQuery` is allowed, and its `app` block must name the display
 * name and the `credentialType` / `vocabBase` pair the wallet needs to match
 * or mint the app-key credential. Violations throw; classification-time
 * callers surface the throw as a malformed-request state. The capability
 * queries are normalized to an array (absent means "no grants requested" --
 * a connect that only recovers the app key is legal).
 *
 * @param queries {IVPRQuery[]}
 * @returns {IAppConnectRequest | null}
 */
export function appConnectRequestOf(
  queries: IVPRQuery[]
): IAppConnectRequest | null {
  const appConnectQueries = queries.filter(
    (query): query is IAppConnectQuery => query.type === 'AppConnectQuery'
  )
  if (appConnectQueries.length === 0) {
    return null
  }
  if (appConnectQueries.length > 1) {
    throw new Error('More than one AppConnectQuery found, exiting.')
  }
  const mixed = queries.some(
    query =>
      query.type === 'QueryByExample' ||
      query.type === 'AuthorizationCapabilityQuery' ||
      query.type === 'ZcapQuery'
  )
  if (mixed) {
    throw new Error(
      'An AppConnectQuery cannot be combined with QueryByExample or ' +
        'standalone capability queries.'
    )
  }
  const { app, capabilityQuery } = appConnectQueries[0]
  if (
    !app ||
    typeof app.name !== 'string' ||
    typeof app.credentialType !== 'string' ||
    typeof app.vocabBase !== 'string'
  ) {
    throw new Error(
      'An AppConnectQuery is missing its app name / credentialType / ' +
        'vocabBase.'
    )
  }
  const capabilityQueries: IAppConnectCapabilityQuery[] =
    capabilityQuery === undefined
      ? []
      : Array.isArray(capabilityQuery)
        ? capabilityQuery
        : [capabilityQuery]
  for (const detail of capabilityQueries) {
    if (!detail || typeof detail !== 'object') {
      throw new Error(
        'An AppConnectQuery carries a malformed capabilityQuery entry.'
      )
    }
  }
  return { app, capabilityQueries }
}

/**
 * Classifies a VPR body onto the independent axes the consent screen and
 * response assembly work from: whether DID Authentication is requested, and
 * separately the credential (`QueryByExample`), capability
 * (`AuthorizationCapabilityQuery` / `ZcapQuery`), and App Connect
 * (`AppConnectQuery`) content asked for. Any combination of the first three
 * is valid, including zcap-only; an App Connect request excludes the
 * credential and standalone capability queries (enforced by
 * `appConnectRequestOf`).
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
    zcapRequests: zcapQueriesOf(queries),
    appConnect: appConnectRequestOf(queries)
  }
}

/**
 * Whether a classified request is DID-Authentication *only*: it asks the wallet
 * to prove control of its DID and nothing else (no credential queries, no
 * capability requests). Derived from the profile so the popup's restore
 * fast-path and its render both dispatch on the one predicate.
 *
 * @param profile {WalletRequestProfile}
 * @returns {boolean}
 */
export function isDidAuthOnly(profile: WalletRequestProfile): boolean {
  return (
    profile.didAuth &&
    profile.vcQueries.length === 0 &&
    profile.zcapRequests.length === 0 &&
    !profile.appConnect
  )
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
