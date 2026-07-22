/**
 * Classification of incoming VC API messages. The CHAPI-event wrapping, the
 * query-normalization helpers, and the DID-Auth detection now live in
 * `@interop/wallet-core/request` and are re-exported here. This module keeps
 * only Freewallet's App Connect-aware layer: `appConnectRequestOf`, and the
 * `classifyRequest` / `isDidAuthOnly` that carry the App Connect axis (the
 * shared classifier covers the three VPR-spec query types).
 */
import {
  isDIDAuthRequested,
  queriesOf as sharedQueriesOf,
  zcapQueriesOf
} from '@interop/wallet-core/request'
import type {
  IVPRDetails as ISpecVPRDetails,
  IVPRQuery as ISpecVPRQuery
} from '@interop/wallet-core/request'
import type {
  IAppConnectCapabilityQuery,
  IAppConnectQuery,
  IAppConnectRequest,
  IQueryByExample,
  IVPRDetails,
  IVPRQuery,
  WalletRequestProfile
} from './types'

export {
  classifyCHAPIGetEvent,
  classifyCHAPIStoreEvent,
  credentialsOf,
  isDIDAuthRequested,
  credentialQueriesOf,
  zcapQueriesOf,
  didAuthMethodSupported
} from '@interop/wallet-core/request'

/**
 * Normalizes a VPR's `query` to an array of typed query objects. Bridges
 * Freewallet's widened `IVPRDetails` (whose `query` may carry an
 * `AppConnectQuery`) to the shared `queriesOf`. App Connect entries flow through
 * the shared structural filter unchanged; the App Connect-aware helpers upcast
 * the returned spec union back to the widened union.
 *
 * @param request {IVPRDetails}
 * @returns {ISpecVPRQuery[]}
 */
export function queriesOf(request: IVPRDetails): ISpecVPRQuery[] {
  return sharedQueriesOf(request as ISpecVPRDetails)
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
 * capability requests, no App Connect). Derived from the profile so the popup's
 * restore fast-path and its render both dispatch on the one predicate.
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
