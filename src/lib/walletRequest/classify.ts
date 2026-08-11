/**
 * Classification of incoming VC API messages. The CHAPI-event wrapping, the
 * query-normalization helpers, the DID-Auth detection, and the App Connect
 * query validation (`appConnectRequestOf`) all live in
 * `@interop/wallet-core/request` and are re-exported here. This module keeps
 * only Freewallet's App Connect-aware `classifyRequest` / `isDidAuthOnly`,
 * which carry the App Connect axis the shared profile does not have.
 */
import {
  appConnectRequestOf,
  isDIDAuthRequested,
  queriesOf as sharedQueriesOf,
  zcapQueriesOf
} from '@interop/wallet-core/request'
import type {
  IVPRDetails as ISpecVPRDetails,
  IVPRQuery as ISpecVPRQuery
} from '@interop/wallet-core/request'
import type {
  IQueryByExample,
  IVPRDetails,
  WalletRequestProfile
} from './types'

export {
  appConnectRequestOf,
  classifyCHAPIGetEvent,
  classifyCHAPIStoreEvent,
  credentialsOf,
  isDIDAuthRequested,
  credentialQueriesOf,
  serializedAppUrl,
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
 * Classifies a VPR body onto the independent axes the consent screen and
 * response assembly work from: whether DID Authentication is requested, and
 * separately the credential (`QueryByExample`), capability
 * (`AuthorizationCapabilityQuery` / `ZcapQuery`), and App Connect
 * (`AppConnectQuery`) content asked for. Any combination of the first three
 * is valid, including zcap-only; an App Connect request excludes the
 * credential and standalone capability queries (enforced by the shared
 * `appConnectRequestOf`, which also validates the `app.appUrl` against the
 * attested requesting origin).
 *
 * @param options {object}
 * @param options.request {IVPRDetails}
 * @param [options.origin] {string} - The attested requesting origin. Required
 *   whenever the body carries an `AppConnectQuery`, whose `appUrl` is
 *   meaningless without an origin to validate it against; a request that
 *   carries one without an origin is malformed and throws.
 * @returns {WalletRequestProfile}
 */
export function classifyRequest({
  request,
  origin
}: {
  request: IVPRDetails
  origin?: string
}): WalletRequestProfile {
  const queries = queriesOf(request)
  const carriesAppConnect = queries.some(
    query => (query.type as string) === 'AppConnectQuery'
  )
  if (carriesAppConnect && !origin) {
    throw new Error('An App Connect request requires a requesting origin.')
  }
  return {
    didAuth: isDIDAuthRequested({ queries }),
    vcQueries: queries.filter(
      (query): query is IQueryByExample => query.type === 'QueryByExample'
    ),
    zcapRequests: zcapQueriesOf(queries),
    appConnect: carriesAppConnect
      ? appConnectRequestOf({ queries, origin: origin! })
      : null
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
