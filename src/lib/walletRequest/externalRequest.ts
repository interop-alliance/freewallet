/**
 * The non-CHAPI request entry point: a request that arrives as an interaction
 * URL (a CLI agent's `di was request-grant` link, a pasted or scanned
 * `...?iuv=1` URL) instead of through a CHAPI popup. The page that renders it
 * (`src/pages/external/ExternalRequestPage.tsx`) is the `WalletGetPage` shape
 * minus CHAPI; everything that can be stated without a DOM lives here, so the
 * refusal matrix is exercisable as plain functions.
 *
 * Two things make this entry point stricter than the popup. There is no
 * attested requesting origin: the only requester signal is the grantee DID
 * and the request-supplied `reason` text, both chosen by whoever wrote the
 * link. And the VPR is wholly link-supplied, so it could name a delivery
 * endpoint on a third host. So the page refuses, before consent, everything
 * that needs an origin (`DIDAuthentication`, a `domain`, an
 * `AppConnectQuery`), every grant class beyond the two an agent may
 * legitimately ask for (`#public-collection` and `#private-collection`
 * descriptors, or plain collection URLs resolving to those classes), a plain
 * collection URL naming an encrypted collection whose current key epoch does
 * not list the agent, and a `interact.service` endpoint on another origin
 * than the exchange.
 *
 * A connection request is the one form that also asks for a write: POST on
 * the wallet's `inbox`, named by the `https://w3id.org/byoe#inbox`
 * descriptor, beside reads on audience collections named by plain URL. The
 * wallet answers it with a presentation signed by a pairwise key, so the
 * request must carry a VPR-root `challenge`, and it must be signed by the
 * key of the controller it names, which keeps the wallet from minting a key
 * toward a party that never asked. It may carry no other write and no other
 * descriptor. Its inbox must stand and be one the wallet would read: not
 * public, not encrypted, and stamped by no requester.
 */
import {
  isInteractionUrl,
  openInteractionRequest,
  presentationEndpointFor,
  verifyCapabilityRequest
} from '@interop/wallet-request'
import type {
  FetchLike,
  IVPRDetails as ISpecVPRDetails
} from '@interop/wallet-request'
import { errorNameOf } from '@interop/wallet-core/menders'
import type { ServiceInfo } from '@interop/was-client'
import { isEd25519DidKey } from '@interop/was-client/edv'
import { classifyRequest, queriesOf } from './classify'
import { isInboxDescriptor, namesInboxTarget } from './connectionRequest'
import {
  asksForWrite,
  urlNamesExistingCollection,
  type ExistingCollections,
  type ResolvedGrant
} from './processZcaps'
import { EXTERNAL_REQUEST_URL_PARAM } from './externalRequestPath'
import type { IVPRDetails, WalletRequestProfile } from './types'

/**
 * The `origin` recorded on the Grant activity for a grant answered through
 * this entry point, which has no requesting origin. A fixed marker rather
 * than the exchange host, so the Applications listing can key agent rows on
 * it beside the grant's `controller` DID.
 */
export const EXTERNAL_REQUEST_ORIGIN = 'n/a (API request)'

/**
 * Whether an activity's `object` was recorded for an agent: it carries the
 * {@link EXTERNAL_REQUEST_ORIGIN} marker and no `appConnect` member (which
 * would make it an App Connect record). The one scope every agent reader
 * shares: the Applications listing, the agent grant revocation, and the
 * agent key rotation.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {boolean}
 */
export function isAgentActivityObject(object: unknown): boolean {
  if (!object || typeof object !== 'object') {
    return false
  }
  const { origin, appConnect } = object as {
    origin?: unknown
    appConnect?: unknown
  }
  return origin === EXTERNAL_REQUEST_ORIGIN && !appConnect
}

/**
 * The grant classes this entry point delegates. Everything else the grant
 * engine supports is refused before consent: a share hands the grantee
 * decryption of the user's own encrypted collections, and a
 * protected-collection read covers plaintext `public-credentials`. Widening
 * the list is a documented decision, not a code change. A plain collection
 * URL resolving to the `collection` class passes this list and faces one
 * more check once the key epochs are read ({@link unreadableGrants}). The
 * `inbox` class is admitted only in a connection request: the resolver
 * produces it for no other request kind.
 */
const ALLOWED_TARGET_CLASSES: readonly string[] = [
  'public-collection',
  'collection',
  'inbox'
]

/**
 * Why a request cannot proceed, each with its own copy cell on the page.
 * `invalidLink` and the exchange-state reasons (`gone`, `unreachable`,
 * `malformedRequest`) come from opening the request; the rest come from the
 * pre-consent check over the VPR the exchange handed back.
 * `enrolledClient` is decided once the account document is read
 * ({@link refuseEnrolledClientController}), `noInbox` and
 * `untrustedInbox` once the inbox's metadata is read
 * ({@link refuseUntrustedInbox}), and `noCreatorAttribution` once the
 * server's features are read ({@link refuseUnattributedServer}). The
 * `connection...` reasons refuse a connection request the precheck cannot
 * accept.
 */
export type ExternalRequestRefusal =
  | 'invalidLink'
  | 'gone'
  | 'unreachable'
  | 'malformedRequest'
  | 'nothingRequested'
  | 'didAuth'
  | 'domain'
  | 'appConnect'
  | 'foreignDelivery'
  | 'barredGrant'
  | 'unreadableTarget'
  | 'multipleGrantees'
  | 'enrolledClient'
  | 'connectionUnsigned'
  | 'connectionWithoutChallenge'
  | 'connectionWithWriteGrant'
  | 'connectionTargetForm'
  | 'noInbox'
  | 'untrustedInbox'
  | 'noCreatorAttribution'

/**
 * A request this entry point refuses before anything is shown or written.
 */
export class ExternalRequestRefusedError extends Error {
  refusal: ExternalRequestRefusal

  constructor(refusal: ExternalRequestRefusal, options?: ErrorOptions) {
    super(`The external request was refused: ${refusal}`, options)
    this.name = 'ExternalRequestRefusedError'
    this.refusal = refusal
  }
}

/**
 * Reads the interaction URL out of the route's query string. Strict: an
 * absolute http(s) URL carrying `iuv`, or an `interaction:` URL, and nothing
 * else -- a bare exchange URL, a relative path, or another scheme is refused.
 *
 * @param search {string}   the route's `location.search`
 * @returns {string | null}   the interaction URL, or null when absent or
 *   refused
 */
export function interactionUrlFromSearch(search: string): string | null {
  const raw = new URLSearchParams(search).get(EXTERNAL_REQUEST_URL_PARAM)
  if (!raw) {
    return null
  }
  const trimmed = raw.trim()
  if (!isInteractionUrl(trimmed)) {
    return null
  }
  if (trimmed.startsWith('interaction:')) {
    return trimmed
  }
  try {
    const parsed = new URL(trimmed)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:'
      ? trimmed
      : null
  } catch {
    return null
  }
}

/**
 * Opens the request behind an interaction URL -- the protocols fetch and the
 * exchange begin -- mapping each failure onto its refusal: a 404 on either
 * fetch is `gone` (the server answers the same for an expired and an unknown
 * exchange, so the copy must not assert expiry), a network failure is
 * `unreachable`, and anything else (no usable protocols map, a begin body
 * that is not a VPR) is `malformedRequest`.
 *
 * @param options {object}
 * @param options.url {string}   the interaction URL
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<{ exchangeUrl: string, request: IVPRDetails }>}
 * @throws {ExternalRequestRefusedError}
 */
export async function openExternalRequest({
  url,
  fetch = globalThis.fetch
}: {
  url: string
  fetch?: FetchLike
}): Promise<{ exchangeUrl: string; request: IVPRDetails }> {
  // A rejected fetch is the one network signal; it is tagged here so it
  // cannot be confused with the helpers' own TypeErrors over a reply they
  // could not read (a `null` JSON body, say), which are malformed replies.
  const tagged: FetchLike = async (input, init) => {
    try {
      return await fetch(input, init)
    } catch (err) {
      throw new ExchangeNetworkError({ cause: err })
    }
  }
  try {
    const { exchangeUrl, request } = await openInteractionRequest({
      url,
      fetch: tagged
    })
    return { exchangeUrl, request: request as IVPRDetails }
  } catch (err) {
    // Dispatch on the name: the class may come from a second copy of
    // wallet-core in a linked install.
    if (errorNameOf(err) === 'EphemeralExchangeGoneError') {
      throw new ExternalRequestRefusedError('gone', { cause: err })
    }
    if (err instanceof ExchangeNetworkError) {
      throw new ExternalRequestRefusedError('unreachable', {
        cause: err.cause
      })
    }
    throw new ExternalRequestRefusedError('malformedRequest', { cause: err })
  }
}

/**
 * A fetch that rejected before any reply arrived, as distinct from a reply
 * the helpers could not read.
 */
class ExchangeNetworkError extends Error {
  constructor(options?: ErrorOptions) {
    super('The exchange server could not be reached.', options)
    this.name = 'ExchangeNetworkError'
  }
}

/**
 * The pre-consent check over the VPR the exchange handed back. Classifies
 * the request and refuses, in this order, everything this entry point cannot
 * answer: an empty query set, an `AppConnectQuery` (checked ahead of
 * classification, which would otherwise throw for the missing origin), a
 * `DIDAuthentication` query (freewallet requires a `domain` for DID Auth and
 * there is no origin to match one against), a `domain` on any request, a
 * request with no capability query, a grantee `controller` that is not a bare
 * Ed25519 did:key, capability queries naming more than one grantee
 * `controller`, and a presentation endpoint on another origin than
 * the exchange's. The delivery
 * host is resolved exactly the way delivery resolves it, so the consent
 * screen names where the response will actually go.
 *
 * A connection request (one naming the `#inbox` descriptor) is then held to
 * its own rules ({@link precheckConnectionRequest}), and the result names
 * the request kind grant resolution takes.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}
 * @param options.exchangeUrl {string}
 * @returns {Promise<{ profile: WalletRequestProfile, deliveryHost: string,
 *   requestKind: 'interaction-url' | 'connection-request' }>}
 * @throws {ExternalRequestRefusedError}
 */
export async function precheckExternalRequest({
  request,
  exchangeUrl
}: {
  request: IVPRDetails
  exchangeUrl: string
}): Promise<{
  profile: WalletRequestProfile
  deliveryHost: string
  requestKind: 'interaction-url' | 'connection-request'
}> {
  const queries = queriesOf(request)
  if (queries.length === 0) {
    throw new ExternalRequestRefusedError('malformedRequest')
  }
  if (queries.some(query => (query.type as string) === 'AppConnectQuery')) {
    throw new ExternalRequestRefusedError('appConnect')
  }
  let profile: WalletRequestProfile
  try {
    profile = classifyRequest({ request })
  } catch (err) {
    // A malformed capability entry or agent member: nothing to consent to.
    throw new ExternalRequestRefusedError('malformedRequest', { cause: err })
  }
  if (profile.didAuth) {
    throw new ExternalRequestRefusedError('didAuth')
  }
  if (request.domain) {
    throw new ExternalRequestRefusedError('domain')
  }
  // Storage access is the only thing this entry point answers: a request
  // with no capability query (credentials only, say) would render an empty
  // consent screen with nothing to approve.
  if (profile.zcapRequests.length === 0) {
    throw new ExternalRequestRefusedError('nothingRequested')
  }
  // Every grantee must be a bare Ed25519 did:key. The enrolled-client check
  // matches the controller exactly against bare client did:keys, so a
  // verification method id (`did:key:z6Mk...#z6Mk...`) naming a client's key
  // would otherwise pass it on a grant class that never derives a recipient.
  if (
    profile.zcapRequests.some(({ controller }) => !isEd25519DidKey(controller))
  ) {
    throw new ExternalRequestRefusedError('malformedRequest')
  }
  // Every grant is delegated to its query's own `controller`, while the
  // Applications page lists and revokes an agent by one controller per
  // approval. A second grantee would hold grants no row names.
  const controllers = new Set(
    profile.zcapRequests.map(({ controller }) => controller)
  )
  if (controllers.size > 1) {
    throw new ExternalRequestRefusedError('multipleGrantees')
  }
  const endpoint = presentationEndpointFor({
    request: request as ISpecVPRDetails,
    exchangeUrl
  })
  let deliveryHost: string
  try {
    const resolved = new URL(endpoint)
    if (resolved.origin !== new URL(exchangeUrl).origin) {
      throw new ExternalRequestRefusedError('foreignDelivery')
    }
    deliveryHost = resolved.host
  } catch (err) {
    if (err instanceof ExternalRequestRefusedError) {
      throw err
    }
    throw new ExternalRequestRefusedError('foreignDelivery', { cause: err })
  }
  if (!namesInboxTarget({ zcapRequests: profile.zcapRequests })) {
    return { profile, deliveryHost, requestKind: 'interaction-url' }
  }
  await precheckConnectionRequest({ request, profile })
  return { profile, deliveryHost, requestKind: 'connection-request' }
}

/**
 * The connection request's own refusals, in this order: a grant naming any
 * descriptor other than `#inbox` (`connectionTargetForm`; an audience is
 * named by its plain container URL), a write on any target but the inbox
 * (`connectionWithWriteGrant`), a missing VPR-root `challenge`
 * (`connectionWithoutChallenge`; one inside the query alone does not count,
 * since the response proof signs over the root one), and a proof that does
 * not verify against the named controller (`connectionUnsigned`). The proof
 * check is wallet-request's, and any failure it reports refuses.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}   the request as the exchange
 *   handed it back, its `proof` included
 * @param options.profile {WalletRequestProfile}   its classification
 * @returns {Promise<void>}
 * @throws {ExternalRequestRefusedError}
 */
async function precheckConnectionRequest({
  request,
  profile
}: {
  request: IVPRDetails
  profile: WalletRequestProfile
}): Promise<void> {
  const others = profile.zcapRequests.filter(
    ({ invocationTarget }) => !isInboxDescriptor(invocationTarget)
  )
  if (
    others.some(({ invocationTarget }) => typeof invocationTarget !== 'string')
  ) {
    throw new ExternalRequestRefusedError('connectionTargetForm')
  }
  if (others.some(asksForWrite)) {
    throw new ExternalRequestRefusedError('connectionWithWriteGrant')
  }
  const { challenge } = request
  if (typeof challenge !== 'string' || challenge === '') {
    throw new ExternalRequestRefusedError('connectionWithoutChallenge')
  }
  try {
    await verifyCapabilityRequest({ request })
  } catch (err) {
    throw new ExternalRequestRefusedError('connectionUnsigned', { cause: err })
  }
}

/**
 * Refuses a connection request whose account has no `inbox` the wallet
 * would read, from the trust reading `StorageManager.readInbox` returns:
 * `noInbox` when the collection is absent, `untrustedInbox` when it stands
 * but is not trusted (public, carrying an `encryption` descriptor, or
 * carrying a `generator` stamp). Run once the session can read the Space,
 * before consent renders.
 *
 * @param options {object}
 * @param options.trust {'absent' | 'untrusted' | 'trusted'}
 * @throws {ExternalRequestRefusedError}   `noInbox` or `untrustedInbox`
 */
export function refuseUntrustedInbox({
  trust
}: {
  trust: 'absent' | 'untrusted' | 'trusted'
}): void {
  if (trust === 'absent') {
    throw new ExternalRequestRefusedError('noInbox')
  }
  if (trust === 'untrusted') {
    throw new ExternalRequestRefusedError('untrustedInbox')
  }
}

/**
 * The core-profile feature token by which a WAS server promises to record
 * `createdBy` on every Resource, Collection, and Space created under a
 * capability invocation.
 */
const CREATED_BY_FEATURE = 'created-by'

/**
 * Refuses a connection request on a server that does not advertise the
 * `created-by` feature token. The inbox pass attributes each message by the
 * `createdBy` the server records, and the token is the server's promise to
 * record it on every Resource. Run after {@link refuseUntrustedInbox}.
 *
 * @param options {object}
 * @param options.service {object}   the server's service information, of
 *   which only `hasFeature(token)` is read
 * @throws {ExternalRequestRefusedError}   `noCreatorAttribution`
 */
export function refuseUnattributedServer({
  service
}: {
  service: Pick<ServiceInfo, 'hasFeature'>
}): void {
  if (!service.hasFeature(CREATED_BY_FEATURE)) {
    throw new ExternalRequestRefusedError('noCreatorAttribution')
  }
}

/**
 * Refuses, before consent renders, a request whose grantee `controller` is
 * the did:key of a wallet client the verified account document lists or
 * ever listed. A revoked client's did:key stays public in the account log
 * for good, and a link naming it would put live grants on that client's
 * retired `connections` entry, which no listing shows and no disconnect
 * reaches. No legitimate requester names a wallet client's key. Run once the
 * session can read the account document, after the precheck.
 *
 * @param options {object}
 * @param options.profile {WalletRequestProfile}   the prechecked request
 * @param options.clientDids {ReadonlySet<string>}   the did:keys of every
 *   wallet client the verified account document lists or ever listed, or
 *   this session's own did:key on an account with no account document
 * @throws {ExternalRequestRefusedError}   `enrolledClient`
 */
export function refuseEnrolledClientController({
  profile,
  clientDids
}: {
  profile: WalletRequestProfile
  clientDids: ReadonlySet<string>
}): void {
  if (
    profile.zcapRequests.some(
      ({ controller }) =>
        typeof controller === 'string' && clientDids.has(controller)
    )
  ) {
    throw new ExternalRequestRefusedError('enrolledClient')
  }
}

/**
 * The grants a resolved request asks for outside this entry point's
 * allowlist. Run once the grants are resolved (the first point a target's
 * class is known); a non-empty result refuses the request before consent.
 * Unsatisfiable grants are not barred -- they delegate nothing and render as
 * "cannot fulfill", as on the popup. A plain URL on an encrypted collection
 * the agent cannot read is refused separately, after the key epochs are read
 * ({@link unreadableGrants}).
 *
 * @param grants {ResolvedGrant[]}
 * @returns {ResolvedGrant[]}
 */
export function barredGrants(grants: ResolvedGrant[]): ResolvedGrant[] {
  return grants.filter(
    ({ target }) =>
      target.targetClass !== undefined &&
      !ALLOWED_TARGET_CLASSES.includes(target.targetClass)
  )
}

/**
 * Whether any grant is a plain URL `invocationTarget` naming a collection
 * that already stands (or a Resource inside one). Only such a grant can be
 * refused by {@link unreadableGrants}, so only then does the page wait for
 * the attribution pass, which reads the key epochs, before consent renders.
 *
 * @param options {object}
 * @param options.grants {ResolvedGrant[]}   the first resolution pass
 * @param options.collections {ExistingCollections}   the pre-request snapshot
 * @returns {boolean}
 */
export function namesExistingCollectionByUrl({
  grants,
  collections
}: {
  grants: ResolvedGrant[]
  collections: ExistingCollections
}): boolean {
  return grants.some(grant =>
    urlNamesExistingCollection({ grant, collections })
  )
}

/**
 * The grants that would hand the agent a live zcap over ciphertext it cannot
 * decrypt: a plain URL `invocationTarget` naming an existing encrypted
 * collection (or a Resource inside one) whose current key epoch was read and
 * does not list the agent. A plain URL admits the grantee to no key roster;
 * the `#private-collection` descriptor naming the same collection does. Run
 * over the attributed grants, since the first pass reads no key epoch. An
 * epoch that could not be read decides nothing, so that grant delegates with
 * the ciphertext note as on the popup. A non-empty result refuses the request
 * before consent.
 *
 * @param grants {ResolvedGrant[]}   the attributed grants
 * @returns {ResolvedGrant[]}
 */
export function unreadableGrants(grants: ResolvedGrant[]): ResolvedGrant[] {
  return grants.filter(({ target }) => target.outsideKeyEpoch === true)
}
