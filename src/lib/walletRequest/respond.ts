/**
 * The CHAPI `get` response sequence: compose the presentation, persist the
 * Grant or Login activity, and only then deliver anything externally. A
 * request whose grants provision a collection persists the Grant earlier,
 * after its
 * delegations are signed and before the grantee is escrowed into any key
 * epoch. The ordering is the security-critical part and lives here rather
 * than in the popup page, so it is stated once and exercisable without a DOM.
 */
import type { WalletResponse } from '@interop/wallet-request'
import type { IVPRDetails as ISpecVPRDetails } from '@interop/wallet-request'
import type { Session } from '@/types/auth'
import { deliverPresentation } from './vcApiExchange'
import { processRequest } from './processRequest'
import type {
  IVerifiableCredential,
  IVPRDetails,
  IZcap,
  WalletRequestProfile
} from './types'
import { ZcapUnavailableError } from './processZcaps'
import { AppKeysUnreadableError } from './appConnect'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:request:respond')

/**
 * Why a response could not be produced or delivered. Mirrors the popup's block
 * reasons so the page can render the matching message without re-deriving it
 * from the underlying error.
 */
type WalletResponseFailureReason =
  'zcapUnavailable' | 'appKeysUnreadable' | 'processFailed' | 'exchangeFailed'

/**
 * A response that was refused before anything reached the requester. When
 * `reason` is `processFailed` after a failed history write, nothing has been
 * delivered: the already-signed delegations stay inert rather than
 * unrevocable. When `reason` is `exchangeFailed`, the request's activity is
 * already recorded and the composed response rides on `response`, so a page
 * with no other channel to the requester can offer it for manual delivery.
 */
export class WalletResponseFailure extends Error {
  reason: WalletResponseFailureReason
  response?: WalletResponse

  constructor(
    reason: WalletResponseFailureReason,
    options?: ErrorOptions & { response?: WalletResponse }
  ) {
    super(`Could not respond to the request: ${reason}`, options)
    this.name = 'WalletResponseFailure'
    this.reason = reason
    this.response = options?.response
  }
}

/**
 * Records the request's activity. A request that connected an app or asked
 * for storage capabilities is recorded as a Grant: the capabilities
 * `processRequest` actually delegated (threaded out alongside the VP), rather
 * than read back off the composed VP's embedded `zcap` array; for App Connect,
 * also the app name, the app's `appUrl`, and whether the app key was minted on
 * this connect. Recording the `appUrl` is what lets the Applications panel
 * attribute a connect to one of several apps sharing an origin. A request
 * that only authenticated the user's DID is recorded as a plain Login, which
 * carries no capabilities.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.profile {WalletRequestProfile}   the classified request
 * @param options.requestOrigin {string}   who the entry is attributed to,
 *   never empty: the CHAPI popup refuses a request it cannot attribute to a
 *   website before consent (`precheckGetRequest`), and the interaction-URL
 *   page, which has no attested origin at all, passes the explicit
 *   `EXTERNAL_REQUEST_ORIGIN` marker its Applications rows key on
 * @param options.zcaps {IZcap[]}   the capabilities actually delegated
 * @param [options.appConnectResult] {WalletResponse['appConnect']}
 * @returns {Promise<string | undefined>}   the recorded activity's id, or
 *   undefined when the request granted nothing worth recording
 */
async function recordRequestActivity({
  session,
  profile,
  requestOrigin,
  zcaps,
  appConnectResult
}: {
  session: Session
  profile: WalletRequestProfile
  requestOrigin: string
  zcaps: IZcap[]
  appConnectResult?: WalletResponse['appConnect']
}): Promise<string | undefined> {
  const isGrant =
    profile.appConnect !== null ||
    profile.zcapRequests.length > 0 ||
    zcaps.length > 0
  if (!isGrant) {
    if (!profile.didAuth) {
      return undefined
    }
    return await session.storage.addHistoryLogin({
      user: session.user,
      origin: requestOrigin
    })
  }
  const grants = zcaps.map(zcap => {
    const allowedAction =
      'allowedAction' in zcap ? zcap.allowedAction : undefined
    return {
      id: zcap.id,
      target: zcap.invocationTarget,
      allowedActions: Array.isArray(allowedAction)
        ? allowedAction
        : allowedAction
          ? [allowedAction]
          : [],
      expires: 'expires' in zcap ? zcap.expires : '',
      // The full delegated capability, kept verbatim alongside the display
      // summary: the WAS revocation endpoint needs the capability document
      // itself, so a later App Connect revocation can retire this grant.
      zcap
    }
  })
  return await session.storage.addHistoryGrant({
    user: session.user,
    origin: requestOrigin,
    grants,
    appConnect:
      appConnectResult && profile.appConnect
        ? {
            name: profile.appConnect.app.name,
            firstRun: appConnectResult.firstRun,
            // The classified request's `appUrl` is already the validated,
            // parsed URL's serialization (`appConnectRequestOf` checked it is
            // absolute, fragment-free, and same-origin with the attested
            // requesting origin), so it joins byte-for-byte with the app-key
            // credential's `credentialSubject.appUrl`.
            appUrl: profile.appConnect.app.appUrl
          }
        : undefined,
    // The requester's self-declared name, for the listing that keys agent
    // rows on the origin marker; it never stands in for the grantee key.
    ...(profile.agent !== undefined && { actor: profile.agent })
  })
}

/**
 * Composes the response VP (selected VCs plus any delegated grants), records
 * the Grant activity when capabilities were granted, and only then delivers
 * the VP externally -- POSTing it to the VC API exchange when the request came
 * from one. Returning the presentation over the CHAPI channel stays with the
 * caller, since only it holds the CHAPI event.
 *
 * Ordering: history/zcap persistence precedes every external delivery, so the
 * requester can never hold live delegated capabilities that lack a
 * revocation hook. It also precedes every key-epoch escrow: when a grant
 * provisions a collection, the Grant is persisted from inside
 * `processRequest`, once the delegations are signed and before the grantee
 * is added to the collection's key epochs, and it is not written again after
 * compose. When the rest of `processRequest` then fails, that Grant is
 * removed again, since nothing was delivered and its grants stay inert. The
 * Grant activity is the stored record App Connect
 * revocation re-reads the zcap documents from, and both the exchange POST and
 * the CHAPI response hand the requester the VP with its embedded,
 * already-signed `zcap` array. Persisting last would let a delivered grant
 * outlive a failed (or torn-down) history write with no way to revoke it from
 * the sharing panel.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}
 * @param options.session {Session}
 * @param options.profile {WalletRequestProfile}   the classified request
 * @param options.requestOrigin {string}   the CHAPI requesting origin, or the
 *   interaction-URL page's `EXTERNAL_REQUEST_ORIGIN` marker; never empty, so
 *   the recorded activity always names a requester
 * @param options.selectedVCs {IVerifiableCredential[]}
 * @param [options.exchangeUrl] {string}   set when the verifier deferred the
 *   request to a VC API exchange
 * @param [options.expectedAppKeyDid] {string}   App Connect: the app-key
 *   subject DID the consent screen displayed, pinning the delegation to the
 *   identity the user actually saw
 * @param [options.delegateStandaloneZcaps] {boolean}   the interaction-URL
 *   page's opt-in to delegating a standalone capability query (see
 *   `processRequest`)
 * @returns {Promise<WalletResponse>}   the composed response (`{}` when there
 *   was nothing to send)
 * @throws {WalletResponseFailure}   nothing was delivered
 */
export async function composeAndDeliverResponse({
  request,
  session,
  profile,
  requestOrigin,
  selectedVCs,
  exchangeUrl,
  expectedAppKeyDid,
  delegateStandaloneZcaps
}: {
  request: IVPRDetails
  session: Session
  profile: WalletRequestProfile
  requestOrigin: string
  selectedVCs: IVerifiableCredential[]
  exchangeUrl?: string | null
  expectedAppKeyDid?: string
  delegateStandaloneZcaps?: boolean
}): Promise<WalletResponse> {
  // Set once the Grant activity is persisted ahead of provisioning, so the
  // post-compose write below does not record the same request twice, and a
  // failed approval can remove it again.
  let persisted = false
  let persistedGrantId: string | undefined
  let response: WalletResponse
  try {
    response = await processRequest({
      request,
      session,
      credentialRequestOrigin: requestOrigin,
      selectedVCs,
      expectedAppKeyDid,
      delegateStandaloneZcaps,
      // Revocation finds a grantee through the Grant activity's recorded
      // grants, so the record must exist before provisioning escrows the
      // grantee into a key epoch. A failed write fails the request closed:
      // nothing is escrowed and nothing is delivered.
      beforeProvision: async ({ zcaps, appConnect }) => {
        try {
          persistedGrantId = await recordRequestActivity({
            session,
            profile,
            requestOrigin,
            zcaps,
            appConnectResult: appConnect
          })
        } catch (err) {
          log.error('Could not record the grant history entry', { err })
          throw err
        }
        persisted = true
      }
    })
  } catch (err) {
    // Nothing was delivered, so a Grant persisted ahead of provisioning
    // records grants the requester never received. Remove it, so the
    // Applications page does not list them and a retry leaves one Grant.
    if (persistedGrantId) {
      try {
        await session.storage.deleteHistoryActivity({ id: persistedGrantId })
      } catch (deleteErr) {
        log.error('Could not remove the grant history entry', {
          err: deleteErr
        })
      }
    }
    // A remote Space that vanished between consent and submit surfaces the
    // same typed error the login-time preflight guards against; map it to the
    // matching block reason rather than the generic processing failure.
    if (err instanceof ZcapUnavailableError) {
      throw new WalletResponseFailure('zcapUnavailable', { cause: err })
    }
    // App Connect refused to mint over an unreadable app-key scan; the user
    // needs the "could not read this app's connection" message, not the
    // generic processing failure.
    if (err instanceof AppKeysUnreadableError) {
      throw new WalletResponseFailure('appKeysUnreadable', { cause: err })
    }
    log.error('CHAPI request processing failed', { err })
    throw new WalletResponseFailure('processFailed', { cause: err })
  }
  const grantedZcaps = response.zcaps ?? []

  // The Grant activity is the stored record App Connect revocation re-reads
  // the zcap documents from, so it must be persisted BEFORE any external
  // delivery -- both the exchange POST below and the CHAPI response hand the
  // requester the VP with its embedded, already-signed `zcap` array, so
  // the revocation hook has to exist first. Persisting last would let a
  // delivered grant outlive a failed (or torn-down) history write with no way
  // to revoke it from the sharing panel.
  if (!persisted) {
    try {
      await recordRequestActivity({
        session,
        profile,
        requestOrigin,
        zcaps: grantedZcaps,
        appConnectResult: response.appConnect
      })
    } catch (err) {
      log.error('Could not record the request history entry', { err })
      if (grantedZcaps.length > 0) {
        // Fail closed: nothing is delivered, so the already-signed
        // delegations stay inert rather than unrevocable. (Conversely, a
        // history write that lands but is followed by a failed exchange POST
        // leaves only a phantom entry -- cleanable from the sharing panel --
        // which is the more recoverable failure of the two.)
        throw new WalletResponseFailure('processFailed', { cause: err })
      }
    }
  }

  // The exchange, not the CHAPI channel, is the verifier's system of record
  // for a VC API request, so a failed delivery is a failed response: report
  // it rather than handing the site a presentation it never received. An
  // empty compose (`{}`) cannot reach this point with an exchange open --
  // Continue is disabled when there is nothing to share -- but if it ever
  // did, skipping the POST is still right: the exchange protocol has no
  // decline message, so an unanswered exchange expires on its own.
  if (exchangeUrl && response.verifiablePresentation) {
    try {
      // `deliverPresentation` owns the reply inspection (a multi-step reply is
      // an unfinished, hence failed, delivery), the same logic
      // `collectIssuedPresentation` uses for the issuance direction.
      await deliverPresentation({
        request: request as ISpecVPRDetails,
        exchangeUrl,
        verifiablePresentation: response.verifiablePresentation
      })
    } catch (err) {
      log.error('Could not deliver the presentation to the exchange', { err })
      throw new WalletResponseFailure('exchangeFailed', {
        cause: err,
        response
      })
    }
  }

  return response
}
