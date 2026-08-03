/**
 * The CHAPI `get` response sequence: compose the presentation, persist the
 * Login activity, and only then deliver anything externally. The ordering is
 * the security-critical part and lives here rather than in the popup page, so
 * it is stated once and exercisable without a DOM.
 */
import type { WalletResponse } from '@interop/wallet-core/request'
import type { IVPRDetails as ISpecVPRDetails } from '@interop/wallet-core/request'
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

/**
 * Why a response could not be produced or delivered. Mirrors the popup's block
 * reasons so the page can render the matching message without re-deriving it
 * from the underlying error.
 */
export type WalletResponseFailureReason =
  'zcapUnavailable' | 'processFailed' | 'exchangeFailed'

/**
 * A response that was refused before anything reached the relying party. When
 * `reason` is `processFailed` after a failed history write, nothing has been
 * delivered: the already-signed delegations stay inert rather than
 * unrevocable.
 */
export class WalletResponseFailure extends Error {
  reason: WalletResponseFailureReason

  constructor(reason: WalletResponseFailureReason, options?: ErrorOptions) {
    super(`Could not respond to the request: ${reason}`, options)
    this.name = 'WalletResponseFailure'
    this.reason = reason
  }
}

/**
 * Records the Login activity when the request granted storage capabilities,
 * connected an app, or authenticated the user's DID -- the capabilities
 * `processRequest` actually delegated (threaded out alongside the VP), rather
 * than read back off the composed VP's embedded `zcap` array; for App Connect,
 * also the app name and whether the app key was minted on this connect.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.profile {WalletRequestProfile}   the classified request
 * @param options.requestOrigin {string}
 * @param options.zcaps {IZcap[]}   the capabilities actually delegated
 * @param [options.appConnectResult] {WalletResponse['appConnect']}
 * @returns {Promise<void>}
 */
async function recordLoginActivity({
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
}): Promise<void> {
  if (
    !profile.didAuth &&
    profile.zcapRequests.length === 0 &&
    !profile.appConnect
  ) {
    return
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
  await session.storage.addHistoryLogin({
    user: session.user,
    origin: requestOrigin,
    grants,
    appConnect:
      appConnectResult && profile.appConnect
        ? {
            name: profile.appConnect.app.name,
            firstRun: appConnectResult.firstRun
          }
        : undefined
  })
}

/**
 * Composes the response VP (selected VCs plus any delegated grants), records
 * the Login activity when capabilities were granted, and only then delivers
 * the VP externally -- POSTing it to the VC API exchange when the request came
 * from one. Returning the presentation over the CHAPI channel stays with the
 * caller, since only it holds the CHAPI event.
 *
 * Ordering: history/zcap persistence precedes every external delivery, so the
 * relying party can never hold live delegated capabilities that lack a
 * revocation hook. The Login activity is the durable record App Connect
 * revocation re-reads the zcap documents from, and both the exchange POST and
 * the CHAPI response hand the relying party the VP with its embedded,
 * already-signed `zcap` array. Persisting last would let a delivered grant
 * outlive a failed (or torn-down) history write with no way to revoke it from
 * the sharing panel.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}
 * @param options.session {Session}
 * @param options.profile {WalletRequestProfile}   the classified request
 * @param options.requestOrigin {string}   the CHAPI requesting origin
 * @param options.selectedVCs {IVerifiableCredential[]}
 * @param [options.exchangeUrl] {string}   set when the verifier deferred the
 *   request to a VC API exchange
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
  exchangeUrl
}: {
  request: IVPRDetails
  session: Session
  profile: WalletRequestProfile
  requestOrigin: string
  selectedVCs: IVerifiableCredential[]
  exchangeUrl?: string | null
}): Promise<WalletResponse> {
  let response: WalletResponse
  try {
    response = await processRequest({
      request,
      session,
      credentialRequestOrigin: requestOrigin,
      selectedVCs
    })
  } catch (err) {
    // A remote Space that vanished between consent and submit surfaces the
    // same typed error the login-time preflight guards against; map it to the
    // matching block reason rather than the generic processing failure.
    if (err instanceof ZcapUnavailableError) {
      throw new WalletResponseFailure('zcapUnavailable', { cause: err })
    }
    console.error('CHAPI request processing failed:', err)
    throw new WalletResponseFailure('processFailed', { cause: err })
  }
  const grantedZcaps = response.zcaps ?? []

  // The Login activity is the durable record App Connect revocation re-reads
  // the zcap documents from, so it must be persisted BEFORE any external
  // delivery -- both the exchange POST below and the CHAPI response hand the
  // relying party the VP with its embedded, already-signed `zcap` array, so
  // the revocation hook has to exist first. Persisting last would let a
  // delivered grant outlive a failed (or torn-down) history write with no way
  // to revoke it from the sharing panel.
  try {
    await recordLoginActivity({
      session,
      profile,
      requestOrigin,
      zcaps: grantedZcaps,
      appConnectResult: response.appConnect
    })
  } catch (err) {
    console.error('Could not record the login history entry:', err)
    if (grantedZcaps.length > 0) {
      // Fail closed: nothing is delivered, so the already-signed delegations
      // stay inert rather than unrevocable. (Conversely, a history write that
      // lands but is followed by a failed exchange POST leaves only a phantom
      // entry -- cleanable from the sharing panel -- which is the more
      // recoverable failure of the two.)
      throw new WalletResponseFailure('processFailed', { cause: err })
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
      console.error('Could not deliver the presentation to the exchange:', err)
      throw new WalletResponseFailure('exchangeFailed', { cause: err })
    }
  }

  return response
}
