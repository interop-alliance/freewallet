/**
 * Request processing wrapper. The framework-agnostic pipeline (classify,
 * negotiate, delegate, compose) lives in `@interop/wallet-core/request`; this
 * wrapper injects Freewallet's app-side side effects (`processZcaps`,
 * `processAppConnect`) and enforces Freewallet's stricter DID Auth rule -- a
 * `domain` is required whenever DID Authentication is requested (the shared
 * layer requires only a `challenge`).
 */
import { processRequest as sharedProcessRequest } from '@interop/wallet-core/request'
import type {
  IVPRDetails as ISpecVPRDetails,
  WalletResponse
} from '@interop/wallet-core/request'
import type { Session } from '@/types/auth'
import { classifyRequest } from './classify'
import { presentationSignerFor } from './composeVP'
import { processAppConnect } from './appConnect'
import { processZcaps } from './processZcaps'
import type { IVerifiableCredential, IVPRDetails } from './types'

export { domainMatchesOrigin } from '@interop/wallet-core/request'

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
 * @param [options.expectedAppKeyDid] {string} - App Connect: the app-key
 *   subject DID the consent screen displayed; approval fails closed when the
 *   authoritative re-match resolves a different DID.
 * @returns {Promise<WalletResponse>} The response VP, or `{}` when there is
 *   nothing to send.
 */
export async function processRequest({
  request,
  session,
  credentialRequestOrigin,
  selectedVCs = [],
  expectedAppKeyDid
}: {
  request: IVPRDetails
  session: Session
  credentialRequestOrigin?: string
  selectedVCs?: IVerifiableCredential[]
  expectedAppKeyDid?: string
}): Promise<WalletResponse> {
  const { didAuth, appConnect } = classifyRequest(request)

  // Freewallet's stricter DID Auth rule: a `domain` is required whenever DID
  // Authentication is requested (the shared layer requires only a `challenge`).
  if (didAuth && !request.domain) {
    throw new Error('Both "challenge" and "domain" are required for DID Auth.')
  }

  // The shared pipeline uses `presentationSigner` only on the non-App-Connect
  // path; the App Connect branch resolves its own signer inside
  // `processAppConnect`. Resolve the (possibly KMS-backed) did:web signer only
  // when it will actually be used, so App Connect avoids a redundant KMS lookup.
  const presentationSigner = appConnect
    ? { signer: session.profile.keyAgent!.getSigner(), holder: session.user.id }
    : await presentationSignerFor(session)

  return sharedProcessRequest({
    // Freewallet widens `IVPRDetails.query` with the app-side `AppConnectQuery`;
    // the shared pipeline reads the query set structurally.
    request: request as ISpecVPRDetails,
    presentationSigner,
    selectedVCs,
    credentialRequestOrigin,
    processors: {
      processZcaps: ({ zcapRequests }) =>
        processZcaps({ zcapRequests, session }),
      // `appConnect` is non-null whenever this branch runs: the shared layer
      // only invokes `processAppConnect` for a request carrying an
      // `AppConnectQuery`, which `classifyRequest` above already parsed (or
      // threw on) into `appConnect`.
      processAppConnect: ({
        origin,
        challenge,
        domain,
        didAuthRequested,
        cryptosuite
      }) =>
        processAppConnect({
          appConnect: appConnect!,
          session,
          origin,
          challenge,
          domain,
          didAuthRequested,
          cryptosuite,
          expectedSubjectDid: expectedAppKeyDid
        })
    }
  })
}
