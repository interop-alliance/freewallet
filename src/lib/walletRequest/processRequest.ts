/**
 * Request processing wrapper. The framework-agnostic pipeline (classify,
 * negotiate, delegate, compose) lives in `@interop/wallet-request`; this
 * wrapper injects Freewallet's app-side side effects (`processZcaps`,
 * `processAppConnect`) and enforces Freewallet's stricter DID Auth rule -- a
 * `domain` is required whenever DID Authentication is requested (the shared
 * layer requires only a `challenge`).
 *
 * A connection request (an interaction-URL request naming the `#inbox`
 * descriptor) is answered by the wallet's pairwise key toward the agent: the
 * caller hands that signer in, and the response is signed with it over the
 * VPR-root `challenge` with no `domain`. That proof answers no DID Auth
 * query, so the DID Auth rule above does not reach it.
 */
import {
  isDIDAuthRequested,
  processRequest as sharedProcessRequest,
  requestingAgentOf
} from '@interop/wallet-request'
import type {
  IVPRDetails as ISpecVPRDetails,
  PresentationSigner,
  WalletResponse
} from '@interop/wallet-request'
import type { Session } from '@/types/auth'
import { queriesOf } from './classify'
import { presentationSignerFor } from './composeVP'
import { processAppConnect } from './appConnect'
import { processZcaps } from './processZcaps'
import { namesInboxTarget } from './connectionRequest'
import type { IVerifiableCredential, IVPRDetails, IZcap } from './types'

export { domainMatchesOrigin } from '@interop/wallet-request'

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
 * @param [options.delegateStandaloneZcaps] {boolean} - Whether a standalone
 *   capability query (one outside an `AppConnectQuery`) is delegated. Only the
 *   interaction-URL page opts in. Without it the pipeline delegates no
 *   standalone grant.
 * @param [options.beforeProvision] {Function}   awaited with the signed
 *   grants (`zcaps`), the share grants' ids (`shareZcapIds`), and, on App
 *   Connect, the connect's `appConnect` result with its app-key Resource id
 *   (`appKey`), once every delegation is signed and before any collection is
 *   provisioned. On App Connect it runs exactly once, before the VP is
 *   composed; on the standalone path only when some grant needs
 *   provisioning. A throw ends the request with nothing provisioned.
 * @param [options.onEscrowed] {Function}   called with the grant ids each
 *   landed escrow covers (see `processZcaps`)
 * @param [options.pairwiseSigner] {PresentationSigner}   a connection
 *   request's pairwise did:key and its signer, which marks the standalone
 *   request as a connection request: the grants then resolve as one, and
 *   the response is signed by this key over the VPR-root `challenge`, with
 *   no `domain`. A request naming `#inbox` without it, or carrying it
 *   without naming `#inbox`, is refused before anything is delegated.
 * @returns {Promise<WalletResponse>} The response VP, or `{}` when there is
 *   nothing to send.
 */
export async function processRequest({
  request,
  session,
  credentialRequestOrigin,
  selectedVCs = [],
  expectedAppKeyDid,
  delegateStandaloneZcaps = false,
  beforeProvision,
  onEscrowed,
  pairwiseSigner
}: {
  request: IVPRDetails
  session: Session
  credentialRequestOrigin?: string
  selectedVCs?: IVerifiableCredential[]
  expectedAppKeyDid?: string
  delegateStandaloneZcaps?: boolean
  beforeProvision?: (options: {
    zcaps: IZcap[]
    shareZcapIds: string[]
    appConnect?: { firstRun: boolean; subjectDid: string; appKey: string }
  }) => Promise<void>
  onEscrowed?: (options: { zcapIds: string[] }) => void
  pairwiseSigner?: PresentationSigner
}): Promise<WalletResponse> {
  const queries = queriesOf(request)
  const didAuth = isDIDAuthRequested({ queries })
  const appConnectRequested = queries.some(
    query => (query.type as string) === 'AppConnectQuery'
  )

  // Freewallet's stricter DID Auth rule: a `domain` is required whenever DID
  // Authentication is requested (the shared layer requires only a `challenge`).
  if (didAuth && !request.domain) {
    throw new Error('Both "challenge" and "domain" are required for DID Auth.')
  }

  // The shared pipeline uses `presentationSigner` only on the non-App-Connect
  // path; the App Connect branch resolves its own signer inside
  // `processAppConnect` (pinned to the client did:key, whatever the request
  // accepts). Resolve the dispatched signer only when it will actually be
  // used, so App Connect avoids a redundant KMS lookup.
  let presentationSigner: PresentationSigner
  if (pairwiseSigner) {
    presentationSigner = pairwiseSigner
  } else if (appConnectRequested) {
    presentationSigner = {
      signer: session.profile.keyAgent!.getSigner(),
      holder: session.user.id
    }
  } else {
    presentationSigner = await presentationSignerFor({ session, queries })
  }

  // Freewallet widens `IVPRDetails.query` with the app-side `AppConnectQuery`;
  // the shared pipeline reads the query set structurally.
  const specRequest = request as ISpecVPRDetails
  return sharedProcessRequest({
    request: specRequest,
    presentationSigner,
    selectedVCs,
    credentialRequestOrigin,
    // The connection request's response proof: the pairwise key over the
    // VPR-root `challenge`, with no `domain`.
    signWithoutDidAuth: pairwiseSigner !== undefined,
    processors: {
      // The shared pipeline delegates no standalone capability query when
      // this processor is absent.
      ...(delegateStandaloneZcaps && {
        processZcaps: async ({ zcapRequests }) => {
          // The pairwise signer marks a connection request. It and the
          // `#inbox` descriptor travel together, so a request cannot take
          // one without the other.
          const connection = pairwiseSigner !== undefined
          if (namesInboxTarget({ zcapRequests }) !== connection) {
            throw new Error(
              'A connection request is answered by its pairwise signer, ' +
                'and only a connection request is.'
            )
          }
          return processZcaps({
            zcapRequests,
            session,
            requestKind: connection ? 'connection-request' : 'interaction-url',
            // The self-declared `agent` name, stamped on each collection
            // the grant provisions. Classification already validated it, so
            // this read does not throw.
            agent: requestingAgentOf(specRequest),
            ...(beforeProvision && { beforeProvision }),
            ...(onEscrowed && { onEscrowed })
          })
        }
      }),
      // The shared layer validates the `AppConnectQuery` (its `app.appUrl`
      // against the attested origin) and hands the validated request in, so
      // nothing is re-parsed here.
      processAppConnect: ({
        appConnect,
        origin,
        challenge,
        domain,
        didAuthRequested,
        cryptosuite
      }) =>
        processAppConnect({
          appConnect,
          session,
          origin,
          challenge,
          domain,
          didAuthRequested,
          cryptosuite,
          expectedSubjectDid: expectedAppKeyDid,
          beforeProvision,
          onEscrowed
        })
    }
  })
}
