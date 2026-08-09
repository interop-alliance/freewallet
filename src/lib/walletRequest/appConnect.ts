/**
 * App Connect request processing: the single-round "connect this app" branch
 * of the wallet's response assembly. Finds (returning user) or mints (first
 * run) the app-key credential for the requesting origin, delegates the
 * requested capabilities to its subject DID -- the wallet fills the
 * `controller` the request could not name in advance -- and composes one
 * signed presentation carrying the credential, the grants, and the
 * wallet-provided `firstRun` marker. Runs only on the consent-approved path;
 * the consent preview reuses `resolveGrants` via
 * `appConnectZcapRequests`.
 */
import type { Session } from '@/types/auth'
import {
  appKeySubjectDid,
  findAppKeyCredential,
  mintAppKeyCredential
} from '@/lib/appKey'
import { composeVP } from './composeVP'
import { processZcaps } from './processZcaps'
import type {
  IAppConnectCapabilityQuery,
  IAppConnectRequest,
  ICapabilityQueryDetail,
  IVerifiableCredential,
  IZcap,
  WalletResponse
} from './types'

/**
 * Fills the `controller` an App Connect capability query leaves open with the
 * app-key subject DID, yielding the standard capability-query details that
 * `resolveGrants` / `processZcaps` operate on. Used with the real subject DID
 * at delegation time, and with a placeholder at consent-preview time (the
 * resolution itself never reads the controller).
 *
 * @param options {object}
 * @param options.capabilityQueries {IAppConnectCapabilityQuery[]}
 * @param options.controller {string}
 * @returns {ICapabilityQueryDetail[]}
 */
export function appConnectZcapRequests({
  capabilityQueries,
  controller
}: {
  capabilityQueries: IAppConnectCapabilityQuery[]
  controller: string
}): ICapabilityQueryDetail[] {
  return capabilityQueries.map(detail => ({ ...detail, controller }))
}

/**
 * Processes an App Connect request on the consent-approved path:
 *
 * 1. finds the stored app-key credential for the app's `credentialType` and
 *    the requesting origin (the wallet-side origin binding: a phishing origin
 *    can neither recover nor be handed another origin's key);
 * 2. on no match, mints a fresh one (32-byte seed, seed-derived did:key,
 *    self-issued) and saves it to the wallet's credential store -- a
 *    wallet-internal store under the same consent, no second popup;
 * 3. delegates the requested capabilities to the credential's subject DID;
 * 4. composes the response VP carrying the credential, the embedded grants,
 *    and the `firstRun` marker.
 *
 * @param options {object}
 * @param options.appConnect {IAppConnectRequest}
 * @param options.session {Session}
 * @param options.origin {string}   the CHAPI requesting origin
 * @param [options.challenge] {string}
 * @param [options.domain] {string}
 * @param options.didAuthRequested {boolean}
 * @param [options.cryptosuite] {string}
 * @returns {Promise<WalletResponse>}
 */
export async function processAppConnect({
  appConnect,
  session,
  origin,
  challenge,
  domain,
  didAuthRequested,
  cryptosuite
}: {
  appConnect: IAppConnectRequest
  session: Session
  origin: string
  challenge?: string
  domain?: string
  didAuthRequested: boolean
  cryptosuite?: string
}): Promise<WalletResponse> {
  const { app, capabilityQueries } = appConnect
  const stored = await session.storage.listCredentials()
  const existing = await findAppKeyCredential({
    credentials: stored,
    credentialType: app.credentialType,
    origin
  })

  const firstRun = !existing
  let credential: IVerifiableCredential
  let subjectDid: string
  if (existing) {
    credential = existing.vc
    const existingDid = appKeySubjectDid(credential)
    if (!existingDid) {
      throw new Error('The stored app-key credential has no subject DID.')
    }
    subjectDid = existingDid
  } else {
    const minted = await mintAppKeyCredential({ app, origin })
    credential = minted.credential
    subjectDid = minted.subjectDid
    // Store before delegating: if delegation fails, the saved key is simply
    // found as "returning" on the next attempt (the store is idempotent on
    // the credential's content id). Through the mint path's own door --
    // `addCredential` refuses every marker credential, wallet-minted or not.
    await session.storage.addMintedAppKey({ credential, user: session.user })
  }

  const zcapRequests = appConnectZcapRequests({
    capabilityQueries,
    controller: subjectDid
  })
  const zcaps: IZcap[] =
    zcapRequests.length > 0
      ? await processZcaps({
          zcapRequests,
          session,
          // Names the app on any share activity this request records, so the
          // settings panel reads "Text Editor (app.example)" and not a did:key.
          app: { name: app.name, origin },
          // A newly provisioned private collection is set up multi-recipient:
          // the app's identity KAK (the X25519 twin of `subjectDid`, derived
          // in `processZcaps`) alongside the user's vault KAK. The seed stays
          // out of the grant path -- the subject DID is all that is needed.
          appProvisioning: true
        })
      : []

  const verifiablePresentation = await composeVP({
    session,
    selectedVCs: [credential],
    challenge,
    domain,
    didAuthRequested,
    cryptosuite,
    zcaps,
    appConnect: { firstRun }
  })
  return { verifiablePresentation, zcaps, appConnect: { firstRun, subjectDid } }
}
