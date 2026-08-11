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
import type { StoredCredential } from '@/types/credential'
import {
  appKeySubjectDid,
  findAppKeyCredential,
  findLegacyAppKeyCredential,
  mintAppKeyCredential,
  reissueAppKeyCredential
} from '@interop/wallet-core/request'
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
 * resolution itself never reads the controller). The entries arrive already
 * rebuilt from the classification-time allowlist (`appConnectRequestOf`), so
 * no undeclared wire-level field (a smuggled `reason`, an attacker-chosen
 * `controller`) can ride through here.
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
 * 1. finds the stored app-key credential for the app's `appUrl` and the
 *    requesting origin (the wallet-side origin binding: a phishing origin can
 *    neither recover nor be handed another origin's key);
 * 2. on no match, looks for a legacy (pre-`appUrl`) key on the origin and
 *    re-issues it in place under the same seed, so the app keeps the identity
 *    and the encrypted data it already has; the legacy record is retired;
 * 3. on neither, mints a fresh one (32-byte seed, seed-derived did:key,
 *    self-issued) and saves it to the wallet's credential store -- a
 *    wallet-internal store under the same consent, no second popup;
 * 4. delegates the requested capabilities to the credential's subject DID;
 * 5. composes the response VP carrying the credential, the embedded grants,
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
 * @param [options.expectedSubjectDid] {string}   the app-key subject DID the
 *   consent screen displayed; approval fails closed when the authoritative
 *   re-match resolves a different DID
 * @returns {Promise<WalletResponse>}
 */
export async function processAppConnect({
  appConnect,
  session,
  origin,
  challenge,
  domain,
  didAuthRequested,
  cryptosuite,
  expectedSubjectDid
}: {
  appConnect: IAppConnectRequest
  session: Session
  origin: string
  challenge?: string
  domain?: string
  didAuthRequested: boolean
  cryptosuite?: string
  expectedSubjectDid?: string
}): Promise<WalletResponse> {
  const { app, capabilityQueries } = appConnect
  const stored = await session.storage.listCredentials()
  const credentials = stored.map(({ vc }) => vc)
  const existing = await findAppKeyCredential({
    credentials,
    appUrl: app.appUrl,
    origin
  })

  let firstRun = !existing
  let credential: IVerifiableCredential
  let subjectDid: string
  if (existing) {
    credential = existing
    const existingDid = appKeySubjectDid(credential)
    if (!existingDid) {
      throw new Error('The stored app-key credential has no subject DID.')
    }
    subjectDid = existingDid
  } else {
    // No current-shape key: an app that connected before the `appUrl` model
    // may still hold a legacy one on this origin. Re-issue it in place under
    // the SAME seed -- a fresh mint would roll the seed and orphan the
    // identity the app encrypted its data under. Ambiguity (two distinct
    // legacy identities on the origin) resolves to undefined, which falls
    // through to a genuine first run.
    const legacy = await findLegacyAppKeyCredential({ credentials, origin })
    const issued = legacy
      ? await reissueAppKeyCredential({ credential: legacy, app, origin })
      : await mintAppKeyCredential({ app, origin })
    credential = issued.credential
    subjectDid = issued.subjectDid
    firstRun = !legacy
    // Store before delegating: if delegation fails, the saved key is simply
    // found as "returning" on the next attempt (the store is idempotent on
    // the credential's content id). Through the mint path's own door --
    // `addCredential` refuses every marker credential, wallet-minted or not.
    await session.storage.addMintedAppKey({ credential, user: session.user })
    if (legacy) {
      await retireLegacyAppKey({ session, stored, legacy })
    }
  }

  // The consent screen displayed a recipient DID, so the delegation must go
  // to exactly that identity. A divergence -- the matched credential deleted
  // or superseded by a later-dated candidate between preview and approval --
  // fails closed rather than silently delegating to a DID the user never saw.
  if (expectedSubjectDid && subjectDid !== expectedSubjectDid) {
    throw new Error(
      'The app-key identity changed between consent and approval; ' +
        'please retry connecting.'
    )
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

/**
 * Removes the legacy app-key record a re-issue superseded, so a second
 * application on the same origin cannot later pick it up as ITS legacy key and
 * be handed this application's identity. Best-effort: the re-issued credential
 * is already stored and outranks the legacy one on every subsequent match, so
 * a failed delete leaves a harmless duplicate rather than a broken connect.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.stored {StoredCredential[]}   the listing the match ran over
 * @param options.legacy {IVerifiableCredential}   the superseded credential
 * @returns {Promise<void>}
 */
async function retireLegacyAppKey({
  session,
  stored,
  legacy
}: {
  session: Session
  stored: StoredCredential[]
  legacy: IVerifiableCredential
}): Promise<void> {
  const record = stored.find(({ vc }) => vc === legacy)
  if (!record) {
    return
  }
  try {
    await session.storage.deleteCredential({ cid: record.cid })
  } catch (err) {
    console.warn('Could not retire the superseded legacy app key:', err)
  }
}
