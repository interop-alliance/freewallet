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
 * The match scan skipped rows this session cannot read, and no stored app key
 * matched. Carries the skipped counts so the popup can say which way the read
 * failed: rows whose key epoch is still unknown after the one descriptor
 * refresh, rows in a known epoch this session holds no wrap for, and
 * envelopes that will not decrypt at all.
 */
export class AppKeysUnreadableError extends Error {
  unknownEpoch: number
  noEpochKey: number
  undecryptable: number

  constructor({
    unknownEpoch,
    noEpochKey,
    undecryptable
  }: {
    unknownEpoch: number
    noEpochKey: number
    undecryptable: number
  }) {
    super(
      'Could not read the stored app keys: ' +
        `${unknownEpoch} row(s) in a still-unknown key epoch, ` +
        `${noEpochKey} row(s) in a key epoch this session holds no key for, ` +
        `${undecryptable} undecryptable row(s).`
    )
    this.name = 'AppKeysUnreadableError'
    this.unknownEpoch = unknownEpoch
    this.noEpochKey = noEpochKey
    this.undecryptable = undecryptable
  }
}

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
 *    requesting origin, in the `app-connections` collection (the wallet-side
 *    origin binding: a phishing origin can neither recover nor be handed
 *    another origin's key);
 * 2. on no match -- a first run -- mints a fresh one (32-byte seed,
 *    seed-derived did:key, self-issued) and saves it to `app-connections`, a
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
  const { appKeys, skipped } = await session.storage.listAppKeys()
  const credentials = appKeys.map(({ vc }) => vc)
  const existing = await findAppKeyCredential({
    credentials,
    appUrl: app.appUrl,
    origin
  })

  // No match, but the scan could not read every row: refuse rather than mint.
  // None of the three buckets is resolvable from here. An unknown-epoch row
  // survived the facade's one descriptor refresh (its fetch failed, or the
  // refresh was already spent earlier this session -- the consent preview
  // scans before this call does); a no-epoch-key row names an epoch this
  // session holds no wrap for (the residue of a rotation whose
  // `app-connections` fan-out did not complete); and an undecryptable
  // envelope will not open under any descriptor. So "no match" here does not
  // mean "this app has never connected", and minting would hand the app a
  // second seed and DID, permanently orphaning whatever it encrypted under
  // the first.
  if (
    !existing &&
    (skipped.unknownEpoch > 0 ||
      skipped.noEpochKey > 0 ||
      skipped.undecryptable > 0)
  ) {
    throw new AppKeysUnreadableError(skipped)
  }

  const firstRun = !existing
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
    const issued = await mintAppKeyCredential({ app, origin })
    credential = issued.credential
    subjectDid = issued.subjectDid
    // Store before delegating: if delegation fails, the saved key is simply
    // found as "returning" on the next attempt (the store is idempotent on
    // the credential's content id). Through the mint path's own door --
    // `addCredential` refuses every marker credential, wallet-minted or not.
    await session.storage.addMintedAppKey({ credential })
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
    // App Connect never dispatches on `acceptedMethods`: the response VP
    // holds and signs as the client did:key -- the enrolled client's on a
    // remembered session, the visit key's bare did:key on a transient one --
    // which is the holder app-side loaders resolve (app-connect-spec
    // `decisions/0004`). The queries are unread behind the override.
    queries: [],
    holderOverride: {
      signer: session.profile.keyAgent!.getSigner(),
      holder: session.user.id
    },
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
