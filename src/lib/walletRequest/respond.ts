/**
 * The CHAPI `get` response sequence, shared with the interaction-URL page:
 * record the consent, then escrow, then compose and deliver. The record is
 * the party's `connections` entry, written first with the grants on it (the
 * revocation index), then the Grant or Login activity (the audit trail). Both
 * are written once the delegations are signed and before the grantee is
 * escrowed into any key epoch or any presentation leaves the wallet. The
 * ordering is the security-critical part and lives here rather than in the
 * popup page, so it is stated once and exercisable without a DOM.
 *
 * A connection request (an interaction-URL request naming the `#inbox`
 * descriptor) adds one step ahead of the delegations: the wallet's pairwise
 * seed toward the agent is read off the agent's entry, its tag checked, or
 * minted fresh. The seed and its tag ride the entry write on whichever
 * record path runs, and the response is signed by the seed's did:key.
 */
import { base64urlnopad } from '@scure/base'
import type {
  PresentationSigner,
  WalletResponse
} from '@interop/wallet-request'
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
import {
  CONNECTION_SEED_BYTES,
  connectionDidKey,
  connectionResourceId,
  connectionSeedTag,
  parseConnectionEntry,
  recordGrants,
  removeGrants,
  retireConnection,
  type ConnectionKind
} from '@interop/wallet-core/connections'
import { ceremonyEvents, type CeremonyEmitter } from '@interop/wallet-core'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:request:respond')

/**
 * The request consent's stage ids for the ceremony event channel. Each fires
 * once its write has landed. `escrow` fires when the first escrow into a key
 * epoch lands, which is the run's pivot. `deliver` fires when the VC API
 * exchange accepts the presentation; a CHAPI return is the caller's, so a
 * run without an exchange ends at `record-activity` or `escrow`.
 */
export const REQUEST_CONSENT_STAGES = [
  'record-entry',
  'record-activity',
  'escrow',
  'deliver'
] as const

/**
 * One value of {@link REQUEST_CONSENT_STAGES}.
 */
export type RequestConsentStage = (typeof REQUEST_CONSENT_STAGES)[number]

/**
 * The failure reasons that classify as `refused` on the event channel: the
 * remote Space was gone, or the app-key scan was unreadable. Both refuse
 * before anything is delivered. Every other failure is `failed`.
 */
const REQUEST_CONSENT_REFUSED_REASONS: ReadonlyArray<string> = [
  'zcapUnavailable',
  'appKeysUnreadable'
]

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
 * The party a consent records grants for, the `connections` entry's
 * subject: an App Connect app, by its app key's subject DID, with its
 * attested origin, its canonical app URL, its app-key Resource id, and its
 * self-declared name; or an interaction-URL agent, by the one controller its
 * grants were delegated to, with its self-declared name. `undefined` for a
 * request that names no party and delegates nothing (a plain DID Auth, a
 * credential request).
 */
type ConsentParty = {
  did: string
  kind: ConnectionKind
  name?: string
  origin?: string
  url?: string
  appKey?: string
}

/**
 * The party a request's consent records grants for (see
 * {@link ConsentParty}).
 *
 * @param options {object}
 * @param options.profile {WalletRequestProfile}   the classified request
 * @param options.requestOrigin {string}   the attested requesting origin
 * @param options.zcaps {IZcap[]}   the capabilities actually delegated
 * @param [options.appConnect] {object}   the App Connect result: the app
 *   key's subject DID and its Resource id
 * @returns {ConsentParty | undefined}
 */
function consentParty({
  profile,
  requestOrigin,
  zcaps,
  appConnect
}: {
  profile: WalletRequestProfile
  requestOrigin: string
  zcaps: IZcap[]
  appConnect?: { subjectDid: string; appKey: string }
}): ConsentParty | undefined {
  if (appConnect && profile.appConnect) {
    return {
      did: appConnect.subjectDid,
      kind: 'app',
      name: profile.appConnect.app.name,
      origin: requestOrigin,
      url: profile.appConnect.app.appUrl,
      appKey: appConnect.appKey
    }
  }
  // The standalone path delegates every grant to its query's one
  // `controller` (the page's precheck refuses more than one).
  const controller = zcaps
    .map(zcap => zcap.controller)
    .find((did): did is string => typeof did === 'string')
  if (controller === undefined) {
    return undefined
  }
  return {
    did: controller,
    kind: 'agent',
    ...(profile.agent?.name !== undefined && { name: profile.agent.name })
  }
}

/**
 * What stood at the party's `connections` entry before this request's
 * consent wrote to it: no entry, a retired one, or a live one. A rollback
 * reads it to decide whether the entry goes back to retired.
 */
type PriorEntryState = 'absent' | 'retired' | 'live'

/**
 * Reads the party's entry ahead of the consent's write and reports its state
 * (see {@link PriorEntryState}). The read is at the id the write itself
 * reads, so the host learns nothing new from it. A body the codec cannot
 * parse counts as `live`, so a rollback never retires it. A failed read
 * throws, which fails the request closed with nothing written.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.party {ConsentParty}
 * @returns {Promise<PriorEntryState>}
 */
async function priorEntryState({
  session,
  party
}: {
  session: Session
  party: ConsentParty
}): Promise<PriorEntryState> {
  const { store, hmacKey } = await session.storage.connectionsDirectory()
  const stored = await store.get({
    resourceId: await connectionResourceId({ hmacKey, did: party.did })
  })
  if (stored === undefined) {
    return 'absent'
  }
  return parseConnectionEntry(stored.body)?.retired !== undefined
    ? 'retired'
    : 'live'
}

/**
 * The wallet's pairwise seed toward a connection request's agent, with its
 * tag, and the presentation signer its did:key holds.
 */
type PairwiseSeed = {
  seed: string
  seedTag: string
  presentationSigner: PresentationSigner
}

/**
 * Resolves the pairwise seed for a connection request, before anything is
 * delegated. It reads the agent's entry at the controller's id, the one
 * direct read the directory allows at consent, since the wallet is about to
 * grant that party. A stored seed is taken once its tag verifies under the
 * directory's blinded-index key. An entry with no seed, or no entry, gets
 * 32 fresh random bytes and their tag. A stored seed whose tag fails, an
 * entry body the codec refuses, or a failed read throws, and the consent
 * fails closed with nothing delivered and no seed written: a host that
 * planted a seed is misbehaving, so the seed is not read as absent.
 *
 * Nothing is written here. The seed rides the consent's entry write, and a
 * minted one that is rolled back with the consent is inert, since nothing
 * outside the wallet saw its did:key.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.did {string}   the agent's did:key, the request's one
 *   grantee `controller`
 * @returns {Promise<PairwiseSeed>}
 */
async function resolvePairwiseSeed({
  session,
  did
}: {
  session: Session
  did: string
}): Promise<PairwiseSeed> {
  const { store, hmacKey } = await session.storage.connectionsDirectory()
  const stored = await store.get({
    resourceId: await connectionResourceId({ hmacKey, did })
  })
  let seed: string | undefined
  let seedTag: string | undefined
  if (stored !== undefined) {
    const entry = parseConnectionEntry(stored.body)
    if (entry === undefined) {
      throw new Error(
        "The agent's connections entry could not be read; its seed is " +
          'not replaced.'
      )
    }
    seed = entry.seed
    seedTag = entry.seedTag
  }
  if (seed === undefined || seedTag === undefined) {
    seed = base64urlnopad.encode(
      crypto.getRandomValues(new Uint8Array(CONNECTION_SEED_BYTES))
    )
    seedTag = await connectionSeedTag({ hmacKey, seed })
  }
  // Verifies the tag before deriving, and throws when it fails.
  const derived = await connectionDidKey({ hmacKey, seed, seedTag })
  return {
    seed,
    seedTag,
    presentationSigner: {
      signer: derived.keyAgent.getSigner(),
      holder: derived.did
    }
  }
}

/**
 * Writes the consent's grants on the party's `connections` entry: created,
 * or merged into, un-retired, `lastSeen` moved, each grant marked `share` or
 * `grant` (`recordGrants`). The entry is the revocation index, so this write
 * precedes every escrow and every delivery, and a failure throws so the
 * request fails closed. An entry at the party's id of another `kind` refuses
 * with wallet-core's `ConnectionKindMismatchError`, which fails the request
 * the same way.
 *
 * On a connection request the pairwise seed and its tag are written in the
 * same write. An entry already carrying a different seed refuses
 * (`recordGrants`): a concurrent consent won the race, the composed
 * response names a did:key the entry does not, and the request fails
 * closed.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.party {ConsentParty}
 * @param options.zcaps {IZcap[]}   the capabilities actually delegated
 * @param options.shareZcapIds {string[]}   the ids of the share grants among
 *   them
 * @param [options.pairwise] {PairwiseSeed}   a connection request's seed
 * @returns {Promise<void>}
 */
async function recordConsentEntry({
  session,
  party,
  zcaps,
  shareZcapIds,
  pairwise
}: {
  session: Session
  party: ConsentParty
  zcaps: IZcap[]
  shareZcapIds: string[]
  pairwise?: PairwiseSeed
}): Promise<void> {
  const shares = new Set(shareZcapIds)
  const { store, hmacKey, spaceUrl } =
    await session.storage.connectionsDirectory()
  await recordGrants({
    store,
    hmacKey,
    did: party.did,
    kind: party.kind,
    ...(spaceUrl !== undefined && { spaceUrl }),
    grants: zcaps.map(zcap => ({
      zcap,
      grantKind: shares.has(zcap.id) ? ('share' as const) : ('grant' as const)
    })),
    ...(party.name !== undefined && { name: party.name }),
    ...(party.origin !== undefined && { origin: party.origin }),
    ...(party.url !== undefined && { url: party.url }),
    ...(party.appKey !== undefined && { appKey: party.appKey }),
    ...(pairwise !== undefined && {
      seed: pairwise.seed,
      seedTag: pairwise.seedTag
    })
  })
}

/**
 * Undoes a failed request's consent on the party's entry. Each grant the
 * request recorded whose escrow did not land is removed, by capability id. A
 * grant whose escrow landed is kept: its grantee holds the decryption
 * material, so it stays recorded and listed, and the user has a row to revoke
 * it from.
 *
 * The consent also un-retired the entry and set its `appKey`. So when no
 * grant of this request escrowed, and the entry was absent or retired before
 * the consent, the entry is retired again (`retireConnection`). Otherwise the
 * Applications page would list a connected party that received nothing. An
 * entry the consent created is retired rather than deleted: it keeps the
 * party's names, and a later consent un-retires it. An entry that was live
 * before stays live. So does any entry once one of this request's grants
 * escrowed, since that grantee needs a row to revoke from.
 *
 * A pairwise seed the consent wrote stays on the entry. Nothing outside the
 * wallet saw its did:key, and the next consent reuses it.
 *
 * Best-effort: a failure is logged, and the grants stay listed, which a
 * revoke then handles.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.party {ConsentParty}
 * @param options.zcapIds {string[]}   every grant this request recorded
 * @param options.escrowed {ReadonlySet<string>}   the grants among them whose
 *   escrow landed
 * @param options.prior {PriorEntryState}   the entry's state before the
 *   consent wrote to it
 * @returns {Promise<void>}
 */
async function rollBackConsentEntry({
  session,
  party,
  zcapIds,
  escrowed,
  prior
}: {
  session: Session
  party: ConsentParty
  zcapIds: string[]
  escrowed: ReadonlySet<string>
  prior: PriorEntryState
}): Promise<void> {
  const undelivered = zcapIds.filter(id => !escrowed.has(id))
  const anyEscrowed = undelivered.length < zcapIds.length
  const retire = !anyEscrowed && prior !== 'live'
  if (undelivered.length === 0 && !retire) {
    return
  }
  try {
    const { store, hmacKey, spaceUrl } =
      await session.storage.connectionsDirectory()
    if (undelivered.length > 0) {
      await removeGrants({
        store,
        hmacKey,
        did: party.did,
        zcapIds: undelivered
      })
    }
    if (retire) {
      await retireConnection({
        store,
        hmacKey,
        did: party.did,
        handledZcapIds: zcapIds,
        ...(spaceUrl !== undefined && { spaceUrl })
      })
    }
  } catch (err) {
    log.error('Could not roll back the consent on the connection', { err })
  }
}

/**
 * Composes the response VP (selected VCs plus any delegated grants), records
 * the consent, and only then delivers the VP externally -- POSTing it to the
 * VC API exchange when the request came from one. Returning the presentation
 * over the CHAPI channel stays with the caller, since only it holds the CHAPI
 * event.
 *
 * Ordering: the consent's record precedes every escrow and every external
 * delivery, so the requester can never hold a live delegated capability, or
 * a key-epoch entry, that lacks a revocation hook. The record is first the
 * party's `connections` entry carrying the grants (the revocation index),
 * then the Grant activity (the audit trail). It is written from inside
 * `processRequest`, once the delegations are signed and before any share is
 * escrowed or collection provisioned: on App Connect always, a zero-grant
 * connect included, and on the interaction-URL path whenever a grant needs
 * escrow. A failed write fails the request closed, with nothing escrowed and
 * nothing delivered. When the rest of `processRequest` then fails, nothing
 * was delivered, and the consent is rolled back. Each of this request's
 * grants on the entry whose escrow did not land is removed. A grant whose
 * escrow landed stays recorded, since its grantee holds the decryption
 * material and the user needs a row to revoke it from. When no grant
 * escrowed, the Grant is removed too, and an entry that was absent or
 * retired before the consent is retired again. When some grant escrowed, the
 * Grant stays as the audit trail for it, and the entry stays live.
 *
 * A request that escrows nothing (an interaction-URL grant on a collection
 * that stands, a plain DID Auth) is recorded after compose and before
 * delivery, inside the same failure path: a failed entry write rolls the
 * consent back (a put may have landed with its response lost) and fails
 * closed, and a failed Grant write after it rolls it back again. Either
 * rollback re-retires an entry that was absent or retired before the
 * consent. A failed delivery to the exchange is not a failure here: the
 * record is kept and the composed response rides on the error for manual
 * delivery.
 *
 * A connection request first resolves the wallet's pairwise seed toward the
 * agent (`resolvePairwiseSeed`). A seed whose tag fails refuses the consent
 * before anything is delegated. The seed and its tag ride the entry write on
 * whichever path records, and the response is signed by the seed's did:key
 * over the request's `challenge`, with no `domain`.
 *
 * This is the request consent ceremony's one entry point, for the CHAPI
 * popup and the interaction-URL page alike, and it emits the run's events.
 * The outcome is `clean` once the response is composed (and delivered, with
 * an exchange). A `WalletResponseFailure` is `refused` for an unavailable
 * Space or an unreadable app-key scan, and `failed` otherwise, its `reason`
 * riding the detail.
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
 * @param [options.requestKind] {'interaction-url' | 'connection-request'}
 *   the interaction-URL page's request kind, as its precheck classed it; a
 *   connection request resolves the pairwise seed
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
  delegateStandaloneZcaps,
  requestKind
}: {
  request: IVPRDetails
  session: Session
  profile: WalletRequestProfile
  requestOrigin: string
  selectedVCs: IVerifiableCredential[]
  exchangeUrl?: string | null
  expectedAppKeyDid?: string
  delegateStandaloneZcaps?: boolean
  requestKind?: 'interaction-url' | 'connection-request'
}): Promise<WalletResponse> {
  const events = ceremonyEvents<RequestConsentStage>({
    ceremony: 'request-consent',
    log
  })
  let response: WalletResponse
  try {
    response = await runRequestConsent({
      request,
      session,
      profile,
      requestOrigin,
      selectedVCs,
      exchangeUrl,
      expectedAppKeyDid,
      delegateStandaloneZcaps,
      requestKind,
      events
    })
  } catch (err) {
    if (err instanceof WalletResponseFailure) {
      const refused = REQUEST_CONSENT_REFUSED_REASONS.includes(err.reason)
      events.outcome(
        refused ? 'refused' : 'failed',
        { reason: err.reason },
        err
      )
    } else {
      events.outcome('failed', undefined, err)
    }
    throw err
  }
  events.outcome('clean', { grants: response.zcaps?.length ?? 0 })
  return response
}

/**
 * The consent sequence {@link composeAndDeliverResponse} runs, marking each
 * stage on the run's emitter as its write lands.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}
 * @param options.session {Session}
 * @param options.profile {WalletRequestProfile}
 * @param options.requestOrigin {string}
 * @param options.selectedVCs {IVerifiableCredential[]}
 * @param [options.exchangeUrl] {string}
 * @param [options.expectedAppKeyDid] {string}
 * @param [options.delegateStandaloneZcaps] {boolean}
 * @param [options.requestKind] {'interaction-url' | 'connection-request'}
 * @param options.events {CeremonyEmitter}   the run's emitter
 * @returns {Promise<WalletResponse>}
 * @throws {WalletResponseFailure}
 */
async function runRequestConsent({
  request,
  session,
  profile,
  requestOrigin,
  selectedVCs,
  exchangeUrl,
  expectedAppKeyDid,
  delegateStandaloneZcaps,
  requestKind,
  events
}: {
  request: IVPRDetails
  session: Session
  profile: WalletRequestProfile
  requestOrigin: string
  selectedVCs: IVerifiableCredential[]
  exchangeUrl?: string | null
  expectedAppKeyDid?: string
  delegateStandaloneZcaps?: boolean
  requestKind?: 'interaction-url' | 'connection-request'
  events: CeremonyEmitter<RequestConsentStage>
}): Promise<WalletResponse> {
  // Set once the consent is recorded ahead of escrow, so the post-compose
  // record below does not run, and a failed approval can roll it back: the
  // party whose entry took the grants, the grants it took, the entry's state
  // before the write, and the Grant activity's id.
  let persisted = false
  let persistedGrantId: string | undefined
  let recordedEntry:
    | { party: ConsentParty; zcapIds: string[]; prior: PriorEntryState }
    | undefined
  // The grants whose escrow landed, which a rollback keeps.
  const escrowed = new Set<string>()
  // A connection request's pairwise seed, resolved before anything is
  // delegated, so a seed that fails its tag refuses with nothing minted.
  let pairwise: PairwiseSeed | undefined
  if (requestKind === 'connection-request') {
    const agent = profile.zcapRequests
      .map(({ controller }) => controller)
      .find((did): did is string => typeof did === 'string')
    try {
      if (agent === undefined) {
        throw new Error('A connection request names no agent.')
      }
      pairwise = await resolvePairwiseSeed({ session, did: agent })
    } catch (err) {
      log.error("Could not resolve the agent's pairwise seed", { err })
      throw new WalletResponseFailure('processFailed', { cause: err })
    }
  }
  let response: WalletResponse
  try {
    response = await processRequest({
      request,
      session,
      credentialRequestOrigin: requestOrigin,
      selectedVCs,
      expectedAppKeyDid,
      delegateStandaloneZcaps,
      ...(pairwise && { pairwiseSigner: pairwise.presentationSigner }),
      // Revocation finds a grantee through its `connections` entry, so the
      // entry must carry the grants before provisioning escrows the grantee
      // into a key epoch. A failed write fails the request closed: nothing
      // is escrowed and nothing is delivered.
      beforeProvision: async ({ zcaps, shareZcapIds, appConnect }) => {
        const party = consentParty({
          profile,
          requestOrigin,
          zcaps,
          appConnect
        })
        try {
          if (party) {
            // Set before the write, so a put that landed with its response
            // lost is still rolled back; a removal over an entry that never
            // took the grants writes nothing.
            recordedEntry = {
              party,
              zcapIds: zcaps.map(zcap => zcap.id),
              prior: await priorEntryState({ session, party })
            }
            await recordConsentEntry({
              session,
              party,
              zcaps,
              shareZcapIds,
              pairwise
            })
            events.stage('record-entry', { grants: zcaps.length })
          } else if (zcaps.length > 0) {
            throw new Error(
              'A request that delegated capabilities names no party to ' +
                'record them on.'
            )
          }
        } catch (err) {
          log.error('Could not record the consent', { err })
          throw err
        }
        try {
          persistedGrantId = await recordRequestActivity({
            session,
            profile,
            requestOrigin,
            zcaps,
            appConnectResult: appConnect
          })
          events.stage('record-activity')
        } catch (err) {
          log.error('Could not record the grant history entry', { err })
          // A zero-grant connect delegated nothing, so its entry is the whole
          // record a disconnect needs, and the audit row's loss does not fail
          // it. Any grant fails closed without its audit row.
          if (zcaps.length > 0) {
            throw err
          }
        }
        persisted = true
      },
      onEscrowed: ({ zcapIds }) => {
        for (const id of zcapIds) {
          escrowed.add(id)
        }
        // The first landing is the pivot; a later one emits nothing more.
        if (zcapIds.length > 0) {
          events.stage('escrow')
        }
      }
    })
  } catch (err) {
    // Nothing was delivered, so the consent recorded ahead of escrow names
    // grants the requester never received. The entry drops each of them
    // whose escrow did not land, so the Applications page does not list
    // them. When nothing escrowed, the entry goes back to retired if it was
    // before, and the Grant is removed, so a retry leaves one Grant. When a
    // grant escrowed, the Grant stays: it is the audit trail for the
    // escrowed grants, and it also names the undelivered ones.
    if (recordedEntry) {
      await rollBackConsentEntry({
        session,
        party: recordedEntry.party,
        zcapIds: recordedEntry.zcapIds,
        escrowed,
        prior: recordedEntry.prior
      })
    }
    if (persistedGrantId && escrowed.size === 0) {
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

  // A request that escrowed nothing is recorded here, still BEFORE any
  // external delivery -- both the exchange POST below and the CHAPI response
  // hand the requester the VP with its embedded, already-signed `zcap`
  // array, so the revocation hook has to exist first.
  if (!persisted) {
    const party = consentParty({ profile, requestOrigin, zcaps: grantedZcaps })
    const zcapIds = grantedZcaps.map(zcap => zcap.id)
    // This path runs only when nothing was recorded ahead of escrow, so
    // nothing escrowed.
    const nothingEscrowed = new Set<string>()
    let prior: PriorEntryState | undefined
    if (party) {
      try {
        prior = await priorEntryState({ session, party })
        await recordConsentEntry({
          session,
          party,
          zcaps: grantedZcaps,
          shareZcapIds: [],
          pairwise
        })
        events.stage('record-entry', { grants: grantedZcaps.length })
      } catch (err) {
        // Fail closed: nothing is delivered, so the already-signed
        // delegations stay inert rather than unrevocable. A put that landed
        // with its response lost is rolled back too; a removal over an entry
        // that never took the grants writes nothing.
        log.error('Could not record the consent', { err })
        if (prior !== undefined) {
          await rollBackConsentEntry({
            session,
            party,
            zcapIds,
            escrowed: nothingEscrowed,
            prior
          })
        }
        throw new WalletResponseFailure('processFailed', { cause: err })
      }
    }
    try {
      await recordRequestActivity({
        session,
        profile,
        requestOrigin,
        zcaps: grantedZcaps,
        appConnectResult: response.appConnect
      })
      events.stage('record-activity')
    } catch (err) {
      log.error('Could not record the request history entry', { err })
      if (grantedZcaps.length > 0) {
        // Fail closed, and roll the consent on the entry back again.
        // (Conversely, a record that lands but is followed by a failed
        // exchange POST leaves grants the requester may never hold --
        // revocable from the Applications page -- which is the more
        // recoverable failure of the two.)
        if (party && prior !== undefined) {
          await rollBackConsentEntry({
            session,
            party,
            zcapIds,
            escrowed: nothingEscrowed,
            prior
          })
        }
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
  // decline message, so an unanswered exchange expires on its own. The
  // recorded consent stands, since the composed response is offered for
  // manual delivery.
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
      events.stage('deliver')
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
