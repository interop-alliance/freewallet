/**
 * Connected-applications model for the Applications settings section. A
 * connected app is one the user linked through the App Connect CHAPI flow: the
 * wallet holds a self-issued app-key credential for it (in the encrypted
 * `app-connections` collection, kept apart from the user's own credentials
 * because each row carries that app's private seed) and each connect wrote a
 * Login activity to `wallet-activity` recording the display name and the
 * storage grants.
 *
 * `listConnectedApps` joins those two sources into one entry per app-key
 * credential: the credential supplies the origin, subject DID, and connected
 * date; the latest matching Login activity supplies the raw display name, the
 * grant summaries, and the last-connected timestamp. The join is on the
 * credential's `appUrl` where both sides carry one, so several apps sharing an
 * origin get their own attribution, and on the origin alone for rows written
 * before activities recorded an `appUrl`. `deriveAppGrantsState`
 * then reads each recorded grant's delegation signer against the account
 * document's current key set: a grant signed by a since-disconnected wallet
 * client is already dead (the current-key-set rule), so its app lists as
 * orphaned -- "reconnect to use again" -- rather than as live.
 * `revokeAppAccess` retires an app: for each app-provisioned encrypted
 * collection it rotates the epoch to drop the app's recipient key (so the app
 * cannot decrypt future writes) and revokes those pull-axis grants
 * indivisibly, then revokes any remaining storage grants (skipped for an
 * orphaned app, whose grants no longer verify anyway), then removes the
 * app-key credential and records the revocation. The honest ceiling stands:
 * ciphertext the app already fetched stays readable to it -- rotation
 * protects only prospective writes.
 *
 * The same page lists connected AGENTS: grantees that answered an
 * interaction-URL request rather than an App Connect popup, so they hold no
 * app key and no attested origin. `listConnectedAgents` joins those rows out
 * of the activity history alone -- the latest agent-grant Login per grantee
 * did:key, hidden again by a Revoke activity naming the same controller --
 * and `revokeAgentAccess` retires one: the recorded capabilities are revoked
 * and the revocation recorded, with no app key to delete and no epoch to
 * rotate.
 */
import type { StorageManager } from '@/stores/storageManager'
import type { User } from '@/types/auth'
import { multibaseOf } from '@interop/wallet-core/webvh'
import {
  appKeyAppUrl,
  appKeyOrigin,
  presentsAsAppKey
} from '@interop/wallet-core/request'
import { subjectId } from '@/lib/vcShape'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'

/**
 * One storage capability an app was granted, summarized as recorded on the
 * App Connect Login activity's `object.zcaps`.
 */
export interface AppGrant {
  id: string
  target: string
  allowedActions: string[]
  expires: string
  /**
   * The verification-method id that signed the recorded delegation
   * (`zcap.proof.verificationMethod`), when the activity recorded the full
   * capability. Absent on legacy summary-only records.
   */
  signerKeyId?: string
}

/**
 * Whether a connected app's recorded grants still verify under the
 * current-key-set rule:
 *
 * - `active` -- at least one recorded grant was signed by a verification
 *   method the account's did:webvh document currently publishes.
 * - `orphaned` -- signers were recorded but none is in the current document:
 *   the wallet client that connected the app has since been disconnected, so
 *   every grant already stopped verifying with that document edit. The app
 *   must reconnect through the ordinary App Connect flow to be usable again.
 * - `unknown` -- nothing to check against (no signers recorded, or no
 *   verified document available this session).
 */
export type AppGrantsState = 'active' | 'orphaned' | 'unknown'

/**
 * A connected application, joined from its app-key credential and the latest
 * matching App Connect Login activity.
 */
export interface ConnectedApp {
  /**
   * The app-key credential's content cid; identifies the app for revocation.
   */
  cid: string
  /**
   * The raw display name (best-effort).
   */
  name: string
  /**
   * The CHAPI requesting origin the app key is bound to.
   */
  origin: string
  /**
   * The application URL the app key is scoped to within that origin, when the
   * credential carries one (absent on a legacy, pre-`appUrl` key). Two
   * applications sharing an origin are distinct connected apps and are told
   * apart by this value.
   */
  appUrl?: string
  /**
   * The app-key credential's subject (self-issued) did:key.
   */
  subjectDid: string
  /**
   * When the app key was issued (the credential's `issuanceDate`).
   */
  connectedAt?: string
  /**
   * The storage grants recorded on the latest matching connect, if any.
   */
  grants: AppGrant[]
  /**
   * The latest matching connect's timestamp, if a Login activity was found.
   */
  lastConnectedAt?: string
}

// The suffix `mintAppKeyCredential` appends to the app name in `vc.name`.
const APP_KEY_NAME_SUFFIX = ' app key'

/**
 * A string-valued member of an unknown object, or undefined when the value is
 * absent or not a string. The one shape guard the recorded-activity readers
 * below share.
 *
 * @param value {unknown}   the (possibly non-object) container
 * @param key {string}   the member to read
 * @returns {string | undefined}
 */
function stringField(value: unknown, key: string): string | undefined {
  if (!value || typeof value !== 'object') {
    return undefined
  }
  const member = (value as Record<string, unknown>)[key]
  return typeof member === 'string' ? member : undefined
}

/**
 * The origin an App Connect Login activity recorded, when it is one.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {string | undefined}
 */
function loginOrigin(object: unknown): string | undefined {
  return stringField(object, 'origin')
}

/**
 * The display name an App Connect Login activity recorded
 * (`object.appConnect.name`), when present.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {string | undefined}
 */
function loginAppName(object: unknown): string | undefined {
  if (!object || typeof object !== 'object') {
    return undefined
  }
  return stringField((object as { appConnect?: unknown }).appConnect, 'name')
}

/**
 * The `appUrl` an App Connect Login activity recorded
 * (`object.appConnect.appUrl`), when present. Rows written before app keys
 * were scoped to an `appUrl` carry none.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {string | undefined}
 */
function loginAppUrl(object: unknown): string | undefined {
  if (!object || typeof object !== 'object') {
    return undefined
  }
  return stringField((object as { appConnect?: unknown }).appConnect, 'appUrl')
}

/**
 * The grant summaries an App Connect Login activity recorded
 * (`object.zcaps`), normalized to {@link AppGrant}s.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {AppGrant[]}
 */
function loginGrants(object: unknown): AppGrant[] {
  if (!object || typeof object !== 'object' || !('zcaps' in object)) {
    return []
  }
  const { zcaps } = object as { zcaps?: unknown }
  if (!Array.isArray(zcaps)) {
    return []
  }
  return zcaps.map(entry => {
    const grant = (entry ?? {}) as {
      id?: unknown
      target?: unknown
      allowedActions?: unknown
      expires?: unknown
      zcap?: unknown
    }
    return {
      id: typeof grant.id === 'string' ? grant.id : '',
      target: typeof grant.target === 'string' ? grant.target : '',
      allowedActions: Array.isArray(grant.allowedActions)
        ? grant.allowedActions.filter(
            (action): action is string => typeof action === 'string'
          )
        : [],
      expires: typeof grant.expires === 'string' ? grant.expires : '',
      signerKeyId: grantSignerKeyId(grant.zcap)
    }
  })
}

/**
 * The verification-method id that signed a recorded grant capability's
 * delegation proof, when the record carries the full zcap (a delegated zcap
 * carries exactly one `capabilityDelegation` proof, but the wire shape allows
 * an array).
 *
 * @param zcap {unknown}   the recorded full capability, if any
 * @returns {string | undefined}
 */
function grantSignerKeyId(zcap: unknown): string | undefined {
  if (!zcap || typeof zcap !== 'object') {
    return undefined
  }
  const { proof } = zcap as { proof?: unknown }
  return stringField(
    Array.isArray(proof) ? proof[0] : proof,
    'verificationMethod'
  )
}

/**
 * The key-multibase fragment of a verification-method id -- the part after
 * `#`, which names the same Ed25519 key whether the id is the did:key form
 * (`did:key:<mb>#<mb>`) or the promoted did:webvh form (`<did>#<mb>`). The
 * fragment guard is this module's: `multibaseOf` returns the whole string for
 * an id that carries no fragment, which is never a key multibase here.
 *
 * @param keyId {string}
 * @returns {string | undefined}
 */
function signerKeyMultibase(keyId: string): string | undefined {
  return keyId.includes('#') ? multibaseOf(keyId) : undefined
}

/**
 * Derives a connected app's {@link AppGrantsState} by checking each recorded
 * grant's delegation signer against the signing keys the account's locally
 * verified did:webvh document currently publishes (the current-key-set rule:
 * a delegation verifies iff its verification method is in the resolved
 * document now). Matching is on the key-multibase fragment, so a grant signed
 * under the did:key spelling of a still-enrolled client's key stays active.
 *
 * @param options {object}
 * @param options.app {ConnectedApp}
 * @param [options.currentSigningKeys] {Set<string>}   the enrolled clients'
 *   signing-key multibases, or undefined when no verified document is
 *   available this session
 * @returns {AppGrantsState}
 */
export function deriveAppGrantsState({
  app,
  currentSigningKeys
}: {
  app: ConnectedApp
  currentSigningKeys?: Set<string>
}): AppGrantsState {
  return deriveGrantsState({ grants: app.grants, currentSigningKeys })
}

/**
 * The grant-state check itself, over a bare grant list -- shared by the app
 * rows ({@link deriveAppGrantsState}) and the agent rows, which have no
 * app-key credential to hang the grants off.
 *
 * @param options {object}
 * @param options.grants {AppGrant[]}
 * @param [options.currentSigningKeys] {Set<string>}   the enrolled clients'
 *   signing-key multibases, or undefined when no verified document is
 *   available this session
 * @returns {AppGrantsState}
 */
export function deriveGrantsState({
  grants,
  currentSigningKeys
}: {
  grants: AppGrant[]
  currentSigningKeys?: Set<string>
}): AppGrantsState {
  if (!currentSigningKeys) {
    return 'unknown'
  }
  const signers = grants
    .map(grant => grant.signerKeyId)
    .filter((keyId): keyId is string => !!keyId)
  if (signers.length === 0) {
    return 'unknown'
  }
  const anyCurrent = signers.some(keyId => {
    const multibase = signerKeyMultibase(keyId)
    return !!multibase && currentSigningKeys.has(multibase)
  })
  return anyCurrent ? 'active' : 'orphaned'
}

/**
 * Whether an activity is the App Connect Login for a given origin. Matches a
 * `Login` activity whose recorded origin equals `origin` and which carries an
 * `appConnect` member (distinguishing it from a plain "Login with Wallet").
 *
 * @param options {object}
 * @param options.doc {{ type?: string[]; object?: unknown }}
 * @param options.origin {string}
 * @returns {boolean}
 */
function isAppConnectLoginFor({
  doc,
  origin
}: {
  doc: { type?: string[]; object?: unknown }
  origin: string
}): boolean {
  return (
    Array.isArray(doc.type) &&
    doc.type.includes('Login') &&
    loginOrigin(doc.object) === origin &&
    loginAppName(doc.object) !== undefined
  )
}

/**
 * Lists the user's connected applications, one per app-key credential in the
 * `app-connections` collection, joined with the latest matching App Connect
 * Login activity.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @returns {Promise<ConnectedApp[]>}   sorted latest-connected first
 */
export async function listConnectedApps({
  storage
}: {
  storage: StorageManager
}): Promise<ConnectedApp[]> {
  const [{ appKeys: credentials }, history] = await Promise.all([
    storage.listAppKeys(),
    storage.listHistoryItems()
  ])

  // One pass over the history, into three indexes, so the per-credential loop
  // below is a lookup rather than a filter-and-sort each:
  //
  // - by `appUrl`, for rows that recorded one -- the precise join, which tells
  //   two apps sharing an origin apart;
  // - by origin over rows WITHOUT an `appUrl`, the fallback for a credential
  //   whose app has not reconnected since rows started carrying one (a row
  //   carrying a different app's `appUrl` must never stand in here);
  // - by origin over every row, the pre-`appUrl` behavior, kept for a legacy
  //   app-key credential that carries no `appUrl` of its own to join on.
  type HistoryItem = (typeof history)[number]
  const latestLoginByAppUrl = new Map<string, HistoryItem>()
  const latestLoginByOrigin = new Map<string, HistoryItem>()
  const latestUnscopedLoginByOrigin = new Map<string, HistoryItem>()
  function keepLatest(
    index: Map<string, HistoryItem>,
    key: string,
    item: HistoryItem
  ): void {
    const current = index.get(key)
    if (!current || (current.doc.created ?? '') < (item.doc.created ?? '')) {
      index.set(key, item)
    }
  }
  for (const item of history) {
    const origin = loginOrigin(item.doc.object)
    if (!origin || !isAppConnectLoginFor({ doc: item.doc, origin })) {
      continue
    }
    keepLatest(latestLoginByOrigin, origin, item)
    const appUrl = loginAppUrl(item.doc.object)
    if (appUrl !== undefined) {
      keepLatest(latestLoginByAppUrl, appUrl, item)
    } else {
      keepLatest(latestUnscopedLoginByOrigin, origin, item)
    }
  }

  const apps: ConnectedApp[] = []
  for (const { cid, vc: credential } of credentials) {
    const subject = subjectId(credential)
    const origin = appKeyOrigin(credential)
    // The collection holds app keys only, so the row check is the marker type
    // plus the two members this listing reads: anything else in there (an
    // opaque row planted server-side through a space import, say) is not
    // something the page can render or revoke.
    if (!presentsAsAppKey(credential) || !subject || !origin) {
      continue
    }

    // The latest matching App Connect Login supplies the raw display name, the
    // grants, and the last-connected timestamp. Matching prefers this app's
    // own `appUrl` and falls back to the origin for activities an older wallet
    // recorded before the `appUrl` claim existed. The origin-only branch is
    // the same fallback for a key carrying no `appUrl` of its own.
    const appUrl = appKeyAppUrl(credential)
    const latestLogin =
      appUrl !== undefined
        ? (latestLoginByAppUrl.get(appUrl) ??
          latestUnscopedLoginByOrigin.get(origin))
        : latestLoginByOrigin.get(origin)

    const vcName = (credential as { name?: unknown }).name
    const strippedName =
      typeof vcName === 'string' && vcName.endsWith(APP_KEY_NAME_SUFFIX)
        ? vcName.slice(0, -APP_KEY_NAME_SUFFIX.length)
        : undefined
    const name =
      (latestLogin && loginAppName(latestLogin.doc.object)) ??
      strippedName ??
      origin

    const issuanceDate = (credential as { issuanceDate?: unknown }).issuanceDate

    apps.push({
      cid,
      name,
      origin,
      ...(appUrl !== undefined && { appUrl }),
      subjectDid: subject,
      connectedAt: typeof issuanceDate === 'string' ? issuanceDate : undefined,
      grants: latestLogin ? loginGrants(latestLogin.doc.object) : [],
      lastConnectedAt: latestLogin?.doc.created
    })
  }

  return apps.sort((first, second) =>
    (second.lastConnectedAt ?? second.connectedAt ?? '').localeCompare(
      first.lastConnectedAt ?? first.connectedAt ?? ''
    )
  )
}

/**
 * Revokes a connected app's access. Order matters: the key rotation and grant
 * revocation happen on the WAS server first, and only if that succeeds is the
 * app-key credential deleted and the revocation recorded. A network failure
 * while revoking the grants therefore surfaces as an error and leaves the
 * credential in place, so the user can retry rather than being left with a
 * deleted key whose grants are still live.
 *
 * The key rotation runs first (`revokeAppCollectionRecipients`): for each
 * app-provisioned encrypted collection it appends a fresh epoch without the
 * app's key and revokes those collections' pull-axis grants indivisibly, so the
 * app cannot decrypt anything written afterward. That rotation is best-effort
 * per collection (a stuck collection is logged, not fatal). Then the remaining
 * grants are revoked (`revokeAppGrants`, which tolerates the double-revocation
 * of the already-rotated collections' grants). Per-capability no-ops (already
 * revoked/expired) are swallowed inside those methods; only a genuine failure
 * propagates.
 *
 * An `orphaned` app (see {@link AppGrantsState}) skips the per-grant server
 * revocation entirely: its grants already stopped verifying when the signing
 * client's verification method left the account document, so the POSTs would
 * only count into `skipped`. The epoch rotation and the credential deletion
 * remain meaningful and still run.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.user {User}   the session user (activity actor)
 * @param options.app {ConnectedApp}
 * @param [options.grantsState] {AppGrantsState}   the derived grant state
 *   (default `unknown`, which revokes like `active`)
 * @returns {Promise<{ revoked: number; skipped: number }>}   the grant outcome
 */
export async function revokeAppAccess({
  storage,
  user,
  app,
  grantsState = 'unknown'
}: {
  storage: StorageManager
  user: User
  app: ConnectedApp
  grantsState?: AppGrantsState
}): Promise<{ revoked: number; skipped: number }> {
  // Both stages below look up the app's recorded grants in the activity
  // history; scan it once here and pass it through.
  const items = await storage.listHistoryItems()
  // Rotate the epoch off the app for each app-provisioned encrypted collection
  // (and revoke those collections' pull-axis grants) before anything else, so a
  // revoked app cannot decrypt future writes.
  await storage.revokeAppCollectionRecipients({
    origin: app.origin,
    subjectDid: app.subjectDid,
    items
  })
  const outcome =
    grantsState === 'orphaned'
      ? { revoked: 0, skipped: 0 }
      : await storage.revokeAppGrants({
          origin: app.origin,
          subjectDid: app.subjectDid,
          items
        })
  await storage.deleteAppKey({ cid: app.cid })
  await storage.addHistoryAppRevoke({
    user,
    origin: app.origin,
    name: app.name,
    cid: app.cid,
    revoked: outcome.revoked,
    skipped: outcome.skipped
  })
  return outcome
}

/**
 * A connected agent: a grantee that answered an interaction-URL request
 * rather than an App Connect popup, so it has no app-key credential and no
 * origin of its own. Its identity is the grantee did:key its grants were
 * delegated to.
 */
export interface ConnectedAgent {
  /**
   * The grantee did:key the grants were delegated to; identifies the agent
   * for revocation.
   */
  controller: string
  /**
   * The self-declared display name the request carried, when it named one.
   * Display-only: the requester chose it, and nothing verifies it.
   */
  name?: string
  /**
   * The origin marker the grant was recorded under (`EXTERNAL_REQUEST_ORIGIN`
   * -- there is no attested requesting origin on this path).
   */
  origin: string
  /**
   * The storage grants recorded on the latest matching request.
   */
  grants: AppGrant[]
  /**
   * When the latest matching request was granted.
   */
  grantedAt?: string
}

/**
 * The self-declared agent name a Login activity recorded (`object.actor.name`),
 * when present.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {string | undefined}
 */
function loginAgentName(object: unknown): string | undefined {
  if (!object || typeof object !== 'object') {
    return undefined
  }
  return stringField((object as { actor?: unknown }).actor, 'name')
}

/**
 * The grantee did:key a Login activity's recorded grants were delegated to:
 * the `controller` of the first recorded full capability. One request page
 * approval delegates every grant to the same controller, so the first one
 * names the agent.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {string | undefined}
 */
function loginGrantController(object: unknown): string | undefined {
  if (!object || typeof object !== 'object') {
    return undefined
  }
  const { zcaps } = object as { zcaps?: unknown }
  if (!Array.isArray(zcaps)) {
    return undefined
  }
  for (const entry of zcaps) {
    const { zcap } = (entry ?? {}) as { zcap?: unknown }
    if (!zcap || typeof zcap !== 'object') {
      continue
    }
    const { controller } = zcap as { controller?: unknown }
    const named = Array.isArray(controller) ? controller[0] : controller
    if (typeof named === 'string' && named) {
      return named
    }
  }
  return undefined
}

/**
 * Whether an activity is an agent-grant Login: a `Login` recorded under the
 * interaction-URL origin marker, carrying no `appConnect` member (which would
 * make it an App Connect connect) and at least one recorded full capability
 * (without one there is nothing to list or revoke).
 *
 * @param options {object}
 * @param options.doc {{ type?: string[]; object?: unknown }}
 * @returns {boolean}
 */
export function isAgentGrantLogin({
  doc
}: {
  doc: { type?: string[]; object?: unknown }
}): boolean {
  return (
    Array.isArray(doc.type) &&
    doc.type.includes('Login') &&
    loginOrigin(doc.object) === EXTERNAL_REQUEST_ORIGIN &&
    loginAppName(doc.object) === undefined &&
    loginGrantController(doc.object) !== undefined
  )
}

/**
 * Whether every recorded grant of an agent row has already expired -- there is
 * nothing left to revoke, so the row is dropped from the listing. A grant with
 * no recorded expiry (or an unparseable one) counts as still live, so a row is
 * never hidden on a missing stamp.
 *
 * @param options {object}
 * @param options.grants {AppGrant[]}
 * @param options.now {number}
 * @returns {boolean}
 */
function allGrantsExpired({
  grants,
  now
}: {
  grants: AppGrant[]
  now: number
}): boolean {
  if (grants.length === 0) {
    return true
  }
  return grants.every(grant => {
    if (!grant.expires) {
      return false
    }
    const expiresAt = new Date(grant.expires).getTime()
    return Number.isFinite(expiresAt) && expiresAt <= now
  })
}

/**
 * Whether an activity is an agent-grant Revoke: the row
 * {@link revokeAgentAccess} writes. Scoped exactly like the agent Login side
 * -- the interaction-URL origin marker, no `appConnect` member -- and carrying
 * a grantee `controller`, so an app revocation (or any other Revoke that
 * happens to name a controller) can never hide an agent row.
 *
 * @param options {object}
 * @param options.doc {{ type?: string[]; object?: unknown }}
 * @returns {boolean}
 */
function isAgentRevoke({
  doc
}: {
  doc: { type?: string[]; object?: unknown }
}): boolean {
  return (
    Array.isArray(doc.type) &&
    doc.type.includes('Revoke') &&
    loginOrigin(doc.object) === EXTERNAL_REQUEST_ORIGIN &&
    loginAppName(doc.object) === undefined &&
    stringField(doc.object, 'controller') !== undefined
  )
}

/**
 * Whether a Revoke hides a Login in the agent join. Deliberately explicit
 * about the missing stamps: a Login carrying no `created` is never hidden (its
 * age is unknowable, and hiding a row silently loses a revocable grant), and a
 * Revoke carrying none never hides. The comparison stays `>=` -- the Revoke
 * writer stamps a forward floor above the Login it retires, so a tie can only
 * be someone else's stamp, and a tie there means the revocation is at least as
 * new as the grant.
 *
 * @param options {object}
 * @param [options.loginCreated] {string}
 * @param [options.revokeCreated] {string}
 * @returns {boolean}
 */
function revokeHidesLogin({
  loginCreated,
  revokeCreated
}: {
  loginCreated?: string
  revokeCreated?: string
}): boolean {
  if (!loginCreated || !revokeCreated) {
    return false
  }
  return revokeCreated >= loginCreated
}

/**
 * Lists the agents holding storage grants answered from an interaction-URL
 * request, one row per grantee did:key.
 *
 * The join is over the activity history alone (there is no credential to hang
 * a row off): every agent-grant Login for a controller that a matching Revoke
 * does not hide contributes its grants, deduplicated by capability id, and
 * `grantedAt` is the newest of those Logins. The union is what the row counts,
 * expires, and checks signers against -- one controller can hold live grants
 * from several requests, and the revocation scans every Login too, so a
 * latest-Login-only view would under-report what is about to be revoked. A row
 * whose every recorded grant has already expired is dropped -- nothing is left
 * to revoke. A later re-grant writes a newer Login and lists again.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @returns {Promise<ConnectedAgent[]>}   sorted latest-granted first
 */
export async function listConnectedAgents({
  storage
}: {
  storage: StorageManager
}): Promise<ConnectedAgent[]> {
  const history = await storage.listHistoryItems()
  type HistoryItem = (typeof history)[number]

  const loginsByController = new Map<string, HistoryItem[]>()
  const latestRevokeByController = new Map<string, string>()
  for (const item of history) {
    const { doc } = item
    if (isAgentGrantLogin({ doc })) {
      const controller = loginGrantController(doc.object)
      if (!controller) {
        continue
      }
      const existing = loginsByController.get(controller)
      if (existing) {
        existing.push(item)
      } else {
        loginsByController.set(controller, [item])
      }
      continue
    }
    if (!isAgentRevoke({ doc })) {
      continue
    }
    const controller = stringField(doc.object, 'controller')
    const created = doc.created
    if (!controller || !created) {
      continue
    }
    if ((latestRevokeByController.get(controller) ?? '') < created) {
      latestRevokeByController.set(controller, created)
    }
  }

  const now = Date.now()
  const agents: ConnectedAgent[] = []
  for (const [controller, logins] of loginsByController) {
    const revokeCreated = latestRevokeByController.get(controller)
    const live = logins.filter(
      ({ doc }) =>
        !revokeHidesLogin({ loginCreated: doc.created, revokeCreated })
    )
    if (live.length === 0) {
      continue
    }

    // The union of every live Login's grants, deduplicated by capability id:
    // one controller can hold grants from several requests, and the newest
    // request is not necessarily the one with the longest-lived grants.
    const grants: AppGrant[] = []
    const seen = new Set<string>()
    for (const { doc } of live) {
      for (const grant of loginGrants(doc.object)) {
        if (grant.id && seen.has(grant.id)) {
          continue
        }
        if (grant.id) {
          seen.add(grant.id)
        }
        grants.push(grant)
      }
    }
    if (allGrantsExpired({ grants, now })) {
      continue
    }

    // The newest live Login supplies the display members and the granted
    // stamp; the grants above are the union across all of them.
    const latest = live.reduce((newest, item) =>
      (newest.doc.created ?? '') < (item.doc.created ?? '') ? item : newest
    )
    const name = loginAgentName(latest.doc.object)
    agents.push({
      controller,
      ...(name !== undefined && { name }),
      origin: EXTERNAL_REQUEST_ORIGIN,
      grants,
      grantedAt: latest.doc.created
    })
  }

  return agents.sort((first, second) =>
    (second.grantedAt ?? '').localeCompare(first.grantedAt ?? '')
  )
}

/**
 * Revokes a connected agent's storage grants: the recorded capabilities are
 * revoked on the WAS server first, and only if that succeeds is the revocation
 * recorded -- a network failure therefore leaves the row listed, so the user
 * can retry. There is no app key to delete and no epoch rotation: an agent is
 * only ever granted the collection classes the interaction-URL allowlist
 * admits, and it is never an epoch recipient.
 *
 * Unlike the app path, an agent revocation ALWAYS posts the revocations, even
 * for a row the listing marks orphaned. An orphaned marking means only that no
 * recorded signer is in the account document now, which does not make an agent
 * grant dead: a grant delegated from a transient session is signed by an annex
 * key the account document never lists and chains under the generation
 * delegation, so it keeps verifying until that delegation's own TTL. A grant
 * whose chain genuinely is dead comes back as a `ValidationError` and counts
 * into `skipped`, which is the honest way to learn it.
 *
 * The recorded Revoke is stamped with a forward floor -- one millisecond past
 * the row's newest Login when this clock is behind it -- so the listing's
 * hide-on-revoke join cannot be defeated by skew between the client that
 * granted and the client that revokes.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.user {User}   the session user (activity actor)
 * @param options.agent {ConnectedAgent}
 * @returns {Promise<{ revoked: number; skipped: number }>}   the grant outcome
 */
export async function revokeAgentAccess({
  storage,
  user,
  agent
}: {
  storage: StorageManager
  user: User
  agent: ConnectedAgent
}): Promise<{ revoked: number; skipped: number }> {
  const outcome = await storage.revokeAgentGrants({
    controller: agent.controller
  })
  await storage.addHistoryAgentRevoke({
    user,
    origin: agent.origin,
    controller: agent.controller,
    zcaps: outcome.revokedIds.map(id => ({ id })),
    ...(agent.name !== undefined && { actor: { name: agent.name } }),
    revoked: outcome.revoked,
    skipped: outcome.skipped,
    created: revokeStampAfter({ grantedAt: agent.grantedAt })
  })
  return { revoked: outcome.revoked, skipped: outcome.skipped }
}

/**
 * The `created` stamp for an agent Revoke: now, floored to one millisecond
 * past the Login it retires when this client's clock is behind the client that
 * granted. Both stamps are wall-clock from possibly different machines, and
 * the listing hides a Login only for a Revoke at or after it, so without the
 * floor a slow clock would write a revocation the listing ignores.
 *
 * @param options {object}
 * @param [options.grantedAt] {string}   the row's newest Login `created`
 * @returns {string}   an ISO stamp
 */
function revokeStampAfter({ grantedAt }: { grantedAt?: string }): string {
  const now = Date.now()
  const granted = grantedAt ? new Date(grantedAt).getTime() : Number.NaN
  const at = Number.isFinite(granted) ? Math.max(now, granted + 1) : now
  return new Date(at).toISOString()
}
