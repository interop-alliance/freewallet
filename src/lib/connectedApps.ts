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
  if (!currentSigningKeys) {
    return 'unknown'
  }
  const signers = app.grants
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
