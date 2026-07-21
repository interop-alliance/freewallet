/**
 * Connected-applications model for the Applications settings section. A
 * connected app is one the user linked through the App Connect CHAPI flow: the
 * wallet holds a self-issued app-key credential for it (in the encrypted
 * `private-credentials` collection) and each connect wrote a Login activity to
 * `wallet-activity` recording the display name and the storage grants.
 *
 * `listConnectedApps` joins those two sources into one entry per app-key
 * credential: the credential supplies the origin, subject DID, and connected
 * date; the latest matching Login activity supplies the raw display name, the
 * grant summaries, and the last-connected timestamp. `revokeAppAccess` retires
 * an app: it revokes the app's storage grants on the WAS server, then removes
 * the app-key credential and records the revocation. The app never receives
 * decryption key material (only zcaps), so revocation is grant-only -- no key
 * or epoch rotation is involved.
 */
import type { StorageManager } from '@/stores/storageManager'
import type { User } from '@/types/auth'
import { appKeyOrigin, appKeySubjectDid } from '@/lib/appKey'
import { issuerId, subjectId } from '@/lib/vcShape'

/**
 * One storage capability an app was granted, summarized as recorded on the
 * App Connect Login activity's `object.zcaps`.
 */
export interface AppGrant {
  id: string
  target: string
  allowedActions: string[]
  expires: string
}

/**
 * A connected application, joined from its app-key credential and the latest
 * matching App Connect Login activity.
 */
export interface ConnectedApp {
  /** The app-key credential's content cid; identifies the app for revocation. */
  cid: string
  /** The raw display name (best-effort). */
  name: string
  /** The CHAPI requesting origin the app key is bound to. */
  origin: string
  /** The app-key credential's subject (self-issued) did:key. */
  subjectDid: string
  /** When the app key was issued (the credential's `issuanceDate`). */
  connectedAt?: string
  /** The storage grants recorded on the latest matching connect, if any. */
  grants: AppGrant[]
  /** The latest matching connect's timestamp, if a Login activity was found. */
  lastConnectedAt?: string
}

// The suffix `mintAppKeyCredential` appends to the app name in `vc.name`.
const APP_KEY_NAME_SUFFIX = ' app key'

/**
 * The origin an App Connect Login activity recorded, when it is one.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {string | undefined}
 */
function loginOrigin(object: unknown): string | undefined {
  if (object && typeof object === 'object' && 'origin' in object) {
    const { origin } = object as { origin?: unknown }
    return typeof origin === 'string' ? origin : undefined
  }
  return undefined
}

/**
 * The display name an App Connect Login activity recorded
 * (`object.appConnect.name`), when present.
 *
 * @param object {unknown}   the activity's `object` member
 * @returns {string | undefined}
 */
function loginAppName(object: unknown): string | undefined {
  if (object && typeof object === 'object' && 'appConnect' in object) {
    const { appConnect } = object as { appConnect?: unknown }
    if (
      appConnect &&
      typeof appConnect === 'object' &&
      'name' in appConnect &&
      typeof (appConnect as { name?: unknown }).name === 'string'
    ) {
      return (appConnect as { name: string }).name
    }
  }
  return undefined
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
    }
    return {
      id: typeof grant.id === 'string' ? grant.id : '',
      target: typeof grant.target === 'string' ? grant.target : '',
      allowedActions: Array.isArray(grant.allowedActions)
        ? grant.allowedActions.filter(
            (action): action is string => typeof action === 'string'
          )
        : [],
      expires: typeof grant.expires === 'string' ? grant.expires : ''
    }
  })
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
 * Lists the user's connected applications, one per self-issued app-key
 * credential, joined with the latest matching App Connect Login activity.
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
  const [credentials, history] = await Promise.all([
    storage.listCredentials(),
    storage.listHistoryItems()
  ])

  const apps: ConnectedApp[] = []
  for (const { cid, vc: credential } of credentials) {
    const issuer = issuerId(credential.issuer)
    const subject = subjectId(credential)
    const origin = appKeyOrigin(credential)
    // A connected app's key is self-issued (issuer == subject) and bound to
    // an origin; anything else is an ordinary stored credential.
    if (!issuer || issuer !== subject || !origin) {
      continue
    }

    // The latest App Connect Login for this origin supplies the raw display
    // name, the grants, and the last-connected timestamp.
    const latestLogin = history
      .filter(({ doc }) => isAppConnectLoginFor({ doc, origin }))
      .sort((first, second) =>
        (second.doc.created ?? '').localeCompare(first.doc.created ?? '')
      )[0]

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
      subjectDid: appKeySubjectDid(credential) ?? subject,
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
 * Revokes a connected app's access. Order matters: the storage grants are
 * revoked on the WAS server first, and only if that succeeds is the app-key
 * credential deleted and the revocation recorded. A network failure while
 * revoking therefore surfaces as an error and leaves the credential in place,
 * so the user can retry rather than being left with a deleted key whose grants
 * are still live. Per-capability no-ops (already revoked/expired) are swallowed
 * inside `revokeAppGrants`; only a genuine failure propagates.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.user {User}   the session user (activity actor)
 * @param options.app {ConnectedApp}
 * @returns {Promise<{ revoked: number; skipped: number }>}   the grant outcome
 */
export async function revokeAppAccess({
  storage,
  user,
  app
}: {
  storage: StorageManager
  user: User
  app: ConnectedApp
}): Promise<{ revoked: number; skipped: number }> {
  const outcome = await storage.revokeAppGrants({
    origin: app.origin,
    subjectDid: app.subjectDid
  })
  await storage.deleteCredential({ cid: app.cid })
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
