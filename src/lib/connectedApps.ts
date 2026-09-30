/**
 * Connected-applications model for the Applications settings section. A
 * connected app is one the user linked through the App Connect CHAPI flow: the
 * wallet holds a self-issued app-key credential for it (in the encrypted
 * `app-connections` collection, kept apart from the user's own credentials
 * because each Resource carries that app's private seed) and each connect wrote
 * a Login activity to `wallet-activity` recording the display name and the
 * storage grants.
 *
 * `listConnectedApps` joins those two sources into one entry per app-key
 * credential: the credential supplies the origin, subject DID, and connected
 * date; the latest matching Login activity supplies the raw display name, the
 * grant summaries, and the last-connected timestamp. The join is on the
 * credential's `appUrl`, which every mint and every connect records, so
 * several apps sharing an origin get their own attribution.
 * `deriveGrantsState` then reads each recorded grant's delegation signer
 * against the account
 * document's current key set (wallet-core's `deriveGrantSignerState`): a grant
 * signed by a since-disconnected wallet client is already dead (the
 * current-key-set rule), so its app lists as orphaned -- "reconnect to use
 * again" -- rather than as live. A grant minted from a transient session is
 * signed by a client-annex per-visit key the document never lists, so it
 * derives as unknown rather than orphaned; its chain is dead exactly when
 * the generation delegation it chains under no longer belongs to the
 * generation the account document points at.
 * `lookupCollectionCreators` reads the same two sources the other way round:
 * given the `generator.id` DIDs stamped on existing collections, it answers each
 * with the creating app's display name and canonical `appUrl`, from the app
 * key where the app is still connected and from its App Connect Login
 * activities where it is not. It is the one reader behind every surface that
 * names a collection's creator: the consent row's existing-collection
 * reading, the Storage page's collection listing, and the collection
 * contents page.
 * Wallet-core's `grantRevocationSkip` (`/clientAnnex`) is the revocation-time
 * reading of the same document, applied per grant by
 * `StorageManager#revokeZcaps`: a grant that is expired, orphaned, or chained
 * under a parent delegation whose signer has left the document (or whose
 * generation is no longer the pointed one) is dead already and is skipped
 * without a POST; every other grant is POSTed, and the server's genuine
 * `AlreadyRevokedError` reads as a confirmed revocation there.
 * `revokeAppAccess` retires an app: for each app-provisioned encrypted
 * collection it rotates the epoch to drop the app's recipient key (so the app
 * cannot decrypt future writes) and revokes those pull-axis grants
 * indivisibly, then revokes any remaining storage grants, then removes the
 * app-key credential and records the revocation. The honest limitation
 * stands: ciphertext the app already fetched stays readable to it --
 * rotation protects only prospective writes.
 *
 * The same page lists connected AGENTS: grantees that answered an
 * interaction-URL request rather than an App Connect popup, so they hold no
 * app key and no attested origin. `listConnectedAgents` joins those rows out
 * of the activity history alone -- the latest agent-grant Login per grantee
 * did:key, hidden again by a Revoke activity naming the same controller.
 * It keeps a row whose grants have all expired while any of them targets
 * an encrypted collection, since the agent's key stays in that collection's
 * key-epoch roster. `revokeAgentAccess` retires one: each private
 * collection the agent was granted is rotated off its recipient key, the
 * recorded capabilities are revoked, and the revocation recorded, with no
 * app key to delete.
 */
import type {
  HistoryItems,
  RecipientRotationOutcome,
  StorageManager
} from '@/stores/storageManager'
import type { User } from '@/types/auth'
import {
  deriveGrantSignerState,
  type GrantSignerState
} from '@interop/wallet-core/clients'
import type { AccountSignerCheck } from '@interop/wallet-core/clientAnnex'
import {
  delegationExpired,
  delegationProofKeyId
} from '@interop/wallet-core/webvh'
import type { IZcap } from '@interop/data-integrity-core'
import {
  appKeyAppUrl,
  appKeyOrigin,
  presentsAsAppKey
} from '@interop/wallet-request'
import { subjectId } from '@/lib/vcShape'
import {
  EXTERNAL_REQUEST_ORIGIN,
  isAgentActivityObject
} from '@/lib/walletRequest/externalRequest'

/**
 * One storage capability an app was granted, summarized as recorded on the
 * App Connect Login activity's `object.zcaps`.
 */
export interface AppGrant {
  id: string
  target: string
  allowedActions: string[]
  /**
   * The recorded capability's own `expires` when the activity recorded the
   * full zcap, else the summary's; empty when neither carries one.
   */
  expires: string
  /**
   * The verification-method id that signed the recorded delegation
   * (`zcap.proof.verificationMethod`), when the activity recorded the full
   * capability. Absent on legacy summary-only records.
   */
  signerKeyId?: string
}

/**
 * What a recorded grant is checked against, read off the session's verified
 * account document; assembled app-side by `currentAccountSignerCheck`
 * (`src/session/clients.ts`) and read by wallet-core's `grantRevocationSkip`.
 */
export type { AccountSignerCheck } from '@interop/wallet-core/clientAnnex'

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
   * The application URL the app key is scoped to within that origin. Two
   * applications sharing an origin are distinct connected apps and are told
   * apart by this value.
   */
  appUrl: string
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
 * (`object.appConnect.appUrl`). Every connect writes one; a record carrying
 * none is not a row this listing can attribute to an app.
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
      expires: grantExpires(grant),
      signerKeyId: grantSignerKeyId(grant.zcap)
    }
  })
}

/**
 * A recorded grant's expiry: the full capability's own `expires` when the
 * activity recorded one (the same value the revocation lookup reads), else
 * the summary's, for a legacy summary-only record; empty when neither.
 *
 * @param record {{ expires?: unknown; zcap?: unknown }}
 * @returns {string}
 */
function grantExpires(record: { expires?: unknown; zcap?: unknown }): string {
  return (
    stringField(record.zcap, 'expires') ??
    (typeof record.expires === 'string' ? record.expires : '')
  )
}

/**
 * The verification-method id that signed a recorded grant capability's
 * delegation proof, when the record carries the full zcap: wallet-core's
 * `delegationProofKeyId`, the same accessor the parent check reads, behind
 * the guard an unvalidated activity record needs.
 *
 * @param zcap {unknown}   the recorded full capability, if any
 * @returns {string | undefined}
 */
function grantSignerKeyId(zcap: unknown): string | undefined {
  return zcap && typeof zcap === 'object'
    ? delegationProofKeyId(zcap as IZcap)
    : undefined
}

/**
 * Whether a row's recorded grants still verify under the current-key-set
 * rule (a delegation verifies iff its verification method is in the resolved
 * account document now), over a bare grant list so the app rows and the agent
 * rows share it. The rule is wallet-core's `deriveGrantSignerState`; this
 * binds it to the recorded {@link AppGrant} shape. `orphaned` means the
 * enrolled client that minted the grants has since been disconnected;
 * `unknown` covers nothing to check against AND a grant a transient session
 * minted, whose annex signer the account document never lists.
 *
 * @param options {object}
 * @param options.grants {AppGrant[]}
 * @param [options.signerCheck] {AccountSignerCheck}   the account DID and
 *   the enrolled clients' signing keys, or undefined when no verified
 *   document is available this session
 * @returns {GrantSignerState}
 */
export function deriveGrantsState({
  grants,
  signerCheck
}: {
  grants: Array<Pick<AppGrant, 'signerKeyId'>>
  signerCheck?: AccountSignerCheck
}): GrantSignerState {
  if (!signerCheck) {
    return 'unknown'
  }
  const { accountDid, currentSigningKeys } = signerCheck
  return deriveGrantSignerState({
    signerKeyIds: grants.map(grant => grant.signerKeyId),
    accountDid,
    currentSigningKeys
  })
}

/**
 * Whether an activity is an App Connect Login: a `Login` activity carrying an
 * `appConnect` member (distinguishing it from a plain "Login with Wallet" and
 * from an agent-grant Login).
 *
 * @param options {object}
 * @param options.doc {{ type?: string[]; object?: unknown }}
 * @returns {boolean}
 */
function isAppConnectLogin({
  doc
}: {
  doc: { type?: string[]; object?: unknown }
}): boolean {
  return (
    Array.isArray(doc.type) &&
    doc.type.includes('Login') &&
    loginAppName(doc.object) !== undefined
  )
}

/**
 * Whether an activity is the App Connect Login for a given origin.
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
  return isAppConnectLogin({ doc }) && loginOrigin(doc.object) === origin
}

/**
 * Lists the user's connected applications, one per app-key credential in the
 * `app-connections` collection, joined with the latest matching App Connect
 * Login activity.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param [options.items] {HistoryItems}
 *   the activity history, when the caller has already read it (the sibling
 *   agent listing scans the same collection)
 * @param [options.appKeys] {Awaited<ReturnType<StorageManager['listAppKeys']>>}
 *   an already-listed app-key collection, so a caller holding one does not
 *   list it again
 * @returns {Promise<ConnectedApp[]>}   sorted latest-connected first
 */
export async function listConnectedApps({
  storage,
  items,
  appKeys
}: {
  storage: StorageManager
  items?: HistoryItems
  appKeys?: Awaited<ReturnType<StorageManager['listAppKeys']>>
}): Promise<ConnectedApp[]> {
  const [{ appKeys: credentials }, history] = await Promise.all([
    appKeys ?? storage.listAppKeys(),
    items ?? storage.listHistoryItems()
  ])

  // One pass over the history, into an index by `appUrl`, so the
  // per-credential loop below is a lookup rather than a filter-and-sort each.
  // The `appUrl` is the join on both sides: every mint writes
  // `credentialSubject.appUrl` and every connect records
  // `object.appConnect.appUrl`, and it is what tells two apps sharing an
  // origin apart.
  type HistoryItem = (typeof history.entries)[number]
  const latestLoginByAppUrl = new Map<string, HistoryItem>()
  for (const item of history.entries) {
    const origin = loginOrigin(item.doc.object)
    if (!origin || !isAppConnectLoginFor({ doc: item.doc, origin })) {
      continue
    }
    const appUrl = loginAppUrl(item.doc.object)
    if (appUrl === undefined) {
      continue
    }
    const current = latestLoginByAppUrl.get(appUrl)
    if (!current || (current.doc.created ?? '') < (item.doc.created ?? '')) {
      latestLoginByAppUrl.set(appUrl, item)
    }
  }

  const apps: ConnectedApp[] = []
  for (const { cid, vc: credential } of credentials) {
    const subject = subjectId(credential)
    const origin = appKeyOrigin(credential)
    const appUrl = appKeyAppUrl(credential)
    // The collection holds app keys only, so the per-Resource check is the
    // marker type plus the three members this listing reads: anything else in
    // there (an opaque Resource planted server-side through a space import,
    // say) is not something the page can render or revoke.
    if (!presentsAsAppKey(credential) || !subject || !origin || !appUrl) {
      continue
    }

    // The latest matching App Connect Login supplies the raw display name, the
    // grants, and the last-connected timestamp.
    const latestLogin = latestLoginByAppUrl.get(appUrl)

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
      appUrl,
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
 * revocation happen on the WAS server first ({@link revokeAppAuthority}), and
 * only if that succeeds is the app-key credential deleted and the revocation
 * recorded. A network failure while revoking the grants therefore surfaces as
 * an error and leaves the credential in place, so the user can retry rather
 * than being left with a deleted key whose grants are still live.
 *
 * Which grants are POSTed is settled by wallet-core's `grantRevocationSkip`
 * against the same verified document the listing marked the row with: an expired
 * grant, an orphaned root-delegated grant, and a grant chained under a parent
 * delegation that has rotted (its signer gone, or its generation no longer
 * the pointed one) are dead already and skipped without a POST. Every other
 * recorded grant is POSTed, whatever the row's
 * marker, since a grant minted in a transient session derives as unknown
 * while chaining under a generation delegation that stays alive until its
 * own TTL. Of the POSTs, the server's genuine `AlreadyRevokedError` counts as
 * revoked. Any other refusal or failure -- a plain `ValidationError`
 * included, since a read-replica lag on a live grant answers the same way as
 * a dead chain -- propagates after the sibling POSTs settle, before the
 * credential is deleted or the Revoke recorded, so the row stays listed and a
 * retry re-runs the whole sequence. The verified document's reading is the
 * storage manager's own, bound at construction; without one (no verified
 * document this session) only the expiry skip applies and everything else is
 * POSTed.
 *
 * What a failure leaves behind: the collections the rotation could re-key
 * are rotated off the app's recipient key, and the grants that could be
 * revoked are revoked, while the credential is kept and no Revoke is
 * recorded. That state is safe to retry from. The rotation is idempotent (a
 * collection whose current epoch no longer lists the app is skipped), the
 * grants that did land are answered `AlreadyRevokedError` on the re-POST and
 * count as revoked then, and the run converges once the failed stage
 * succeeds.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.user {User}   the session user (activity actor)
 * @param options.app {ConnectedApp}
 * @returns {Promise<{ revoked: number; withdrawn: number; skipped: number;
 *   rotated: number }>}   the grant outcome, plus the collections the
 *   rotation re-keyed. `withdrawn` counts the grants this call's own POSTs
 *   revoked, leaving out any already revoked
 */
export async function revokeAppAccess({
  storage,
  user,
  app
}: {
  storage: StorageManager
  user: User
  app: ConnectedApp
}): Promise<{
  revoked: number
  withdrawn: number
  skipped: number
  rotated: number
}> {
  const { outcome, rotated } = await revokeAppAuthority({
    storage,
    origin: app.origin,
    subjectDid: app.subjectDid
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
  return { ...outcome, rotated }
}

/**
 * Retires an app's live authority on the WAS server, the sequence both the
 * interactive revoke ({@link revokeAppAccess}) and the login-time sweep of
 * stranded app keys run. The key rotation runs first
 * (`revokeAppCollectionRecipients`): for each collection the app provisioned
 * or was granted -- found through the Collection Metadata `generator.id`
 * attribution as well as the recorded grants, so an app whose grants have all
 * expired is still rotated out -- it appends a fresh epoch without the app's
 * key and revokes those collections' pull-axis grants with it, so the app
 * cannot decrypt anything written afterward. Then the remaining grants are
 * revoked (`revokeAppGrants`). See {@link rotateThenRevokeGrants} for what a
 * failure in either stage does.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.origin {string}   the app's origin
 * @param options.subjectDid {string}   the app-key credential's subject DID
 * @param [options.items] {HistoryItems}   the activity history, when the
 *   caller has already read it
 * @param [options.collections] {Array<StorageCollection>}   the Space
 *   collection listing, when the caller has already read it
 * @returns {Promise<{ outcome: { revoked: number; withdrawn: number;
 *   skipped: number }; rotated: number }>}   the grant stage's outcome, plus
 *   the collections the rotation re-keyed
 */
export async function revokeAppAuthority({
  storage,
  origin,
  subjectDid,
  items,
  collections
}: {
  storage: StorageManager
  origin: string
  subjectDid: string
  items?: HistoryItems
  collections?: Awaited<ReturnType<StorageManager['listCollections']>>
}): Promise<{
  outcome: { revoked: number; withdrawn: number; skipped: number }
  rotated: number
}> {
  return await rotateThenRevokeGrants({
    items: items ?? (await storage.listHistoryItems()),
    rotate: history =>
      storage.revokeAppCollectionRecipients({
        origin,
        subjectDid,
        items: history,
        ...(collections && { collections })
      }),
    revokeGrants: ({ items: history, revokedByRotation }) =>
      storage.revokeAppGrants({
        origin,
        subjectDid,
        items: history,
        revokedByRotation
      }),
    failureMessage:
      'Could not rotate every collection off the app being disconnected.'
  })
}

/**
 * The two server-side stages both revocations share, over one history scan.
 * The key rotation runs first, so a revoked grantee cannot decrypt future
 * writes, and the capabilities its pull axis confirmed revoked are handed to
 * the grant stage, which counts them without a second POST. The grant stage
 * runs even when some collection could not be re-keyed, so every grant that
 * can be revoked is revoked now. A rotation that left the grantee a
 * recipient of some collection's current epoch then throws, so the caller
 * keeps its row and records no Revoke, and the revoke can be retried. A
 * collection whose rotation landed but whose pull failed is not counted in
 * `rotation.failed`: the grant stage POSTs the capabilities the pull missed
 * and throws if any still fails. So this throws only when some authority
 * remains, a recipient entry or a live grant. The
 * grants withdrawn on the failed run reach the Revoke the retry records,
 * since a re-POST answered `AlreadyRevokedError` counts as revoked. A
 * Revoke recorded on the failed run would hide an agent's row, which is
 * what the retry needs.
 *
 * @param options {object}
 * @param options.items {HistoryItems}   the activity history both stages read
 * @param options.rotate {Function}   the grantee's key-rotation stage
 * @param options.revokeGrants {Function}   the grantee's grant stage
 * @param options.failureMessage {string}   the error a failed rotation throws
 * @returns {Promise<{ outcome: Outcome; rotated: number }>}   the grant
 *   stage's outcome, plus the collections the rotation re-keyed
 */
async function rotateThenRevokeGrants<Outcome>({
  items,
  rotate,
  revokeGrants,
  failureMessage
}: {
  items: HistoryItems
  rotate: (items: HistoryItems) => Promise<RecipientRotationOutcome>
  revokeGrants: (options: {
    items: HistoryItems
    revokedByRotation: string[]
  }) => Promise<Outcome>
  failureMessage: string
}): Promise<{ outcome: Outcome; rotated: number }> {
  const rotation = await rotate(items)
  const outcome = await revokeGrants({
    items,
    revokedByRotation: rotation.revokedIds
  })
  if (rotation.failed > 0) {
    throw new Error(failureMessage)
  }
  return { outcome, rotated: rotation.rotated }
}

/**
 * The application that created a collection, as the wallet's own records
 * name it: what every surface showing a collection's creator reads, by the
 * `generator.id` did:key stamped on the collection.
 */
export interface CollectionCreator {
  /**
   * The display name the app's latest App Connect Login recorded.
   */
  name: string
  /**
   * The canonical application URL, which tells apps sharing an origin apart.
   */
  appUrl: string
  /**
   * The app-key credential's cid while the app is still connected, for a link
   * to its Applications row. A disconnected creator has no row, so it carries
   * none.
   */
  cid?: string
}

/**
 * What the wallet's own records say about the applications that created a
 * set of collections, by the `generator.id` did:key stamped on each: the display
 * name and the canonical `appUrl`. A connected app answers from its app key
 * and latest Login ({@link listConnectedApps}), with its app-key cid. A
 * disconnected one has no app key left, since removing it is what a
 * disconnect does, so its App Connect Login activities answer instead: the
 * latest one whose recorded grants were delegated to that DID supplies both
 * members. A creator neither source knows is absent from the result, and the
 * surface names its origin. Callers hand in app stamps alone (those carrying
 * a `generator.origin`). An agent's stamp has no app key or App Connect Login
 * to answer it, and names itself.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.generators {Iterable<string>}   the `generator.id` DIDs to look
 *   up
 * @param [options.items] {HistoryItems}
 *   the activity history, when the caller has already read it
 * @param [options.appKeys] {Awaited<ReturnType<StorageManager['listAppKeys']>>}
 *   an already-listed app-key collection, so a caller holding one does not
 *   list it again
 * @returns {Promise<ReadonlyMap<string, CollectionCreator>>}   keyed by
 *   `generator.id` DID
 */
export async function lookupCollectionCreators({
  storage,
  generators,
  items,
  appKeys
}: {
  storage: StorageManager
  generators: Iterable<string>
  items?: HistoryItems
  appKeys?: Awaited<ReturnType<StorageManager['listAppKeys']>>
}): Promise<ReadonlyMap<string, CollectionCreator>> {
  const wanted = new Set(generators)
  const creators = new Map<string, CollectionCreator>()
  if (wanted.size === 0) {
    return creators
  }
  const [history, listedAppKeys] = await Promise.all([
    items ?? storage.listHistoryItems(),
    appKeys ?? storage.listAppKeys()
  ])
  // Latest connect first, so the first entry for a subject DID stays.
  for (const app of await listConnectedApps({
    storage,
    items: history,
    appKeys: listedAppKeys
  })) {
    if (wanted.has(app.subjectDid) && !creators.has(app.subjectDid)) {
      creators.set(app.subjectDid, {
        name: app.name,
        appUrl: app.appUrl,
        cid: app.cid
      })
    }
  }
  // The rest are disconnected: the latest App Connect Login that recorded
  // grants delegated to the DID still names the app.
  const latestLoginByController = new Map<
    string,
    { created: string; name: string; appUrl: string }
  >()
  for (const { doc } of history.entries) {
    if (!isAppConnectLogin({ doc })) {
      continue
    }
    const controller = loginGrantController(doc.object)
    if (!controller || !wanted.has(controller) || creators.has(controller)) {
      continue
    }
    const appUrl = loginAppUrl(doc.object)
    const name = loginAppName(doc.object)
    const created = doc.created ?? ''
    const current = latestLoginByController.get(controller)
    if (appUrl && name && (!current || current.created < created)) {
      latestLoginByController.set(controller, { created, name, appUrl })
    }
  }
  for (const [controller, { name, appUrl }] of latestLoginByController) {
    creators.set(controller, { name, appUrl })
  }
  return creators
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
  /**
   * Set when every recorded grant has expired. Such a row is listed only
   * because a grant targets an encrypted collection, whose key-epoch roster
   * still holds the agent's key until a revocation rotates it away.
   */
  expired?: true
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
 * the `controller` of the first recorded full capability. The request page's
 * precheck (`precheckExternalRequest`) refuses a request whose capability
 * queries name more than one `controller`, and each grant is delegated to its
 * query's own, so every grant a request page approval records names the same
 * controller and the first one names the agent.
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
 * Whether an activity is an agent-grant Login: a `Login` whose object is an
 * agent's (`isAgentActivityObject`: the interaction-URL origin marker and no
 * `appConnect` member), carrying at least one recorded full capability
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
    isAgentActivityObject(doc.object) &&
    loginGrantController(doc.object) !== undefined
  )
}

/**
 * Whether every recorded grant of an agent row has already expired. The
 * expiry is the grant's `expires` as {@link AppGrant} carries it (the
 * capability's own where recorded), under wallet-core's `delegationExpired`.
 * A grant with no recorded expiry (or an unparseable one) counts as still
 * live, so a row is never hidden on a missing stamp.
 *
 * An expired row is not simply dropped. It stays listed while the agent's key
 * still sits in a granted collection's current key epoch (see
 * {@link expiredRowsToDrop}).
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
  return grants.every(grant =>
    delegationExpired({
      zcap: { expires: grant.expires } as unknown as IZcap,
      now
    })
  )
}

/**
 * Which fully expired agent rows are dropped from the listing, by controller.
 * A row stays while the agent's key still sits in the current key epoch of a
 * collection its grants target, the rule the revocation rotates on
 * (`StorageManager.granteeRosterCollections`). The grants are dead, but that
 * roster entry does not expire, and only a revocation rotates it away. A row
 * whose targets list the agent in no current epoch is dropped.
 *
 * One roster read covers every expired row, so a collection several rows
 * target is read once. When there is no remote store, or a collection's key
 * epochs cannot be read, the roster read reports a failure and the row is
 * kept: hiding a row that may still be revocable is the worse failure.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.agents {ConnectedAgent[]}   the fully expired rows
 * @returns {Promise<Set<string>>}   the controllers whose rows are dropped
 */
async function expiredRowsToDrop({
  storage,
  agents
}: {
  storage: StorageManager
  agents: ConnectedAgent[]
}): Promise<Set<string>> {
  const outcomes = await storage.granteeRosterCollections({
    grantees: agents.map(({ controller, grants }) => ({
      controller,
      targets: grants.map(grant => grant.target)
    }))
  })
  return new Set(
    outcomes
      .filter(
        ({ collectionIds, failed }) =>
          collectionIds.length === 0 && failed === 0
      )
      .map(({ controller }) => controller)
  )
}

/**
 * Whether an activity is an agent-grant Revoke: the activity
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
    isAgentActivityObject(doc.object) &&
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
 * The agent-grant Logins in the activity history, grouped by grantee
 * controller, minus those a matching agent Revoke hides
 * ({@link revokeHidesLogin}). A controller whose every Login is hidden is
 * absent, so each group holds at least one Login.
 *
 * @param options {object}
 * @param options.items {HistoryItems}
 * @returns {Map<string, HistoryItems['entries']>}   the live Logins, by
 *   controller
 */
function liveAgentLogins({
  items
}: {
  items: HistoryItems
}): Map<string, HistoryItems['entries']> {
  const loginsByController = new Map<string, HistoryItems['entries']>()
  const latestRevokeByController = new Map<string, string>()
  for (const item of items.entries) {
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

  const live = new Map<string, HistoryItems['entries']>()
  for (const [controller, logins] of loginsByController) {
    const revokeCreated = latestRevokeByController.get(controller)
    const unhidden = logins.filter(
      ({ doc }) =>
        !revokeHidesLogin({ loginCreated: doc.created, revokeCreated })
    )
    if (unhidden.length > 0) {
      live.set(controller, unhidden)
    }
  }
  return live
}

/**
 * The newest of a non-empty set of Logins by `created` stamp. A Login with no
 * stamp sorts oldest.
 *
 * @param logins {HistoryItems['entries']}   at least one Login
 * @returns {HistoryItems['entries'][number]}
 */
function newestLogin(
  logins: HistoryItems['entries']
): HistoryItems['entries'][number] {
  return logins.reduce((newest, item) =>
    (newest.doc.created ?? '') < (item.doc.created ?? '') ? item : newest
  )
}

/**
 * Which of the given controllers this account has granted storage to through
 * an interaction-URL request and not since revoked: a controller with at
 * least one agent-grant Login no later agent Revoke hides. Each entry carries
 * the newest such Login's self-declared name and `created` stamp, the same
 * newest-Login rule {@link listConnectedAgents} applies.
 *
 * Unlike the listing, this reads no key-epoch roster for fully expired rows.
 * The claim it backs is only "you granted this key before and have not
 * revoked it", which holds for an expired grant too. Naming someone else's
 * DID gains a requester nothing, since only the key holder can invoke grants
 * delegated to it, so the result is safe to show without a proof of
 * possession.
 *
 * @param options {object}
 * @param options.items {HistoryItems}   the activity history
 * @param options.controllers {string[]}   the grantee DIDs to look up
 * @returns {Map<string, { name?: string; grantedAt?: string }>}
 *   the known controllers only
 */
export function findKnownAgents({
  items,
  controllers
}: {
  items: HistoryItems
  controllers: string[]
}): Map<string, { name?: string; grantedAt?: string }> {
  const live = liveAgentLogins({ items })
  const known = new Map<string, { name?: string; grantedAt?: string }>()
  for (const controller of controllers) {
    const logins = live.get(controller)
    if (!logins) {
      continue
    }
    const latest = newestLogin(logins)
    const name = loginAgentName(latest.doc.object)
    known.set(controller, {
      ...(name !== undefined && { name }),
      ...(latest.doc.created !== undefined && {
        grantedAt: latest.doc.created
      })
    })
  }
  return known
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
 * whose every recorded grant has already expired is kept, flagged `expired`,
 * while any grant targets an encrypted collection of this Space: the agent's
 * key stays in that collection's key-epoch roster until a revocation rotates
 * it away. It is dropped when every grant targets a public collection or
 * something outside this Space. That check reads the governed descriptor of
 * each distinct collection the expired rows' grants target, once however many
 * rows target it, and only when some row has fully expired. A later re-grant writes a newer
 * Login and lists again.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param [options.items] {HistoryItems}
 *   the activity history, when the caller has already read it (the sibling
 *   app listing scans the same collection)
 * @returns {Promise<ConnectedAgent[]>}   sorted latest-granted first
 */
export async function listConnectedAgents({
  storage,
  items
}: {
  storage: StorageManager
  items?: HistoryItems
}): Promise<ConnectedAgent[]> {
  const history = items ?? (await storage.listHistoryItems())

  const now = Date.now()
  const agents: ConnectedAgent[] = []
  for (const [controller, live] of liveAgentLogins({ items: history })) {
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
    const expired = allGrantsExpired({ grants, now })

    // The newest live Login supplies the display members and the granted
    // stamp; the grants above are the union across all of them.
    const latest = newestLogin(live)
    const name = loginAgentName(latest.doc.object)
    agents.push({
      controller,
      ...(name !== undefined && { name }),
      origin: EXTERNAL_REQUEST_ORIGIN,
      grants,
      grantedAt: latest.doc.created,
      ...(expired && { expired: true as const })
    })
  }

  let listed = agents
  const expiredAgents = agents.filter(agent => agent.expired)
  if (expiredAgents.length > 0) {
    const drop = await expiredRowsToDrop({ storage, agents: expiredAgents })
    listed = agents.filter(agent => !drop.has(agent.controller))
  }
  return listed.sort((first, second) =>
    (second.grantedAt ?? '').localeCompare(first.grantedAt ?? '')
  )
}

/**
 * Revokes a connected agent's storage grants: the key rotation and the grant
 * revocation run on the WAS server first, and only if both succeed is the
 * revocation recorded -- a network failure therefore leaves the row listed,
 * so the user can retry. There is no app key to delete.
 *
 * The key rotation runs first (`revokeAgentCollectionRecipients`), as on the
 * app path: a private collection provisioned for an agent escrows the agent's
 * identity key-agreement key into its key epochs, so each collection the
 * agent's recorded grants target or its `generator` stamp names gains a
 * fresh epoch without that key, and its pull-axis grants are revoked with
 * it. The grant stage counts the ones
 * the rotation confirmed revoked and names them on the recorded Revoke
 * without POSTing them again. A collection the rotation could not re-key
 * keeps the agent a recipient of the current epoch, so the call throws once
 * the grant revocation has run, and records no Revoke: a Revoke would hide
 * the row the retry needs. The retry's Revoke names the grants the failed
 * run withdrew, since their re-POST is answered `AlreadyRevokedError`.
 *
 * Which recorded grants are POSTed follows the app path exactly
 * (wallet-core's `grantRevocationSkip` over the storage manager's own
 * verified-document reading): an expired grant, an
 * orphaned root-delegated grant, and a grant under a rotted parent
 * delegation are skipped without a POST, and every other
 * grant is POSTed whatever the row's marker, since a grant delegated from a
 * transient session is signed by an annex key the account document never
 * lists and keeps verifying under the generation delegation until that
 * delegation's own TTL. The server's `AlreadyRevokedError` counts as
 * revoked there; any other refusal or failure propagates from
 * `revokeAgentGrants` before the Revoke is recorded, so the row stays listed.
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
 * @returns {Promise<{ revoked: number; withdrawn: number; skipped: number;
 *   unrevocable: number; rotated: number }>}   the grant outcome, plus the
 *   collections the rotation re-keyed. `withdrawn` counts the grants this
 *   call's own POSTs revoked, leaving out any already revoked. `unrevocable`
 *   counts the grants with no capability to POST, which end only at their
 *   own expiry
 */
export async function revokeAgentAccess({
  storage,
  user,
  agent
}: {
  storage: StorageManager
  user: User
  agent: ConnectedAgent
}): Promise<{
  revoked: number
  withdrawn: number
  skipped: number
  unrevocable: number
  rotated: number
}> {
  const { outcome, rotated } = await rotateThenRevokeGrants({
    items: await storage.listHistoryItems(),
    rotate: items =>
      storage.revokeAgentCollectionRecipients({
        controller: agent.controller,
        items
      }),
    revokeGrants: ({ items, revokedByRotation }) =>
      storage.revokeAgentGrants({
        controller: agent.controller,
        items,
        revokedByRotation
      }),
    failureMessage:
      'Could not rotate every collection off the agent being revoked.'
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
  return {
    revoked: outcome.revoked,
    withdrawn: outcome.withdrawn,
    skipped: outcome.skipped,
    unrevocable: outcome.unrevocable,
    rotated
  }
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
