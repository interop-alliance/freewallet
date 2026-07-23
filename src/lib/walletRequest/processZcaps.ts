/**
 * Zcap request processing for "Login with Wallet": resolves each requested
 * capability's abstract `invocationTarget` descriptor onto the user's own WAS
 * Space, provisions any missing RP collection, and delegates a capability to
 * the relying party's DID. All delegations are rooted at the user's Space root
 * capability (`urn:zcap:root:<spaceUrl>`); targets outside the Space are
 * unsatisfiable by construction.
 *
 * Two attenuation caps hold every grant read-only unless the RP owns the
 * target:
 *
 * - whole-Space grants are stripped to read-only (a Space-wide write would
 *   permit rewriting the Space Description, i.e. controller takeover);
 * - grants on a protected wallet collection -- the standard collections
 *   (`private-credentials`, `public-credentials`, `wallet-activity`), the `id`
 *   collection holding the user's published DID artifacts, and the `key-map`
 *   collection holding the private key-id map -- are stripped to read-only too:
 *   an RP may read but never rewrite or delete the user's own credentials,
 *   published identity, or key map.
 *
 * Only an RP-provisioned (non-protected) collection keeps its requested write
 * actions. The cap applies whether the target arrives as a descriptor object
 * or as a plain URL string under the Space (the collection id is derived from
 * the first path segment after the Space URL either way), so a string target
 * cannot bypass it.
 *
 * A `urn:was:public-collection` grant provisions a plaintext collection with a
 * collection-level world-readable (PublicCanRead) policy, set by the wallet at
 * provisioning time. Public covers only unauthenticated reads; writes stay
 * capability-only, so the grant still delegates the usual collection-scoped
 * zcap (with the ordinary write TTL). A public grant on a protected wallet
 * collection is unsatisfiable, unconditionally.
 *
 * Resolution (`resolveGrants`) is pure and drives the consent preview; the
 * delegation step (`processZcaps`) runs only on the consent-approved path.
 * Write grants (any action beyond GET/HEAD) are delegated for a shorter TTL
 * than read-only grants.
 */
import { generateZcapUri } from '@interop/ezcap'
import type { Session } from '@/types/auth'
import {
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  RP_ZCAP_TTL_MS,
  RP_ZCAP_WRITE_TTL_MS,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'
import type { ICapabilityQueryDetail, IZcap } from './types'

/**
 * Default actions for a grant whose `allowedAction` is absent: read-only.
 * Never inherit-all (an empty `allowedActions` array means "all actions").
 */
const DEFAULT_ACTIONS = ['GET', 'HEAD']

/**
 * The read-only action cap. A Space-wide write capability would permit
 * rewriting the Space Description (controller takeover), a write on a
 * standard wallet collection would let an RP rewrite or delete the user's own
 * credentials, a write on the `id` collection would let an RP rewrite the
 * user's published DID document, and a write on the `key-map` collection would
 * let an RP rewrite the private key-id map -- so all are always delegated
 * read-only.
 */
const READ_ONLY_ACTIONS = ['GET', 'HEAD']

/**
 * Whether an action set includes anything beyond read-only (GET/HEAD): a
 * write-bearing grant, used to pick the shorter TTL and warn on consent.
 *
 * @param allowedActions {string[]}
 * @returns {boolean}
 */
function includesWrite(allowedActions: string[]): boolean {
  return allowedActions.some(
    action => !READ_ONLY_ACTIONS.includes(action.toUpperCase())
  )
}

/**
 * Whether a resolved collection id names a protected wallet collection --
 * a standard collection (`private-credentials`, `public-credentials`,
 * `wallet-activity`), the `id` collection holding the user's published DID
 * artifacts, or the `key-map` collection holding the private key-id map --
 * which an RP may read but never write.
 *
 * @param collectionId {string | undefined}
 * @returns {boolean}
 */
function isProtectedCollection(collectionId: string | undefined): boolean {
  return (
    !!collectionId &&
    (collectionId === ID_COLLECTION.id ||
      collectionId === KEY_MAP_COLLECTION.id ||
      WALLET_STANDARD_COLLECTIONS.some(entry => entry.id === collectionId))
  )
}

/**
 * Collection id naming rule (D2): lowercase alphanumerics and hyphens, not
 * starting with a hyphen, up to 64 characters.
 */
const COLLECTION_NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/

/**
 * A requested capability's `invocationTarget` resolved against the user's own
 * Space. `satisfiable: false` means the descriptor cannot be fulfilled (a
 * foreign URL, an invalid collection name, or an unknown descriptor type); it
 * is skipped at delegation time and shown as "cannot fulfill" on consent.
 */
export interface ResolvedTarget {
  satisfiable: boolean
  // The concrete WAS URL to delegate against (absent when unsatisfiable).
  invocationTarget?: string
  // The grant targets the whole Space (capped to read-only).
  wholeSpace: boolean
  // A named RP collection that does not exist yet and must be provisioned.
  needsProvisioning: boolean
  // The WAS collection id, when the target is a (standard or RP) collection.
  collectionId?: string
  // A standard EDV-encrypted collection: the RP will only see ciphertext.
  encrypted: boolean
  // A `urn:was:public-collection` grant: provisioned plaintext with a
  // collection-level PublicCanRead policy, so anyone on the web can read it.
  isPublic: boolean
}

/**
 * A requested capability paired with its resolved target and the normalized,
 * security-capped actions it would be granted. Drives both the consent preview
 * and the delegation step.
 */
export interface ResolvedGrant {
  descriptor: ICapabilityQueryDetail
  target: ResolvedTarget
  allowedActions: string[]
  // The capped actions include a write (anything beyond GET/HEAD): drives the
  // consent write warning and the shorter write-grant TTL.
  write: boolean
}

/**
 * Raised when a zcap request arrives but the session has no remote WAS Space to
 * delegate against (a guest, or a no-WAS build). The page maps this to the
 * `zcapUnavailable` block reason.
 */
export class ZcapUnavailableError extends Error {
  constructor(message = 'This wallet has no remote storage to delegate.') {
    super(message)
    this.name = 'ZcapUnavailableError'
  }
}

/**
 * Whether a session can back a zcap request at all: it must have a remote WAS
 * Space (both a remote store and a resolved `spaceUrl`) to delegate against.
 * This is the exact condition `processZcaps` enforces before delegating (it
 * throws `ZcapUnavailableError` otherwise), exposed so a caller can surface the
 * same block earlier -- before showing consent -- without re-deriving (and
 * under-specifying) the guard.
 *
 * @param session {Session}
 * @returns {boolean}
 */
export function hasZcapStorage(session: Session): boolean {
  return !!session.storage.hasRemoteStorage && !!session.storage.spaceUrl
}

const UNSATISFIABLE: ResolvedTarget = {
  satisfiable: false,
  wholeSpace: false,
  needsProvisioning: false,
  encrypted: false,
  isPublic: false
}

/**
 * Resolves an abstract `invocationTarget` descriptor against the user's Space:
 *
 * - a plain URL string under `spaceUrl` -- used verbatim (an exact `spaceUrl`
 *   is treated as a whole-Space grant); the collection id is derived from the
 *   first path segment after the Space URL (so a URL under a standard
 *   collection, or a resource inside one, is flagged `collectionId` /
 *   `encrypted` and gets the same read-only cap as its descriptor form); any
 *   other string -- unsatisfiable;
 * - `{ type: 'urn:was:collection', name }` -- `${spaceUrl}/${name}` after
 *   validating `name`, flagged `needsProvisioning` unless it is a standard
 *   collection (and `encrypted` for the two EDV collections);
 * - `{ type: 'urn:was:public-collection', name }` -- like `urn:was:collection`
 *   but flagged `isPublic`: provisioned plaintext with a world-readable
 *   (PublicCanRead) policy. Unsatisfiable on a protected wallet collection --
 *   an RP must never be able to flip the user's own collections public;
 * - `{ type: 'urn:was:space' }` -- `spaceUrl`, flagged `wholeSpace`;
 * - anything else -- unsatisfiable.
 *
 * @param options {object}
 * @param options.descriptor {string | { type: string; name?: string }}
 * @param options.spaceUrl {string}
 * @returns {ResolvedTarget}
 */
export function resolveInvocationTarget({
  descriptor,
  spaceUrl
}: {
  descriptor: string | { type?: string; name?: string }
  spaceUrl: string
}): ResolvedTarget {
  if (typeof descriptor === 'string') {
    if (descriptor === spaceUrl) {
      return {
        satisfiable: true,
        invocationTarget: descriptor,
        wholeSpace: true,
        needsProvisioning: false,
        encrypted: false,
        isPublic: false
      }
    }
    if (descriptor.startsWith(`${spaceUrl}/`)) {
      // Derive the collection id from the first path segment after the Space
      // URL, so a plain URL under a standard collection is capped exactly like
      // its `urn:was:collection` descriptor form.
      const rest = descriptor.slice(spaceUrl.length + 1)
      const segment = rest.split('/')[0]
      const standard = WALLET_STANDARD_COLLECTIONS.find(
        entry => entry.id === segment
      )
      return {
        satisfiable: true,
        invocationTarget: descriptor,
        wholeSpace: false,
        needsProvisioning: false,
        collectionId: segment || undefined,
        encrypted: !!standard?.encryption,
        isPublic: false
      }
    }
    return UNSATISFIABLE
  }

  if (descriptor?.type === 'urn:was:space') {
    return {
      satisfiable: true,
      invocationTarget: spaceUrl,
      wholeSpace: true,
      needsProvisioning: false,
      encrypted: false,
      isPublic: false
    }
  }

  if (descriptor?.type === 'urn:was:collection') {
    const { name } = descriptor
    if (!name || !COLLECTION_NAME_RE.test(name)) {
      return UNSATISFIABLE
    }
    const standard = WALLET_STANDARD_COLLECTIONS.find(
      entry => entry.id === name
    )
    return {
      satisfiable: true,
      invocationTarget: `${spaceUrl}/${name}`,
      wholeSpace: false,
      // The `id` and `key-map` collections are provisioned at login, like the
      // standard ones.
      needsProvisioning:
        !standard &&
        name !== ID_COLLECTION.id &&
        name !== KEY_MAP_COLLECTION.id,
      collectionId: name,
      encrypted: !!standard?.encryption,
      isPublic: false
    }
  }

  if (descriptor?.type === 'urn:was:public-collection') {
    const { name } = descriptor
    if (!name || !COLLECTION_NAME_RE.test(name)) {
      return UNSATISFIABLE
    }
    // A public grant on a protected wallet collection is refused
    // unconditionally: an RP must never be able to make the user's own
    // credentials, activity log, or published identity world-readable.
    if (isProtectedCollection(name)) {
      return UNSATISFIABLE
    }
    return {
      satisfiable: true,
      invocationTarget: `${spaceUrl}/${name}`,
      wholeSpace: false,
      needsProvisioning: true,
      collectionId: name,
      // Public implies plaintext: the collection is provisioned without an
      // encryption marker, so a ciphertext note never applies.
      encrypted: false,
      isPublic: true
    }
  }

  return UNSATISFIABLE
}

/**
 * Normalizes a query's `allowedAction` to an array; an absent value defaults to
 * read-only (`['GET', 'HEAD']`), never inherit-all.
 *
 * @param allowedAction {string | string[] | undefined}
 * @returns {string[]}
 */
function normalizeActions(
  allowedAction: string | object | Array<string | object> | undefined
): string[] {
  if (allowedAction === undefined) {
    return [...DEFAULT_ACTIONS]
  }
  const actions = Array.isArray(allowedAction) ? allowedAction : [allowedAction]
  return actions.map(action =>
    typeof action === 'string' ? action : String(action)
  )
}

/**
 * Resolves a single requested capability into a `ResolvedGrant`: its target
 * plus the normalized, security-capped actions. Whole-Space grants and grants
 * on a protected wallet collection are forced to read-only; only an
 * RP-provisioned collection keeps its requested write actions. The resulting
 * `write` flag records whether the capped actions still include a write.
 *
 * @param options {object}
 * @param options.descriptor {ICapabilityQueryDetail}
 * @param options.spaceUrl {string}
 * @returns {ResolvedGrant}
 */
export function resolveGrant({
  descriptor,
  spaceUrl
}: {
  descriptor: ICapabilityQueryDetail
  spaceUrl: string
}): ResolvedGrant {
  const target = resolveInvocationTarget({
    descriptor: descriptor.invocationTarget,
    spaceUrl
  })
  const readOnly =
    target.wholeSpace || isProtectedCollection(target.collectionId)
  const allowedActions = readOnly
    ? [...READ_ONLY_ACTIONS]
    : normalizeActions(descriptor.allowedAction)
  return {
    descriptor,
    target,
    allowedActions,
    write: includesWrite(allowedActions)
  }
}

/**
 * Resolves every requested capability against the user's Space, for the consent
 * preview. Pure -- no provisioning or delegation.
 *
 * @param options {object}
 * @param options.zcapRequests {ICapabilityQueryDetail[]}
 * @param options.spaceUrl {string}
 * @returns {ResolvedGrant[]}
 */
export function resolveGrants({
  zcapRequests,
  spaceUrl
}: {
  zcapRequests: ICapabilityQueryDetail[]
  spaceUrl: string
}): ResolvedGrant[] {
  return zcapRequests.map(descriptor => resolveGrant({ descriptor, spaceUrl }))
}

/**
 * Delegates capabilities to the relying parties named in the requests, on the
 * consent-approved path. Provisions any missing RP collection first, then
 * delegates each satisfiable grant rooted at the user's Space root capability.
 * Requires a session with a remote Space. Unsatisfiable grants are skipped
 * (they never reach a delegation). Returns the delegated capabilities, in
 * request order.
 *
 * @param options {object}
 * @param options.zcapRequests {ICapabilityQueryDetail[]}
 * @param options.session {Session}
 * @param [options.ttlMs] {number}   read-only grant lifetime; defaults to
 *   RP_ZCAP_TTL_MS
 * @param [options.writeTtlMs] {number}   write grant lifetime; defaults to
 *   RP_ZCAP_WRITE_TTL_MS (shorter than the read TTL)
 * @returns {Promise<IZcap[]>}
 */
export async function processZcaps({
  zcapRequests,
  session,
  ttlMs = RP_ZCAP_TTL_MS,
  writeTtlMs = RP_ZCAP_WRITE_TTL_MS
}: {
  zcapRequests: ICapabilityQueryDetail[]
  session: Session
  ttlMs?: number
  writeTtlMs?: number
}): Promise<IZcap[]> {
  if (!hasZcapStorage(session)) {
    throw new ZcapUnavailableError()
  }

  // `hasZcapStorage` above guarantees a resolved `spaceUrl`.
  const spaceUrl = session.storage.spaceUrl!
  const spaceRootCapability = await generateZcapUri({ url: spaceUrl })
  const now = Date.now()
  const { zcapClient } = session.profile

  const zcaps: IZcap[] = []
  for (const descriptor of zcapRequests) {
    const { target, allowedActions, write } = resolveGrant({
      descriptor,
      spaceUrl
    })
    if (!target.satisfiable || !target.invocationTarget) {
      continue
    }
    if (target.needsProvisioning && target.collectionId) {
      // A public-collection grant provisions plaintext plus a collection-level
      // PublicCanRead policy; the wallet (holding the space root) sets the
      // policy -- the RP's delegated zcap could not.
      await session.storage.ensureCollection({
        id: target.collectionId,
        isPublic: target.isPublic
      })
    }
    // Write grants live for the shorter write TTL; read-only grants for the
    // longer read TTL.
    const expires = new Date(now + (write ? writeTtlMs : ttlMs))
    const zcap = await zcapClient.delegate({
      capability: spaceRootCapability,
      invocationTarget: target.invocationTarget,
      controller: descriptor.controller,
      allowedActions,
      expires
    })
    zcaps.push(zcap as IZcap)
  }
  return zcaps
}
