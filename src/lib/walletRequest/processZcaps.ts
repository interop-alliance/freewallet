/**
 * Zcap request processing for "Login with Wallet": resolves each requested
 * capability's abstract `invocationTarget` descriptor onto the user's own WAS
 * Space, provisions any missing RP collection, and delegates a capability to
 * the relying party's DID. All delegations are rooted at the user's Space root
 * capability (`urn:zcap:root:<spaceUrl>`); targets outside the Space are
 * unsatisfiable by construction, and whole-Space grants are stripped to
 * read-only (never write) -- the same attenuation reasoning as
 * `src/session/delegatedSession.ts`.
 *
 * Resolution (`resolveGrants`) is pure and drives the consent preview; the
 * delegation step (`processZcaps`) runs only on the consent-approved path.
 */
import type { Session } from '@/types/auth'
import { RP_ZCAP_TTL_MS, WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import type { ICapabilityQueryDetail, IZcap } from './types'

/**
 * Default actions for a grant whose `allowedAction` is absent: read-only.
 * Never inherit-all (an empty `allowedActions` array means "all actions").
 */
const DEFAULT_ACTIONS = ['GET', 'HEAD']

/**
 * The actions a whole-Space grant is capped at. A Space-wide write capability
 * would permit rewriting the Space Description (controller takeover), so
 * `urn:was:space` grants are always delegated read-only.
 */
const SPACE_READ_ACTIONS = ['GET', 'HEAD']

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
 * Raised when delegation is attempted without the full-tier signer (a restored
 * delegated session cannot delegate by design).
 */
export class ZcapRequiresFullSessionError extends Error {
  constructor(
    message = 'Delegating capabilities requires a full (passphrase) session.'
  ) {
    super(message)
    this.name = 'ZcapRequiresFullSessionError'
  }
}

const UNSATISFIABLE: ResolvedTarget = {
  satisfiable: false,
  wholeSpace: false,
  needsProvisioning: false,
  encrypted: false
}

/**
 * Resolves an abstract `invocationTarget` descriptor against the user's Space:
 *
 * - a plain URL string under `spaceUrl` -- used verbatim (an exact `spaceUrl`
 *   is treated as a whole-Space grant); any other string -- unsatisfiable;
 * - `{ type: 'urn:was:collection', name }` -- `${spaceUrl}/${name}` after
 *   validating `name`, flagged `needsProvisioning` unless it is a standard
 *   collection (and `encrypted` for the two EDV collections);
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
  descriptor: string | { type: string; name?: string }
  spaceUrl: string
}): ResolvedTarget {
  if (typeof descriptor === 'string') {
    if (descriptor === spaceUrl || descriptor.startsWith(`${spaceUrl}/`)) {
      return {
        satisfiable: true,
        invocationTarget: descriptor,
        wholeSpace: descriptor === spaceUrl,
        needsProvisioning: false,
        encrypted: false
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
      encrypted: false
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
      needsProvisioning: !standard,
      collectionId: name,
      encrypted: !!standard?.encryption
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
  allowedAction: string | string[] | undefined
): string[] {
  if (allowedAction === undefined) {
    return [...DEFAULT_ACTIONS]
  }
  return Array.isArray(allowedAction) ? [...allowedAction] : [allowedAction]
}

/**
 * Resolves a single requested capability into a `ResolvedGrant`: its target
 * plus the normalized, security-capped actions (whole-Space grants forced to
 * read-only).
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
  const allowedActions = target.wholeSpace
    ? [...SPACE_READ_ACTIONS]
    : normalizeActions(descriptor.allowedAction)
  return { descriptor, target, allowedActions }
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
 * Requires a full-tier session with a remote Space. Unsatisfiable grants are
 * skipped (they never reach a delegation). Returns the delegated capabilities,
 * in request order.
 *
 * @param options {object}
 * @param options.zcapRequests {ICapabilityQueryDetail[]}
 * @param options.session {Session}
 * @param [options.ttlMs] {number}   grant lifetime; defaults to RP_ZCAP_TTL_MS
 * @returns {Promise<IZcap[]>}
 */
export async function processZcaps({
  zcapRequests,
  session,
  ttlMs = RP_ZCAP_TTL_MS
}: {
  zcapRequests: ICapabilityQueryDetail[]
  session: Session
  ttlMs?: number
}): Promise<IZcap[]> {
  if (!session.storage.hasRemoteStorage || !session.storage.spaceUrl) {
    throw new ZcapUnavailableError()
  }
  if (session.tier !== 'full' || !session.profile.keyAgent) {
    throw new ZcapRequiresFullSessionError()
  }

  const spaceUrl = session.storage.spaceUrl
  const spaceRootCapability = `urn:zcap:root:${encodeURIComponent(spaceUrl)}`
  const expires = new Date(Date.now() + ttlMs)
  const { zcapClient } = session.profile

  const zcaps: IZcap[] = []
  for (const descriptor of zcapRequests) {
    const { target, allowedActions } = resolveGrant({ descriptor, spaceUrl })
    if (!target.satisfiable || !target.invocationTarget) {
      continue
    }
    if (target.needsProvisioning && target.collectionId) {
      await session.storage.ensureCollection({ id: target.collectionId })
    }
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
