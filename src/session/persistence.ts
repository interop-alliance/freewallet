/**
 * The session persistence seam: one typed handle, chosen at login, through
 * which every posture-sensitive local write travels. Durability is a property
 * of the handle's TYPE, never a flag a write site consults -- the durable
 * variant reaches the `freewallet-session` IndexedDB database (it alone
 * carries the `idb` factory), durable localStorage caches, and the durable
 * `writerId` mint, while the transient variant holds an in-memory pin store,
 * an in-memory roster-epoch pin, a per-visit in-memory `writerId`, and one
 * in-memory descriptor/meta cache pair -- and no sessionKey factory at all,
 * so code needing the durable database must hold (and assert for) the
 * durable variant. This is the typed seam
 * `decisions/0001-no-memory-overlay-storage-fork.md` requires in place of a
 * transparent in-memory storage fork.
 */
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorCache } from '@interop/wallet-core/descriptors'
import {
  memoryResourceLogPinStore,
  type ResourceLogPinStore
} from '@interop/wallet-core/resourceLog'
import { uuidv7 } from 'uuidv7'
import { getOrCreateWriterId } from '@/lib/writerId'
import {
  deletePasskeySafetyNotice,
  deleteUnlockMethodsCache,
  loadPasskeySafetyNotice,
  loadUnlockMethodsCache,
  loadUserKeyEpochPin,
  savePasskeySafetyNotice,
  savePinFromDescriptor,
  saveUnlockMethodsCache,
  sessionLogPinStore
} from '@/lib/sessionKey'

/**
 * The two durability postures, as the handle's type discriminant. Write
 * sites never compare these directly -- they use {@link isDurableSession}
 * or the asserts below.
 */
export const DURABILITY_INDEXEDDB = 'indexeddb'
export const DURABILITY_IN_MEMORY = 'in-memory'

// The localStorage key prefixes for the durable cache pair. Established
// key names -- existing browsers hold entries under them.
const DESCRIPTOR_CACHE_PREFIX = 'freewallet:collection-encryption'
const META_CACHE_PREFIX = 'freewallet:collection-meta'

/**
 * The cache for a collection's stored `/meta` value (the `custom` envelope
 * carrying the persisted blinded-index schema), beside the encryption
 * descriptor cache and under the same posture.
 */
export interface CollectionMetaCache {
  readMeta(options: {
    collectionId: string
  }): Promise<{ custom?: unknown } | undefined>
  writeMeta(options: {
    collectionId: string
    meta: { custom?: unknown }
  }): Promise<void>
}

/**
 * The user key roster-epoch pin, behind the seam: the durable variant is the
 * `user-key-epoch-pin/<accountDid>` family in the session database, the
 * transient variant an in-memory map guarding the visit alone.
 */
export interface UserKeyEpochPinStore {
  load(options: { accountDid: string }): Promise<string | null>
  saveFromDescriptor(options: {
    accountDid: string
    epochId: string
    descriptor: { epochs?: Array<{ id: string }> }
  }): Promise<void>
}

/**
 * The unlock-methods registry cache behind the seam: the wrapped record the
 * remote read write-through-caches (or, with no WAS server, the only copy).
 * The record is stored wrapped, so the cache holds ciphertext either way.
 */
export interface UnlockMethodsCache {
  load(options: { controller: string }): Promise<unknown | null>
  save(options: { controller: string; record: unknown }): Promise<void>
  delete(options: { controller: string }): Promise<void>
}

/**
 * The passkey-safety notice (a device-bound-passkey warning captured at
 * registration) behind the seam. Only durable flows write one -- passkey
 * registration is itself a durable ceremony -- so the transient variant
 * serves an empty in-memory store.
 */
export interface PasskeySafetyNoticeStore {
  load(options: { controller: string }): Promise<{
    backupEligibility: boolean
    backupState: boolean
    createdAt: string
  } | null>
  save(options: {
    controller: string
    backupEligibility: boolean
    backupState: boolean
  }): Promise<void>
  delete(options: { controller: string }): Promise<void>
}

/**
 * The members both variants carry -- what a posture-agnostic write site is
 * allowed to depend on.
 */
interface SessionPersistenceBase {
  // The keyed chain-head pin store every resource-log read rides
  // (the account log, the roster log).
  logPins: ResourceLogPinStore
  // The roster-epoch pin (chainless, keyed by account DID).
  epochPins: UserKeyEpochPinStore
  // The unlock-methods registry's local cache (the write-through on every
  // successful remote read; the only copy with no WAS server).
  unlockMethodsCache: UnlockMethodsCache
  // The passkey-safety notice the dashboard reads on first render.
  passkeyNotices: PasskeySafetyNoticeStore
  // This session's writer id for history attribution and LWW tie-breaks.
  getWriterId(): string
  // The per-scope encryption-descriptor cache (the offline fallback). One
  // instance per scope per session; a handle that persists no caches (a
  // guest's mint-only descriptors) serves a session-lifetime in-memory one.
  descriptorCache(options: { scope: string }): EncryptionDescriptorCache
  // The collection-metadata cache beside it, same lifecycle.
  metaCache(options: { scope: string }): CollectionMetaCache
}

/**
 * The durable posture: today's behavior. Alone in carrying `idb` -- the
 * first-party `freewallet-session` factory (the Storage Access seam threads
 * through it) -- so sessionKey access is structurally durable-only.
 */
export interface DurableSessionPersistence extends SessionPersistenceBase {
  durability: typeof DURABILITY_INDEXEDDB
  idb?: IDBFactory
}

/**
 * The transient posture: a public-terminal visit. Nothing this handle serves
 * outlives the tab, and it has no member reaching the session database.
 */
export interface TransientSessionPersistence extends SessionPersistenceBase {
  durability: typeof DURABILITY_IN_MEMORY
}

export type SessionPersistence =
  DurableSessionPersistence | TransientSessionPersistence

/**
 * The localStorage-backed `EncryptionDescriptorCache` for one scope (an
 * account's Space id, or `local:<clientDid>` in local mode): a collection's
 * last-seen encryption descriptor under
 * `freewallet:collection-encryption:<scope>:<collectionId>`, scoped so two
 * accounts on one browser never collide. The cache is the offline fallback:
 * when a descriptor fetch fails, a previously-shared collection must keep
 * encrypting under its current epoch. Reads treat a corrupt entry (or a
 * non-browser environment) as absent; writes no-op without localStorage.
 *
 * @param options {object}
 * @param options.scope {string}
 * @returns {EncryptionDescriptorCache}
 */
export function localStorageDescriptorCache({
  scope
}: {
  scope: string
}): EncryptionDescriptorCache {
  const cacheKey = (collectionId: string): string =>
    `${DESCRIPTOR_CACHE_PREFIX}:${scope}:${collectionId}`
  return {
    async readDescriptor({ collectionId }) {
      if (typeof localStorage === 'undefined') {
        return undefined
      }
      const raw = localStorage.getItem(cacheKey(collectionId))
      if (!raw) {
        return undefined
      }
      try {
        return JSON.parse(raw) as CollectionEncryption
      } catch {
        return undefined
      }
    },
    async writeDescriptor({ collectionId, descriptor }) {
      if (typeof localStorage === 'undefined') {
        return
      }
      localStorage.setItem(cacheKey(collectionId), JSON.stringify(descriptor))
    }
  }
}

/**
 * The localStorage cache for a collection's stored `/meta` value, under
 * `freewallet:collection-meta:<scope>:<collectionId>`. Same posture as the
 * descriptor cache: the offline fallback, with a corrupt entry (or a
 * non-browser environment) read as absent and writes no-oping without
 * localStorage.
 *
 * @param options {object}
 * @param options.scope {string}
 * @returns {CollectionMetaCache}
 */
export function localStorageMetaCache({
  scope
}: {
  scope: string
}): CollectionMetaCache {
  const cacheKey = (collectionId: string): string =>
    `${META_CACHE_PREFIX}:${scope}:${collectionId}`
  return {
    async readMeta({ collectionId }) {
      if (typeof localStorage === 'undefined') {
        return undefined
      }
      const raw = localStorage.getItem(cacheKey(collectionId))
      if (!raw) {
        return undefined
      }
      try {
        return JSON.parse(raw) as { custom?: unknown }
      } catch {
        return undefined
      }
    },
    async writeMeta({ collectionId, meta }) {
      if (typeof localStorage === 'undefined') {
        return
      }
      localStorage.setItem(cacheKey(collectionId), JSON.stringify(meta))
    }
  }
}

/**
 * Deletes every persisted descriptor-cache and meta-cache entry for one
 * scope (an account's Space id, or `local:<clientDid>` in local mode).
 * Consumed by the shared wipe enumeration -- outside it, no code path
 * deletes these families, so they would otherwise outlive the account.
 * Scoped deletion only: another account's entries are never touched.
 *
 * @param options {object}
 * @param options.scope {string}
 * @returns {void}
 */
export function deleteLocalCacheFamilies({ scope }: { scope: string }): void {
  deleteLocalStorageByPrefixes([
    `${DESCRIPTOR_CACHE_PREFIX}:${scope}:`,
    `${META_CACHE_PREFIX}:${scope}:`
  ])
}

/**
 * Deletes every persisted descriptor-cache and meta-cache entry across ALL
 * scopes: the whole-database forget grade's localStorage half, which cannot
 * attribute scopes to accounts (attribution needs the unlock material that
 * grade lacks) and deletes the families wholesale instead. Global UI prefs
 * live under other keys and are untouched.
 *
 * @returns {void}
 */
export function deleteAllLocalCacheFamilies(): void {
  deleteLocalStorageByPrefixes([
    `${DESCRIPTOR_CACHE_PREFIX}:`,
    `${META_CACHE_PREFIX}:`
  ])
}

/**
 * Removes every `localStorage` key carrying one of the given prefixes, in
 * one pass over the store. The shared body of both cache-family deleters
 * above -- they differ only in whether the prefixes are scope-qualified.
 * A non-browser environment is a no-op.
 *
 * @param prefixes {string[]}
 * @returns {void}
 */
function deleteLocalStorageByPrefixes(prefixes: string[]): void {
  if (typeof localStorage === 'undefined') {
    return
  }
  const doomed: string[] = []
  for (let index = 0; index < localStorage.length; index++) {
    const key = localStorage.key(index)
    if (key && prefixes.some(prefix => key.startsWith(prefix))) {
      doomed.push(key)
    }
  }
  for (const key of doomed) {
    localStorage.removeItem(key)
  }
}

/**
 * An in-memory `EncryptionDescriptorCache`: the transient session's cache,
 * seeded by the login-time acquisition and retaining that snapshot when a
 * mid-session refresh fails (a failed fetch falls back to what login saw,
 * never to an empty cache).
 *
 * @returns {EncryptionDescriptorCache}
 */
export function memoryDescriptorCache(): EncryptionDescriptorCache {
  const entries = new Map<string, CollectionEncryption>()
  return {
    async readDescriptor({ collectionId }) {
      return entries.get(collectionId)
    },
    async writeDescriptor({ collectionId, descriptor }) {
      entries.set(collectionId, descriptor)
    }
  }
}

/**
 * The in-memory metadata cache beside {@link memoryDescriptorCache}.
 *
 * @returns {CollectionMetaCache}
 */
export function memoryMetaCache(): CollectionMetaCache {
  const entries = new Map<string, { custom?: unknown }>()
  return {
    async readMeta({ collectionId }) {
      return entries.get(collectionId)
    },
    async writeMeta({ collectionId, meta }) {
      entries.set(collectionId, meta)
    }
  }
}

/**
 * Builds the durable persistence handle -- today's posture, and the default
 * every login constructs unless the caller supplies a transient handle.
 *
 * @param options {object}
 * @param [options.idb] {IDBFactory}   first-party IndexedDB (CHAPI popups
 *   thread the Storage Access API handle here)
 * @param [options.persistCaches] {boolean}   false for a guest: the cache
 *   pair is in-memory for the session and never persisted (a guest's
 *   identity is random and its data dies with the session); default true
 * @returns {DurableSessionPersistence}
 */
export function durableSessionPersistence({
  idb,
  persistCaches = true
}: {
  idb?: IDBFactory
  persistCaches?: boolean
} = {}): DurableSessionPersistence {
  const descriptorCaches = new Map<string, EncryptionDescriptorCache>()
  const metaCaches = new Map<string, CollectionMetaCache>()
  return {
    durability: DURABILITY_INDEXEDDB,
    ...(idb ? { idb } : {}),
    logPins: sessionLogPinStore({ idb }),
    epochPins: {
      async load({ accountDid }) {
        return await loadUserKeyEpochPin({ accountDid, idb })
      },
      async saveFromDescriptor({ accountDid, epochId, descriptor }) {
        await savePinFromDescriptor({ accountDid, epochId, descriptor, idb })
      }
    },
    unlockMethodsCache: {
      async load({ controller }) {
        return await loadUnlockMethodsCache({ controller, idb })
      },
      async save({ controller, record }) {
        await saveUnlockMethodsCache({ controller, record, idb })
      },
      async delete({ controller }) {
        await deleteUnlockMethodsCache({ controller, idb })
      }
    },
    passkeyNotices: {
      async load({ controller }) {
        return await loadPasskeySafetyNotice({ controller, idb })
      },
      async save({ controller, backupEligibility, backupState }) {
        await savePasskeySafetyNotice({
          controller,
          backupEligibility,
          backupState,
          idb
        })
      },
      async delete({ controller }) {
        await deletePasskeySafetyNotice({ controller, idb })
      }
    },
    getWriterId() {
      return getOrCreateWriterId()
    },
    descriptorCache({ scope }) {
      let cache = descriptorCaches.get(scope)
      if (!cache) {
        cache = persistCaches
          ? localStorageDescriptorCache({ scope })
          : memoryDescriptorCache()
        descriptorCaches.set(scope, cache)
      }
      return cache
    },
    metaCache({ scope }) {
      let cache = metaCaches.get(scope)
      if (!cache) {
        cache = persistCaches
          ? localStorageMetaCache({ scope })
          : memoryMetaCache()
        metaCaches.set(scope, cache)
      }
      return cache
    }
  }
}

/**
 * Builds the transient persistence handle: a public-terminal visit's, whose
 * every member is in-memory and dies with the tab. There is deliberately no
 * member reaching the `freewallet-session` database -- a transient session
 * must never create it, even on a read (the versioned open is durable).
 *
 * @returns {TransientSessionPersistence}
 */
export function transientSessionPersistence(): TransientSessionPersistence {
  const epochPins = new Map<string, string>()
  const unlockMethods = new Map<string, unknown>()
  // One cache pair for the whole session, whatever scope asks: a transient
  // session serves exactly one account, and the pair is seeded once at login.
  const descriptors = memoryDescriptorCache()
  const metas = memoryMetaCache()
  const writerId = uuidv7()
  return {
    durability: DURABILITY_IN_MEMORY,
    logPins: memoryResourceLogPinStore(),
    epochPins: {
      async load({ accountDid }) {
        return epochPins.get(accountDid) ?? null
      },
      async saveFromDescriptor({ accountDid, epochId, descriptor }) {
        // Forward-only within the visit, like the durable pin: a write that
        // would move the pin backward along the served epoch order (or that
        // cannot be ordered against it) is dropped rather than adopted.
        const stored = epochPins.get(accountDid)
        if (stored && stored !== epochId) {
          const epochIds = (descriptor.epochs ?? []).map(epoch => epoch.id)
          if (epochIds.indexOf(epochId) <= epochIds.indexOf(stored)) {
            return
          }
        }
        epochPins.set(accountDid, epochId)
      }
    },
    unlockMethodsCache: {
      async load({ controller }) {
        return unlockMethods.get(controller) ?? null
      },
      async save({ controller, record }) {
        unlockMethods.set(controller, record)
      },
      async delete({ controller }) {
        unlockMethods.delete(controller)
      }
    },
    // A transient visit never registers a passkey (registration is a durable
    // ceremony), so the store starts and stays empty: reads answer null,
    // writes are visit-scoped no-ops kept only for interface uniformity.
    passkeyNotices: {
      async load() {
        return null
      },
      async save() {},
      async delete() {}
    },
    getWriterId() {
      return writerId
    },
    descriptorCache() {
      return descriptors
    },
    metaCache() {
      return metas
    }
  }
}

/**
 * Thrown when a ceremony that publishes durable state was invoked from a
 * transient session and no step-up applies: update-key rotation, whose
 * persist-before-publish invariant needs a durable client-key record to
 * persist into (and whose subject -- this browser's durable update key --
 * does not exist in a transient session).
 */
export class DurableSessionRequiredError extends Error {
  ceremony: string

  constructor({ ceremony }: { ceremony: string }) {
    super(`${ceremony} requires a durable session on a remembered browser.`)
    this.name = 'DurableSessionRequiredError'
    this.ceremony = ceremony
  }
}

/**
 * Thrown when an account-management ceremony was invoked from a transient
 * session outside a step-up: the ceremony is reachable from a public
 * terminal, but only bracketed by the step-up ceremony's loud enroll and
 * retire entries (the in-memory FW-154 self-enrollment), never bare.
 */
export class StepUpRequiredError extends Error {
  ceremony: string

  constructor({ ceremony }: { ceremony: string }) {
    super(
      `${ceremony} requires a step-up from a transient session: ` +
        'the ceremony runs as a loudly enrolled in-memory client, never bare.'
    )
    this.name = 'StepUpRequiredError'
    this.ceremony = ceremony
  }
}

/**
 * Whether this session's persistence is the durable posture -- the one
 * predicate gating sites use in place of comparing the discriminant.
 *
 * @param persistence {SessionPersistence}
 * @returns {boolean}
 */
export function isDurableSession(
  persistence: SessionPersistence
): persistence is DurableSessionPersistence {
  return persistence.durability === DURABILITY_INDEXEDDB
}

/**
 * Refuses a ceremony whose subject or persist half is structurally durable
 * (update-key rotation). A caller needing the narrowed type uses
 * {@link isDurableSession} (a destructured option cannot carry an `asserts`
 * predicate).
 *
 * @param options {object}
 * @param options.persistence {SessionPersistence}
 * @param options.ceremony {string}   names the ceremony in the refusal
 * @returns {void}
 */
export function assertDurableSession({
  persistence,
  ceremony
}: {
  persistence: SessionPersistence
  ceremony: string
}): void {
  if (!isDurableSession(persistence)) {
    throw new DurableSessionRequiredError({ ceremony })
  }
}

/**
 * Refuses an account-management ceremony invoked from a transient session
 * outside a step-up. The step-up ceremony itself (an in-memory enrolled
 * client bracketed by ladder-signed enroll and retire entries) supplies the
 * context that satisfies this gate when it lands; until then every transient
 * invocation refuses.
 *
 * @param options {object}
 * @param options.persistence {SessionPersistence}
 * @param options.ceremony {string}   names the ceremony in the refusal
 * @returns {void}
 */
export function assertAccountCeremonyAllowed({
  persistence,
  ceremony
}: {
  persistence: SessionPersistence
  ceremony: string
}): void {
  if (!isDurableSession(persistence)) {
    throw new StepUpRequiredError({ ceremony })
  }
}
