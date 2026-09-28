/**
 * The collection fan-out of the user key rotation cascade: after the `key-map`
 * roster has moved to a fresh user key (a client revoked, a recovery code spent or
 * revoked), every encrypted collection in the Space -- the encrypted standard
 * collections AND the app-provisioned ones -- is re-epoch'd onto the fresh
 * key in parallel, so writes stop landing under epochs the revoked party can
 * decrypt. The driving (and the per-collection staleness/rotation op) lives
 * in `@interop/wallet-core/keys`; this module owns what only this wallet
 * knows -- which collections exist, and how each one's encryption
 * declaration is reached through the remote store. Each collection's
 * descriptor store is the caller's: a log-governed store whose appends are
 * signed by whichever key the caller's ceremony is licensed to sign with
 * (`sessionCollectionStores` in `src/session/collectionLogStore.ts` for a
 * live session, wallet-core's `accountCollectionStores` for a bare-parts
 * caller), so the fan-out takes the lookup rather than building one.
 *
 * Convergence is the design, not an afterthought: staleness is detected from
 * durable data alone (a collection is stale exactly when its current epoch
 * names a non-current user key generation), so a mid-cascade crash followed by a
 * naive full re-run rotates only what is still stranded, with zero redundant
 * epochs. Failures are collected per collection rather than aborting the
 * fan-out; the cascade-completion sweep is the standing backstop.
 */
import type { CollectionEncryption } from '@interop/was-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import {
  cascadeCollectionsToUserKey as driveCascade,
  type CollectionStoreFor,
  type UserKey,
  type UserKeyCascadeResult
} from '@interop/wallet-core/keys'
import type { CascadeCollections } from '@interop/wallet-core/clients'
import type { WebvhResourceLogController } from '@interop/wallet-core/resourceLog'
import { ENCRYPTED_STANDARD_COLLECTIONS } from '@/app.config'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:cascade')

export type { UserKeyCascadeResult } from '@interop/wallet-core/keys'

/**
 * The Space's collection ids, the cascade's candidate set. The listing only
 * enumerates: whether each candidate is encrypted is answered by its own
 * governing log (`isEncrypted` below), so the lean listing is enough and no
 * collection is described here.
 *
 * The listing is best-effort: offline it yields nothing, the standard
 * encrypted set still rotates, and the sweep covers the rest at a later
 * login.
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @returns {Promise<Set<string>>}
 */
async function listedCollectionIds({
  remoteStore
}: {
  remoteStore: WASRemoteStore
}): Promise<Set<string>> {
  const ids = new Set<string>()
  try {
    for (const item of await remoteStore.listCollectionPublicStates()) {
      if (item.id) {
        ids.add(item.id)
      }
    }
  } catch (err) {
    log.warn(
      'Could not list remote collections for the user key cascade; rotating the standard collections only',
      { err }
    )
  }
  return ids
}

/**
 * The fan-out's work, as the shared cascade orchestrator expects it: which
 * encrypted collections exist in this Space, each one's descriptor store,
 * and how its encryption declaration is reached.
 *
 * The candidates are the standard encrypted collections plus every
 * collection the Space listing names, deduplicated. The host-served
 * `encryption` member plays no part: `isEncrypted` reads each candidate's
 * own verified log and only drops one that has no log.
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @param options.storeFor {CollectionStoreFor}   each collection's
 *   log-governed descriptor store, signed by the key the calling ceremony
 *   is licensed to append with at the post-edit document
 * @returns {CascadeCollections}   with `collectionIds` narrowed to the
 *   resolver form, so callers driving the cascade themselves can await it
 */
export function cascadeCollections({
  remoteStore,
  storeFor
}: {
  remoteStore: WASRemoteStore
  storeFor: CollectionStoreFor
}): CascadeCollections & { collectionIds: () => Promise<string[]> } {
  // One store per collection for the whole fan-out, so the encryption check
  // and the rotation share one verified log read.
  const stores = new Map<string, ReturnType<CollectionStoreFor>>()
  const storeOnce: CollectionStoreFor = collectionId => {
    let store = stores.get(collectionId)
    if (!store) {
      store = storeFor(collectionId)
      stores.set(collectionId, store)
    }
    return store
  }
  return {
    collectionIds: async () => {
      const ids = new Set<string>(
        ENCRYPTED_STANDARD_COLLECTIONS.map(spec => spec.id)
      )
      for (const id of await listedCollectionIds({ remoteStore })) {
        ids.add(id)
      }
      return [...ids]
    },
    storeFor: storeOnce,
    // Skip a candidate that carries no governing log (a plaintext one, or a
    // standard collection on an account that never provisioned it).
    // Answered from the collection's own verified log rather than the
    // server's derived `encryption` member, and only ever removing a
    // listed candidate: a host omitting the member for one collection
    // cannot keep it out of a rotation.
    isEncrypted: async collectionId =>
      (await storeOnce(collectionId).read()) !== null
  }
}

/**
 * Re-epochs every encrypted collection onto the roster's current user key, in
 * parallel. A collection with no governing log is skipped; a collection
 * that fails is reported in `failed` and the rest proceed.
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @param options.storeFor {CollectionStoreFor}   each collection's
 *   log-governed descriptor store (see `cascadeCollections`)
 * @param options.rosterDescriptor {CollectionEncryption}   the freshly read
 *   `key-map/user-key.jsonl` roster (the source of the user key generations)
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key, unwrapping the generations
 * @param options.userKey {UserKey}   the roster's current user key
 * @param [options.controller] {WebvhResourceLogController}   a ceremony's
 *   post-edit controller view, set as every sealable store's minimum
 *   controller version before its first append so no collection append
 *   anchors behind the edit. Omitted, each store's own resolver decides,
 *   which is the login sweep's case
 * @returns {Promise<UserKeyCascadeResult>}
 */
export async function cascadeCollectionsToUserKey({
  remoteStore,
  storeFor,
  rosterDescriptor,
  clientKeyAgreementKey,
  userKey,
  controller
}: {
  remoteStore: WASRemoteStore
  storeFor: CollectionStoreFor
  rosterDescriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  userKey: UserKey
  controller?: WebvhResourceLogController
}): Promise<UserKeyCascadeResult> {
  const work = cascadeCollections({ remoteStore, storeFor })
  const result = await driveCascade({
    collectionIds: await work.collectionIds(),
    storeFor: work.storeFor,
    ...(work.isEncrypted ? { isEncrypted: work.isEncrypted } : {}),
    rosterDescriptor,
    clientKeyAgreementKey,
    userKey,
    ...(controller ? { controller } : {})
  })
  for (const { collectionId, error } of result.failed) {
    log.warn('Could not rotate collection onto the current user key', {
      collectionId,
      err: error
    })
  }
  return result
}
