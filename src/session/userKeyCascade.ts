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
 * (`src/session/collectionLogStore.ts`), so the fan-out takes the lookup
 * rather than building one.
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
  type UserKey,
  type UserKeyCascadeResult
} from '@interop/wallet-core/keys'
import type { CascadeCollections } from '@interop/wallet-core/clients'
import type { WebvhResourceLogController } from '@interop/wallet-core/resourceLog'
import { ENCRYPTED_STANDARD_COLLECTIONS } from '@/app.config'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import type { CollectionStoreFor } from '@/session/collectionLogStore'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:cascade')

export type { UserKeyCascadeResult } from '@interop/wallet-core/keys'

/**
 * The Space's collection listing, reduced to what the cascade asks of it:
 * which collections exist remotely and which of those the server declares
 * encrypted. One listing answers both questions -- the enumeration and the
 * per-collection `isEncrypted` probe -- so the fan-out no longer re-describes
 * every collection it is about to rotate.
 *
 * The listing is best-effort: offline, `listed` is false, the standard
 * encrypted set still rotates, and the probe falls back to a describe per
 * collection (the sweep covers the rest at a later login).
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @returns {Promise<{ listed: boolean, ids: Set<string>, encrypted: Set<string> }>}
 */
async function listedCollections({
  remoteStore
}: {
  remoteStore: WASRemoteStore
}): Promise<{ listed: boolean; ids: Set<string>; encrypted: Set<string> }> {
  const ids = new Set<string>()
  const encrypted = new Set<string>()
  try {
    for (const item of await remoteStore.listCollections()) {
      if (!item.id) {
        continue
      }
      ids.add(item.id)
      if (item.isEncrypted) {
        encrypted.add(item.id)
      }
    }
  } catch (err) {
    log.warn(
      'Could not list remote collections for the user key cascade; rotating the standard collections only',
      { err }
    )
    return { listed: false, ids, encrypted }
  }
  return { listed: true, ids, encrypted }
}

/**
 * The fan-out's work, as the shared cascade orchestrator expects it: which
 * encrypted collections exist in this Space (the standard collections that
 * declare encryption, plus every remotely listed encrypted collection,
 * deduplicated), each one's descriptor store, and how its encryption
 * declaration is reached through the remote store.
 *
 * The remote listing is read once per cascade and memoized, since the
 * orchestrator asks for the ids and then for each collection's encryption
 * state.
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
  let listing: Promise<{
    listed: boolean
    ids: Set<string>
    encrypted: Set<string>
  }> | null = null
  const listOnce = () => (listing ??= listedCollections({ remoteStore }))

  return {
    collectionIds: async () => {
      const { encrypted } = await listOnce()
      const ids = new Set<string>(
        ENCRYPTED_STANDARD_COLLECTIONS.map(spec => spec.id)
      )
      for (const id of encrypted) {
        ids.add(id)
      }
      return [...ids]
    },
    storeFor,
    // Skip a collection that carries no governing log (a plaintext one, or
    // a standard collection on an account that never provisioned it).
    // Answered from the collection's own verified log rather than the
    // server's derived `encryption` member: the listing above only
    // enumerates, since a host omitting the member for one collection could
    // otherwise keep it out of every rotation and leave it keyed to the
    // retired generation.
    isEncrypted: async collectionId =>
      (await storeFor(collectionId).read()) !== null
  }
}

/**
 * Re-epochs every encrypted collection onto the roster's current user key, in
 * parallel. Collections not declared encrypted server-side are skipped; a
 * collection that fails is reported in `failed` and the rest proceed.
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
