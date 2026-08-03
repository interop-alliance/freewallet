/**
 * The collection fan-out of the PUK rotation cascade: after the `key-map`
 * roster has moved to a fresh PUK (a client revoked, a recovery code spent or
 * revoked), every encrypted collection in the Space -- the encrypted standard
 * collections AND the app-provisioned ones -- is re-epoch'd onto the fresh
 * key in parallel, so writes stop landing under epochs the revoked party can
 * decrypt. The driving (and the per-collection staleness/rotation op) lives
 * in `@interop/wallet-core/keys`; this module owns what only this wallet
 * knows -- which collections exist, and how each one's descriptor store and
 * encryption declaration are reached through the remote store.
 *
 * Convergence is the design, not an afterthought: staleness is detected from
 * durable data alone (a collection is stale exactly when its current epoch
 * names a non-current PUK generation), so a mid-cascade crash followed by a
 * naive full re-run rotates only what is still stranded, with zero redundant
 * epochs. Failures are collected per collection rather than aborting the
 * fan-out; the cascade-completion sweep is the standing backstop.
 */
import { collectionDescriptorStore } from '@interop/was-client/edv'
import type { CollectionEncryption } from '@interop/was-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import {
  cascadeCollectionsToPuk as driveCascade,
  type Puk,
  type PukCascadeResult
} from '@interop/wallet-core/keys'
import type { CascadeCollections } from '@interop/wallet-core/clients'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

export type { PukCascadeResult } from '@interop/wallet-core/keys'

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
    console.warn(
      'Could not list remote collections for the PUK cascade; rotating the ' +
        'standard collections only:',
      err
    )
    return { listed: false, ids, encrypted }
  }
  return { listed: true, ids, encrypted }
}

/**
 * The fan-out's work, as the shared cascade orchestrator expects it: which
 * encrypted collections exist in this Space (the standard collections that
 * declare encryption, plus every remotely listed encrypted collection,
 * deduplicated), and how each one's descriptor store and encryption
 * declaration are reached through the remote store.
 *
 * The remote listing is read once per cascade and memoized, since the
 * orchestrator asks for the ids and then for each collection's encryption
 * state.
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @returns {CascadeCollections}   with `collectionIds` narrowed to the
 *   resolver form, so callers driving the cascade themselves can await it
 */
export function cascadeCollections({
  remoteStore
}: {
  remoteStore: WASRemoteStore
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
        WALLET_STANDARD_COLLECTIONS.filter(spec => spec.encryption).map(
          spec => spec.id
        )
      )
      for (const id of encrypted) {
        ids.add(id)
      }
      return [...ids]
    },
    storeFor: collectionId =>
      collectionDescriptorStore({
        collection: remoteStore.collectionHandle({ collectionId })
      }),
    // Skip a collection the server does not declare encrypted (e.g. a
    // standard collection on an account that never provisioned it). Answered
    // from the listing above; a collection the listing did not cover (or a
    // listing that failed) still falls back to one describe.
    isEncrypted: async collectionId => {
      const { ids, encrypted } = await listOnce()
      if (ids.has(collectionId)) {
        return encrypted.has(collectionId)
      }
      return Boolean(await remoteStore.collectionEncryption({ collectionId }))
    }
  }
}

/**
 * Re-epochs every encrypted collection onto the roster's current PUK, in
 * parallel. Collections not declared encrypted server-side are skipped; a
 * collection that fails is reported in `failed` and the rest proceed.
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @param options.rosterDescriptor {CollectionEncryption}   the freshly read
 *   `key-map/puk.json` roster (the source of the PUK generations)
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key, unwrapping the generations
 * @param options.puk {Puk}   the roster's current PUK
 * @returns {Promise<PukCascadeResult>}
 */
export async function cascadeCollectionsToPuk({
  remoteStore,
  rosterDescriptor,
  clientKeyAgreementKey,
  puk
}: {
  remoteStore: WASRemoteStore
  rosterDescriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  puk: Puk
}): Promise<PukCascadeResult> {
  const work = cascadeCollections({ remoteStore })
  const result = await driveCascade({
    collectionIds: await work.collectionIds(),
    storeFor: work.storeFor,
    ...(work.isEncrypted ? { isEncrypted: work.isEncrypted } : {}),
    rosterDescriptor,
    clientKeyAgreementKey,
    puk
  })
  for (const { collectionId, error } of result.failed) {
    console.warn(
      `Could not rotate collection "${collectionId}" onto the current PUK:`,
      error
    )
  }
  return result
}
