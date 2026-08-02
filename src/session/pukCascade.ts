/**
 * The collection fan-out of the PUK rotation cascade: after the `key-map`
 * roster has moved to a fresh PUK (a client revoked, a recovery code spent or
 * revoked), every encrypted collection in the Space -- the encrypted standard
 * collections AND the app-provisioned ones -- is re-epoch'd onto the fresh
 * key in parallel, so writes stop landing under epochs the revoked party can
 * decrypt. The per-collection op lives in `@interop/wallet-core/keys`
 * (`rotateCollectionEpochsToPuk`); this module owns what only the wallet
 * knows -- which collections exist -- and the parallel best-effort driving.
 *
 * Convergence is the design, not an afterthought: staleness is detected from
 * durable data alone (a collection is stale exactly when its current epoch
 * names a non-current PUK generation), so a mid-cascade crash followed by a
 * naive full re-run rotates only what is still stranded, with zero redundant
 * epochs. Failures are collected per collection rather than aborting the
 * fan-out; the cascade-completion sweep is the standing backstop.
 */
import {
  collectionDescriptorStore,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import type { CollectionEncryption } from '@interop/was-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import {
  rotateCollectionEpochsToPuk,
  unwrapPukGenerations,
  type CollectionPukRotationOutcome,
  type Puk
} from '@interop/wallet-core/keys'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

/**
 * What the fan-out did, per collection id: the outcomes for every collection
 * that needed (or took) work, and the per-collection failures the caller
 * surfaces -- the cascade never aborts on one stuck collection.
 */
export interface PukCascadeResult {
  outcomes: Record<string, CollectionPukRotationOutcome>
  failed: Array<{ collectionId: string; error: unknown }>
}

/**
 * The encrypted collections the cascade covers: the standard collections that
 * declare encryption, plus every remotely listed collection whose Description
 * carries an encryption descriptor (the app-provisioned ones). The remote
 * listing is best-effort -- offline, the standard set still rotates and the
 * sweep covers the rest later.
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @returns {Promise<string[]>}   collection ids, deduplicated
 */
async function encryptedCollectionIds({
  remoteStore
}: {
  remoteStore: WASRemoteStore
}): Promise<string[]> {
  const ids = new Set<string>(
    WALLET_STANDARD_COLLECTIONS.filter(spec => spec.encryption).map(
      spec => spec.id
    )
  )
  try {
    for (const item of await remoteStore.listCollections()) {
      if (item.isEncrypted && item.id) {
        ids.add(item.id)
      }
    }
  } catch (err) {
    console.warn(
      'Could not list remote collections for the PUK cascade; rotating the ' +
        'standard collections only:',
      err
    )
  }
  return [...ids]
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
  const generations = await unwrapPukGenerations({
    descriptor: rosterDescriptor,
    clientKeyAgreementKey
  })
  const collectionIds = await encryptedCollectionIds({ remoteStore })

  const outcomes: Record<string, CollectionPukRotationOutcome> = {}
  const failed: Array<{ collectionId: string; error: unknown }> = []
  await Promise.all(
    collectionIds.map(async collectionId => {
      try {
        // Skip a collection the server does not declare encrypted (e.g. a
        // standard collection on an account that never provisioned it).
        const descriptor = await remoteStore.collectionEncryption({
          collectionId
        })
        if (!descriptor) {
          return
        }
        const store: EncryptionDescriptorStore = collectionDescriptorStore({
          collection: remoteStore.collectionHandle({ collectionId })
        })
        outcomes[collectionId] = await rotateCollectionEpochsToPuk({
          store,
          puk,
          generations
        })
      } catch (err) {
        console.warn(
          `Could not rotate collection "${collectionId}" onto the current ` +
            'PUK:',
          err
        )
        failed.push({ collectionId, error: err })
      }
    })
  )
  return { outcomes, failed }
}
