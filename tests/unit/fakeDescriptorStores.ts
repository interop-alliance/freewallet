/**
 * In-memory `EncryptionDescriptorStore`s keyed by collection id -- the
 * `storeFor` lookup a log-governed collection's epoch install, share, and
 * fan-out take, with real create-if-absent and compare-and-swap etag
 * semantics. It stands in for `src/session/collectionLogStore.ts`'s stores in
 * a unit test, so a test asserts on the descriptor a ceremony left behind
 * rather than on a faked Collection Description.
 *
 * State lives in one map rather than inside a store closure, so a caller that
 * builds a fresh store per collection (as the real builders do) still sees
 * what an earlier store wrote. It mirrors wallet-core's own fixture of the
 * same name; nothing is imported from that package's test tree.
 */
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import type {
  EncryptionDescriptorSource,
  EncryptionDescriptorStore
} from '@interop/was-client/edv'
import type { SealableEncryptionDescriptorStore } from '@interop/wallet-core/keys'
import type { WebvhResourceLogController } from '@interop/wallet-core/resourceLog'

/**
 * What {@link memoryDescriptorStores} hands back: the lookup itself, the
 * read-only source the storage layer acquires descriptors through, a reader
 * over the settled descriptors, and the write/anchor records assertions read.
 */
export interface MemoryDescriptorStores {
  storeFor(collectionId: string): SealableEncryptionDescriptorStore
  /**
   * The read-only counterpart, the `EncryptionDescriptorSource` shape
   * `acquireDescriptors` and `StorageManager` take.
   */
  source: EncryptionDescriptorSource
  descriptorOf(collectionId: string): CollectionEncryption | undefined
  /**
   * Seeds a collection's descriptor, as a run that already installed
   * epoch[0] would have left it.
   */
  seed(collectionId: string, descriptor: CollectionEncryption): void
  /**
   * Every write, in order, as `<collectionId>` -- one entry per landed
   * `create` or `replace`.
   */
  writes: string[]
  /**
   * Every `setMinimumControllerVersion` a store took, in order -- the
   * post-edit anchoring a cascade owes each collection.
   */
  anchors: Array<{
    collectionId: string
    controller: WebvhResourceLogController
  }>
  /**
   * Every `seal()` a store ran, in order.
   */
  seals: string[]
}

/**
 * Builds the lookup.
 *
 * @param [options] {object}
 * @param [options.descriptors] {Record<string, CollectionEncryption>}   the
 *   descriptors already governed, keyed by collection id
 * @param [options.failFor] {function}   `(collectionId) => boolean` -- every
 *   read for a matching collection throws (a transient server failure)
 * @returns {MemoryDescriptorStores}
 */
export function memoryDescriptorStores({
  descriptors = {},
  failFor
}: {
  descriptors?: Record<string, CollectionEncryption>
  failFor?: (collectionId: string) => boolean
} = {}): MemoryDescriptorStores {
  const stored = new Map<
    string,
    { descriptor: CollectionEncryption; version: number }
  >()
  for (const [collectionId, descriptor] of Object.entries(descriptors)) {
    stored.set(collectionId, {
      descriptor: structuredClone(descriptor),
      version: 0
    })
  }
  const writes: string[] = []
  const seals: string[] = []
  const anchors: MemoryDescriptorStores['anchors'] = []

  function readOne(collectionId: string) {
    if (failFor?.(collectionId)) {
      throw new Error(`Service unavailable for "${collectionId}".`)
    }
    const entry = stored.get(collectionId)
    return entry
      ? {
          descriptor: structuredClone(entry.descriptor),
          etag: `v${entry.version}`
        }
      : null
  }

  function storeFor(collectionId: string): SealableEncryptionDescriptorStore {
    const base: EncryptionDescriptorStore = {
      async read() {
        return readOne(collectionId)
      },
      async replace(next, { ifMatch }: { ifMatch?: string }) {
        const entry = stored.get(collectionId)
        if (!entry || ifMatch !== `v${entry.version}`) {
          throw new PreconditionFailedError('stale descriptor etag')
        }
        entry.descriptor = structuredClone(next)
        entry.version++
        writes.push(collectionId)
      },
      async create(next: CollectionEncryption) {
        if (stored.has(collectionId)) {
          throw new PreconditionFailedError('the governing log already exists')
        }
        stored.set(collectionId, {
          descriptor: structuredClone(next),
          version: 0
        })
        writes.push(collectionId)
      }
    }
    return {
      ...base,
      create: descriptor => base.create!(descriptor),
      async seal() {
        seals.push(collectionId)
        return 'noop'
      },
      setMinimumControllerVersion({ controller }) {
        anchors.push({ collectionId, controller })
      }
    }
  }

  return {
    storeFor,
    source: {
      async collectionEncryption({ collectionId }) {
        return readOne(collectionId)?.descriptor ?? undefined
      }
    },
    descriptorOf: collectionId => stored.get(collectionId)?.descriptor,
    seed: (collectionId, descriptor) => {
      stored.set(collectionId, {
        descriptor: structuredClone(descriptor),
        version: 0
      })
    },
    writes,
    anchors,
    seals
  }
}

/**
 * The `DescriptorLogs` seam `StorageManager.initStorageClients` takes,
 * backed by {@link memoryDescriptorStores}.
 *
 * @param stores {MemoryDescriptorStores}
 * @returns {object}   `{ source, storeFor }`
 */
export function descriptorLogsFrom(stores: MemoryDescriptorStores): {
  source: EncryptionDescriptorSource
  storeFor: (collectionId: string) => Promise<SealableEncryptionDescriptorStore>
} {
  return {
    source: stores.source,
    storeFor: async collectionId => stores.storeFor(collectionId)
  }
}
