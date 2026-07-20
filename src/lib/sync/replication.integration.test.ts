/**
 * Integration test: drives the generic adapter through a REAL RxDB collection
 * (memory storage) against a stateful in-memory fake WAS server, proving the
 * full replication machine -- schema, checkpoint iteration, `deletedField`,
 * push/pull round-trips -- not just the handlers in isolation.
 *
 * @vitest-environment node
 */
import { afterEach, describe, it, expect } from 'vitest'
import { createRxDatabase, type RxDatabase } from 'rxdb/plugins/core'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { createWasReplication } from './wasReplication'
import {
  syncedDocMigrationStrategies,
  syncedDocSchema
} from './syncedDocSchema'
import { formatEtag } from './pushWrites'
import {
  WasSyncConflictError,
  type Json,
  type SyncCheckpoint,
  type WasSyncPort,
  type WireDoc
} from './types'

/**
 * A minimal stateful in-memory WAS server exposing a `WasSyncPort`. Documents
 * are ordered by a monotonic tick used as `updatedAt`, so the change feed and
 * checkpoints behave like the real server.
 */
class FakeWasServer {
  private docs = new Map<
    string,
    {
      version: number
      updatedAt: string
      deleted: boolean
      data?: Json
      epoch?: string
    }
  >()
  private tick = 0

  private nextUpdatedAt(): string {
    this.tick += 1
    return String(this.tick).padStart(12, '0')
  }

  /** Directly seed a document as if another client had written it. */
  seed(id: string, data: Json, epoch?: string): void {
    this.docs.set(id, {
      version: 1,
      updatedAt: this.nextUpdatedAt(),
      deleted: false,
      data,
      ...(epoch !== undefined && { epoch })
    })
  }

  has(id: string): boolean {
    const doc = this.docs.get(id)
    return doc !== undefined && !doc.deleted
  }

  dataFor(id: string): Json | undefined {
    return this.docs.get(id)?.data
  }

  epochFor(id: string): string | undefined {
    return this.docs.get(id)?.epoch
  }

  port(): WasSyncPort {
    return {
      query: async ({ checkpoint, limit }) => {
        const ordered = [...this.docs.entries()]
          .map(([id, doc]) => ({ id, ...doc }))
          .sort((left, right) =>
            left.updatedAt === right.updatedAt
              ? left.id.localeCompare(right.id)
              : left.updatedAt.localeCompare(right.updatedAt)
          )
        const after = checkpoint
          ? ordered.filter(
              doc =>
                doc.updatedAt > checkpoint.updatedAt ||
                (doc.updatedAt === checkpoint.updatedAt &&
                  doc.id > checkpoint.id)
            )
          : ordered
        const page = after.slice(0, limit)
        const documents: WireDoc[] = page.map(doc => ({
          id: doc.id,
          _deleted: doc.deleted,
          updatedAt: doc.updatedAt,
          version: doc.version,
          ...(doc.epoch !== undefined && !doc.deleted && { epoch: doc.epoch }),
          ...(doc.data !== undefined && !doc.deleted && { data: doc.data })
        }))
        const last = page[page.length - 1]
        const nextCheckpoint: SyncCheckpoint | null = last
          ? { id: last.id, updatedAt: last.updatedAt }
          : null
        return { documents, checkpoint: nextCheckpoint }
      },

      putContent: async ({ id, data, ifMatch, ifNoneMatch, epoch }) => {
        const existing = this.docs.get(id)
        const live = existing && !existing.deleted
        if (ifNoneMatch && live) {
          throw new WasSyncConflictError()
        }
        if (
          ifMatch !== undefined &&
          (!existing || formatEtag(existing.version) !== ifMatch)
        ) {
          throw new WasSyncConflictError()
        }
        // The port implements `WasSyncPort` directly, so the `epoch` param stands
        // in for the `WAS-Key-Epoch` header the real server stamps (absent leaves
        // no stamp).
        this.docs.set(id, {
          version: (existing?.version ?? 0) + 1,
          updatedAt: this.nextUpdatedAt(),
          deleted: false,
          data,
          ...(epoch !== undefined && { epoch })
        })
      },

      deleteContent: async ({ id, ifMatch }) => {
        const existing = this.docs.get(id)
        if (
          ifMatch !== undefined &&
          existing &&
          formatEtag(existing.version) !== ifMatch
        ) {
          throw new WasSyncConflictError()
        }
        this.docs.set(id, {
          version: (existing?.version ?? 0) + 1,
          updatedAt: this.nextUpdatedAt(),
          deleted: true
        })
      },

      putMeta: async () => {
        // Metadata is not exercised by this content-only test.
      },

      get: async ({ id }) => {
        const doc = this.docs.get(id)
        if (!doc || doc.deleted) {
          return null
        }
        return {
          version: doc.version,
          updatedAt: doc.updatedAt,
          deleted: false,
          data: doc.data,
          ...(doc.epoch !== undefined && { epoch: doc.epoch })
        }
      }
    }
  }
}

let db: RxDatabase | undefined

afterEach(async () => {
  if (db) {
    await db.close()
    db = undefined
  }
})

async function openCollection() {
  db = await createRxDatabase({
    name: 'synctest' + Math.floor(performance.now()).toString(36),
    storage: getRxStorageMemory(),
    multiInstance: false
  })
  const { synced } = await db.addCollections({
    synced: {
      schema: syncedDocSchema(),
      migrationStrategies: syncedDocMigrationStrategies()
    }
  })
  return synced
}

/**
 * Waits until `predicate` holds, nudging replication and polling. Avoids
 * depending on exact RxDB cycle timing.
 */
async function eventually(
  predicate: () => boolean | Promise<boolean>,
  nudge?: () => void
): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await predicate()) {
      return
    }
    nudge?.()
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  throw new Error('Condition not met within timeout.')
}

describe('WAS replication (RxDB + fake server)', () => {
  it('pushes a locally-inserted document to the server', async () => {
    const collection = await openCollection()
    const server = new FakeWasServer()
    const replication = createWasReplication({
      rxCollection: collection,
      wasPort: server.port(),
      replicationIdentifier: 'test-push'
    })
    await replication.awaitInitialReplication()

    await collection.insert({
      id: 'cid-1',
      updatedAt: '000000000001',
      version: 0,
      data: { hello: 'world' }
    })

    await eventually(() => server.has('cid-1'))
    expect(server.dataFor('cid-1')).toEqual({ hello: 'world' })

    await replication.cancel()
  })

  it('pulls a server-side document into the local collection', async () => {
    const collection = await openCollection()
    const server = new FakeWasServer()
    server.seed('cid-remote', { from: 'server' })

    const replication = createWasReplication({
      rxCollection: collection,
      wasPort: server.port(),
      replicationIdentifier: 'test-pull'
    })
    await replication.awaitInitialReplication()

    const doc = await collection.findOne('cid-remote').exec()
    expect(doc?.toJSON().data).toEqual({ from: 'server' })

    await replication.cancel()
  })

  it('round-trips the key-epoch id: a local epoch-stamped doc pushes and pulls back with it intact', async () => {
    const collection = await openCollection()
    const server = new FakeWasServer()
    const replication = createWasReplication({
      rxCollection: collection,
      wasPort: server.port(),
      replicationIdentifier: 'test-epoch-roundtrip'
    })
    await replication.awaitInitialReplication()

    await collection.insert({
      id: 'cid-epoch',
      updatedAt: '000000000001',
      version: 0,
      epoch: 'epoch-1',
      data: { hello: 'world' }
    })

    // Push carries the epoch to the server (its `WAS-Key-Epoch` stamp).
    await eventually(
      () => server.epochFor('cid-epoch') === 'epoch-1',
      () => replication.reSync()
    )
    expect(server.dataFor('cid-epoch')).toEqual({ hello: 'world' })

    // ...and the epoch pulls back down the feed onto the local document.
    await eventually(
      async () => {
        const current = await collection.findOne('cid-epoch').exec()
        return current?.toJSON().epoch === 'epoch-1'
      },
      () => replication.reSync()
    )
    const doc = await collection.findOne('cid-epoch').exec()
    expect(doc?.toJSON().epoch).toBe('epoch-1')
  })

  it('replicates an epoch-stamped opaque envelope verbatim with no cipher (locked vault still syncs)', async () => {
    const collection = await openCollection()
    const server = new FakeWasServer()
    // An opaque EDV-style envelope the replicating reader cannot decrypt: the
    // sync layer never touches keys, so it moves the body and its epoch verbatim.
    const envelope: Json = { jwe: { ciphertext: 'opaque', protected: 'hdr' } }
    server.seed('cid-sealed', envelope, 'epoch-7')

    const replication = createWasReplication({
      rxCollection: collection,
      wasPort: server.port(),
      replicationIdentifier: 'test-epoch-pull'
    })
    await replication.awaitInitialReplication()

    const doc = await collection.findOne('cid-sealed').exec()
    expect(doc?.toJSON().data).toEqual(envelope)
    expect(doc?.toJSON().epoch).toBe('epoch-7')

    await replication.cancel()
  })

  it('replicates a local delete as a server tombstone', async () => {
    const collection = await openCollection()
    const server = new FakeWasServer()
    const replication = createWasReplication({
      rxCollection: collection,
      wasPort: server.port(),
      replicationIdentifier: 'test-delete'
    })
    await replication.awaitInitialReplication()

    await collection.insert({
      id: 'cid-del',
      updatedAt: '000000000001',
      version: 0,
      data: { x: 1 }
    })
    // Wait for the create to fully round-trip: pushed to the server AND the
    // server `version` echoed back locally, so the delete's `If-Match` is not
    // stale (the create-then-immediate-delete race of tension 1).
    await eventually(
      async () => {
        const current = await collection.findOne('cid-del').exec()
        return server.has('cid-del') && (current?.toJSON().version ?? 0) >= 1
      },
      () => replication.reSync()
    )

    const doc = await collection.findOne('cid-del').exec()
    await doc!.remove()

    await eventually(
      () => !server.has('cid-del'),
      () => replication.reSync()
    )
    expect(server.has('cid-del')).toBe(false)

    await replication.cancel()
  })
})
