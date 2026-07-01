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
import { syncedDocSchema } from './syncedDocSchema'
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
    { version: number; updatedAt: string; deleted: boolean; data?: Json }
  >()
  private tick = 0

  private nextUpdatedAt(): string {
    this.tick += 1
    return String(this.tick).padStart(12, '0')
  }

  /** Directly seed a document as if another client had written it. */
  seed(id: string, data: Json): void {
    this.docs.set(id, {
      version: 1,
      updatedAt: this.nextUpdatedAt(),
      deleted: false,
      data
    })
  }

  has(id: string): boolean {
    const doc = this.docs.get(id)
    return doc !== undefined && !doc.deleted
  }

  dataFor(id: string): Json | undefined {
    return this.docs.get(id)?.data
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
          ...(doc.data !== undefined && !doc.deleted && { data: doc.data })
        }))
        const last = page[page.length - 1]
        const nextCheckpoint: SyncCheckpoint | null = last
          ? { id: last.id, updatedAt: last.updatedAt }
          : null
        return { documents, checkpoint: nextCheckpoint }
      },

      putContent: async ({ id, data, ifMatch, ifNoneMatch }) => {
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
        this.docs.set(id, {
          version: (existing?.version ?? 0) + 1,
          updatedAt: this.nextUpdatedAt(),
          deleted: false,
          data
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
          data: doc.data
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
    synced: { schema: syncedDocSchema() }
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
