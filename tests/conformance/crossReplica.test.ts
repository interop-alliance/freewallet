/**
 * Cross-replica round-trip conformance: the two WAS sync engines against a
 * real server.
 *
 * DCW (the mobile wallet) replicates with `@interop/wallet-core/sync`'s
 * `SyncEngine`; this wallet replicates with the RxDB driver in
 * `@interop/was-sync`. They are two independent implementations of one wire
 * protocol, written to agree, and this exercise is the proof that they do:
 * both replicas attach to the SAME Space on a real in-process
 * `was-teaching-server` (no fakes anywhere on the wire) and round-trip
 * create / edit / delete in both directions, including an edit collision,
 * across all three id/mutation models -- `contacts` (mutable head),
 * `private-credentials` (content-addressed, immutable), `contacts-history`
 * (append-only).
 *
 * A second block runs a mixed feed under writer attribution: both replicas
 * push under their own `writerId`, beside an unlabeled write, a
 * foreign-labeled one, and tombstones. It checks that the replicas converge
 * with the SyncEngine side suppressing its own echoes, that the feed echoes
 * each writer's label (the deleting writer's on a tombstone), and that
 * suppression skips decrypting only the engine's own held revisions. The
 * engine's suppression on/off matrix is wallet-core's own sync suite's.
 *
 * Each replica is assembled from its app's REAL parts wherever the part is on
 * the compatibility surface: the engine, the port (`createWasSyncPort`), the
 * EDV cipher (`createEdvDocCipher`), the LWW rule (`remotePayloadWins`), and
 * -- for this wallet -- the whole RxDB driver (`createWasReplication`,
 * `syncedDocSchema`, `contactsConflictHandler`). Only the app-local
 * persistence glue is stood in: DCW's SQLite `SyncStore` becomes an in-memory
 * store with the same reconciliation (mirroring `dcw/app/model/syncedDoc.ts`,
 * kept in step with `dcw/test-node/contactsSyncEngine.test.ts`), and this
 * wallet's `BrowserStore` write paths are reproduced verbatim over a memory
 * RxDB. Both replicas build the contacts cipher per the spec
 * (`idDerivation: 'random'`), key the row with the cipher-minted EDV id, and
 * update in place via `encryptUpdate`.
 *
 * Divergences this exercise pins down (see
 * `wallet-core/docs/cross-replica-sync-compatibility.md` for the written
 * contract):
 * - EDV `sequence` stays advisory on the wire: an updater advances from
 *   whatever it finds rather than trusting a count. The server ETag `version`
 *   is the enforced concurrency control.
 * - A resource id is first-class on the update path: was-client accepts a
 *   pre-existing id verbatim when a `current` envelope is supplied (the id is
 *   already on the server, so the URL-leak guard only covers creates).
 *
 * Needs the sibling `../was-teaching-server` checkout built (override with
 * `WAS_SERVER_DIR`). Run: `pnpm run test:conformance`.
 *
 * @vitest-environment node
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { AddressInfo } from 'node:net'

import { createRxDatabase, type RxCollection } from 'rxdb/plugins/core'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { uuidv7 } from 'uuidv7'

import { createWasReplication } from '@interop/was-sync/rxdb'
import {
  syncedDocSchema,
  type SyncedDoc,
  type WasSyncPort as FwWasSyncPort
} from '@interop/was-sync'
import { createContactsConflictHandler } from '../../src/stores/contactsConflictHandler'

import { WasClient, type CollectionEncryption } from '@interop/was-client'
import {
  createEdvDocCipher,
  createEdvEncryption,
  ensureFirstEpoch,
  ownerRecipient,
  type DocCipher
} from '@interop/was-client/edv'
import {
  createWasSyncPort,
  deriveSpaceId,
  ensureSpaceAndCollection
} from '@interop/was-client/sync'
import { SyncEngine } from '@interop/wallet-core/sync'
import type {
  Json,
  MasterState,
  ProjectionAction,
  ResolveConflict,
  SyncCheckpoint,
  SyncStore,
  SyncedRow,
  WasSyncPort,
  WireDoc
} from '@interop/wallet-core/sync'
import { agentsFromSeed } from '@interop/was-client/identity'
import { PRIVATE_CREDENTIALS_COLLECTION } from '@interop/wallet-core/space'
import {
  CONTACTS_COLLECTION,
  CONTACTS_HISTORY_COLLECTION,
  isContactHeadPayload,
  isContactRevisionPayload,
  remotePayloadWins,
  type ContactHeadPayload,
  type ContactRevisionPayload
} from '@interop/social-core'

const dirname = path.dirname(fileURLToPath(import.meta.url))

// --------------------------------------------------------------------------
// The real WAS server, in process (the teaching server's own test idiom)
// --------------------------------------------------------------------------

interface TeachingServer {
  listen(options: { port: number }): Promise<unknown>
  close(): Promise<unknown>
  server: { address(): AddressInfo | string | null }
  serverUrl?: string
}

const serverDir =
  process.env.WAS_SERVER_DIR ??
  path.resolve(dirname, '../../../was-teaching-server')

type ServerModule = {
  createApp(options?: { serverUrl?: string; backend?: unknown }): TeachingServer
  FileSystemBackend: new (options: { dataDir: string }) => unknown
}

/**
 * Starts the teaching server in process: filesystem backend in a temp dir,
 * listen on an ephemeral port, then fix up serverUrl to the actual
 * localhost:port (the teaching server's own test/helpers.ts recipe).
 *
 * @returns {Promise<{ fastify: TeachingServer; serverUrl: string; dataDir: string }>}
 */
async function startTeachingServer(): Promise<{
  fastify: TeachingServer
  serverUrl: string
  dataDir: string
}> {
  const { createApp, FileSystemBackend } = serverModule!
  const dataDir = await mkdtemp(path.join(tmpdir(), 'was-conformance-'))
  const fastify = createApp({
    serverUrl: 'http://localhost',
    backend: new FileSystemBackend({ dataDir })
  })
  await fastify.listen({ port: 0 })
  const port = (fastify.server.address() as AddressInfo).port
  const serverUrl = `http://localhost:${port}`
  fastify.serverUrl = serverUrl
  return { fastify, serverUrl, dataDir }
}

/**
 * A WasClient over one replica's agents, mirroring wasRemoteStore's
 * codec-bypassing client: a no-op keystore, envelopes move verbatim.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param options.zcapClient {object}
 * @returns {WasClient}
 */
function wasClientFor({
  serverUrl,
  zcapClient
}: {
  serverUrl: string
  zcapClient: ConstructorParameters<typeof WasClient>[0]['zcapClient']
}): WasClient {
  return new WasClient({
    serverUrl,
    zcapClient,
    encryption: createEdvEncryption({ resolveKeys: async () => null })
  })
}

/**
 * The SyncEngine lifecycle hooks no conformance case exercises. No timers in
 * a test: a failed cycle surfaces as status 'error' instead of scheduling a
 * background retry.
 */
const NO_OP_ENGINE_LIFECYCLE = {
  ensureProvisioned: async () => {},
  isMigrated: async () => true,
  runLazyMigration: async () => {},
  stampMigrated: async () => {},
  stampLastSynced: async () => {},
  schedule: () => () => {}
}

/**
 * One SyncEngine cycle, throwing when it ends in error.
 *
 * @param options {object}
 * @param options.engine {SyncEngine}
 * @param options.label {string}
 * @returns {Promise<void>}
 */
async function syncEngineOnce({
  engine,
  label
}: {
  engine: SyncEngine
  label: string
}): Promise<void> {
  await engine.sync()
  if (engine.status === 'error') {
    throw new Error(`dcw engine for "${label}" ended in error`)
  }
}

/**
 * One non-live freewallet replication run to in-sync, throwing the first
 * error it emitted.
 *
 * @param options {object}
 * @param options.rxCollection {RxCollection<SyncedDoc>}
 * @param options.wasPort {WasSyncPort}
 * @param options.replicationIdentifier {string}
 * @param [options.writerId] {string}
 * @returns {Promise<void>}
 */
async function replicateFwOnce({
  rxCollection,
  wasPort,
  replicationIdentifier,
  writerId
}: {
  rxCollection: RxCollection<SyncedDoc>
  wasPort: WasSyncPort
  replicationIdentifier: string
  writerId?: string
}): Promise<void> {
  const state = createWasReplication({
    rxCollection,
    wasPort: wasPort as unknown as FwWasSyncPort,
    replicationIdentifier,
    live: false,
    ...(writerId !== undefined && { writerId })
  })
  const errors: unknown[] = []
  const sub = state.error$.subscribe(err => errors.push(err))
  await state.awaitInitialReplication()
  await state.awaitInSync()
  sub.unsubscribe()
  await state.cancel()
  if (errors.length > 0) {
    throw new Error(
      `fw replication "${replicationIdentifier}" errored: ${String(errors[0])}`
    )
  }
}

let serverModule: ServerModule | undefined
try {
  serverModule = (await import(
    pathToFileURL(path.join(serverDir, 'dist', 'index.js')).href
  )) as ServerModule
} catch {
  serverModule = undefined
}

// --------------------------------------------------------------------------
// DCW replica: an in-memory SyncStore with dcw's reconciliation semantics
// --------------------------------------------------------------------------

interface Row {
  id: string
  version: number
  etag?: string
  updatedAt: string
  deleted: boolean
  data: Json | null
  dirty: boolean
}

/**
 * In-memory `SyncStore` whose reconciliation mirrors dcw's SQLite layer
 * (`app/model/syncedDoc.ts`); the `projection` map stands in for the decrypted
 * read-model rows. Each row records the opaque `etag` it was last acked or
 * pulled at, which `heldRevisions` (the engine's own-writer echo check)
 * compares against.
 */
class InMemoryStore implements SyncStore {
  rows = new Map<string, Row>()
  projection = new Map<string, Json>()
  checkpoint: SyncCheckpoint | undefined

  async heldRevisions({
    documents
  }: {
    documents: Array<{ id: string; etag?: string }>
  }): Promise<Set<string>> {
    return new Set(
      documents
        .filter(({ id, etag }) => this.rows.get(id)?.etag === etag)
        .map(({ id }) => id)
    )
  }

  localCreate(id: string, envelope: Json, payload: Json): void {
    this.rows.set(id, {
      id,
      version: 0,
      updatedAt: '',
      deleted: false,
      data: envelope,
      dirty: true
    })
    this.projection.set(id, payload)
  }

  markDirtyUpdate(id: string, envelope: Json, payload: Json): void {
    const row = this.rows.get(id)
    if (!row) {
      throw new Error(`no row ${id}`)
    }
    this.rows.set(id, { ...row, data: envelope, deleted: false, dirty: true })
    this.projection.set(id, payload)
  }

  localDelete(id: string): void {
    const row = this.rows.get(id)
    if (!row) {
      throw new Error(`no row ${id}`)
    }
    this.rows.set(id, { ...row, deleted: true, dirty: true })
    this.projection.delete(id)
  }

  /** The LWW "local newer" settlement: stamp master version, keep dirty. */
  overwriteDirty(
    id: string,
    version: number,
    etag: string | undefined,
    envelope: Json,
    updatedAt: string
  ): void {
    const row = this.rows.get(id)
    if (!row) {
      throw new Error(`no row ${id}`)
    }
    this.rows.set(id, {
      ...row,
      version,
      etag,
      updatedAt,
      data: envelope,
      deleted: false,
      dirty: true
    })
  }

  async getCheckpoint(): Promise<SyncCheckpoint | undefined> {
    return this.checkpoint
  }

  async getDirtyRows(): Promise<SyncedRow[]> {
    return [...this.rows.values()]
      .filter(r => r.dirty)
      .map(({ id, version, etag, updatedAt, deleted, data }) => ({
        id,
        version,
        etag,
        updatedAt,
        deleted,
        data
      }))
  }

  private applyProjection(
    id: string,
    action: ProjectionAction | undefined
  ): void {
    if (!action) {
      return
    }
    if (action.kind === 'upsert') {
      this.projection.set(id, action.payload)
    } else if (action.kind === 'delete') {
      this.projection.delete(id)
    }
  }

  async applyPulledPage({
    documents,
    checkpoint,
    projections
  }: {
    documents: WireDoc[]
    checkpoint: SyncCheckpoint
    projections: Map<string, ProjectionAction>
  }): Promise<void> {
    for (const doc of documents) {
      const existing = this.rows.get(doc.id)
      if (doc._deleted) {
        this.rows.set(doc.id, {
          id: doc.id,
          version: doc.version,
          etag: doc.etag,
          updatedAt: doc.updatedAt,
          deleted: true,
          data: null,
          dirty: false
        })
        this.projection.delete(doc.id)
        continue
      }
      if (existing?.dirty) {
        // Pending live local write: keep the dirty envelope + projection, only
        // refresh version/updatedAt (the push half settles the winner).
        this.rows.set(doc.id, {
          ...existing,
          version: doc.version,
          etag: doc.etag,
          updatedAt: doc.updatedAt
        })
        continue
      }
      this.rows.set(doc.id, {
        id: doc.id,
        version: doc.version,
        etag: doc.etag,
        updatedAt: doc.updatedAt,
        deleted: false,
        data: (doc.data as Json | undefined) ?? null,
        dirty: false
      })
      this.applyProjection(doc.id, projections.get(doc.id))
    }
    this.checkpoint = checkpoint
  }

  async markPushed({
    id,
    version,
    etag
  }: {
    id: string
    version?: number
    etag?: string
  }): Promise<void> {
    const row = this.rows.get(id)
    if (!row) {
      return
    }
    this.rows.set(id, {
      ...row,
      dirty: false,
      ...(version !== undefined && { version }),
      ...(etag !== undefined && { etag })
    })
  }

  async markDeletedPushed({
    id,
    version,
    etag
  }: {
    id: string
    version?: number
    etag?: string
  }): Promise<void> {
    const row = this.rows.get(id)
    if (!row) {
      return
    }
    this.rows.set(id, {
      ...row,
      deleted: true,
      data: null,
      dirty: false,
      ...(version !== undefined && { version }),
      ...(etag !== undefined && { etag })
    })
  }

  async adoptLatest({
    id,
    latest,
    projection
  }: {
    id: string
    latest: MasterState | null
    projection: ProjectionAction
  }): Promise<void> {
    const row = this.rows.get(id)
    if (latest === null) {
      this.rows.set(id, {
        id,
        version: row?.version ?? 0,
        etag: row?.etag,
        updatedAt: row?.updatedAt ?? '',
        deleted: true,
        data: null,
        dirty: false
      })
    } else {
      this.rows.set(id, {
        id,
        version: latest.version,
        etag: latest.etag,
        updatedAt: latest.updatedAt,
        // A non-null MasterState is never a tombstone (the port folds those
        // into `get` resolving null).
        deleted: false,
        data: latest.data ?? row?.data ?? null,
        dirty: false
      })
    }
    this.applyProjection(id, projection)
  }
}

/**
 * DCW's contacts conflict rule (`makeContactResolveConflict` in
 * `app/lib/sync/collections.ts`) over the real port and real cipher: re-read
 * master, run last-write-wins over the decrypted heads, adopt the remote
 * payload or re-encrypt the local one over the master envelope (advancing its
 * `sequence`) and keep it dirty for the next push.
 */
function makeDcwContactResolve({
  store,
  port,
  cipher
}: {
  store: InMemoryStore
  port: WasSyncPort
  cipher: DocCipher
}): ResolveConflict {
  return async ({ id, data }) => {
    const master = await port.get({ id })
    if (master === null) {
      await store.adoptLatest({
        id,
        latest: null,
        projection: { kind: 'delete' }
      })
      return
    }
    if (master.data == null) {
      await store.adoptLatest({
        id,
        latest: master,
        projection: { kind: 'none' }
      })
      return
    }
    const remoteBody = await cipher.decrypt({ id, envelope: master.data })
    const remote = isContactHeadPayload(remoteBody) ? remoteBody : null
    const localBody =
      data != null ? await cipher.decrypt({ id, envelope: data }) : null
    const local =
      localBody != null && isContactHeadPayload(localBody) ? localBody : null

    if (
      remote !== null &&
      (local === null || remotePayloadWins(remote, local))
    ) {
      await store.adoptLatest({
        id,
        latest: master,
        projection: { kind: 'upsert', payload: remoteBody as Json }
      })
      return
    }
    if (local === null) {
      await store.adoptLatest({
        id,
        latest: master,
        projection: { kind: 'none' }
      })
      return
    }
    if (!cipher.encryptUpdate) {
      throw new Error('contacts cipher has no in-place update')
    }
    const { envelope } = await cipher.encryptUpdate({
      id,
      data: local as unknown as Json,
      current: master.data
    })
    store.overwriteDirty(
      id,
      master.version,
      master.etag,
      envelope,
      local.updatedAt
    )
  }
}

// --------------------------------------------------------------------------
// The exercise
// --------------------------------------------------------------------------

const describeConformance = serverModule ? describe : describe.skip
if (!serverModule) {
  console.warn(
    `cross-replica conformance skipped: no built was-teaching-server at ` +
      `"${serverDir}" (set WAS_SERVER_DIR or run its build).`
  )
}

describeConformance('cross-replica round-trip conformance', () => {
  let dataDir: string
  let fastify: TeachingServer
  let serverUrl: string
  let spaceId: string

  // One controller identity, derived independently by each replica from the
  // same seed -- exactly the property `@interop/was-client/identity` exists
  // to guarantee.
  const seed = new Uint8Array(32).fill(7)

  const COLLECTIONS = [
    CONTACTS_COLLECTION,
    CONTACTS_HISTORY_COLLECTION,
    PRIVATE_CREDENTIALS_COLLECTION
  ] as const
  type CollectionId = (typeof COLLECTIONS)[number]

  // DCW replica parts, per collection.
  const dcwCiphers = {} as Record<CollectionId, DocCipher>
  const dcwStores = {} as Record<CollectionId, InMemoryStore>
  const dcwPorts = {} as Record<CollectionId, WasSyncPort>
  const dcwEngines = {} as Record<CollectionId, SyncEngine>

  // Freewallet replica parts.
  const fwCiphers = {} as Record<CollectionId, DocCipher>
  const fwPorts = {} as Record<CollectionId, WasSyncPort>
  let fwCollections: Record<CollectionId, RxCollection<SyncedDoc>>
  let fwDb: Awaited<ReturnType<typeof createRxDatabase>>

  async function dcwSync(collectionId: CollectionId): Promise<void> {
    await syncEngineOnce({
      engine: dcwEngines[collectionId],
      label: collectionId
    })
  }

  async function fwSync(collectionId: CollectionId): Promise<void> {
    await replicateFwOnce({
      rxCollection: fwCollections[collectionId],
      wasPort: fwPorts[collectionId],
      replicationIdentifier: `conformance:${spaceId}:${collectionId}`
    })
  }

  async function syncBoth(collectionId: CollectionId): Promise<void> {
    await dcwSync(collectionId)
    await fwSync(collectionId)
  }

  // ---- freewallet write paths, verbatim from browserStore ----------------

  /** `browserStore.addContact`: cipher-minted random EDV row id, version 0. */
  async function fwAddContact(
    contact: ContactHeadPayload['contact'],
    writerId: string
  ): Promise<{ id: string; head: ContactHeadPayload }> {
    const head: ContactHeadPayload = {
      contactId: uuidv7(),
      updatedAt: new Date().toISOString(),
      writerId,
      contact
    }
    const { id, envelope } = await fwCiphers[CONTACTS_COLLECTION].encrypt({
      data: head as unknown as Json
    })
    await fwCollections[CONTACTS_COLLECTION].insert({
      id,
      updatedAt: head.updatedAt,
      version: 0,
      data: envelope
    } as SyncedDoc)
    return { id, head }
  }

  /**
   * `browserStore.updateContact`: decrypt the existing head, preserve its
   * `contactId`, re-encrypt in place through `encryptUpdate` (the envelope
   * stays bound to the row id and its `sequence` advances from the prior
   * envelope), and patch the row.
   */
  async function fwUpdateContact(
    id: string,
    contact: ContactHeadPayload['contact'],
    writerId: string,
    updatedAt = new Date().toISOString()
  ): Promise<ContactHeadPayload> {
    const doc = await fwCollections[CONTACTS_COLLECTION].findOne(id).exec()
    if (!doc) {
      throw new Error(`no fw contacts row ${id}`)
    }
    const current = doc.toMutableJSON().data as Json
    const existing = (await fwCiphers[CONTACTS_COLLECTION].decrypt({
      id,
      envelope: current
    })) as unknown as ContactHeadPayload
    const head: ContactHeadPayload = {
      contactId: existing.contactId ?? id,
      updatedAt,
      writerId,
      contact
    }
    const { envelope } = await fwCiphers[CONTACTS_COLLECTION].encryptUpdate!({
      id,
      data: head as unknown as Json,
      current
    })
    await doc.incrementalPatch({ updatedAt, data: envelope })
    return head
  }

  /** `browserStore.deleteContact`: soft delete; replication pushes the tombstone. */
  async function fwDeleteContact(id: string): Promise<void> {
    const doc = await fwCollections[CONTACTS_COLLECTION].findOne(id).exec()
    if (!doc) {
      throw new Error(`no fw contacts row ${id}`)
    }
    await doc.remove()
  }

  /**
   * `browserStore.#insertEncrypted` with `contentAddressed: true` (the
   * `private-credentials` / `contacts-history` path): the cipher's minted id
   * (this wallet's ciphers derive it from content) becomes the row id.
   */
  async function fwAddContentDoc(
    collectionId: CollectionId,
    payload: Json
  ): Promise<string> {
    const { id, envelope } = await fwCiphers[collectionId].encrypt({
      data: payload
    })
    await fwCollections[collectionId].insert({
      id,
      updatedAt: new Date().toISOString(),
      version: 0,
      data: envelope
    } as SyncedDoc)
    return id
  }

  /** Decrypted view of a freewallet row (undefined when absent or deleted). */
  async function fwRead(
    collectionId: CollectionId,
    id: string
  ): Promise<Json | undefined> {
    const doc = await fwCollections[collectionId].findOne(id).exec()
    if (!doc || doc.deleted) {
      return undefined
    }
    // Every collection here is JSON; `decrypt` widened to `Json | Blob` for
    // the chunked-document case, which none of these exercise.
    return (await fwCiphers[collectionId].decrypt({
      id,
      envelope: doc.toMutableJSON().data as Json
    })) as Json
  }

  // ---- dcw write paths (syncManager's encrypt* helpers over the store) ---

  async function dcwAddContact(
    contact: ContactHeadPayload['contact'],
    writerId: string,
    updatedAt = new Date().toISOString()
  ): Promise<{ id: string; head: ContactHeadPayload }> {
    const head: ContactHeadPayload = {
      contactId: uuidv7(),
      updatedAt,
      writerId,
      contact
    }
    const { id, envelope } = await dcwCiphers[CONTACTS_COLLECTION].encrypt({
      data: head as unknown as Json
    })
    dcwStores[CONTACTS_COLLECTION].localCreate(
      id,
      envelope,
      head as unknown as Json
    )
    return { id, head }
  }

  /** `syncManager.encryptContactHeadUpdate`: in-place `encryptUpdate`. */
  async function dcwUpdateContact(
    id: string,
    contact: ContactHeadPayload['contact'],
    writerId: string,
    updatedAt = new Date().toISOString()
  ): Promise<ContactHeadPayload> {
    const store = dcwStores[CONTACTS_COLLECTION]
    const row = store.rows.get(id)
    if (!row?.data) {
      throw new Error(`no dcw contacts row ${id}`)
    }
    const cipher = dcwCiphers[CONTACTS_COLLECTION]
    const existing = (await cipher.decrypt({
      id,
      envelope: row.data
    })) as unknown as ContactHeadPayload
    const head: ContactHeadPayload = {
      contactId: existing.contactId ?? id,
      updatedAt,
      writerId,
      contact
    }
    if (!cipher.encryptUpdate) {
      throw new Error('no encryptUpdate')
    }
    const { envelope } = await cipher.encryptUpdate({
      id,
      data: head as unknown as Json,
      current: row.data
    })
    store.markDirtyUpdate(id, envelope, head as unknown as Json)
    return head
  }

  async function dcwAddContentDoc(
    collectionId: CollectionId,
    payload: Json
  ): Promise<string> {
    const { id, envelope } = await dcwCiphers[collectionId].encrypt({
      data: payload
    })
    dcwStores[collectionId].localCreate(id, envelope, payload)
    return id
  }

  /** The raw server-side envelope for one resource (sequence inspection). */
  async function serverEnvelope(
    collectionId: CollectionId,
    id: string
  ): Promise<{ sequence?: number } | null> {
    const master = await dcwPorts[collectionId].get({ id })
    return (master?.data as { sequence?: number } | undefined) ?? null
  }

  beforeAll(async () => {
    ;({ fastify, serverUrl, dataDir } = await startTeachingServer())

    // Two wallets, one identity: each replica derives its own agents from the
    // shared seed and gets its own WasClient.
    const dcwAgents = await agentsFromSeed({ seed })
    const fwAgents = await agentsFromSeed({ seed })
    expect(fwAgents.controllerDid).toBe(dcwAgents.controllerDid)
    spaceId = deriveSpaceId(dcwAgents.controllerDid)

    const dcwWas = wasClientFor({
      serverUrl,
      zcapClient: dcwAgents.zcapClient
    })
    const fwWas = wasClientFor({ serverUrl, zcapClient: fwAgents.zcapClient })

    // Freewallet created the account; DCW attaches without re-provisioning.
    // The provisioning two-step: declare each collection encrypted, then
    // install its key epoch[0] (create-if-absent) wrapped to the account KAK
    // -- every encrypted collection carries its epochs from birth, and the
    // ciphers below refuse to build without a descriptor.
    const descriptors: Record<string, CollectionEncryption> = {}
    for (const collectionId of COLLECTIONS) {
      await ensureSpaceAndCollection({
        was: fwWas,
        spaceId,
        controllerDid: fwAgents.controllerDid,
        collectionId,
        encryption: 'edv'
      })
      const { descriptor } = await ensureFirstEpoch({
        collection: fwWas.space(spaceId).collection(collectionId),
        recipients: [
          ownerRecipient({ keyAgreementKey: fwAgents.keyAgreementKey })
        ]
      })
      descriptors[collectionId] = descriptor
    }

    // Ciphers: each app's REAL construction -- both now pass the collection
    // spec's idDerivation ('random' for the mutable contacts head, 'content'
    // for the content-addressed collections) plus the collection's
    // epoch-bearing descriptor; freewallet wires both through
    // `storageManager.#buildCiphers` from `WALLET_STANDARD_COLLECTIONS`.
    for (const collectionId of COLLECTIONS) {
      dcwCiphers[collectionId] = await createEdvDocCipher({
        keyAgreementKey: dcwAgents.keyAgreementKey,
        keyResolver: dcwAgents.keyResolver,
        collectionId,
        idDerivation:
          collectionId === CONTACTS_COLLECTION ? 'random' : 'content',
        encryption: descriptors[collectionId]
      })
      fwCiphers[collectionId] = await createEdvDocCipher({
        keyAgreementKey: fwAgents.keyAgreementKey,
        keyResolver: fwAgents.keyResolver,
        collectionId,
        idDerivation:
          collectionId === CONTACTS_COLLECTION ? 'random' : 'content',
        encryption: descriptors[collectionId]
      })
      dcwPorts[collectionId] = createWasSyncPort({
        was: dcwWas,
        spaceId,
        collectionId
      })
      fwPorts[collectionId] = createWasSyncPort({
        was: fwWas,
        spaceId,
        collectionId
      })
    }
    // Freewallet replica: memory RxDB with the real schema + conflict handler.
    fwDb = await createRxDatabase({
      name: 'conformance-wallet-db',
      storage: getRxStorageMemory(),
      multiInstance: false
    })
    const added = await fwDb.addCollections({
      contacts: {
        schema: syncedDocSchema(),
        conflictHandler: createContactsConflictHandler({
          getCipher: () => fwCiphers[CONTACTS_COLLECTION]
        })
      },
      contactsHistory: {
        schema: syncedDocSchema()
      },
      privateCredentials: {
        schema: syncedDocSchema()
      }
    })
    fwCollections = {
      [CONTACTS_COLLECTION]: added.contacts as RxCollection<SyncedDoc>,
      [CONTACTS_HISTORY_COLLECTION]:
        added.contactsHistory as RxCollection<SyncedDoc>,
      [PRIVATE_CREDENTIALS_COLLECTION]:
        added.privateCredentials as RxCollection<SyncedDoc>
    }

    // DCW replica: SyncEngine per collection over the in-memory store.
    for (const collectionId of COLLECTIONS) {
      const store = new InMemoryStore()
      dcwStores[collectionId] = store
      const cipher = dcwCiphers[collectionId]
      const port = dcwPorts[collectionId]
      dcwEngines[collectionId] = new SyncEngine({
        port,
        store,
        decryptDoc: async ({ id, envelope }) =>
          (await cipher.decrypt({ id, envelope })) as Json,
        validatePayload:
          collectionId === CONTACTS_COLLECTION
            ? isContactHeadPayload
            : collectionId === CONTACTS_HISTORY_COLLECTION
              ? isContactRevisionPayload
              : undefined,
        resolveConflict:
          collectionId === CONTACTS_COLLECTION
            ? makeDcwContactResolve({ store, port, cipher })
            : undefined,
        ...NO_OP_ENGINE_LIFECYCLE
      })
    }
  })

  afterAll(async () => {
    for (const engine of Object.values(dcwEngines)) {
      engine.stop()
    }
    await fwDb?.close()
    await fastify?.close()
    if (dataDir) {
      await rm(dataDir, { recursive: true, force: true })
    }
  })

  // ---- contacts: the mutable head --------------------------------------

  let dcwAuthoredId: string
  let fwAuthoredId: string

  it('round-trips a DCW-authored contact to freewallet', async () => {
    const { id, head } = await dcwAddContact(
      { displayName: 'Ada Lovelace' } as ContactHeadPayload['contact'],
      'dcw-writer'
    )
    dcwAuthoredId = id
    await dcwSync(CONTACTS_COLLECTION)
    await fwSync(CONTACTS_COLLECTION)

    const seen = (await fwRead(
      CONTACTS_COLLECTION,
      id
    )) as unknown as ContactHeadPayload
    expect(seen).toBeDefined()
    expect(seen).toEqual(head)
  })

  it('round-trips a freewallet-authored contact to DCW', async () => {
    const { id, head } = await fwAddContact(
      { displayName: 'Grace Hopper' } as ContactHeadPayload['contact'],
      'fw-writer'
    )
    fwAuthoredId = id
    await fwSync(CONTACTS_COLLECTION)
    await dcwSync(CONTACTS_COLLECTION)

    expect(dcwStores[CONTACTS_COLLECTION].projection.get(id)).toEqual(head)
  })

  it('applies a freewallet edit of the DCW-authored contact in place (sequence advances)', async () => {
    const head = await fwUpdateContact(
      dcwAuthoredId,
      {
        displayName: 'Ada Lovelace (edited on web)'
      } as ContactHeadPayload['contact'],
      'fw-writer'
    )
    await fwSync(CONTACTS_COLLECTION)
    await dcwSync(CONTACTS_COLLECTION)

    // DCW applied the edit in place: same row id, no second row.
    expect(
      dcwStores[CONTACTS_COLLECTION].projection.get(dcwAuthoredId)
    ).toEqual(head)
    const contactRows = [
      ...dcwStores[CONTACTS_COLLECTION].rows.values()
    ].filter(r => !r.deleted)
    expect(contactRows).toHaveLength(2) // dcw-authored + fw-authored, no dupes

    // Both replicas update through `encryptUpdate`: freewallet advanced the
    // DCW-authored envelope's EDV sequence from 0 to 1. (The server ETag
    // `version`, not the sequence, remains the enforced concurrency control.)
    const envelope = await serverEnvelope(CONTACTS_COLLECTION, dcwAuthoredId)
    expect(envelope?.sequence).toBe(1)
  })

  it('applies a DCW in-place edit over the freewallet envelope (sequence advances) back to freewallet', async () => {
    const head = await dcwUpdateContact(
      dcwAuthoredId,
      {
        displayName: 'Ada Lovelace (edited on mobile)'
      } as ContactHeadPayload['contact'],
      'dcw-writer'
    )
    await dcwSync(CONTACTS_COLLECTION)

    // DCW's encryptUpdate advanced the sequence from freewallet's envelope:
    // the two implementations agree on the update convention.
    const envelope = await serverEnvelope(CONTACTS_COLLECTION, dcwAuthoredId)
    expect(envelope?.sequence).toBe(2)

    await fwSync(CONTACTS_COLLECTION)
    const seen = (await fwRead(
      CONTACTS_COLLECTION,
      dcwAuthoredId
    )) as unknown as ContactHeadPayload
    expect(seen).toEqual(head)
  })

  it('converges an edit collision to the LWW winner on both replicas (DCW newer)', async () => {
    const base = Date.now()
    // Freewallet edits first (older timestamp) and syncs first, taking the
    // server; DCW's competing edit (newer) then hits a version conflict.
    const fwHead = await fwUpdateContact(
      dcwAuthoredId,
      {
        displayName: 'Ada Lovelace (web edit)'
      } as ContactHeadPayload['contact'],
      'fw-writer',
      new Date(base).toISOString()
    )
    const dcwHead = await dcwUpdateContact(
      dcwAuthoredId,
      {
        displayName: 'Ada Lovelace (mobile edit)'
      } as ContactHeadPayload['contact'],
      'dcw-writer',
      new Date(base + 60_000).toISOString()
    )
    expect(remotePayloadWins(dcwHead, fwHead)).toBe(true)

    await fwSync(CONTACTS_COLLECTION)
    // Cycle 1: DCW's push conflicts, the LWW rule keeps the newer local edit
    // dirty over the adopted master; cycle 2 pushes it clean.
    await dcwSync(CONTACTS_COLLECTION)
    await dcwSync(CONTACTS_COLLECTION)
    await fwSync(CONTACTS_COLLECTION)

    expect(
      dcwStores[CONTACTS_COLLECTION].projection.get(dcwAuthoredId)
    ).toEqual(dcwHead)
    const fwSeen = (await fwRead(
      CONTACTS_COLLECTION,
      dcwAuthoredId
    )) as unknown as ContactHeadPayload
    expect(fwSeen).toEqual(dcwHead)

    // No duplicate row materialized on either side.
    expect(
      [...dcwStores[CONTACTS_COLLECTION].rows.values()].filter(r => !r.deleted)
    ).toHaveLength(2)
    expect(await fwCollections[CONTACTS_COLLECTION].find().exec()).toHaveLength(
      2
    )
  })

  it('converges an edit collision to the LWW winner on both replicas (freewallet newer)', async () => {
    const base = Date.now()
    const dcwHead = await dcwUpdateContact(
      dcwAuthoredId,
      {
        displayName: 'Ada Lovelace (older mobile edit)'
      } as ContactHeadPayload['contact'],
      'dcw-writer',
      new Date(base).toISOString()
    )
    const fwHead = await fwUpdateContact(
      dcwAuthoredId,
      {
        displayName: 'Ada Lovelace (newer web edit)'
      } as ContactHeadPayload['contact'],
      'fw-writer',
      new Date(base + 60_000).toISOString()
    )
    expect(remotePayloadWins(fwHead, dcwHead)).toBe(true)

    // DCW takes the server first this time; freewallet's push conflicts and
    // its conflict handler (remotePayloadWins over decrypted heads) keeps the
    // newer local edit for the retry push.
    await dcwSync(CONTACTS_COLLECTION)
    await fwSync(CONTACTS_COLLECTION)
    await dcwSync(CONTACTS_COLLECTION)

    expect(
      dcwStores[CONTACTS_COLLECTION].projection.get(dcwAuthoredId)
    ).toEqual(fwHead)
    const fwSeen = (await fwRead(
      CONTACTS_COLLECTION,
      dcwAuthoredId
    )) as unknown as ContactHeadPayload
    expect(fwSeen).toEqual(fwHead)
  })

  it('round-trips a DCW in-place edit of a freewallet-authored contact (the once-pinned defect)', async () => {
    // Formerly pinned as an open defect: freewallet minted uuidv7 row ids that
    // failed was-client's `assertDocId` multibase check, so DCW's
    // `encryptUpdate` refused every web-authored contact. Fixed from both
    // ends -- freewallet's contacts rows are now keyed by the cipher-minted
    // EDV id (spec `idDerivation: 'random'`), and was-client's update path
    // accepts a pre-existing resource id verbatim. This exercises the edit
    // round trip.
    const head = await dcwUpdateContact(
      fwAuthoredId,
      {
        displayName: 'Grace Hopper (mobile edit)'
      } as ContactHeadPayload['contact'],
      'dcw-writer'
    )
    await dcwSync(CONTACTS_COLLECTION)
    await fwSync(CONTACTS_COLLECTION)

    const seen = (await fwRead(
      CONTACTS_COLLECTION,
      fwAuthoredId
    )) as unknown as ContactHeadPayload
    expect(seen).toEqual(head)
    // In place: still exactly the two contact rows on both replicas.
    expect(
      [...dcwStores[CONTACTS_COLLECTION].rows.values()].filter(r => !r.deleted)
    ).toHaveLength(2)
    expect(await fwCollections[CONTACTS_COLLECTION].find().exec()).toHaveLength(
      2
    )
  })

  it('propagates a freewallet delete to DCW', async () => {
    // Pull first so the collision win's acked version has round-tripped:
    // `pushWrites` deliberately does not consume the write's ETag, and a
    // delete pushed against the stale assumed version 412s -- at which point
    // the contacts conflict handler's tombstone fallback keeps the live
    // master and the delete is silently dropped (a real, pinned-down
    // property; see the compatibility contract). The live app's poll loop
    // closes this window on its own.
    await fwSync(CONTACTS_COLLECTION)
    await fwDeleteContact(dcwAuthoredId)
    await fwSync(CONTACTS_COLLECTION)
    await dcwSync(CONTACTS_COLLECTION)

    expect(
      dcwStores[CONTACTS_COLLECTION].projection.get(dcwAuthoredId)
    ).toBeUndefined()
    expect(
      dcwStores[CONTACTS_COLLECTION].rows.get(dcwAuthoredId)?.deleted
    ).toBe(true)
  })

  it('propagates a DCW delete to freewallet', async () => {
    dcwStores[CONTACTS_COLLECTION].localDelete(fwAuthoredId)
    await dcwSync(CONTACTS_COLLECTION)
    await fwSync(CONTACTS_COLLECTION)

    expect(await fwRead(CONTACTS_COLLECTION, fwAuthoredId)).toBeUndefined()
  })

  // ---- private-credentials: content-addressed, immutable ----------------

  it('round-trips private credentials in both directions', async () => {
    const dcwVc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      credentialSubject: { id: 'did:example:alice', name: 'Alice' }
    } as unknown as Json
    const fwVc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      credentialSubject: { id: 'did:example:bob', name: 'Bob' }
    } as unknown as Json

    const dcwMintedId = await dcwAddContentDoc(
      PRIVATE_CREDENTIALS_COLLECTION,
      dcwVc
    )
    const fwMintedId = await fwAddContentDoc(
      PRIVATE_CREDENTIALS_COLLECTION,
      fwVc
    )
    await syncBoth(PRIVATE_CREDENTIALS_COLLECTION)
    await syncBoth(PRIVATE_CREDENTIALS_COLLECTION)

    expect(await fwRead(PRIVATE_CREDENTIALS_COLLECTION, dcwMintedId)).toEqual(
      dcwVc
    )
    expect(
      dcwStores[PRIVATE_CREDENTIALS_COLLECTION].projection.get(fwMintedId)
    ).toEqual(fwVc)
  })

  // ---- contacts-history: append-only ------------------------------------

  it('appends contact revisions from both replicas and converges', async () => {
    const contactId = uuidv7()
    const dcwRevision: ContactRevisionPayload = {
      contactId,
      action: 'create',
      timestamp: new Date().toISOString(),
      writerId: 'dcw-writer',
      snapshot: { displayName: 'Rev from mobile' }
    }
    const fwRevision: ContactRevisionPayload = {
      contactId,
      action: 'update',
      timestamp: new Date(Date.now() + 1_000).toISOString(),
      writerId: 'fw-writer',
      snapshot: { displayName: 'Rev from web' }
    }

    const dcwRevId = await dcwAddContentDoc(
      CONTACTS_HISTORY_COLLECTION,
      dcwRevision as unknown as Json
    )
    const fwRevId = await fwAddContentDoc(
      CONTACTS_HISTORY_COLLECTION,
      fwRevision as unknown as Json
    )
    await syncBoth(CONTACTS_HISTORY_COLLECTION)
    await syncBoth(CONTACTS_HISTORY_COLLECTION)

    expect(await fwRead(CONTACTS_HISTORY_COLLECTION, dcwRevId)).toEqual(
      dcwRevision
    )
    expect(
      dcwStores[CONTACTS_HISTORY_COLLECTION].projection.get(fwRevId)
    ).toEqual(fwRevision)
  })
})

// --------------------------------------------------------------------------
// Writer attribution: a mixed feed under echo suppression
// --------------------------------------------------------------------------

describeConformance('cross-replica writer attribution', () => {
  const DCW_WRITER_ID = 'dcw-writer'
  const FW_WRITER_ID = 'fw-writer'
  const FOREIGN_WRITER_ID = 'foreign-writer'
  const collectionId = PRIVATE_CREDENTIALS_COLLECTION

  let fastify: TeachingServer
  let dataDir: string
  let spaceId: string
  let dcwCipher: DocCipher
  let fwCipher: DocCipher
  let fwPort: WasSyncPort
  let thirdPort: WasSyncPort
  let dcwStore: InMemoryStore
  let dcwEngine: SyncEngine
  let fwDb: Awaited<ReturnType<typeof createRxDatabase>>
  let fwCollection: RxCollection<SyncedDoc>
  // Every id the SyncEngine side's pull handed to its decrypt.
  const dcwDecrypted: string[] = []

  async function dcwSync(): Promise<void> {
    await syncEngineOnce({ engine: dcwEngine, label: collectionId })
  }

  async function fwSync(): Promise<void> {
    await replicateFwOnce({
      rxCollection: fwCollection,
      wasPort: fwPort,
      replicationIdentifier: `conformance:${spaceId}:${collectionId}`,
      writerId: FW_WRITER_ID
    })
  }

  /**
   * The whole changes feed from the start, as `id to WireDoc`.
   *
   * @returns {Promise<Map<string, WireDoc>>}
   */
  async function readFeed(): Promise<Map<string, WireDoc>> {
    const feed = new Map<string, WireDoc>()
    let checkpoint: SyncCheckpoint | undefined
    for (;;) {
      const page = await thirdPort.query({ checkpoint, limit: 100 })
      for (const doc of page.documents) {
        feed.set(doc.id, doc)
      }
      if (page.checkpoint === null || page.documents.length === 0) {
        return feed
      }
      checkpoint = page.checkpoint
    }
  }

  /**
   * Writes a credential through a third writer that is neither replica,
   * straight onto the port, declaring `writerId` or no label at all.
   *
   * @param options {object}
   * @param options.payload {Json}
   * @param [options.writerId] {string}
   * @returns {Promise<string>}
   */
  async function thirdWriterPut({
    payload,
    writerId
  }: {
    payload: Json
    writerId?: string
  }): Promise<string> {
    const { id, envelope } = await dcwCipher.encrypt({ data: payload })
    await thirdPort.putContent({
      id,
      data: envelope,
      ifNoneMatch: true,
      ...(writerId !== undefined && { writerId })
    })
    return id
  }

  /**
   * A minimal credential body, distinct per `name`.
   *
   * @param name {string}
   * @returns {Json}
   */
  function credential(name: string): Json {
    return {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      credentialSubject: { id: `did:example:${name}`, name }
    } as unknown as Json
  }

  /**
   * dcw's content-addressed write path: a dirty local row keyed by the
   * cipher-minted id.
   *
   * @param name {string}
   * @returns {Promise<string>} The row id.
   */
  async function dcwAddCredential(name: string): Promise<string> {
    const payload = credential(name)
    const { id, envelope } = await dcwCipher.encrypt({ data: payload })
    dcwStore.localCreate(id, envelope, payload)
    return id
  }

  /**
   * `browserStore.#insertEncrypted` with `contentAddressed: true`.
   *
   * @param name {string}
   * @returns {Promise<string>} The row id.
   */
  async function fwAddCredential(name: string): Promise<string> {
    const { id, envelope } = await fwCipher.encrypt({
      data: credential(name)
    })
    await fwCollection.insert({
      id,
      updatedAt: new Date().toISOString(),
      version: 0,
      data: envelope
    } as SyncedDoc)
    return id
  }

  /**
   * Decrypted view of a freewallet row (undefined when absent or deleted).
   *
   * @param id {string}
   * @returns {Promise<Json | undefined>}
   */
  async function fwRead(id: string): Promise<Json | undefined> {
    const doc = await fwCollection.findOne(id).exec()
    if (!doc || doc.deleted) {
      return undefined
    }
    return (await fwCipher.decrypt({
      id,
      envelope: doc.toMutableJSON().data as Json
    })) as Json
  }

  beforeAll(async () => {
    let serverUrl: string
    ;({ fastify, serverUrl, dataDir } = await startTeachingServer())

    // Each case starts its own server, so a fixed seed still gives each
    // case its own Space and feed.
    const seed = new Uint8Array(32).fill(11)
    const dcwAgents = await agentsFromSeed({ seed })
    const fwAgents = await agentsFromSeed({ seed })
    spaceId = deriveSpaceId(dcwAgents.controllerDid)
    const dcwWas = wasClientFor({
      serverUrl,
      zcapClient: dcwAgents.zcapClient
    })
    const fwWas = wasClientFor({ serverUrl, zcapClient: fwAgents.zcapClient })

    await ensureSpaceAndCollection({
      was: fwWas,
      spaceId,
      controllerDid: fwAgents.controllerDid,
      collectionId,
      encryption: 'edv'
    })
    const { descriptor } = await ensureFirstEpoch({
      collection: fwWas.space(spaceId).collection(collectionId),
      recipients: [
        ownerRecipient({ keyAgreementKey: fwAgents.keyAgreementKey })
      ]
    })
    dcwCipher = await createEdvDocCipher({
      keyAgreementKey: dcwAgents.keyAgreementKey,
      keyResolver: dcwAgents.keyResolver,
      collectionId,
      idDerivation: 'content',
      encryption: descriptor
    })
    fwCipher = await createEdvDocCipher({
      keyAgreementKey: fwAgents.keyAgreementKey,
      keyResolver: fwAgents.keyResolver,
      collectionId,
      idDerivation: 'content',
      encryption: descriptor
    })
    const dcwPort = createWasSyncPort({ was: dcwWas, spaceId, collectionId })
    fwPort = createWasSyncPort({ was: fwWas, spaceId, collectionId })
    // The third writer is told apart by its label alone, so it can share
    // dcw's client.
    thirdPort = createWasSyncPort({ was: dcwWas, spaceId, collectionId })

    fwDb = await createRxDatabase({
      name: 'conformance-writer-attribution',
      storage: getRxStorageMemory(),
      multiInstance: false
    })
    const added = await fwDb.addCollections({
      privateCredentials: { schema: syncedDocSchema() }
    })
    fwCollection = added.privateCredentials as RxCollection<SyncedDoc>

    dcwStore = new InMemoryStore()
    dcwEngine = new SyncEngine({
      port: dcwPort,
      store: dcwStore,
      decryptDoc: async ({ id, envelope }) => {
        dcwDecrypted.push(id)
        return (await dcwCipher.decrypt({ id, envelope })) as Json
      },
      writerId: DCW_WRITER_ID,
      ...NO_OP_ENGINE_LIFECYCLE
    })
  })

  afterAll(async () => {
    dcwEngine?.stop()
    await fwDb?.close()
    await fastify?.close()
    if (dataDir) {
      await rm(dataDir, { recursive: true, force: true })
    }
  })

  it('converges a mixed feed and echoes each writer label', async () => {
    // Both replicas write with their own labels; a third writer adds one
    // unlabeled and one foreign-labeled credential.
    const dcwKept = await dcwAddCredential('dcw-kept')
    const dcwDeleted = await dcwAddCredential('dcw-deleted')
    const fwKept = await fwAddCredential('fw-kept')
    const fwDeleted = await fwAddCredential('fw-deleted')
    const unlabeled = await thirdWriterPut({
      payload: credential('unlabeled')
    })
    const foreign = await thirdWriterPut({
      payload: credential('foreign'),
      writerId: FOREIGN_WRITER_ID
    })

    await dcwSync()
    await fwSync()
    await dcwSync()
    await fwSync()

    // Each replica deletes one of the other's credentials: a tombstone per
    // deleting writer.
    dcwStore.localDelete(fwDeleted)
    const fwDoc = await fwCollection.findOne(dcwDeleted).exec()
    if (!fwDoc) {
      throw new Error(`no fw row ${dcwDeleted}`)
    }
    await fwDoc.remove()

    await dcwSync()
    await fwSync()
    await dcwSync()
    await fwSync()

    // (a) Both replicas hold identical content.
    const live = {
      [dcwKept]: credential('dcw-kept'),
      [fwKept]: credential('fw-kept'),
      [unlabeled]: credential('unlabeled'),
      [foreign]: credential('foreign')
    }
    for (const [id, payload] of Object.entries(live)) {
      expect(dcwStore.projection.get(id)).toEqual(payload)
      expect(await fwRead(id)).toEqual(payload)
    }
    for (const id of [dcwDeleted, fwDeleted]) {
      expect(dcwStore.projection.has(id)).toBe(false)
      expect(dcwStore.rows.get(id)?.deleted).toBe(true)
      expect(await fwRead(id)).toBeUndefined()
    }
    expect([...dcwStore.projection.keys()].sort()).toEqual(
      Object.keys(live).sort()
    )

    // (b) The feed carries each writer's own label, a tombstone carrying
    // the deleting writer's, and no label where none was declared.
    const feed = await readFeed()
    expect(feed.get(dcwKept)?.writerId).toBe(DCW_WRITER_ID)
    expect(feed.get(fwKept)?.writerId).toBe(FW_WRITER_ID)
    expect(feed.get(unlabeled)?.writerId).toBeUndefined()
    expect(feed.get(foreign)?.writerId).toBe(FOREIGN_WRITER_ID)
    expect(feed.get(fwDeleted)?._deleted).toBe(true)
    expect(feed.get(fwDeleted)?.writerId).toBe(DCW_WRITER_ID)
    expect(feed.get(dcwDeleted)?._deleted).toBe(true)
    expect(feed.get(dcwDeleted)?.writerId).toBe(FW_WRITER_ID)

    // (c) The engine never decrypted the echoes of its own held writes,
    // and decrypted every other live document.
    for (const id of [fwKept, unlabeled, foreign]) {
      expect(dcwDecrypted).toContain(id)
    }
    for (const id of [dcwKept, dcwDeleted]) {
      expect(dcwDecrypted).not.toContain(id)
    }
  })
})
