/**
 * Cross-replica round-trip conformance: the two WAS sync engines against a
 * real server.
 *
 * DCW (the mobile wallet) replicates with `@interop/wallet-core/sync`'s
 * `SyncEngine`; this wallet replicates with its own RxDB adapter
 * (`src/lib/sync/`). They are two independent implementations of one wire
 * protocol, written to agree, and this exercise is the proof that they do:
 * both replicas attach to the SAME Space on a real in-process
 * `was-teaching-server` (no fakes anywhere on the wire) and round-trip
 * create / edit / delete in both directions, including an edit collision,
 * across all three id/mutation models -- `contacts` (mutable head),
 * `private-credentials` (content-addressed, immutable), `contacts-history`
 * (append-only).
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
 * RxDB. Both replicas now build the contacts cipher per the spec
 * (`idDerivation: 'random'`), key the row with the cipher-minted EDV id, and
 * update in place via `encryptUpdate` -- and both must keep tolerating what
 * the LEGACY freewallet paths left on servers: uuidv7 resource ids and
 * `sequence: 0` at any revision (fresh `cipher.encrypt` on every save). A
 * dedicated legacy-row test covers that tail.
 *
 * Divergences this exercise pins down (see
 * `wallet-core/docs/cross-replica-sync-compatibility.md` for the written
 * contract):
 * - EDV `sequence` stays advisory on the wire: legacy freewallet envelopes are
 *   `sequence: 0` whatever the revision count, and an updater must advance
 *   from whatever it finds. The server ETag `version` is the enforced
 *   concurrency control.
 * - Legacy uuid resource ids stay first-class on the update path: was-client
 *   accepts a pre-existing id verbatim when a `current` envelope is supplied
 *   (the id is already on the server, so the URL-leak guard only covers
 *   creates).
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

import {
  createWasReplication,
  syncedDocMigrationStrategies,
  syncedDocSchema
} from '../../src/lib/sync'
import type {
  SyncedDoc,
  WasSyncPort as FwWasSyncPort
} from '../../src/lib/sync/types'
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
import { agentsFromSeed } from '@interop/wallet-core/identity'
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
  updatedAt: string
  deleted: boolean
  data: Json | null
  dirty: boolean
}

/**
 * In-memory `SyncStore` whose reconciliation mirrors dcw's SQLite layer
 * (`app/model/syncedDoc.ts`); the `projection` map stands in for the decrypted
 * read-model rows.
 */
class InMemoryStore implements SyncStore {
  rows = new Map<string, Row>()
  projection = new Map<string, Json>()
  checkpoint: SyncCheckpoint | undefined

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
      .map(({ id, version, updatedAt, deleted, data }) => ({
        id,
        version,
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
          updatedAt: doc.updatedAt
        })
        continue
      }
      this.rows.set(doc.id, {
        id: doc.id,
        version: doc.version,
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
    version
  }: {
    id: string
    version?: number
  }): Promise<void> {
    const row = this.rows.get(id)
    if (!row) {
      return
    }
    this.rows.set(id, {
      ...row,
      dirty: false,
      ...(version !== undefined && { version })
    })
  }

  async markDeletedPushed({
    id,
    version
  }: {
    id: string
    version?: number
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
      ...(version !== undefined && { version })
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
        updatedAt: row?.updatedAt ?? '',
        deleted: true,
        data: null,
        dirty: false
      })
    } else {
      this.rows.set(id, {
        id,
        version: latest.version,
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
    const remoteBody = await cipher.decrypt({ envelope: master.data })
    const remote = isContactHeadPayload(remoteBody) ? remoteBody : null
    const localBody =
      data != null ? await cipher.decrypt({ envelope: data }) : null
    const local =
      localBody != null && isContactHeadPayload(localBody) ? localBody : null

    if (
      remote !== null &&
      (local === null || remotePayloadWins(remote, local))
    ) {
      await store.adoptLatest({
        id,
        latest: master,
        projection: { kind: 'upsert', payload: remoteBody }
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
    store.overwriteDirty(id, master.version, envelope, local.updatedAt)
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
  // same seed -- exactly the property `@interop/wallet-core/identity` exists
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
  // The PRE-FIX freewallet contacts cipher construction (no `idDerivation`, so
  // 'content' mode): used only to author LEGACY rows -- app-minted uuidv7
  // resource id, fresh encrypt each save -- whose tolerance both replicas must
  // keep.
  let fwLegacyContactsCipher: DocCipher
  const fwPorts = {} as Record<CollectionId, WasSyncPort>
  let fwCollections: Record<CollectionId, RxCollection<SyncedDoc>>
  let fwDb: Awaited<ReturnType<typeof createRxDatabase>>

  async function dcwSync(collectionId: CollectionId): Promise<void> {
    const engine = dcwEngines[collectionId]
    await engine.sync()
    if (engine.status === 'error') {
      throw new Error(`dcw engine for "${collectionId}" ended in error`)
    }
  }

  async function fwSync(collectionId: CollectionId): Promise<void> {
    const state = createWasReplication({
      rxCollection: fwCollections[collectionId],
      wasPort: fwPorts[collectionId] as unknown as FwWasSyncPort,
      replicationIdentifier: `conformance:${spaceId}:${collectionId}`,
      live: false
    })
    const errors: unknown[] = []
    const sub = state.error$.subscribe(err => errors.push(err))
    await state.awaitInitialReplication()
    await state.awaitInSync()
    sub.unsubscribe()
    await state.cancel()
    if (errors.length > 0) {
      throw new Error(
        `fw replication for "${collectionId}" errored: ${String(errors[0])}`
      )
    }
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
   * The LEGACY `browserStore.addContact` (pre-fix): app-minted uuidv7 row id,
   * content-mode cipher whose minted id is discarded, fresh encrypt
   * (`sequence: 0`). Authors the rows the legacy-tolerance test edits.
   */
  async function fwAddLegacyContact(
    contact: ContactHeadPayload['contact'],
    writerId: string
  ): Promise<{ id: string; head: ContactHeadPayload }> {
    const id = uuidv7()
    const head: ContactHeadPayload = {
      contactId: uuidv7(),
      updatedAt: new Date().toISOString(),
      writerId,
      contact
    }
    const { envelope } = await fwLegacyContactsCipher.encrypt({
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
    return fwCiphers[collectionId].decrypt({
      envelope: doc.toMutableJSON().data as Json
    })
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
    // The teaching server's own in-process recipe (its test/helpers.ts):
    // filesystem backend in a temp dir, listen on an ephemeral port, then fix
    // up serverUrl to the actual localhost:port.
    const { createApp, FileSystemBackend } = serverModule!
    dataDir = await mkdtemp(path.join(tmpdir(), 'was-conformance-'))
    fastify = createApp({
      serverUrl: 'http://localhost',
      backend: new FileSystemBackend({ dataDir })
    })
    await fastify.listen({ port: 0 })
    const port = (fastify.server.address() as AddressInfo).port
    serverUrl = `http://localhost:${port}`
    fastify.serverUrl = serverUrl

    // Two wallets, one identity: each replica derives its own agents from the
    // shared seed and gets its own WasClient (mirroring wasRemoteStore's
    // codec-bypassing client: a no-op keystore, envelopes move verbatim).
    const dcwAgents = await agentsFromSeed({ seed })
    const fwAgents = await agentsFromSeed({ seed })
    expect(fwAgents.controllerDid).toBe(dcwAgents.controllerDid)
    spaceId = deriveSpaceId(dcwAgents.controllerDid)

    const dcwWas = new WasClient({
      serverUrl,
      zcapClient: dcwAgents.zcapClient,
      encryption: createEdvEncryption({ resolveKeys: async () => null })
    })
    const fwWas = new WasClient({
      serverUrl,
      zcapClient: fwAgents.zcapClient,
      encryption: createEdvEncryption({ resolveKeys: async () => null })
    })

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
    fwLegacyContactsCipher = await createEdvDocCipher({
      keyAgreementKey: fwAgents.keyAgreementKey,
      keyResolver: fwAgents.keyResolver,
      collectionId: CONTACTS_COLLECTION,
      encryption: descriptors[CONTACTS_COLLECTION]
    })

    // Freewallet replica: memory RxDB with the real schema + conflict handler.
    fwDb = await createRxDatabase({
      name: 'conformance-wallet-db',
      storage: getRxStorageMemory(),
      multiInstance: false
    })
    const added = await fwDb.addCollections({
      contacts: {
        schema: syncedDocSchema(),
        migrationStrategies: syncedDocMigrationStrategies(),
        conflictHandler: createContactsConflictHandler({
          getCipher: () => fwCiphers[CONTACTS_COLLECTION]
        })
      },
      contactsHistory: {
        schema: syncedDocSchema(),
        migrationStrategies: syncedDocMigrationStrategies()
      },
      privateCredentials: {
        schema: syncedDocSchema(),
        migrationStrategies: syncedDocMigrationStrategies()
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
        decryptDoc: envelope => cipher.decrypt({ envelope }),
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
        ensureProvisioned: async () => {},
        isMigrated: async () => true,
        runLazyMigration: async () => {},
        stampMigrated: async () => {},
        stampLastSynced: async () => {},
        // No timers in a test: a failed cycle surfaces as status 'error'
        // instead of scheduling a background retry.
        schedule: () => () => {}
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

    // Both replicas now update through `encryptUpdate`: freewallet advanced
    // the DCW-authored envelope's EDV sequence from 0 to 1. (The server ETag
    // `version`, not the sequence, remains the enforced concurrency control;
    // legacy fresh-encrypt envelopes are pinned separately below.)
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
    // round trip; the legacy uuid-id tail is pinned in the next test.
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

  it('DCW in-place edits a LEGACY freewallet contact (uuid row id, sequence-0 envelope)', async () => {
    // Rows authored by the pre-fix freewallet write path live on real servers:
    // an app-minted uuidv7 resource id and a content-mode fresh-encrypt
    // envelope (`sequence: 0` whatever the revision). Both tolerances must
    // hold together on the update path -- was-client takes the pre-existing
    // uuid id verbatim (`current` supplied) and advances the sequence from
    // the legacy envelope's 0.
    const { id: legacyId, head } = await fwAddLegacyContact(
      { displayName: 'Legacy Row' } as ContactHeadPayload['contact'],
      'fw-writer'
    )
    await fwSync(CONTACTS_COLLECTION)
    await dcwSync(CONTACTS_COLLECTION)
    expect(dcwStores[CONTACTS_COLLECTION].projection.get(legacyId)).toEqual(
      head
    )

    const edited = await dcwUpdateContact(
      legacyId,
      {
        displayName: 'Legacy Row (edited on mobile)'
      } as ContactHeadPayload['contact'],
      'dcw-writer'
    )
    await dcwSync(CONTACTS_COLLECTION)
    await fwSync(CONTACTS_COLLECTION)

    const seen = (await fwRead(
      CONTACTS_COLLECTION,
      legacyId
    )) as unknown as ContactHeadPayload
    expect(seen).toEqual(edited)
    // The uuid row was edited in place under its own id, sequence advanced
    // from the legacy envelope's 0.
    const envelope = await serverEnvelope(CONTACTS_COLLECTION, legacyId)
    expect(envelope?.sequence).toBe(1)

    // Leave the board as the delete tests expect: exactly the two standard
    // contact rows.
    await fwDeleteContact(legacyId)
    await fwSync(CONTACTS_COLLECTION)
    await dcwSync(CONTACTS_COLLECTION)
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
