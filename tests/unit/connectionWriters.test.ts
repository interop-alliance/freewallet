// @vitest-environment node
/**
 * The `connections` directory's writer arm bindings
 * (`src/session/connectionWriters.ts`, and the writer-sweep encounter site in
 * `src/session/menders/encounterSites.ts`).
 *
 * - Registration runs on a remembered session only. The first session writes
 *   the first-seen record and leaves the directory alone, and a second
 *   session registers this client's writer on its own entry. A transient
 *   session writes nothing.
 * - An entry a forget left retired, torn before its removal entry, is
 *   un-retired while the document still lists this client, whatever the
 *   second-session rule and the touch interval say.
 * - The writer sweep runs at the directory listing read, through the
 *   encounter runner. Its entries reach the page's report and the event
 *   channel, and `session.mends` does not carry them.
 *
 * The directory logic in `@interop/wallet-core/connections` is real, over an
 * in-memory store; the account context, the verified log, and the document's
 * signing keys are doubles.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'

const CLIENT_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const CLIENT_KEY = CLIENT_DID.slice('did:key:'.length)
const ACCOUNT_DID = 'did:webvh:QmScid:was.example:space:s'
const POINTER = {
  did: ACCOUNT_DID,
  spaceUrl: 'https://was.example/space/s/'
}
const DAY_MS = 24 * 60 * 60 * 1000

const state = vi.hoisted(() => ({
  enrolled: true,
  listed: true
}))

vi.mock('@/session/accountCeremonyContext', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@/session/accountCeremonyContext')
  >()),
  enrolledCeremonyContext: vi.fn(() =>
    state.enrolled
      ? { kind: 'enrolled', pointer: POINTER, keyAgent: { id: CLIENT_DID } }
      : null
  ),
  accountCeremonyContext: vi.fn(async () =>
    state.enrolled ? { kind: 'enrolled', pointer: POINTER } : null
  )
}))

vi.mock('@/session/verifiedLog', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/verifiedLog')>()),
  verifiedAccountLog: vi.fn(async () => ({}))
}))

vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  currentAccountSigningKeys: vi.fn(async () =>
    state.listed ? new Set([CLIENT_KEY]) : new Set<string>()
  )
}))

const {
  connectionResourceId,
  parseConnectionEntry,
  recordGrants,
  retireConnection
} = await import('@interop/wallet-core/connections')
const { registerOwnConnectionWriter } =
  await import('@/session/connectionWriters')
const { connectionWritersMend } =
  await import('@/session/menders/encounterSites')
const { readDirectoryEntries } = await import('@/session/clients')
const {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores
} = await import('@/session/persistence')
const { sessionDisposalSignal } = await import('@/session/sessionLifecycle')
const { HMAC_KEY, memoryConnectionsStore } = await import('./memoryConnections')
const { createFakeSessionIdb } = await import('./fakeSessionIdb')
const { saveClientKeyRecord } = await import('@/lib/sessionKey')
const { captureCeremonyEvents } = await import('./ceremonyEventCapture')

type Directory = ReturnType<typeof memoryConnectionsStore>

/**
 * A session database holding a client-key record under the unlock Space id
 * the sessions below log in with, as a remembered browser's does. The
 * first-seen store writes nothing without one.
 *
 * @returns {Promise<ReturnType<typeof createFakeSessionIdb>>}
 */
async function rememberedSessionIdb(): Promise<
  ReturnType<typeof createFakeSessionIdb>
> {
  const fake = createFakeSessionIdb()
  await saveClientKeyRecord({ spaceId: 'unlock-1', record: {}, idb: fake.idb })
  return fake
}

/**
 * A live session over an in-memory directory.
 *
 * @param options {object}
 * @param options.directory {Directory}
 * @param options.kind {'remembered' | 'transient'}
 * @param [options.idb] {IDBFactory}
 * @returns {Session}
 */
function makeSession({
  directory,
  kind,
  idb
}: {
  directory: Directory
  kind: 'remembered' | 'transient'
  idb?: IDBFactory
}): Session {
  const persistence =
    kind === 'remembered'
      ? {
          ...browserLocalSessionPersistence({ idb }),
          getWriterId: () => 'writer-1'
        }
      : inMemorySessionPersistence({
          stores: transientSessionStores(),
          clientAnnex: {
            clientAnnexDid: 'did:webvh:example:annex',
            invocationCapability: {} as IZcap
          }
        })
  return {
    user: { id: CLIENT_DID },
    isGuest: false,
    profile: {
      accountPointer: POINTER,
      unlockMethod: { type: 'passphrase', unlockSpaceId: 'unlock-1' }
    },
    persistence,
    storage: {
      connectionsDirectory: vi.fn(async () => ({
        store: directory.store,
        hmacKey: HMAC_KEY,
        spaceUrl: 'https://was.example/space/s/'
      }))
    },
    disposal: sessionDisposalSignal(),
    encounterGate: Promise.resolve(),
    mends: Promise.resolve([])
  } as unknown as Session
}

/**
 * The stored entry at this client's own id.
 *
 * @param directory {Directory}
 * @returns {Promise<unknown>}
 */
async function ownEntry(directory: Directory): Promise<unknown> {
  const resourceId = await connectionResourceId({
    hmacKey: HMAC_KEY,
    did: CLIENT_DID
  })
  return directory.rows.get(resourceId)?.body
}

beforeEach(() => {
  state.enrolled = true
  state.listed = true
})

let stopCapture: (() => void) | undefined
afterEach(() => {
  stopCapture?.()
  stopCapture = undefined
})

describe('registerOwnConnectionWriter', () => {
  it('defers in the first session and registers in the second, on a remembered session', async () => {
    const directory = memoryConnectionsStore()
    const { idb, sessionStore } = await rememberedSessionIdb()
    const first = makeSession({ directory, kind: 'remembered', idb })
    const firstStart = new Date('2026-10-01T00:00:00.000Z')
    expect(
      await registerOwnConnectionWriter({
        session: first,
        sessionStartedAt: firstStart
      })
    ).toBe('deferred')
    expect(directory.writes).toEqual([])
    expect(sessionStore.get('writer-first-seen/unlock-1')).toEqual({
      accountDid: ACCOUNT_DID,
      writerId: 'writer-1',
      firstSessionAt: firstStart.toISOString()
    })

    const second = makeSession({ directory, kind: 'remembered', idb })
    expect(
      await registerOwnConnectionWriter({
        session: second,
        sessionStartedAt: new Date(firstStart.getTime() + DAY_MS)
      })
    ).toBe('registered')
    const entry = parseConnectionEntry(await ownEntry(directory))
    expect(entry).toMatchObject({ kind: 'wallet-client', id: CLIENT_DID })
    expect(entry?.writers.map(writer => writer.writerId)).toEqual(['writer-1'])
  })

  it('writes nothing on a transient session', async () => {
    const directory = memoryConnectionsStore()
    const session = makeSession({ directory, kind: 'transient' })
    expect(
      await registerOwnConnectionWriter({
        session,
        sessionStartedAt: new Date()
      })
    ).toBeUndefined()
    expect(directory.writes).toEqual([])
    expect(session.storage.connectionsDirectory).not.toHaveBeenCalled()
  })

  it('writes nothing for a remembered session with no enrolled client', async () => {
    state.enrolled = false
    const directory = memoryConnectionsStore()
    const { idb, sessionStore } = createFakeSessionIdb()
    const session = makeSession({ directory, kind: 'remembered', idb })
    expect(
      await registerOwnConnectionWriter({
        session,
        sessionStartedAt: new Date()
      })
    ).toBeUndefined()
    expect(directory.writes).toEqual([])
    expect(sessionStore.size).toBe(0)
  })
})

describe('registerOwnConnectionWriter: a forget torn after its retirement', () => {
  /**
   * Seeds this client's named entry, then retires it the way the forget
   * does ahead of its removal entry.
   *
   * @param directory {Directory}
   * @returns {Promise<void>}
   */
  async function seedRetiredOwnEntry(directory: Directory): Promise<void> {
    await recordGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: CLIENT_DID,
      kind: 'wallet-client',
      grants: [],
      name: 'Chrome on Linux'
    })
    await retireConnection({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: CLIENT_DID,
      handledZcapIds: []
    })
    expect(
      parseConnectionEntry(await ownEntry(directory))?.retired
    ).toBeDefined()
  }

  it('un-retires the entry in a first session the rule defers', async () => {
    const directory = memoryConnectionsStore()
    await seedRetiredOwnEntry(directory)
    const { idb } = await rememberedSessionIdb()
    const session = makeSession({ directory, kind: 'remembered', idb })
    expect(
      await registerOwnConnectionWriter({
        session,
        sessionStartedAt: new Date()
      })
    ).toBe('deferred')
    const entry = parseConnectionEntry(await ownEntry(directory))
    expect(entry?.retired).toBeUndefined()
    expect(entry).toMatchObject({
      kind: 'wallet-client',
      id: CLIENT_DID,
      name: 'Chrome on Linux',
      grants: []
    })
  })

  it('un-retires the entry within the touch interval', async () => {
    const directory = memoryConnectionsStore()
    const { idb } = await rememberedSessionIdb()
    const firstStart = new Date(Date.now() - 2 * DAY_MS)
    await registerOwnConnectionWriter({
      session: makeSession({ directory, kind: 'remembered', idb }),
      sessionStartedAt: firstStart
    })
    expect(
      await registerOwnConnectionWriter({
        session: makeSession({ directory, kind: 'remembered', idb }),
        sessionStartedAt: new Date(firstStart.getTime() + DAY_MS)
      })
    ).toBe('registered')
    await retireConnection({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: CLIENT_DID,
      handledZcapIds: []
    })
    expect(
      await registerOwnConnectionWriter({
        session: makeSession({ directory, kind: 'remembered', idb }),
        sessionStartedAt: new Date()
      })
    ).toBe('fresh')
    const entry = parseConnectionEntry(await ownEntry(directory))
    expect(entry?.retired).toBeUndefined()
    expect(entry?.writers.map(writer => writer.writerId)).toEqual(['writer-1'])
  })

  it('leaves the entry retired once the document no longer lists this client', async () => {
    const directory = memoryConnectionsStore()
    await seedRetiredOwnEntry(directory)
    state.listed = false
    const writesBefore = directory.writes.length
    const { idb } = await rememberedSessionIdb()
    await registerOwnConnectionWriter({
      session: makeSession({ directory, kind: 'remembered', idb }),
      sessionStartedAt: new Date()
    })
    expect(directory.writes).toHaveLength(writesBefore)
    expect(
      parseConnectionEntry(await ownEntry(directory))?.retired
    ).toBeDefined()
  })

  it('writes nothing to an entry that is not retired', async () => {
    const directory = memoryConnectionsStore()
    await recordGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: CLIENT_DID,
      kind: 'wallet-client',
      grants: []
    })
    const writesBefore = directory.writes.length
    const { idb } = await rememberedSessionIdb()
    await registerOwnConnectionWriter({
      session: makeSession({ directory, kind: 'remembered', idb }),
      sessionStartedAt: new Date()
    })
    expect(directory.writes).toHaveLength(writesBefore)
  })
})

describe('the writer sweep at the directory listing read', () => {
  /**
   * Seeds this client's entry with one writer last seen `ageDays` ago.
   *
   * @param options {object}
   * @param options.directory {Directory}
   * @param options.ageDays {number}
   * @returns {Promise<void>}
   */
  async function seedWriter({
    directory,
    ageDays
  }: {
    directory: Directory
    ageDays: number
  }): Promise<void> {
    const stamp = new Date(Date.now() - ageDays * DAY_MS).toISOString()
    await directory.store.put({
      resourceId: await connectionResourceId({
        hmacKey: HMAC_KEY,
        did: CLIENT_DID
      }),
      body: {
        version: 1,
        kind: 'wallet-client',
        id: CLIENT_DID,
        name: 'Freewallet',
        firstSeen: stamp,
        lastSeen: stamp,
        grants: [],
        writers: [
          {
            writerId: 'writer-old',
            label: 'Freewallet',
            lastSeen: stamp,
            active: true
          }
        ]
      },
      ifNoneMatch: true
    })
  }

  for (const kind of ['remembered', 'transient'] as const) {
    it(`marks an expired writer inactive, reporting to the page and the event channel (${kind})`, async () => {
      const events = captureCeremonyEvents()
      stopCapture = events.stop
      const directory = memoryConnectionsStore()
      await seedWriter({ directory, ageDays: 100 })
      const { idb } = createFakeSessionIdb()
      const session = makeSession({ directory, kind, idb })
      const mends = session.mends

      const entries = await readDirectoryEntries({ session })
      // The listing returns what it read; the sweep runs behind it.
      expect(entries[0]?.writers[0]?.active).toBe(true)
      const report = await connectionWritersMend({ session })
      expect(report).toEqual([
        {
          invariant: 'no-registered-writer-outlives-its-expiry',
          outcome: 'clean',
          detail: { markedInactive: 1, dropped: 0, failed: 0 }
        }
      ])
      expect(
        parseConnectionEntry(await ownEntry(directory))?.writers[0]?.active
      ).toBe(false)
      expect(
        events.menders('no-registered-writer-outlives-its-expiry')
      ).toHaveLength(1)
      // `session.mends` is the login's report and is left as it was.
      expect(session.mends).toBe(mends)
      expect(await session.mends).toEqual([])
    })
  }

  it('reports a noop and writes nothing when no writer has expired', async () => {
    const directory = memoryConnectionsStore()
    await seedWriter({ directory, ageDays: 1 })
    const session = makeSession({ directory, kind: 'transient' })
    const writesBefore = directory.writes.length
    await readDirectoryEntries({ session })
    expect(await connectionWritersMend({ session })).toEqual([
      {
        invariant: 'no-registered-writer-outlives-its-expiry',
        outcome: 'noop',
        detail: { markedInactive: 0, dropped: 0, failed: 0 }
      }
    ])
    expect(directory.writes).toHaveLength(writesBefore)
  })

  it('resolves before any listing read has started a sweep', async () => {
    const session = makeSession({
      directory: memoryConnectionsStore(),
      kind: 'transient'
    })
    expect(await connectionWritersMend({ session })).toEqual([])
  })
})
