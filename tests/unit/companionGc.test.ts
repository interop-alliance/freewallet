// @vitest-environment node
/**
 * Unit tests for the companion GC sweep (`src/session/companionGc.ts`): the
 * login-time driver of wallet-core's `runCompanionGc`. The ceremony itself is
 * mocked at the module seam so what this module actually supplies -- the
 * durable-posture and enrolled-client preconditions, the verified-log memo,
 * the options it threads, the GenerationCollect digest write, and the local
 * pin-slot cleanup -- is what runs; the pure companion helpers
 * (`companionDidParts`, `companionLogPinId`, `delegatedClientsPointer`,
 * `isWebvhDid`) run for real against fixture documents.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  runCompanionGc: vi.fn()
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  WasClient: vi.fn(function WasClientStub(this: Record<string, unknown>) {
    this.isWasClientStub = true
  })
}))

vi.mock('@/lib/sessionKey', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/sessionKey')>()),
  deleteLogPin: vi.fn()
}))

vi.mock('@/session/enrolledContext', () => ({
  enrolledClientContext: vi.fn()
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(),
  invalidateVerifiedLog: vi.fn()
}))

import { companionLogPinId, runCompanionGc } from '@interop/wallet-core/webvh'
import { deleteLogPin } from '@/lib/sessionKey'
import { sweepCompanionGenerations } from '@/session/companionGc'
import { enrolledClientContext } from '@/session/enrolledContext'
import {
  durableSessionPersistence,
  transientSessionPersistence
} from '@/session/persistence'
import type { SessionPersistence } from '@/session/persistence'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const COMPANION_DID =
  'did:webvh:QmCompanionScid:was.example.test:space:companion-space-1:gen-Ux3v0kQf9aPmB2hZ'
const COMPANION_SPACE_ID = 'companion-space-1'
const CLIENT_WEBVH_KEYS = { current: { seed: 'current' } }
const ID_STORE = { isIdStore: true }
const REPORT = {
  swap: 'not-due',
  pointedDid: COMPANION_DID,
  collected: [],
  failed: []
}

/**
 * An account document carrying the delegated-clients service entry the
 * sweep's real `delegatedClientsPointer` reads the companion DID out of.
 */
function accountDoc({ pointed = true }: { pointed?: boolean } = {}) {
  return {
    id: POINTER.did,
    ...(pointed
      ? {
          service: [
            {
              id: `${POINTER.did}#delegated-clients`,
              type: 'https://w3id.org/byoe#DelegatedClients',
              serviceEndpoint: COMPANION_DID
            }
          ]
        }
      : {})
  }
}

/**
 * A live durable session shaped as much as the sweep reads it: the
 * persistence handle, the zcap client, the storage facade (a plain mock),
 * and the user the digest is attributed to.
 */
function makeSession({
  persistence = durableSessionPersistence()
}: { persistence?: SessionPersistence } = {}): Session {
  return {
    user: { id: 'did:key:z6MkClient', email: 'user@example.test' },
    isGuest: false,
    profile: {
      persistence,
      zcapClient: { isZcapClient: true }
    },
    storage: {
      addHistoryGenerationCollected: vi.fn(async () => undefined)
    }
  } as unknown as Session
}

/**
 * Primes the happy path: an enrolled context, a verified account log whose
 * document points at a companion generation, and a canned GC report.
 */
function primeHappyPath() {
  vi.mocked(enrolledClientContext).mockReturnValue({
    remoteStore: { webvhIdStore: vi.fn(() => ID_STORE) },
    pointer: POINTER,
    clientWebvhKeys: CLIENT_WEBVH_KEYS
  } as never)
  vi.mocked(verifiedAccountLog).mockResolvedValue({
    doc: accountDoc(),
    log: [{ entry: 1 }],
    updateKeys: [],
    nextKeyHashes: []
  } as never)
  vi.mocked(runCompanionGc).mockResolvedValue(REPORT as never)
}

/**
 * The options `runCompanionGc` was called with on the current pass.
 */
function gcOptions() {
  return vi.mocked(runCompanionGc).mock.calls[0]![0]
}

beforeEach(() => {
  primeHappyPath()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('sweepCompanionGenerations -- the preconditions', () => {
  it('skips a transient session', async () => {
    const session = makeSession({
      persistence: transientSessionPersistence()
    })
    await expect(sweepCompanionGenerations({ session })).resolves.toBeNull()
    expect(runCompanionGc).not.toHaveBeenCalled()
    expect(enrolledClientContext).not.toHaveBeenCalled()
  })

  it('skips a session that cannot act as the account', async () => {
    vi.mocked(enrolledClientContext).mockReturnValue(null)
    const session = makeSession()
    await expect(sweepCompanionGenerations({ session })).resolves.toBeNull()
    expect(runCompanionGc).not.toHaveBeenCalled()
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it('skips an unpromoted (did:key) account pointer', async () => {
    vi.mocked(enrolledClientContext).mockReturnValue({
      remoteStore: { webvhIdStore: vi.fn(() => ID_STORE) },
      pointer: { ...POINTER, did: 'did:key:z6MkNotWebvh' },
      clientWebvhKeys: CLIENT_WEBVH_KEYS
    } as never)
    const session = makeSession()
    await expect(sweepCompanionGenerations({ session })).resolves.toBeNull()
    expect(runCompanionGc).not.toHaveBeenCalled()
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it('skips an account with no companion posture in its document', async () => {
    vi.mocked(verifiedAccountLog).mockResolvedValue({
      doc: accountDoc({ pointed: false }),
      log: [{ entry: 1 }],
      updateKeys: [],
      nextKeyHashes: []
    } as never)
    const session = makeSession()
    await expect(sweepCompanionGenerations({ session })).resolves.toBeNull()
    expect(verifiedAccountLog).toHaveBeenCalledWith({
      profile: session.profile,
      pointer: POINTER
    })
    expect(runCompanionGc).not.toHaveBeenCalled()
  })
})

describe('sweepCompanionGenerations -- the pass', () => {
  it('runs one pass with the account, the id store, and this client keys', async () => {
    const persistence = durableSessionPersistence()
    const session = makeSession({ persistence })
    const ladderSeed = new Uint8Array(32).fill(7)

    const report = await sweepCompanionGenerations({ session, ladderSeed })

    expect(report).toBe(REPORT)
    expect(runCompanionGc).toHaveBeenCalledTimes(1)
    const options = gcOptions()
    expect(options.wasServerUrl).toBe(POINTER.host)
    expect(options.accountSpaceId).toBe(POINTER.spaceId)
    expect(options.account).toEqual({
      did: POINTER.did,
      doc: accountDoc(),
      log: [{ entry: 1 }]
    })
    expect(options.idStore).toBe(ID_STORE)
    expect(options.updateKeys).toBe(CLIENT_WEBVH_KEYS)
    expect(options.ladderSeed).toBe(ladderSeed)
    expect(options.pinStore).toBe(persistence.logPins)
  })

  it('omits ladderSeed entirely when none is supplied', async () => {
    await sweepCompanionGenerations({ session: makeSession() })
    expect('ladderSeed' in gcOptions()).toBe(false)
  })

  it('writes the digest through the storage facade', async () => {
    const session = makeSession()
    await sweepCompanionGenerations({ session })
    await gcOptions().recordDigest({
      generationId: 'gen-Ux3v0kQf9aPmB2hZ',
      firstEntry: '2026-05-01T00:00:00Z',
      lastEntry: '2026-08-01T00:00:00Z',
      entryCount: 4
    })
    expect(session.storage.addHistoryGenerationCollected).toHaveBeenCalledWith({
      user: session.user,
      generationId: 'gen-Ux3v0kQf9aPmB2hZ',
      firstEntry: '2026-05-01T00:00:00Z',
      lastEntry: '2026-08-01T00:00:00Z',
      entryCount: 4
    })
  })

  it('drops the collected generation pin slot, in the companion Space', async () => {
    const idb = { isIdbFactory: true } as unknown as IDBFactory
    const session = makeSession({
      persistence: durableSessionPersistence({ idb })
    })
    await sweepCompanionGenerations({ session })
    await gcOptions().onCollected!({ generationId: 'gen-Ux3v0kQf9aPmB2hZ' })
    expect(deleteLogPin).toHaveBeenCalledWith({
      logId: companionLogPinId({
        spaceId: COMPANION_SPACE_ID,
        generationId: 'gen-Ux3v0kQf9aPmB2hZ'
      }),
      idb
    })
  })

  it('invalidates the verified-log memo after a swap', async () => {
    vi.mocked(runCompanionGc).mockResolvedValue({
      ...REPORT,
      swap: 'replaced'
    } as never)
    const session = makeSession()
    await sweepCompanionGenerations({ session })
    expect(invalidateVerifiedLog).toHaveBeenCalledWith({
      profile: session.profile
    })
  })

  it('leaves the memo alone when no swap was due', async () => {
    await sweepCompanionGenerations({ session: makeSession() })
    expect(invalidateVerifiedLog).not.toHaveBeenCalled()
  })
})
