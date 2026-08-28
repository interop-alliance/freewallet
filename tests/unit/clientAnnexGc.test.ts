// @vitest-environment node
/**
 * Unit tests for the annex GC sweep (`src/session/clientAnnexGc.ts`): the
 * login-time driver of wallet-core's `runClientAnnexGc`. The ceremony itself is
 * mocked at the module seam so what this module actually supplies -- the
 * remembered-session and enrolled-client preconditions, the verified-log
 * memo, the options it threads, and the GenerationCollect digest write -- is
 * what runs; the pure annex helpers (`clientAnnexDidParts`,
 * `delegatedClientsPointer`, `isWebvhDid`) run for real against fixture
 * documents.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  runClientAnnexGc: vi.fn()
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  WasClient: vi.fn(function WasClientStub(this: Record<string, unknown>) {
    this.isWasClientStub = true
  })
}))

vi.mock('@/session/enrolledContext', () => ({
  enrolledClientContext: vi.fn()
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(),
  invalidateVerifiedLog: vi.fn()
}))

import { runClientAnnexGc } from '@interop/wallet-core/clientAnnex'
import { sweepClientAnnexGenerations } from '@/session/clientAnnexGc'
import { enrolledClientContext } from '@/session/enrolledContext'
import {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores
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
const CLIENT_ANNEX_DID =
  'did:webvh:QmClientAnnexScid:was.example.test:space:clientAnnex-space-1:gen-Ux3v0kQf9aPmB2hZ'
const CLIENT_WEBVH_KEYS = { current: { seed: 'current' } }
const ID_STORE = { isIdStore: true }
const REPORT = {
  swap: 'not-due',
  pointedDid: CLIENT_ANNEX_DID,
  collected: [],
  failed: []
}

/**
 * An account document carrying the delegated-clients service entry the
 * sweep's real `delegatedClientsPointer` reads the annex DID out of.
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
              serviceEndpoint: CLIENT_ANNEX_DID
            }
          ]
        }
      : {})
  }
}

/**
 * A live remembered session shaped as much as the sweep reads it: the
 * persistence handle, the zcap client, the storage facade (a plain mock),
 * and the user the digest is attributed to.
 */
function makeSession({
  persistence = browserLocalSessionPersistence()
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
 * document points at an annex generation, and a canned GC report.
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
  vi.mocked(runClientAnnexGc).mockResolvedValue(REPORT as never)
}

/**
 * The options `runClientAnnexGc` was called with on the current pass.
 */
function gcOptions() {
  return vi.mocked(runClientAnnexGc).mock.calls[0]![0]
}

beforeEach(() => {
  primeHappyPath()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('sweepClientAnnexGenerations -- the preconditions', () => {
  it('skips a transient session', async () => {
    const session = makeSession({
      persistence: inMemorySessionPersistence({
        stores: transientSessionStores(),
        clientAnnex: {
          clientAnnexDid: 'did:webvh:example:annex',
          invocationCapability: {} as never
        }
      })
    })
    await expect(sweepClientAnnexGenerations({ session })).resolves.toBeNull()
    expect(runClientAnnexGc).not.toHaveBeenCalled()
    expect(enrolledClientContext).not.toHaveBeenCalled()
  })

  it('skips a session that cannot act as the account', async () => {
    vi.mocked(enrolledClientContext).mockReturnValue(null)
    const session = makeSession()
    await expect(sweepClientAnnexGenerations({ session })).resolves.toBeNull()
    expect(runClientAnnexGc).not.toHaveBeenCalled()
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it('skips an unpromoted (did:key) account pointer', async () => {
    vi.mocked(enrolledClientContext).mockReturnValue({
      remoteStore: { webvhIdStore: vi.fn(() => ID_STORE) },
      pointer: { ...POINTER, did: 'did:key:z6MkNotWebvh' },
      clientWebvhKeys: CLIENT_WEBVH_KEYS
    } as never)
    const session = makeSession()
    await expect(sweepClientAnnexGenerations({ session })).resolves.toBeNull()
    expect(runClientAnnexGc).not.toHaveBeenCalled()
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it('skips an account with no annex inventory in its document', async () => {
    vi.mocked(verifiedAccountLog).mockResolvedValue({
      doc: accountDoc({ pointed: false }),
      log: [{ entry: 1 }],
      updateKeys: [],
      nextKeyHashes: []
    } as never)
    const session = makeSession()
    await expect(sweepClientAnnexGenerations({ session })).resolves.toBeNull()
    expect(verifiedAccountLog).toHaveBeenCalledWith({
      profile: session.profile,
      pointer: POINTER
    })
    expect(runClientAnnexGc).not.toHaveBeenCalled()
  })
})

describe('sweepClientAnnexGenerations -- the pass', () => {
  it('runs one pass with the account, the id store, and this client keys', async () => {
    const persistence = browserLocalSessionPersistence()
    const session = makeSession({ persistence })
    const ladderSeed = new Uint8Array(32).fill(7)

    const report = await sweepClientAnnexGenerations({ session, ladderSeed })

    expect(report).toBe(REPORT)
    expect(runClientAnnexGc).toHaveBeenCalledTimes(1)
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
    await sweepClientAnnexGenerations({ session: makeSession() })
    expect('ladderSeed' in gcOptions()).toBe(false)
  })

  it('writes the digest through the storage facade', async () => {
    const session = makeSession()
    await sweepClientAnnexGenerations({ session })
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

  it('invalidates the verified-log memo after a swap', async () => {
    vi.mocked(runClientAnnexGc).mockResolvedValue({
      ...REPORT,
      swap: 'replaced'
    } as never)
    const session = makeSession()
    await sweepClientAnnexGenerations({ session })
    expect(invalidateVerifiedLog).toHaveBeenCalledWith({
      profile: session.profile
    })
  })

  it('leaves the memo alone when no swap was due', async () => {
    await sweepClientAnnexGenerations({ session: makeSession() })
    expect(invalidateVerifiedLog).not.toHaveBeenCalled()
  })
})
