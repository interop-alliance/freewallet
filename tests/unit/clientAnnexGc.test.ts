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

vi.mock('@interop/pws-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/pws-client')>()),
  PwsClient: vi.fn(function WasClientStub(this: Record<string, unknown>) {
    this.isWasClientStub = true
  })
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  enrolledCeremonyContext: vi.fn()
}))

vi.mock('@/session/replicaRestate', () => ({
  restatedReplicaServers: vi.fn(async () => [])
}))
vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(),
  refreshVerifiedAccountLog: vi.fn(),
  invalidateVerifiedLog: vi.fn()
}))

import { runClientAnnexGc } from '@interop/wallet-core/clientAnnex'
import { restatedReplicaServers } from '@/session/replicaRestate'
import { sweepClientAnnexGenerations } from '@/session/clientAnnexGc'
import { enrolledCeremonyContext } from '@/session/accountCeremonyContext'
import {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import type { SessionPersistence } from '@/session/persistence'
import {
  invalidateVerifiedLog,
  refreshVerifiedAccountLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceUrl: 'https://was.example.test/space/space-123/'
}
const CLIENT_ANNEX_DID =
  'did:webvh:QmClientAnnexScid:was.example.test:space:clientAnnex-space-1:gen-Ux3v0kQf9aPmB2hZ'
const CLIENT_WEBVH_KEYS = { current: { seed: 'current' } }
const ID_STORE = { isIdStore: true }
const SIBLING_ANNEX_DID =
  'did:webvh:QmClientAnnexScid2:was.example.test:space:clientAnnex-space-1:gen-Ps7w1mRt4bNcK8yD'
const REPORT = {
  swap: 'not-due',
  pointedDid: CLIENT_ANNEX_DID,
  collected: [],
  deferred: [],
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
    persistence,
    profile: {
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
  vi.mocked(enrolledCeremonyContext).mockReturnValue({
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
    await expect(sweepClientAnnexGenerations({ session })).resolves.toEqual(
      expect.objectContaining({ skipped: expect.any(String) })
    )
    expect(runClientAnnexGc).not.toHaveBeenCalled()
    expect(enrolledCeremonyContext).not.toHaveBeenCalled()
  })

  it('skips a session that cannot act as the account', async () => {
    vi.mocked(enrolledCeremonyContext).mockReturnValue(null)
    const session = makeSession()
    await expect(sweepClientAnnexGenerations({ session })).resolves.toEqual(
      expect.objectContaining({ skipped: expect.any(String) })
    )
    expect(runClientAnnexGc).not.toHaveBeenCalled()
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it('skips an unpromoted (did:key) account pointer', async () => {
    vi.mocked(enrolledCeremonyContext).mockReturnValue({
      remoteStore: { webvhIdStore: vi.fn(() => ID_STORE) },
      pointer: { ...POINTER, did: 'did:key:z6MkNotWebvh' },
      clientWebvhKeys: CLIENT_WEBVH_KEYS
    } as never)
    const session = makeSession()
    await expect(sweepClientAnnexGenerations({ session })).resolves.toEqual(
      expect.objectContaining({ skipped: expect.any(String) })
    )
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
    await expect(sweepClientAnnexGenerations({ session })).resolves.toEqual(
      expect.objectContaining({ skipped: expect.any(String) })
    )
    expect(verifiedAccountLog).toHaveBeenCalledWith({
      session,
      pointer: POINTER
    })
    expect(runClientAnnexGc).not.toHaveBeenCalled()
  })
})

describe('sweepClientAnnexGenerations -- the pass', () => {
  it('hands the restated replica servers to the pass', async () => {
    const session = makeSession()
    vi.mocked(restatedReplicaServers).mockResolvedValueOnce([
      'did:key:z6MkReplicaServer'
    ])

    await sweepClientAnnexGenerations({ session })

    expect(gcOptions().replicaServerDids).toEqual(['did:key:z6MkReplicaServer'])
  })

  it('refuses the pass before its mint when the replica list cannot be read', async () => {
    const session = makeSession()
    vi.mocked(restatedReplicaServers).mockRejectedValueOnce(
      new Error('directory unreadable')
    )

    await expect(sweepClientAnnexGenerations({ session })).rejects.toThrow(
      'directory unreadable'
    )
    expect(runClientAnnexGc).not.toHaveBeenCalled()
  })

  it('runs one pass with the account, the id store, and this client keys', async () => {
    const persistence = browserLocalSessionPersistence()
    const session = makeSession({ persistence })
    const ladderSeed = new Uint8Array(32).fill(7)

    const swept = await sweepClientAnnexGenerations({ session, ladderSeed })

    expect(swept).toEqual({ report: REPORT })
    expect(runClientAnnexGc).toHaveBeenCalledTimes(1)
    const options = gcOptions()
    expect(options.baseServerUrl).toBe('https://was.example.test/')
    expect(options.accountSpaceId).toBe('space-123')
    expect(options.account).toEqual({
      did: POINTER.did,
      doc: accountDoc(),
      log: [{ entry: 1 }]
    })
    expect(options.idStore).toBe(ID_STORE)
    expect(options.updateKeys).toBe(CLIENT_WEBVH_KEYS)
    // An account with no replica-server entry restates an empty list.
    expect(options.replicaServerDids).toEqual([])
    expect(restatedReplicaServers).toHaveBeenCalledWith({ session })
    expect(options.ladderSeed).toBe(ladderSeed)
  })

  it('refreshes the verified-log memo before reading the pointer', async () => {
    // A memo taken before a sibling client's swap names a generation that
    // sibling collected; the pass would repair off the sibling's live one.
    const session = makeSession()
    await sweepClientAnnexGenerations({ session })
    expect(refreshVerifiedAccountLog).toHaveBeenCalledWith({ session })
    expect(
      vi.mocked(refreshVerifiedAccountLog).mock.invocationCallOrder[0]
    ).toBeLessThan(vi.mocked(verifiedAccountLog).mock.invocationCallOrder[0]!)
  })

  it('runs no pass when the refresh fails', async () => {
    vi.mocked(refreshVerifiedAccountLog).mockRejectedValueOnce(
      new Error('offline')
    )
    await expect(
      sweepClientAnnexGenerations({ session: makeSession() })
    ).rejects.toThrow('offline')
    expect(runClientAnnexGc).not.toHaveBeenCalled()
  })

  it('invalidates the memo when the pass rejects', async () => {
    // The pass rejects only after its swap stage, so a re-point may have
    // landed before the re-read or the collection listing failed.
    vi.mocked(runClientAnnexGc).mockRejectedValue(new Error('listing failed'))
    const session = makeSession()
    await expect(sweepClientAnnexGenerations({ session })).rejects.toThrow(
      'listing failed'
    )
    expect(invalidateVerifiedLog).toHaveBeenCalledWith({
      profile: session.profile
    })
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

  it('invalidates the verified-log memo after a repair of a dead pointer', async () => {
    vi.mocked(runClientAnnexGc).mockResolvedValue({
      ...REPORT,
      swap: 'repaired',
      pointedDid: SIBLING_ANNEX_DID
    } as never)
    const session = makeSession()
    await sweepClientAnnexGenerations({ session })
    expect(invalidateVerifiedLog).toHaveBeenCalledWith({
      profile: session.profile
    })
  })

  it('invalidates the verified-log memo after a readmission of the login credential', async () => {
    // A passkey whose rung an unnamed retirement swap left out, used only
    // through this enrolled client since: the pass swaps off the cadence,
    // restating the pointed log's standing set beside the passkey's hash,
    // and the account points at the fresh generation.
    vi.mocked(runClientAnnexGc).mockResolvedValue({
      ...REPORT,
      swap: 'readmitted',
      pointedDid: SIBLING_ANNEX_DID
    } as never)
    const session = makeSession()
    const ladderSeed = new Uint8Array(32).fill(9)
    const swept = await sweepClientAnnexGenerations({ session, ladderSeed })
    expect(swept).toEqual({
      report: expect.objectContaining({
        swap: 'readmitted',
        pointedDid: SIBLING_ANNEX_DID
      })
    })
    expect(gcOptions().ladderSeed).toBe(ladderSeed)
    expect(invalidateVerifiedLog).toHaveBeenCalledWith({
      profile: session.profile
    })
  })

  it('invalidates the memo when the re-read pointer moved under a swap that did not land', async () => {
    // A `failed` swap whose re-point landed, or a sibling client's swap:
    // either way the log the memo holds is behind the host's.
    for (const swap of ['failed', 'not-due', 'no-ladder-seed']) {
      vi.mocked(invalidateVerifiedLog).mockClear()
      vi.mocked(runClientAnnexGc).mockResolvedValue({
        ...REPORT,
        swap,
        pointedDid: SIBLING_ANNEX_DID
      } as never)
      const session = makeSession()
      await sweepClientAnnexGenerations({ session })
      expect(invalidateVerifiedLog, swap).toHaveBeenCalledWith({
        profile: session.profile
      })
    }
  })

  it('invalidates the memo when the re-read log carries no pointer', async () => {
    vi.mocked(runClientAnnexGc).mockResolvedValue({
      swap: 'not-due',
      collected: [],
      deferred: [],
      failed: []
    } as never)
    const session = makeSession()
    await sweepClientAnnexGenerations({ session })
    expect(invalidateVerifiedLog).toHaveBeenCalledWith({
      profile: session.profile
    })
  })

  it('leaves the memo alone when no swap was due and the pointer is unchanged', async () => {
    vi.mocked(runClientAnnexGc).mockResolvedValue({
      ...REPORT,
      collected: ['gen-Ux3v0kQf9aPmB2hY'],
      deferred: ['gen-Ux3v0kQf9aPmB2hX']
    } as never)
    await sweepClientAnnexGenerations({ session: makeSession() })
    expect(invalidateVerifiedLog).not.toHaveBeenCalled()
  })
})
