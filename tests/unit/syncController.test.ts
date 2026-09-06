/**
 * Unit tests for the sync binding's lifecycle contract
 * (`src/stores/syncController.ts`): the gate that decides which sessions
 * replicate at all, and the re-login / account-switch rule that a controller
 * left running by a previous session is torn down before the new one starts.
 * `restart()` is the one entry point that starts replication.
 *
 * The replication core in `@interop/was-sync/rxdb` is stubbed, so what these
 * cases exercise is the binding's own bookkeeping: which sessions reach the
 * core, how many cores it constructs, which it stops, and how it serializes
 * overlapping transitions. `stop()` is terminal for a core instance, so a
 * restart must construct a fresh one rather than re-starting the old.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/app.config', () => ({
  WAS_SERVER_URL: 'https://was.example',
  WAS_SYNC_BATCH_SIZE: undefined,
  WAS_SYNC_RETRY_MS: undefined,
  WAS_SYNC_POLL_MS: 0,
  SYNCED_COLLECTIONS: [
    { key: 'privateCredentials', id: 'private-credentials' },
    { key: 'publicCredentials', id: 'public-credentials' },
    { key: 'walletActivity', id: 'wallet-activity' }
  ]
}))

// Each `createSyncController` call yields a distinct stub core, so the test can
// count constructions and track which cores get stopped.
const cores = vi.hoisted(() => ({
  created: [] as Array<{
    spaceId: string
    start: ReturnType<typeof vi.fn>
    stop: ReturnType<typeof vi.fn>
    reSync: ReturnType<typeof vi.fn>
  }>
}))

vi.mock('@interop/was-sync/rxdb', () => ({
  createSyncController: vi.fn(({ port }: { port: { spaceId: string } }) => {
    const core = {
      spaceId: port.spaceId,
      start: vi.fn().mockResolvedValue(undefined),
      stop: vi.fn().mockResolvedValue(undefined),
      reSync: vi.fn()
    }
    cores.created.push(core)
    return core
  })
}))

vi.mock('@/stores/syncStatusStore', () => ({
  useSyncStatusStore: {
    getState: () => ({ setStatus: vi.fn(), reset: vi.fn() })
  }
}))

import { createSyncController } from '@interop/was-sync/rxdb'
import { syncController } from '@/stores/syncController'
import type { Session } from '@/types/auth'

/**
 * Builds a minimal non-guest session whose storage looks like it has a
 * configured remote WAS replica and a local one, so the binding proceeds past
 * its gate.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @returns {Session}
 */
function fakeSession({ spaceId }: { spaceId: string }): Session {
  return {
    isGuest: false,
    storage: {
      wasClient: { fake: true },
      spaceId,
      hasLocalReplica: true,
      localCollection: vi.fn(() => ({ fakeCollection: true }))
    }
  } as unknown as Session
}

beforeEach(() => {
  cores.created.length = 0
  vi.mocked(createSyncController).mockClear()
})

afterEach(async () => {
  await syncController.stop()
})

describe('sync binding lifecycle', () => {
  it('restart() stops the running core and constructs a fresh one', async () => {
    await syncController.restart({ session: fakeSession({ spaceId: 'A' }) })
    expect(cores.created).toHaveLength(1)
    expect(cores.created[0].start).toHaveBeenCalledTimes(1)

    await syncController.restart({ session: fakeSession({ spaceId: 'B' }) })
    // The first core is stopped -- terminal for that instance -- and the new
    // session gets a core of its own, aimed at account B's Space.
    expect(cores.created[0].stop).toHaveBeenCalledTimes(1)
    expect(cores.created).toHaveLength(2)
    expect(cores.created[1].spaceId).toBe('B')
    expect(cores.created[1].stop).not.toHaveBeenCalled()
  })

  it('serializes overlapping restart() calls without interleaving', async () => {
    // Two restarts fired without awaiting the first: the queue must run them
    // one after the other, leaving exactly one live core and no dangling one
    // from the intermediate transition.
    const first = syncController.restart({
      session: fakeSession({ spaceId: 'A' })
    })
    const second = syncController.restart({
      session: fakeSession({ spaceId: 'B' })
    })
    await Promise.all([first, second])

    expect(cores.created).toHaveLength(2)
    expect(cores.created[0].stop).toHaveBeenCalledTimes(1)
    expect(cores.created[1].stop).not.toHaveBeenCalled()
  })

  it('reSync() reaches the live core and is a no-op once stopped', async () => {
    await syncController.restart({ session: fakeSession({ spaceId: 'A' }) })
    syncController.reSync()
    expect(cores.created[0].reSync).toHaveBeenCalledTimes(1)

    await syncController.stop()
    syncController.reSync()
    expect(cores.created[0].reSync).toHaveBeenCalledTimes(1)
  })

  it('a guest session does not start replication', async () => {
    const guest = { ...fakeSession({ spaceId: 'A' }), isGuest: true } as Session
    await syncController.restart({ session: guest })
    expect(createSyncController).not.toHaveBeenCalled()
  })

  it('a replica-less session does not start replication', async () => {
    const session = fakeSession({ spaceId: 'A' })
    ;(
      session.storage as unknown as { hasLocalReplica: boolean }
    ).hasLocalReplica = false
    await syncController.restart({ session })
    expect(createSyncController).not.toHaveBeenCalled()
  })

  it('a session with no remote Space does not start replication', async () => {
    const session = fakeSession({ spaceId: '' })
    await syncController.restart({ session })
    expect(createSyncController).not.toHaveBeenCalled()
  })
})
