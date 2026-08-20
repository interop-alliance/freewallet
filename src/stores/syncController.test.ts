/**
 * Unit tests for the SyncController's background pull-poll timer: it is
 * installed at `WAS_SYNC_POLL_MS` once replications are running, skips ticks
 * while offline, and is torn down by `stop()` so login/logout cycles leak no
 * timers. Replication itself is faked -- no RxDB engine, no server.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { Session } from '@/types/auth'

const POLL_MS = 1000

const config = vi.hoisted(() => ({ pollMs: 1000 }))

vi.mock('@/app.config', () => ({
  SYNCED_COLLECTIONS: [
    { key: 'privateCredentials', id: 'private-credentials' },
    { key: 'walletActivity', id: 'wallet-activity' }
  ],
  WAS_SERVER_URL: 'https://was.example',
  WAS_SYNC_BATCH_SIZE: 10,
  WAS_SYNC_RETRY_MS: 5000,
  get WAS_SYNC_POLL_MS() {
    return config.pollMs
  }
}))

const replications = vi.hoisted(() => ({
  created: [] as Array<{ reSync: ReturnType<typeof vi.fn> }>
}))

vi.mock('@/lib/sync', () => ({
  createWasReplication: vi.fn(() => {
    const state = {
      reSync: vi.fn(),
      cancel: vi.fn().mockResolvedValue(undefined),
      active$: { subscribe: () => ({ unsubscribe: vi.fn() }) },
      error$: { subscribe: () => ({ unsubscribe: vi.fn() }) }
    }
    replications.created.push(state)
    return state
  })
}))

vi.mock('@interop/was-client/sync', () => ({
  createWasSyncPort: vi.fn(() => ({}))
}))

vi.mock('@/stores/syncStatusStore', () => ({
  useSyncStatusStore: {
    getState: () => ({ setStatus: vi.fn(), reset: vi.fn() })
  }
}))

import { syncController } from './syncController'

/**
 * A session shaped just enough for the controller: not a guest, a remote WAS
 * client and space id present, and a local collection handle per key.
 */
function fakeSession(): Session {
  return {
    isGuest: false,
    storage: {
      wasClient: {},
      spaceId: 'space-1',
      hasLocalReplica: true,
      localCollection: vi.fn(() => ({}))
    }
  } as unknown as Session
}

/**
 * Total `reSync()` calls across every replication created so far.
 *
 * @returns {number}
 */
function totalReSyncCalls(): number {
  return replications.created.reduce(
    (total, state) => total + state.reSync.mock.calls.length,
    0
  )
}

let onLine = true

beforeEach(() => {
  vi.useFakeTimers()
  replications.created = []
  config.pollMs = POLL_MS
  onLine = true
  vi.spyOn(window.navigator, 'onLine', 'get').mockImplementation(() => onLine)
})

afterEach(async () => {
  await syncController.stop()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('SyncController background pull poll', () => {
  it('reSyncs every replication once per poll interval while online', async () => {
    await syncController.start({ session: fakeSession() })
    expect(replications.created).toHaveLength(2)

    await vi.advanceTimersByTimeAsync(POLL_MS)
    for (const state of replications.created) {
      expect(state.reSync).toHaveBeenCalledTimes(1)
    }

    await vi.advanceTimersByTimeAsync(POLL_MS * 3)
    for (const state of replications.created) {
      expect(state.reSync).toHaveBeenCalledTimes(4)
    }
  })

  it('skips ticks while offline and resumes once back online', async () => {
    onLine = false
    await syncController.start({ session: fakeSession() })

    await vi.advanceTimersByTimeAsync(POLL_MS * 3)
    expect(totalReSyncCalls()).toBe(0)

    onLine = true
    await vi.advanceTimersByTimeAsync(POLL_MS)
    for (const state of replications.created) {
      expect(state.reSync).toHaveBeenCalledTimes(1)
    }
  })

  it('installs no timer when the poll interval is zero', async () => {
    config.pollMs = 0
    await syncController.start({ session: fakeSession() })

    await vi.advanceTimersByTimeAsync(POLL_MS * 10)
    expect(totalReSyncCalls()).toBe(0)
  })

  it('clears the timer on stop', async () => {
    await syncController.start({ session: fakeSession() })
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(totalReSyncCalls()).toBe(2)

    await syncController.stop()
    await vi.advanceTimersByTimeAsync(POLL_MS * 5)
    expect(totalReSyncCalls()).toBe(2)
  })

  it('leaves exactly one timer running across start/stop cycles', async () => {
    await syncController.start({ session: fakeSession() })
    await syncController.stop()

    replications.created = []
    await syncController.start({ session: fakeSession() })
    expect(replications.created).toHaveLength(2)

    await vi.advanceTimersByTimeAsync(POLL_MS)
    // One tick, one reSync per live replication: a leaked timer from the first
    // cycle would double these counts.
    for (const state of replications.created) {
      expect(state.reSync).toHaveBeenCalledTimes(1)
    }
  })
})
