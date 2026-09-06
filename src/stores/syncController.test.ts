/**
 * Unit tests for the port and callbacks the sync binding
 * (`src/stores/syncController.ts`) hands the replication core in
 * `@interop/was-sync/rxdb`. The core itself is that package's, with its own
 * suites, so it is stubbed here: what these cases pin is the seam between the
 * session and the core -- which collections, which handles, where status goes,
 * and which reachability signal the poll tick reads.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { SyncStatus } from '@interop/was-client/sync'
import type { Session } from '@/types/auth'

const POLL_MS = 30_000

vi.mock('@/app.config', () => ({
  SYNCED_COLLECTIONS: [
    { key: 'privateCredentials', id: 'private-credentials' },
    { key: 'walletActivity', id: 'wallet-activity' }
  ],
  WAS_SERVER_URL: 'https://was.example',
  WAS_SYNC_BATCH_SIZE: 10,
  WAS_SYNC_RETRY_MS: 5000,
  WAS_SYNC_POLL_MS: 30_000
}))

const cores = vi.hoisted(() => ({
  options: [] as unknown[],
  instances: [] as Array<{
    start: ReturnType<typeof vi.fn>
    stop: ReturnType<typeof vi.fn>
    reSync: ReturnType<typeof vi.fn>
  }>,
  startRejection: undefined as Error | undefined
}))

vi.mock('@interop/was-sync/rxdb', () => ({
  createSyncController: vi.fn((options: unknown) => {
    cores.options.push(options)
    const instance = {
      start: vi.fn(() =>
        cores.startRejection
          ? Promise.reject(cores.startRejection)
          : Promise.resolve()
      ),
      stop: vi.fn().mockResolvedValue(undefined),
      reSync: vi.fn()
    }
    cores.instances.push(instance)
    return instance
  })
}))

const statusStore = vi.hoisted(() => ({
  setStatus: vi.fn(),
  reset: vi.fn()
}))

vi.mock('@/stores/syncStatusStore', () => ({
  useSyncStatusStore: { getState: () => statusStore }
}))

import { syncController } from './syncController'

/**
 * The core options the binding builds, as these cases read them back.
 */
interface CoreOptions {
  port: {
    wasClient: unknown
    spaceId: string
    serverUrl: string
    collections: Array<{ key: string; id: string }>
    rxCollection: (key: string) => unknown
    batchSize?: number
    retryTime?: number
  }
  onStatus: (key: string, collectionId: string, status: SyncStatus) => void
  onlineSource: {
    isOnline: () => boolean
    subscribe: (onOnline: () => void) => () => void
  }
  pollMs: number
}

/**
 * The options handed to the most recently constructed core.
 *
 * @returns {CoreOptions}
 */
function lastOptions(): CoreOptions {
  return cores.options[cores.options.length - 1] as CoreOptions
}

const localCollection = vi.fn((key: string) => ({ localKey: key }))

/**
 * A session shaped just enough for the binding: not a guest, a remote WAS
 * client and space id present, and a local replica behind `localCollection`.
 *
 * @returns {Session}
 */
function fakeSession(): Session {
  return {
    isGuest: false,
    storage: {
      wasClient: { fake: 'client' },
      spaceId: 'space-1',
      hasLocalReplica: true,
      localCollection
    }
  } as unknown as Session
}

beforeEach(() => {
  cores.options = []
  cores.instances = []
  cores.startRejection = undefined
  statusStore.setStatus.mockClear()
  statusStore.reset.mockClear()
  localCollection.mockClear()
})

afterEach(async () => {
  await syncController.stop()
  vi.restoreAllMocks()
})

describe('sync binding: the port handed to the core', () => {
  it('locates the Space and carries the configured collection set', async () => {
    await syncController.restart({ session: fakeSession() })

    const { port, pollMs } = lastOptions()
    expect(port.serverUrl).toBe('https://was.example')
    expect(port.spaceId).toBe('space-1')
    expect(port.wasClient).toEqual({ fake: 'client' })
    expect(port.collections).toEqual([
      { key: 'privateCredentials', id: 'private-credentials' },
      { key: 'walletActivity', id: 'wallet-activity' }
    ])
    expect(port.batchSize).toBe(10)
    expect(port.retryTime).toBe(5000)
    expect(pollMs).toBe(POLL_MS)
  })

  it('resolves the local end of replication through the session storage', async () => {
    await syncController.restart({ session: fakeSession() })

    expect(lastOptions().port.rxCollection('walletActivity')).toEqual({
      localKey: 'walletActivity'
    })
    expect(localCollection).toHaveBeenCalledWith('walletActivity')
  })

  it('writes status keyed on the WAS collection id, not the logical key', async () => {
    await syncController.restart({ session: fakeSession() })

    lastOptions().onStatus('walletActivity', 'wallet-activity', 'syncing')
    expect(statusStore.setStatus).toHaveBeenCalledWith(
      'wallet-activity',
      'syncing'
    )
  })

  it('reads reachability off the browser and resyncs on the online event', async () => {
    const addEventListener = vi.spyOn(window, 'addEventListener')
    const removeEventListener = vi.spyOn(window, 'removeEventListener')
    let onLine = false
    vi.spyOn(window.navigator, 'onLine', 'get').mockImplementation(() => onLine)

    await syncController.restart({ session: fakeSession() })
    const { onlineSource } = lastOptions()

    expect(onlineSource.isOnline()).toBe(false)
    onLine = true
    expect(onlineSource.isOnline()).toBe(true)

    const onOnline = vi.fn()
    const unsubscribe = onlineSource.subscribe(onOnline)
    expect(addEventListener).toHaveBeenCalledWith('online', onOnline)
    window.dispatchEvent(new Event('online'))
    expect(onOnline).toHaveBeenCalledTimes(1)

    unsubscribe()
    expect(removeEventListener).toHaveBeenCalledWith('online', onOnline)
  })
})

describe('sync binding: start failure and teardown', () => {
  it('logs a failed start rather than rejecting (the login path is fire-and-forget)', async () => {
    cores.startRejection = new Error('bring-up failed')

    await expect(
      syncController.restart({ session: fakeSession() })
    ).resolves.toBeUndefined()
  })

  it('resets the status store when replication stops', async () => {
    await syncController.restart({ session: fakeSession() })
    statusStore.reset.mockClear()

    await syncController.stop()
    expect(cores.instances[0].stop).toHaveBeenCalledTimes(1)
    expect(statusStore.reset).toHaveBeenCalled()
  })
})
