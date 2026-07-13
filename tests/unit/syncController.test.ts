/**
 * Unit tests for `SyncController`'s lifecycle contract
 * (`src/stores/syncController.ts`), focused on the re-login / account-switch
 * fix: the login path must tear down a controller left running by a previous
 * session before starting the new one. A bare `start()` no-ops on its
 * already-running guard, so `restart()` (stop-then-start, serialized) is the
 * login entry point.
 *
 * The RxDB replication machinery and the WAS sync port are mocked so the test
 * exercises only the controller's own lifecycle bookkeeping: how many
 * replications it creates, which it cancels, and how it serializes overlapping
 * transitions. `app.config` is mocked to configure a remote WAS replica (a
 * truthy `WAS_SERVER_URL`) so the controller does not bail on the no-remote
 * guard.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/app.config', () => ({
  WAS_SERVER_URL: 'https://was.example',
  WAS_SYNC_BATCH_SIZE: undefined,
  WAS_SYNC_RETRY_MS: undefined,
  SYNCED_COLLECTIONS: [
    { key: 'privateCredentials', id: 'private-credentials' },
    { key: 'publicCredentials', id: 'public-credentials' },
    { key: 'walletActivity', id: 'wallet-activity' }
  ]
}))

vi.mock('@/stores/wasSyncPort', () => ({
  createWasSyncPort: vi.fn(() => ({ fakePort: true }))
}))

// Each `createWasReplication` call yields a distinct fake replication state so
// the test can count creations and track which states get cancelled.
const createdStates: Array<{ id: string; cancel: ReturnType<typeof vi.fn> }> =
  []
vi.mock('@/lib/sync', () => ({
  createWasReplication: vi.fn(({ replicationIdentifier }) => {
    const state = {
      id: replicationIdentifier,
      cancel: vi.fn().mockResolvedValue(undefined),
      reSync: vi.fn(),
      active$: { subscribe: vi.fn(() => ({ unsubscribe: vi.fn() })) },
      error$: { subscribe: vi.fn(() => ({ unsubscribe: vi.fn() })) }
    }
    createdStates.push(state)
    return state
  })
}))

import { createWasReplication } from '@/lib/sync'
import { syncController } from '@/stores/syncController'
import type { Session } from '@/types/auth'

const COLLECTION_COUNT = 3

/**
 * Builds a minimal non-guest session whose storage looks like it has a
 * configured remote WAS replica, so the controller proceeds past its guards.
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
      localCollection: vi.fn(() => ({ fakeCollection: true })),
      collectionCapability: vi.fn(() => undefined)
    }
  } as unknown as Session
}

beforeEach(() => {
  createdStates.length = 0
  vi.mocked(createWasReplication).mockClear()
})

afterEach(async () => {
  await syncController.stop()
})

describe('SyncController lifecycle', () => {
  it('a bare second start() no-ops on the already-running guard', async () => {
    await syncController.start({ session: fakeSession({ spaceId: 'A' }) })
    expect(createWasReplication).toHaveBeenCalledTimes(COLLECTION_COUNT)

    await syncController.start({ session: fakeSession({ spaceId: 'A' }) })
    // Still only the first batch: this is exactly the bug `restart()` fixes.
    expect(createWasReplication).toHaveBeenCalledTimes(COLLECTION_COUNT)
  })

  it('restart() cancels the running replications and starts fresh', async () => {
    await syncController.restart({ session: fakeSession({ spaceId: 'A' }) })
    expect(createWasReplication).toHaveBeenCalledTimes(COLLECTION_COUNT)
    const firstBatch = createdStates.slice(0, COLLECTION_COUNT)

    await syncController.restart({ session: fakeSession({ spaceId: 'B' }) })
    // Old replications torn down, a new batch created.
    for (const state of firstBatch) {
      expect(state.cancel).toHaveBeenCalledTimes(1)
    }
    expect(createWasReplication).toHaveBeenCalledTimes(2 * COLLECTION_COUNT)
    // The new batch targets account B's space.
    const secondBatch = createdStates.slice(COLLECTION_COUNT)
    for (const state of secondBatch) {
      expect(state.id).toContain(':B:')
      expect(state.cancel).not.toHaveBeenCalled()
    }
  })

  it('serializes overlapping restart() calls without interleaving', async () => {
    // Two restarts fired without awaiting the first: the queue must run them
    // one after the other, leaving exactly one live batch and no dangling
    // replications from the intermediate transition.
    const first = syncController.restart({
      session: fakeSession({ spaceId: 'A' })
    })
    const second = syncController.restart({
      session: fakeSession({ spaceId: 'B' })
    })
    await Promise.all([first, second])

    // Two full batches created across the two starts...
    expect(createWasReplication).toHaveBeenCalledTimes(2 * COLLECTION_COUNT)
    // ...and the first batch was cancelled by the second restart's stop phase,
    // so only the last batch remains live.
    const firstBatch = createdStates.slice(0, COLLECTION_COUNT)
    const secondBatch = createdStates.slice(COLLECTION_COUNT)
    for (const state of firstBatch) {
      expect(state.cancel).toHaveBeenCalledTimes(1)
    }
    for (const state of secondBatch) {
      expect(state.cancel).not.toHaveBeenCalled()
    }
  })

  it('a guest session does not start replication', async () => {
    const guest = { ...fakeSession({ spaceId: 'A' }), isGuest: true } as Session
    await syncController.start({ session: guest })
    expect(createWasReplication).not.toHaveBeenCalled()
  })
})
