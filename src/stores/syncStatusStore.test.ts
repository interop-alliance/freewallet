/**
 * Unit tests for `awaitCollectionsInSync`: the courtesy wait a bulk read
 * (the content migration's merge checks) takes before it decides against a
 * replica that may still be catching up.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it } from 'vitest'
import {
  awaitCollectionsInSync,
  useSyncStatusStore
} from '@/stores/syncStatusStore'

afterEach(() => {
  useSyncStatusStore.getState().reset()
})

describe('awaitCollectionsInSync', () => {
  it('resolves at once when every collection has settled', async () => {
    const { setStatus } = useSyncStatusStore.getState()
    setStatus('contacts', 'synced')
    setStatus('private-credentials', 'error')

    await expect(
      awaitCollectionsInSync({
        collectionIds: ['contacts', 'private-credentials', 'wallet-activity'],
        timeoutMs: 50
      })
    ).resolves.toBe(true)
  })

  it('gives up after the timeout while a collection is still syncing', async () => {
    useSyncStatusStore.getState().setStatus('contacts', 'syncing')

    await expect(
      awaitCollectionsInSync({ collectionIds: ['contacts'], timeoutMs: 20 })
    ).resolves.toBe(false)
  })

  it('resolves as soon as the last syncing collection settles', async () => {
    const { setStatus } = useSyncStatusStore.getState()
    setStatus('contacts', 'syncing')
    const waiting = awaitCollectionsInSync({
      collectionIds: ['contacts'],
      timeoutMs: 2000
    })
    setStatus('contacts', 'synced')

    await expect(waiting).resolves.toBe(true)
  })
})
