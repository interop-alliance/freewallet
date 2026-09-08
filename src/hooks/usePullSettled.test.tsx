import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useSyncStatusStore } from '@/stores/syncStatusStore'
import { usePullSettled } from './usePullSettled'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

/**
 * Renders a probe component around the hook, without a testing library.
 */
async function mount({
  collectionIds,
  onSettled
}: {
  collectionIds: string[]
  onSettled: () => void
}): Promise<{ unmount: () => Promise<void> }> {
  const container = document.createElement('div')
  const root: Root = createRoot(container)
  function Probe() {
    usePullSettled({ collectionIds, onSettled })
    return null
  }
  await act(async () => {
    root.render(<Probe />)
  })
  return {
    unmount: () =>
      act(async () => {
        root.unmount()
      })
  }
}

async function setStatus(collectionId: string, status: 'syncing' | 'synced') {
  await act(async () => {
    useSyncStatusStore.getState().setStatus(collectionId, status)
  })
}

describe('usePullSettled', () => {
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
    useSyncStatusStore.getState().reset()
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('fires once when a watched collection settles out of syncing', async () => {
    const onSettled = vi.fn()
    const probe = await mount({
      collectionIds: ['private-credentials'],
      onSettled
    })
    expect(onSettled).not.toHaveBeenCalled()
    await setStatus('private-credentials', 'syncing')
    expect(onSettled).not.toHaveBeenCalled()
    await setStatus('private-credentials', 'synced')
    expect(onSettled).toHaveBeenCalledTimes(1)
    // A second cycle fires again; a repeated `synced` does not.
    await setStatus('private-credentials', 'synced')
    expect(onSettled).toHaveBeenCalledTimes(1)
    await setStatus('private-credentials', 'syncing')
    await setStatus('private-credentials', 'synced')
    expect(onSettled).toHaveBeenCalledTimes(2)
    await probe.unmount()
  })

  it('ignores collections it does not watch', async () => {
    const onSettled = vi.fn()
    const probe = await mount({
      collectionIds: ['app-connections'],
      onSettled
    })
    await setStatus('contacts', 'syncing')
    await setStatus('contacts', 'synced')
    expect(onSettled).not.toHaveBeenCalled()
    await probe.unmount()
  })

  it('fires once for a status update that settles several watched collections', async () => {
    const onSettled = vi.fn()
    const probe = await mount({
      collectionIds: ['app-connections', 'wallet-activity'],
      onSettled
    })
    await setStatus('app-connections', 'syncing')
    await setStatus('wallet-activity', 'syncing')
    await act(async () => {
      useSyncStatusStore.setState(state => ({
        statuses: {
          ...state.statuses,
          'app-connections': 'synced',
          'wallet-activity': 'synced'
        }
      }))
    })
    expect(onSettled).toHaveBeenCalledTimes(1)
    await probe.unmount()
  })
})
