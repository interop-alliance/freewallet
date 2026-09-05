import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useAsyncLoad } from './useAsyncLoad'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

/**
 * Renders a probe component around the hook and exposes its latest return
 * value, without a testing library.
 */
async function mount<T>(
  props: () => Parameters<typeof useAsyncLoad<T>>
): Promise<{
  latest: () => ReturnType<typeof useAsyncLoad<T>>
  rerender: () => Promise<void>
  unmount: () => Promise<void>
}> {
  const container = document.createElement('div')
  const root: Root = createRoot(container)
  let latest: ReturnType<typeof useAsyncLoad<T>> | undefined
  function Probe() {
    latest = useAsyncLoad<T>(...props())
    return null
  }
  const render = () =>
    act(async () => {
      root.render(<Probe />)
    })
  await render()
  return {
    latest: () => {
      if (!latest) {
        throw new Error('not rendered')
      }
      return latest
    },
    rerender: render,
    unmount: () =>
      act(async () => {
        root.unmount()
      })
  }
}

describe('useAsyncLoad', () => {
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('holds the loaded value and reports loading until it settles', async () => {
    let resolve!: (value: string) => void
    const probe = await mount<string>(() => [
      () => new Promise<string>(res => (resolve = res)),
      []
    ])
    await act(async () => {})
    expect(probe.latest().loading).toBe(true)
    expect(probe.latest().data).toBeUndefined()
    await act(async () => resolve('loaded'))
    expect(probe.latest()).toMatchObject({
      loading: false,
      data: 'loaded',
      error: null
    })
  })

  it('surfaces a thrown value as error and reports it to onError', async () => {
    const failure = new Error('boom')
    const onError = vi.fn()
    const probe = await mount<string>(() => [
      () => Promise.reject(failure),
      [],
      { onError }
    ])
    await act(async () => {})
    expect(probe.latest()).toMatchObject({ loading: false, error: failure })
    expect(onError).toHaveBeenCalledWith(failure)
  })

  it('drops the result of a run superseded by a deps change', async () => {
    const resolvers: Array<(value: string) => void> = []
    let dep = 'a'
    const probe = await mount<string>(() => [
      () =>
        new Promise<string>(res => {
          // Resolves whether or not the run was superseded; the hook must
          // ignore the stale one on its own.
          resolvers.push(res)
        }),
      [dep]
    ])
    await act(async () => {})
    dep = 'b'
    await probe.rerender()
    expect(resolvers).toHaveLength(2)
    await act(async () => resolvers[0]('stale'))
    expect(probe.latest().data).toBeUndefined()
    expect(probe.latest().loading).toBe(true)
    await act(async () => resolvers[1]('fresh'))
    expect(probe.latest()).toMatchObject({ loading: false, data: 'fresh' })
  })

  it('tells the loader it was cancelled after unmount', async () => {
    let cancelledAtResolve: boolean | undefined
    let resolve!: () => void
    const probe = await mount<void>(() => [
      async ({ isCancelled }) => {
        await new Promise<void>(res => (resolve = res))
        cancelledAtResolve = isCancelled()
      },
      []
    ])
    await act(async () => {})
    await probe.unmount()
    await act(async () => resolve())
    expect(cancelledAtResolve).toBe(true)
  })

  it('reload re-runs the load without flipping loading back on', async () => {
    let value = 'first'
    const probe = await mount<string>(() => [async () => value, []])
    await act(async () => {})
    expect(probe.latest().data).toBe('first')
    value = 'second'
    let loadingDuringReload: boolean | undefined
    await act(async () => {
      const reloading = probe.latest().reload()
      loadingDuringReload = probe.latest().loading
      await reloading
    })
    expect(loadingDuringReload).toBe(false)
    expect(probe.latest().data).toBe('second')
  })

  it('runs nothing while disabled and reports not loading', async () => {
    const load = vi.fn(async () => 'x')
    const probe = await mount<string>(() => [load, [], { enabled: false }])
    await act(async () => {})
    expect(load).not.toHaveBeenCalled()
    expect(probe.latest().loading).toBe(false)
  })
})
