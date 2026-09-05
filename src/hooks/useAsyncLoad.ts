import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type DependencyList
} from 'react'

/**
 * React hook for the one load-on-mount shape every page and section shares:
 * run an async `load`, hold its result, and never set state on a component
 * whose effect has since been cleaned up.
 *
 * The cancellation guard lives here instead of in each effect. Every run
 * takes a fresh run id; the effect cleanup (a deps change or an unmount) and
 * every later run supersede it, so a superseded run's result is dropped
 * rather than written over a newer one. Loaders that set state of their own
 * as they go (a listing that lands before its counts, say) get the same guard
 * as `isCancelled` and check it before each write.
 *
 * `reload` re-runs `load` on demand and resolves once it has settled. It does
 * not flip `loading` back on: a manual refresh keeps the current data on
 * screen behind whatever indicator the caller shows for it.
 *
 * `load` is read through a ref, so it need not be memoized; `deps` is what
 * decides when the effect re-runs, checked by `react-hooks/exhaustive-deps`
 * like a `useEffect` list.
 *
 * @param load {(options: { isCancelled: () => boolean }) => Promise<T>}
 * @param deps {DependencyList} - Re-runs the load when these change.
 * @param [options] {object}
 * @param [options.enabled] {boolean} - When false, nothing runs and
 *   `loading` is false. Defaults to `true`.
 * @param [options.onError] {(err: unknown) => void} - Called with the thrown
 *   value of a failed run, cancelled or not; the place to log.
 * @returns {{ data: T | undefined, loading: boolean, error: unknown,
 *   reload: () => Promise<void> }}
 */
export function useAsyncLoad<T>(
  load: (options: { isCancelled: () => boolean }) => Promise<T>,
  deps: DependencyList,
  {
    enabled = true,
    onError
  }: { enabled?: boolean; onError?: (err: unknown) => void } = {}
): {
  data: T | undefined
  loading: boolean
  error: unknown
  reload: () => Promise<void>
} {
  const [data, setData] = useState<T | undefined>(undefined)
  const [error, setError] = useState<unknown>(null)
  // The deps list as one identity. A deps change mints a new generation, so
  // `loading` flips on in that same render with no state reset; a run marks
  // the generation it settled.
  // eslint-disable-next-line react-hooks/exhaustive-deps, react-hooks/use-memo
  const generation = useMemo(() => ({}), deps)
  const [settledGeneration, setSettledGeneration] = useState<object | null>(
    null
  )
  const runIdRef = useRef(0)
  const loadRef = useRef(load)
  const onErrorRef = useRef(onError)

  // Declared before the load effect so the refs are fresh when it runs.
  useEffect(() => {
    loadRef.current = load
    onErrorRef.current = onError
  })

  const startRun = useCallback((settles: object) => {
    const runId = ++runIdRef.current
    const isCancelled = () => runIdRef.current !== runId
    const done = (async () => {
      try {
        const result = await loadRef.current({ isCancelled })
        if (!isCancelled()) {
          setData(result)
          setError(null)
        }
      } catch (err) {
        onErrorRef.current?.(err)
        if (!isCancelled()) {
          setError(err)
        }
      } finally {
        if (!isCancelled()) {
          setSettledGeneration(settles)
        }
      }
    })()
    // Supersedes this run: its writes are dropped from here on.
    const cancel = () => {
      if (runIdRef.current === runId) {
        runIdRef.current++
      }
    }
    return { done, cancel }
  }, [])

  useEffect(() => {
    if (!enabled) {
      return
    }
    return startRun(generation).cancel
  }, [enabled, generation, startRun])

  const reload = useCallback(
    () => startRun(generation).done,
    [startRun, generation]
  )

  return {
    data,
    loading: enabled && settledGeneration !== generation,
    error,
    reload
  }
}
