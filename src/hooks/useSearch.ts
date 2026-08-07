import { useMemo, useState } from 'react'
import Fuse, { type FuseOptionKey } from 'fuse.js'

/**
 * React hook wrapping a Fuse.js fuzzy-search index over a list of items, for
 * reuse across every page that needs a search box over an in-memory list
 * (history, credentials, contacts, ...).
 *
 * Index construction is the expensive part, so it's memoized on `items`
 * (and `keys`/`threshold`/`minMatchCharLength`) independently of `query` --
 * typing re-runs `fuse.search` against the standing index rather than
 * rebuilding it. `keys` should be referentially stable across renders (a
 * module-level constant, not an inline array literal) since it participates
 * in that memoization.
 *
 * @param options {object}
 * @param options.items {T[]}
 * @param options.keys {FuseOptionKey<T>[]} - Fuse.js key paths, e.g.
 *   `[{ name: 'doc.summary', weight: 0.7 }]`.
 * @param [options.threshold] {number} - Fuse.js match threshold (0 = exact,
 *   1 = match anything). Defaults to `0.35`.
 * @param [options.minMatchCharLength] {number} - Minimum query length before
 *   a fuzzy match counts. Defaults to `2`.
 * @returns {{ query: string, setQuery: (query: string) => void, results: T[] }}
 */
export function useSearch<T>({
  items,
  keys,
  threshold = 0.35,
  minMatchCharLength = 2
}: {
  items: T[]
  keys: FuseOptionKey<T>[]
  threshold?: number
  minMatchCharLength?: number
}) {
  const [query, setQuery] = useState('')

  const fuse = useMemo(
    () =>
      new Fuse(items, {
        keys,
        threshold,
        minMatchCharLength,
        ignoreLocation: true
      }),
    [items, keys, threshold, minMatchCharLength]
  )

  // Memoized so the returned array keeps a stable identity between renders --
  // consumers key their own memos on it.
  const results = useMemo(() => {
    const normalizedQuery = query.trim()
    return normalizedQuery
      ? fuse.search(normalizedQuery).map(result => result.item)
      : items
  }, [fuse, query, items])

  return { query, setQuery, results }
}
