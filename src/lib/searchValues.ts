/**
 * Walks an arbitrary JSON-shaped value down to its leaves and returns every
 * string/number/boolean found -- the shared traversal behind every "search
 * across all fields" index (credentials, contacts, ...). `excludeKeys` skips
 * whole subtrees by key name, e.g. a credential's `proof`, which is
 * cryptographic material rather than user-facing data. Each leaf comes back
 * as its own array entry (rather than one joined blob) so Fuse.js matches
 * against short field values instead of fuzzy-matching across a huge string.
 *
 * @param root {unknown}
 * @param [excludeKeys] {string[]}
 * @returns {string[]}
 */
export function flattenSearchValues(
  root: unknown,
  excludeKeys: string[] = []
): string[] {
  const values: string[] = []
  const stack: unknown[] = [root]
  while (stack.length > 0) {
    const node = stack.pop()
    if (node === null || node === undefined) {
      continue
    }
    if (typeof node === 'string') {
      values.push(node)
    } else if (typeof node === 'number' || typeof node === 'boolean') {
      values.push(String(node))
    } else if (Array.isArray(node)) {
      stack.push(...node)
    } else if (typeof node === 'object') {
      for (const [key, value] of Object.entries(node)) {
        if (!excludeKeys.includes(key)) {
          stack.push(value)
        }
      }
    }
  }
  return values
}
