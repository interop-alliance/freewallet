/**
 * Extracts up to two uppercase initials from a name string.
 * Returns '?' for empty/falsy input.
 */
export function initials(name: string): string {
  if (!name) {
    return '?'
  }
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map(w => w[0])
    .join('')
    .toUpperCase()
}
