/**
 * The UI-prefs sibling of the persistence strategy
 * (`src/session/persistence.ts` is the session half): global preferences --
 * the theme and the UI language -- are not session state, so they cannot ride
 * the profile's persistence strategy, but a transient visit must still leave
 * no browser-local residue. While the transient session is active, writes
 * land in an in-memory overlay that shadows reads and dies with the tab;
 * otherwise reads and writes go to localStorage as before. Reads outside
 * the overlay still fall through to
 * localStorage -- a public terminal's stored prefs belong to the terminal
 * and reading them writes nothing.
 */

let overlay: Map<string, string> | null = null

/**
 * Switches the prefs storage tier. Activated when a transient session logs in
 * and deactivated (overlay discarded) when it ends; the auth store drives it
 * from the session's persistence strategy.
 *
 * @param options {object}
 * @param options.active {boolean}
 * @returns {void}
 */
export function setTransientPrefs({ active }: { active: boolean }): void {
  overlay = active ? new Map() : null
}

/**
 * Reads one preference: the transient overlay first, then localStorage.
 *
 * @param key {string}
 * @returns {string | null}
 */
export function readPref(key: string): string | null {
  if (overlay?.has(key)) {
    return overlay.get(key) ?? null
  }
  if (typeof localStorage === 'undefined') {
    return null
  }
  return localStorage.getItem(key)
}

/**
 * Writes one preference: into the overlay while the transient session is
 * active, into localStorage otherwise.
 *
 * @param options {object}
 * @param options.key {string}
 * @param options.value {string}
 * @returns {void}
 */
export function writePref({
  key,
  value
}: {
  key: string
  value: string
}): void {
  if (overlay) {
    overlay.set(key, value)
    return
  }
  if (typeof localStorage === 'undefined') {
    return
  }
  localStorage.setItem(key, value)
}
