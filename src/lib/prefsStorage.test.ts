/**
 * The UI-prefs half of the posture seam: the transient overlay shadows
 * localStorage for the visit and leaves it untouched.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { readPref, setTransientPrefs, writePref } from '@/lib/prefsStorage'

const KEY = 'fw-prefs-test'

afterEach(() => {
  setTransientPrefs({ active: false })
  localStorage.removeItem(KEY)
})

describe('the prefs storage seam', () => {
  it('reads and writes localStorage in the durable posture', () => {
    writePref({ key: KEY, value: 'stored' })
    expect(localStorage.getItem(KEY)).toBe('stored')
    expect(readPref(KEY)).toBe('stored')
  })

  it('writes only the overlay while the transient posture is active', () => {
    localStorage.setItem(KEY, 'durable')
    setTransientPrefs({ active: true })
    // A pref never toggled this visit still reads the terminal's stored one.
    expect(readPref(KEY)).toBe('durable')
    writePref({ key: KEY, value: 'transient' })
    expect(readPref(KEY)).toBe('transient')
    expect(localStorage.getItem(KEY)).toBe('durable')
  })

  it('discards the overlay when the transient posture ends', () => {
    setTransientPrefs({ active: true })
    writePref({ key: KEY, value: 'transient' })
    setTransientPrefs({ active: false })
    expect(readPref(KEY)).toBeNull()
    expect(localStorage.getItem(KEY)).toBeNull()
  })

  it('starts each transient activation with a fresh overlay', () => {
    setTransientPrefs({ active: true })
    writePref({ key: KEY, value: 'first-visit' })
    setTransientPrefs({ active: true })
    expect(readPref(KEY)).toBeNull()
  })
})
