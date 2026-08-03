import { afterEach, describe, expect, it } from 'vitest'
import {
  detectUiLanguage,
  normalizeToUiLanguageCode,
  persistUiLanguage,
  readStoredUiLanguage
} from './uiLanguages'

describe('detectUiLanguage', () => {
  it('picks the first supported language in preference order', () => {
    expect(detectUiLanguage(['fr', 'es-MX', 'en'])).toBe('es')
  })

  it('matches on the base subtag, case-insensitively', () => {
    expect(detectUiLanguage(['EN-us'])).toBe('en')
  })

  it('falls back to en when nothing in the list is supported', () => {
    expect(detectUiLanguage(['fr', 'de'])).toBe('en')
  })

  it('falls back to en for an empty list', () => {
    expect(detectUiLanguage([])).toBe('en')
  })
})

describe('normalizeToUiLanguageCode', () => {
  it('maps a regional variant to its base language', () => {
    expect(normalizeToUiLanguageCode('es-MX')).toBe('es')
  })

  it('falls back to en for an unsupported locale', () => {
    expect(normalizeToUiLanguageCode('fr-FR')).toBe('en')
  })
})

describe('readStoredUiLanguage / persistUiLanguage', () => {
  afterEach(() => {
    localStorage.clear()
  })

  it('returns null when nothing has been persisted', () => {
    expect(readStoredUiLanguage()).toBeNull()
  })

  it('returns the persisted choice', () => {
    persistUiLanguage('es')
    expect(readStoredUiLanguage()).toBe('es')
  })

  it('ignores a corrupted/unsupported stored value', () => {
    localStorage.setItem('fw-ui-language', 'not-a-language')
    expect(readStoredUiLanguage()).toBeNull()
  })
})
