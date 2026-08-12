/**
 * Locales in the language selector. `name` is the spelled-out language name.
 * When adding a locale: append here and register resources in `i18n/index.ts`.
 */
export const UI_LANGUAGES = [
  { code: 'es', name: 'Español' },
  { code: 'en', name: 'English' }
] as const

export type UiLanguageCode = (typeof UI_LANGUAGES)[number]['code']

const UI_LANGUAGE_STORAGE_KEY = 'fw-ui-language'

export function languageOptionLabel(code: UiLanguageCode): string {
  const row = UI_LANGUAGES.find(lang => lang.code === code)
  return row ? `${row.code} | ${row.name}` : code
}

export function supportedUiLanguageCodes(): UiLanguageCode[] {
  return UI_LANGUAGES.map(lang => lang.code)
}

function isUiLanguageCode(
  value: string | null | undefined
): value is UiLanguageCode {
  return UI_LANGUAGES.some(lang => lang.code === value)
}

/**
 * Picks a supported UI language from an ordered list of locale preferences
 * (e.g. `navigator.languages`). Matches each candidate on its base subtag
 * (e.g. `es-MX` -> `es`), case-insensitively, so a less-preferred entry can
 * still win over an unsupported top choice. Falls back to 'en' when nothing
 * in the list is supported.
 */
export function detectUiLanguage(languages: readonly string[]): UiLanguageCode {
  for (const lng of languages) {
    const base = lng.split('-')[0]?.toLowerCase() ?? ''
    if (isUiLanguageCode(base)) {
      return base
    }
  }
  return 'en'
}

/**
 * Maps a single `i18n.language`-style value (e.g. es-MX) to a supported UI
 * code, falling back to 'en' when unsupported.
 */
export function normalizeToUiLanguageCode(lng: string): UiLanguageCode {
  return detectUiLanguage([lng])
}

/**
 * The user's persisted language choice, or null when none has been made yet
 * -- in which case the caller should fall back to browser-locale detection.
 */
export function readStoredUiLanguage(): UiLanguageCode | null {
  const stored = localStorage.getItem(UI_LANGUAGE_STORAGE_KEY)
  return isUiLanguageCode(stored) ? stored : null
}

export function persistUiLanguage(code: UiLanguageCode): void {
  localStorage.setItem(UI_LANGUAGE_STORAGE_KEY, code)
}
