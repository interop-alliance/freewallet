/**
 * Languages offered in the UI selector (endonyms).
 * When adding a locale: append here and register resources in `i18n/index.ts`.
 */
export const UI_LANGUAGES = [
  { code: 'es', label: 'Español' },
  { code: 'en', label: 'English' }
] as const

export type UiLanguageCode = (typeof UI_LANGUAGES)[number]['code']

export function supportedUiLanguageCodes(): UiLanguageCode[] {
  return UI_LANGUAGES.map(l => l.code)
}

/** Maps `i18n.language` (e.g. es-MX) to a supported UI code. */
export function normalizeToUiLanguageCode(lng: string): UiLanguageCode {
  const base = lng.split('-')[0]?.toLowerCase() ?? ''
  const match = UI_LANGUAGES.find(l => l.code === base)
  return match?.code ?? 'es'
}
