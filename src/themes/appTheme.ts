export const APP_THEME_STORAGE_KEY = 'fw-theme'

/** Register new themes here and add a matching src/themes/<id>.css file. */
export const APP_THEME_IDS = ['default', 'redish'] as const

export type AppThemeId = (typeof APP_THEME_IDS)[number]

export function isAppThemeId(
  value: string | null | undefined
): value is AppThemeId {
  return APP_THEME_IDS.includes(value as AppThemeId)
}

export function readStoredAppTheme(): AppThemeId {
  const stored = localStorage.getItem(APP_THEME_STORAGE_KEY)
  if (isAppThemeId(stored)) {
    return stored
  }
  return APP_THEME_IDS[0]
}

export function persistAppTheme(themeId: AppThemeId): void {
  localStorage.setItem(APP_THEME_STORAGE_KEY, themeId)
}

export function applyAppThemeToDocument(themeId: AppThemeId): void {
  document.documentElement.dataset.theme = themeId
}
