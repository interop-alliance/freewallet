export const APP_THEME_STORAGE_KEY = 'fw-theme'
export const APP_THEME_MODE_STORAGE_KEY = 'fw-theme-mode'

export type ThemeMode = 'light' | 'dark'

/**
 * Register new themes here and add a matching src/themes/<id>.css file.
 */
export const APP_THEME_IDS = ['default', 'west-coast'] as const

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

/**
 * @returns {ThemeMode | null} The user's persisted light/dark override, or
 *   null when the system preference should be followed.
 */
export function readStoredThemeMode(): ThemeMode | null {
  const stored = localStorage.getItem(APP_THEME_MODE_STORAGE_KEY)
  if (stored === 'light' || stored === 'dark') {
    return stored
  }
  return null
}

export function persistThemeMode(mode: ThemeMode): void {
  localStorage.setItem(APP_THEME_MODE_STORAGE_KEY, mode)
}

export function persistAppTheme(themeId: AppThemeId): void {
  localStorage.setItem(APP_THEME_STORAGE_KEY, themeId)
}

export function applyAppThemeToDocument(themeId: AppThemeId): void {
  document.documentElement.dataset.theme = themeId
}
