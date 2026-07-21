import { createContext, useContext } from 'react'
import type { AppThemeId, ThemeMode } from '@/themes/appTheme'

export type AppThemeContextValue = {
  themeId: AppThemeId
  setThemeId: (themeId: AppThemeId) => void
  mode: ThemeMode
  toggleMode: () => void
}

export const AppThemeContext = createContext<AppThemeContextValue | null>(null)

export function useAppTheme(): AppThemeContextValue {
  const context = useContext(AppThemeContext)
  if (!context) {
    throw new Error('useAppTheme must be used within FreewalletThemeProvider')
  }
  return context
}
