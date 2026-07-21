import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from 'react'
import {
  CssBaseline,
  ThemeProvider,
  createTheme,
  useMediaQuery
} from '@mui/material'
import { AppThemeContext } from '@/context/appThemeContext'
import {
  applyAppThemeToDocument,
  persistAppTheme,
  persistThemeMode,
  readStoredAppTheme,
  readStoredThemeMode,
  type AppThemeId,
  type ThemeMode
} from '@/themes/appTheme'
import { buildMuiThemeOptions } from '@/themes/themeConfig'

export function FreewalletThemeProvider({ children }: { children: ReactNode }) {
  const [themeId, setThemeIdState] = useState<AppThemeId>(readStoredAppTheme)
  // A persisted user override wins; otherwise follow the system preference.
  const [modeOverride, setModeOverride] = useState<ThemeMode | null>(
    readStoredThemeMode
  )
  const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)')
  const mode: ThemeMode = modeOverride ?? (prefersDarkMode ? 'dark' : 'light')

  useEffect(() => {
    applyAppThemeToDocument(themeId)
  }, [themeId])

  const setThemeId = useCallback((nextThemeId: AppThemeId) => {
    persistAppTheme(nextThemeId)
    setThemeIdState(nextThemeId)
  }, [])

  const toggleMode = useCallback(() => {
    const nextMode: ThemeMode = mode === 'dark' ? 'light' : 'dark'
    persistThemeMode(nextMode)
    setModeOverride(nextMode)
  }, [mode])

  const muiTheme = useMemo(
    () => createTheme(buildMuiThemeOptions(themeId, mode)),
    [themeId, mode]
  )

  const appThemeContextValue = useMemo(
    () => ({ themeId, setThemeId, mode, toggleMode }),
    [themeId, setThemeId, mode, toggleMode]
  )

  return (
    <AppThemeContext.Provider value={appThemeContextValue}>
      <ThemeProvider theme={muiTheme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </AppThemeContext.Provider>
  )
}
