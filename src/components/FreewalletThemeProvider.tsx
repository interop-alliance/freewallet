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
  readStoredAppTheme,
  type AppThemeId
} from '@/themes/appTheme'
import { getThemePalette } from '@/themes/themePalettes'

export function FreewalletThemeProvider({ children }: { children: ReactNode }) {
  const [themeId, setThemeIdState] = useState<AppThemeId>(readStoredAppTheme)
  const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)')
  const mode = prefersDarkMode ? 'dark' : 'light'

  useEffect(() => {
    applyAppThemeToDocument(themeId)
  }, [themeId])

  const setThemeId = useCallback((nextThemeId: AppThemeId) => {
    persistAppTheme(nextThemeId)
    setThemeIdState(nextThemeId)
  }, [])

  const muiTheme = useMemo(() => {
    const palette = getThemePalette(themeId, mode)

    return createTheme({
      palette: {
        mode,
        background: palette.background,
        primary: palette.primary
      },
      typography: {
        fontFamily: '"Inter", "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
      },
      components: {
        MuiButton: {
          styleOverrides: {
            root: {
              whiteSpace: 'nowrap'
            }
          }
        }
      }
    })
  }, [themeId, mode])

  const appThemeContextValue = useMemo(
    () => ({ themeId, setThemeId }),
    [themeId, setThemeId]
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
