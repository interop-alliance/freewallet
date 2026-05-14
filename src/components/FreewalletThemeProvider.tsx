import { useMemo, type ReactNode } from 'react'
import {
  CssBaseline,
  ThemeProvider,
  createTheme,
  useMediaQuery
} from '@mui/material'

export function FreewalletThemeProvider({ children }: { children: ReactNode }) {
  const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)')
  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: prefersDarkMode ? 'dark' : 'light',
          background: prefersDarkMode
            ? {
                default: '#101418',
                paper: '#171c21'
              }
            : {
                default: '#f7f7f7',
                paper: '#ffffff'
              }
        },
        typography: {
          fontFamily:
            '"Inter", "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
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
      }),
    [prefersDarkMode]
  )

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {children}
    </ThemeProvider>
  )
}
