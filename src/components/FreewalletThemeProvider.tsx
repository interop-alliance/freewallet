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
          primary: {
            main:  '#F25C2A',
            light: '#FBE6DC',
            dark:  '#e44d1d'
          },
          background: prefersDarkMode
            ? { default: '#0E0D11', paper: '#1B1A22' }
            : { default: '#FAF6EF', paper: '#FFFFFF' }
        },
        typography: {
          fontFamily:
            '"Helvetica Neue", Helvetica, Inter, system-ui, sans-serif'
        },
        components: {
          MuiButton: {
            styleOverrides: {
              root: {
                whiteSpace: 'nowrap',
                borderRadius: 'var(--fw-radius-md)',
                fontWeight: 700,
                letterSpacing: '0.4px',
              },
              sizeLarge: {
                height: 50,
                minWidth: 160,
                padding: '0 22px',
                fontSize: 13,
              },
              contained: {
                '&:not(:disabled)': {
                  boxShadow: 'var(--fw-shadow-primary)',
                },
                '&:hover': {
                  boxShadow: 'var(--fw-shadow-primary)',
                },
              },
            },
          },
          MuiCard: {
            styleOverrides: {
              root: {
                borderRadius: 'var(--fw-radius-lg)',
              },
            },
          },
          MuiOutlinedInput: {
            styleOverrides: {
              root: {
                borderRadius: 'var(--fw-radius-md)',
                '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                  borderColor: 'var(--fw-orange)',
                },
              },
            },
          },
          MuiDrawer: {
            styleOverrides: {
              paper: {
                borderRight: '1px solid var(--fw-hairline)',
              },
            },
          },
        },
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
