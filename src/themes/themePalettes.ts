import type { AppThemeId } from '@/themes/appTheme'

type ThemeMode = 'light' | 'dark'

type ThemePaletteValues = {
  background: {
    default: string
    paper: string
  }
  primary: {
    main: string
  }
}

const THEME_PALETTES: Record<
  AppThemeId,
  Record<ThemeMode, ThemePaletteValues>
> = {
  default: {
    light: {
      background: { default: '#f7f7f7', paper: '#ffffff' },
      primary: { main: '#1976d2' }
    },
    dark: {
      background: { default: '#101418', paper: '#171c21' },
      primary: { main: '#90caf9' }
    }
  },
  redish: {
    light: {
      background: { default: '#fff0f0', paper: '#fff8f8' },
      primary: { main: '#c0392b' }
    },
    dark: {
      background: { default: '#3d1515', paper: '#4a1a1a' },
      primary: { main: '#e57373' }
    }
  }
}

export function getThemePalette(
  themeId: AppThemeId,
  mode: ThemeMode
): ThemePaletteValues {
  return THEME_PALETTES[themeId][mode]
}

/** CSS token values kept in sync with MUI palette for non-MUI surfaces. */
export function getThemeCssTokens(
  themeId: AppThemeId,
  mode: ThemeMode
): { bg: string; surface: string } {
  const { background } = getThemePalette(themeId, mode)
  return {
    bg: background.default,
    surface: background.paper
  }
}
