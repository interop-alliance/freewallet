/**
 * The app bar's right-hand control cluster: the labelled language and theme
 * pickers plus the colour-mode toggle, shared by the dashboard app bar and the
 * pre-auth page header so the two read as the same application. Anything a
 * caller passes as children (the dashboard's log in / log out button) sits at
 * the end of the same row.
 */
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { LanguageSelector } from '@/components/LanguageSelector'
import { ThemeModeToggle } from '@/components/ThemeModeToggle'
import { ThemePicker } from '@/components/ThemePicker'
import { dashboardStyles } from '@/styles/appStyles'

/**
 * Renders the app bar control cluster.
 *
 * @param options {object}
 * @param [options.children] {ReactNode}   extra controls for the end of the row
 * @returns {JSX.Element}
 */
export function AppBarControls({ children }: { children?: ReactNode }) {
  const { t } = useTranslation()

  return (
    <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
      <Stack sx={dashboardStyles.navControlGroup}>
        <Typography component="span" sx={dashboardStyles.navControlLabel}>
          {t('common.language')}:
        </Typography>
        <LanguageSelector showLabel={false} />
      </Stack>
      <Stack sx={dashboardStyles.navControlGroup}>
        <Typography component="span" sx={dashboardStyles.navControlLabel}>
          {t('common.theme')}:
        </Typography>
        <ThemePicker showLabel={false} />
      </Stack>
      <ThemeModeToggle />
      {children}
    </Stack>
  )
}
