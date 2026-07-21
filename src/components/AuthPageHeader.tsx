/**
 * Slim top app bar for the pre-auth pages (login, signup, guest mode):
 * brand icon and app name on the left (linking back to the landing page),
 * language / theme / color-mode controls on the right. Mirrors the
 * dashboard app bar so the pre-auth pages read as part of the same
 * application.
 */
import AppBar from '@mui/material/AppBar'
import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { Link as RouterLink } from 'react-router'
import { LanguageSelector } from '@/components/LanguageSelector'
import { ThemeModeToggle } from '@/components/ThemeModeToggle'
import { ThemePicker } from '@/components/ThemePicker'
import { dashboardStyles } from '@/styles/appStyles'
import walletIcon from '@/assets/wallet.svg'

export function AuthPageHeader() {
  const { t } = useTranslation()

  return (
    <AppBar
      position="static"
      color="default"
      elevation={1}
      sx={{ position: 'relative', zIndex: 2 }}
    >
      <Toolbar>
        <Box
          component={RouterLink}
          to="/"
          sx={{
            display: 'flex',
            alignItems: 'center',
            flexGrow: 1,
            color: 'inherit',
            textDecoration: 'none',
            '&:hover': { opacity: 0.8 }
          }}
        >
          <Box
            component="img"
            src={walletIcon}
            alt=""
            sx={dashboardStyles.walletIcon}
          />
          <Typography variant="h6" sx={dashboardStyles.navBrandTitle}>
            {t('common.brand')}
          </Typography>
        </Box>
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
        </Stack>
      </Toolbar>
    </AppBar>
  )
}
