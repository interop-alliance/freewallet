import { useParams, Link as RouterLink } from 'react-router'
import AppBar from '@mui/material/AppBar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import walletIcon from '@/assets/wallet.svg'
import { useAuthStore } from '@/stores/authStore'
import { dashboardStyles } from '@/styles/appStyles'
import { DocContent } from '@/components/DocContent'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { LanguageSelector } from '@/components/LanguageSelector'
import Stack from '@mui/material/Stack'
import { useTranslation } from 'react-i18next'

export function DocsPage() {
  const { t } = useTranslation()
  const { fileName } = useParams()
  const session = useAuthStore(state => state.session)

  if (!fileName) {
    return <NotFoundPage />
  }

  return (
    <Box>
      <AppBar position="fixed" color="default" elevation={1}>
        <Toolbar>
          <Box
            component={RouterLink}
            to="/"
            sx={dashboardStyles.appBarBrandLink}
          >
            <Box
              component="img"
              src={walletIcon}
              alt={t('common.brand')}
              sx={dashboardStyles.walletIcon}
            />
            <Typography variant="h6" sx={dashboardStyles.navBrandTitle}>
              {t('common.brand')}
            </Typography>
          </Box>
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
            <LanguageSelector showLabel={false} />
            {session ? (
              <Button variant="outlined" component={RouterLink} to="/logout">
                {t('common.logOut')}
              </Button>
            ) : (
              <Button variant="outlined" component={RouterLink} to="/login">
                {t('common.logIn')}
              </Button>
            )}
          </Stack>
        </Toolbar>
      </AppBar>
      <Box sx={{ maxWidth: 780, mx: 'auto', px: { xs: 2, md: 4 }, pt: 4 }}>
        <Toolbar />
        <DocContent key={fileName} fileName={fileName} />
      </Box>
    </Box>
  )
}
