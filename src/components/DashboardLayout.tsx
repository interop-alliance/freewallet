import Alert from '@mui/material/Alert'
import AppBar from '@mui/material/AppBar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Drawer from '@mui/material/Drawer'
import List from '@mui/material/List'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemText from '@mui/material/ListItemText'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import { LanguageSelector } from '@/components/LanguageSelector'
import { ThemePicker } from '@/components/ThemePicker'
import { Toast } from '@/components/Toast'
import { dashboardStyles } from '@/styles/appStyles'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router'
import { useAuthStore } from '@/stores/authStore'
import walletIcon from '@/assets/wallet.svg'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

interface DashboardLayoutProps {
  title: string
  children?: ReactNode
}

const primaryNavItems = [
  { labelKey: 'nav.dashboard', to: '/dashboard' },
  { labelKey: 'nav.contacts', to: '/contacts' }
] as const

const settingsNavItems = [
  { labelKey: 'nav.applications', to: '/applications' },
  { labelKey: 'nav.storage', to: '/storage' },
  { labelKey: 'nav.history', to: '/history' }
] as const

export function DashboardLayout({ title, children }: DashboardLayoutProps) {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)

  function handleLogout() {
    navigate('/logout')
  }

  return (
    <Box sx={dashboardStyles.container}>
      <AppBar
        position="fixed"
        color="default"
        elevation={1}
        sx={{ zIndex: theme => theme.zIndex.drawer + 1 }}
      >
        <Toolbar>
          <Box
            component="img"
            src={walletIcon}
            alt={t('common.brand')}
            sx={dashboardStyles.walletIcon}
          />
          <Typography
            variant="h6"
            sx={{ flexGrow: 1, ...dashboardStyles.navBrandTitle }}
          >
            {t('common.brand')}
          </Typography>
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
            <LanguageSelector showLabel={false} />
            <ThemePicker showLabel={false} />
            {session ? (
              <Button variant="outlined" onClick={handleLogout}>
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

      <Drawer variant="permanent" sx={dashboardStyles.drawer}>
        <Toolbar />
        <List sx={dashboardStyles.navList}>
          {primaryNavItems.map(item => (
            <ListItemButton
              key={item.to}
              component={RouterLink}
              to={item.to}
              selected={pathname === item.to}
              sx={dashboardStyles.navItem}
            >
              <ListItemText
                primary={t(item.labelKey)}
                sx={dashboardStyles.navItemText}
              />
            </ListItemButton>
          ))}

          <ListItemButton
            component={RouterLink}
            to="/settings"
            selected={pathname === '/settings'}
            sx={dashboardStyles.navSectionTitleButton}
          >
            <ListItemText
              primary={t('nav.settings')}
              sx={dashboardStyles.navSectionTitle}
            />
          </ListItemButton>

          <List sx={dashboardStyles.navSubList}>
            {settingsNavItems.map(item => (
              <ListItemButton
                key={item.to}
                component={RouterLink}
                to={item.to}
                selected={pathname === item.to}
                sx={dashboardStyles.navSubItem}
              >
                <ListItemText
                  primary={t(item.labelKey)}
                  sx={dashboardStyles.navItemText}
                />
              </ListItemButton>
            ))}
          </List>
        </List>
      </Drawer>

      <Box component="main" sx={dashboardStyles.main}>
        <Toolbar />
        {/* A restored (delegated) session whose vault KAK could not be
            recovered from the session vault envelope has locked encrypted
            collections until the user logs back in. */}
        {session?.storage.vaultLocked && (
          <Alert
            severity="info"
            sx={{ mb: 2 }}
            action={
              <Button
                color="inherit"
                size="small"
                component={RouterLink}
                to="/login"
              >
                {t('session.unlock')}
              </Button>
            }
          >
            {t('session.lockedVault')}
          </Alert>
        )}
        <Typography variant="h3" component="h3" sx={dashboardStyles.title}>
          {title}
        </Typography>
        {children}
      </Box>

      <Toast />
    </Box>
  )
}
