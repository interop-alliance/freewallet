import AppBar from '@mui/material/AppBar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Drawer from '@mui/material/Drawer'
import List from '@mui/material/List'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemText from '@mui/material/ListItemText'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import { dashboardStyles } from '@/styles/appStyles'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router'
import { useAuthStore } from '@/stores/authStore'
import walletIcon from '@/assets/wallet.svg'
import type { ReactNode } from 'react'

interface DashboardLayoutProps {
  title: string
  children?: ReactNode
}

const navItems = [
  { label: 'Dashboard', to: '/dashboard' },
  { label: 'History', to: '/history' },
  { label: 'Settings', to: '/settings' }
]

export function DashboardLayout({ title, children }: DashboardLayoutProps) {
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
            alt="Freewallet"
            sx={dashboardStyles.walletIcon}
          />
          <Typography variant="h6" sx={{ flexGrow: 1, ...dashboardStyles.navBrandTitle }}>
            Freewallet
          </Typography>
          {session ? (
            <Button variant="outlined" onClick={handleLogout}>
              Log out
            </Button>
          ) : (
            <Button variant="outlined" component={RouterLink} to="/login">
              Log in
            </Button>
          )}
        </Toolbar>
      </AppBar>

      <Drawer variant="permanent" sx={dashboardStyles.drawer}>
        <Toolbar />
        <List sx={dashboardStyles.navList}>
          {navItems.map(item => (
            <ListItemButton
              key={item.to}
              component={RouterLink}
              to={item.to}
              selected={pathname === item.to}
              sx={dashboardStyles.navItem}
            >
              <ListItemText
                primary={item.label}
                sx={dashboardStyles.navItemText}
              />
            </ListItemButton>
          ))}
        </List>
      </Drawer>

      <Box component="main" sx={dashboardStyles.main}>
        <Toolbar />
        <Typography variant="h2" component="h1" sx={dashboardStyles.title}>
          {title}
        </Typography>
        {children}
      </Box>
    </Box>
  )
}
