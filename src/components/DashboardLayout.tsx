import Box from '@mui/material/Box'
import Drawer from '@mui/material/Drawer'
import List from '@mui/material/List'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemText from '@mui/material/ListItemText'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import walletIcon from '@/assets/wallet.svg'
import { dashboardStyles } from '@/styles/appStyles'
import { Link as RouterLink, useLocation } from 'react-router'
import type { ReactNode } from 'react'

interface DashboardLayoutProps {
  title: string
  children?: ReactNode
  actions?: ReactNode
}

const navItems = [
  { label: 'Dashboard', to: '/dashboard' },
  { label: 'Settings', to: '/settings' }
]

export function DashboardLayout({
  title,
  children,
  actions
}: DashboardLayoutProps) {
  const { pathname } = useLocation()

  return (
    <Box sx={dashboardStyles.container}>
      <Drawer variant="permanent" sx={dashboardStyles.drawer}>
        <Box sx={dashboardStyles.navHeader}>
          <Stack direction="row" spacing={1.5}>
            <Box
              component="img"
              src={walletIcon}
              alt="Wallet icon"
              sx={dashboardStyles.walletIcon}
            />
            <Typography variant="h5" component="p" fontWeight={600}>
              Freewallet
            </Typography>
          </Stack>
        </Box>
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
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="center"
        >
          <Typography variant="h2" component="h1" sx={dashboardStyles.title}>
            {title}
          </Typography>
          {actions}
        </Stack>
        {children}
      </Box>
    </Box>
  )
}
