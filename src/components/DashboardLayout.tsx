import Box from '@mui/material/Box'
import Drawer from '@mui/material/Drawer'
import List from '@mui/material/List'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemText from '@mui/material/ListItemText'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import { dashboardStyles } from '@/styles/appStyles'
import { Link as RouterLink, useLocation } from 'react-router'
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

export function DashboardLayout({
  title,
  children
}: DashboardLayoutProps) {
  const { pathname } = useLocation()

  return (
    <Box sx={dashboardStyles.container}>
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
