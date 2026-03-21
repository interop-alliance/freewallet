import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Drawer from '@mui/material/Drawer'
import Stack from '@mui/material/Stack'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import { useNavigate } from 'react-router'
import walletIcon from '../assets/wallet.svg'
import { dashboardStyles } from '../styles/appStyles.ts'

export function DashboardPage() {
  const navigate = useNavigate()

  return (
    <Box sx={dashboardStyles.container}>
      <Drawer variant="permanent" sx={dashboardStyles.drawer}>
        <Toolbar />
        <Box sx={dashboardStyles.navHeader}>
          <Stack direction="row" spacing={1.5} alignItems="center">
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
      </Drawer>

      <Box component="main" sx={dashboardStyles.main}>
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="center"
        >
          <Typography variant="h2" component="h1" sx={dashboardStyles.title}>
            Freewallet Dashboard
          </Typography>
          <Button variant="outlined" onClick={() => navigate('/')}>
            Log out
          </Button>
        </Stack>
      </Box>
    </Box>
  )
}
