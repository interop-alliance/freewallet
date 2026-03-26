import { Navigate, Outlet, useNavigate } from 'react-router'
import { AppBar, Box, Button, Toolbar, Typography } from '@mui/material'
import walletIcon from '@/assets/wallet.svg'
import { useAuthStore } from '@/stores/authStore'
import { useEffect } from 'react'

export function ProtectedRoute() {
  const session = useAuthStore(state => state.session)
  const navigate = useNavigate()
  useEffect(() => {
    console.log('Session:', session)
  })

  if (!session) {
    return <Navigate to="/logout" replace />
  }

  const handleLogout = () => {
    navigate('/logout')
  }

  return (
    <>
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
            alt="Wallet icon"
            sx={{ width: 28, height: 28, mr: 1.5 }}
          />
          <Typography variant="h6" sx={{ flexGrow: 1, fontWeight: 600 }}>
            Freewallet
          </Typography>
          <Button variant="outlined" onClick={handleLogout}>
            Log out
          </Button>
        </Toolbar>
      </AppBar>
      <Outlet />
    </>
  )
}
