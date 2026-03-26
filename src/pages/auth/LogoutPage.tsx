import { useEffect } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { Typography, Box } from '@mui/material'
import { useNavigate } from 'react-router'

export function LogoutPage() {
  const session = useAuthStore(state => state.session)
  const logout = useAuthStore(state => state.logout)
  const navigate = useNavigate()

  useEffect(() => {
    if (session) {
      logout(session).then(() => navigate('/'))
    } else {
      navigate('/')
    }
  }, [logout, navigate, session])

  return (
    <Box
      sx={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh'
      }}
    >
      <Typography variant="h5">Logging out...</Typography>
    </Box>
  )
}
