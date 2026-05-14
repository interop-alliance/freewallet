import { useEffect } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { Typography, Box } from '@mui/material'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'

export function LogoutPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const logout = useAuthStore(state => state.logout)
  const navigate = useNavigate()

  useEffect(() => {
    if (session) {
      if (session.isGuest) {
        console.log('Wiping user data...')
        session.storage?.wipeStorage({ profile: session.profile }).then(() => {
          console.log('User data cleared.')
          window.location.href = '/'
        })
      }
      logout().then(() => navigate('/', { replace: true }))
    } else {
      navigate('/', { replace: true })
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
      <Typography variant="h5">{t('logout.message')}</Typography>
    </Box>
  )
}
