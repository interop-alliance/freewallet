import { useEffect, useRef } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { Typography, Box } from '@mui/material'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { wipeGuestState } from '@/session/wipe'

export function LogoutPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const logout = useAuthStore(state => state.logout)
  const navigate = useNavigate()
  const didLogout = useRef(false)

  useEffect(() => {
    // Run exactly once. The ref guard neutralises both React StrictMode's
    // double-invoke and the re-run triggered when logout() clears `session`;
    // otherwise multiple deferred navigate('/') calls fire, and a late one can
    // yank the router off whatever page the user has since navigated to.
    if (didLogout.current) {
      return
    }
    didLogout.current = true

    async function performLogout() {
      if (session?.isGuest) {
        console.log('Wiping user data...')
        // The shared wipe enumeration's guest consumer: the replica
        // databases plus the guest's localStorage families (migration
        // markers, local-mode caches). Best-effort -- a blocked replica
        // must not wedge the logout, and the failure is already logged.
        await wipeGuestState({ session })
        console.log('User data cleared.')
        await logout()
        window.location.href = '/'
        return
      }
      await logout()
      navigate('/', { replace: true })
    }

    void performLogout()
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
