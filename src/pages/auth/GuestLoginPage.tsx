import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemText from '@mui/material/ListItemText'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { AuthPageHeader } from '@/components/AuthPageHeader'
import { authStyles } from '@/styles/appStyles'
import type { SubmitEvent } from 'react'
import { useEffect, useState } from 'react'
import { initGuestSession } from '@/session/initSession'
import { provisionNewWallet } from '@/session/provisionNewWallet'
import { useAuthStore } from '@/stores/authStore'
import { registerWallet } from '@/lib/registerWallet'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:guest')

export function GuestLoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [setupError, setSetupError] = useState(false)

  useEffect(() => {
    void registerWallet()
  }, [])

  /**
   * Handles form submit event
   */
  const handleGuestLogin = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (isSubmitting) {
      return
    }
    setIsSubmitting(true)
    setSetupError(false)
    try {
      // initGuestSession builds the session's StorageManager (guest sessions
      // get no remote replica).
      const { session } = await initGuestSession()

      // Provision collections, record the initial history, and seed the
      // welcome credential -- the same new-wallet sequence signup runs.
      await provisionNewWallet({ session })
      login(session)
      navigate('/dashboard')
    } catch (err) {
      log.error('Error starting guest session', { err })
      setSetupError(true)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Box component="main" className="fw-page" sx={authStyles.page}>
      <AuthPageHeader />
      <Box sx={authStyles.pageContent}>
        <Box
          component="form"
          onSubmit={handleGuestLogin}
          sx={authStyles.content}
        >
          <Typography variant="h4" component="h1" sx={authStyles.title}>
            <Box component="span" sx={authStyles.guestIcon}>
              <FaGhost />
            </Box>
            {t('auth.guest.heading')}
          </Typography>

          <List dense sx={{ listStyleType: 'disc', pl: 4 }}>
            <ListItem disableGutters sx={{ display: 'list-item', px: 0 }}>
              <ListItemText
                primary={t('auth.guest.bulletRandom')}
                slotProps={{ primary: { variant: 'h5' } }}
              />
            </ListItem>
            <ListItem disableGutters sx={{ display: 'list-item', px: 0 }}>
              <ListItemText
                primary={t('auth.guest.bulletEphemeral')}
                slotProps={{ primary: { variant: 'h5' } }}
              />
            </ListItem>
          </List>

          {setupError && (
            <Alert severity="error" sx={authStyles.userMessage}>
              {t('auth.errors.setupFailed')}
            </Alert>
          )}

          <Button
            variant="contained"
            type="submit"
            loading={isSubmitting}
            loadingPosition="start"
            startIcon={<FaGhost />}
            sx={authStyles.actionButton}
          >
            {t('auth.guest.submit')}
          </Button>
        </Box>
      </Box>
    </Box>
  )
}
