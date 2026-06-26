import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { LanguageSelector } from '@/components/LanguageSelector'
import { ThemePicker } from '@/components/ThemePicker'
import { authStyles } from '@/styles/appStyles'
import type { SubmitEvent } from 'react'
import { useEffect, useState } from 'react'
import { initGuestSession } from '@/session/initSession'
import { useAuthStore } from '@/stores/authStore'
import { StorageManager } from '@/stores/storageManager'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import { registerWallet } from '@/lib/registerWallet'

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
      const { session } = await initGuestSession()

      const { storage } = await StorageManager.initStorageClients(session)
      session.storage = storage

      await storage.ensureUserCollections({ user: session.user })

      // Now that we have somewhere to write _to_, start the history
      await session.storage.addHistoryNewAccount({ user: session.user })
      await session.storage.addHistorySpaceCreated({ user: session.user })

      // Add a "welcome" credential to storage
      await session.storage.addCredential({ credential: welcomeCredential })
      login(session)
      navigate('/dashboard')
    } catch (err) {
      console.error('Error starting guest session:', err)
      setSetupError(true)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Box component="main" className="fw-page" sx={authStyles.page}>
      <Box component="form" onSubmit={handleGuestLogin} sx={authStyles.content}>
        <Box sx={authStyles.languageBar}>
          <LanguageSelector />
          <ThemePicker />
        </Box>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          {t('landing.title')}
        </Typography>
        <Typography variant="h3" component="h2" sx={authStyles.title}>
          <Box component="span" sx={authStyles.guestIcon}>
            <FaGhost />
          </Box>
          {t('auth.guest.heading')}
        </Typography>

        <ul>
          <Typography variant="h5" component="li">
            {t('auth.guest.bulletRandom')}
          </Typography>
          <Typography variant="h5" component="li">
            {t('auth.guest.bulletEphemeral')}
          </Typography>
        </ul>

        {setupError && (
          <Typography variant="body1" color="error" sx={authStyles.userMessage}>
            {t('auth.errors.setupFailed')}
          </Typography>
        )}

        <Button
          variant="contained"
          type="submit"
          disabled={isSubmitting}
          startIcon={
            isSubmitting ? (
              <CircularProgress size={18} color="inherit" />
            ) : (
              <FaGhost />
            )
          }
          sx={authStyles.actionButton}
        >
          {t('auth.guest.submit')}
        </Button>
      </Box>
    </Box>
  )
}
