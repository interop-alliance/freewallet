import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { useNavigate } from 'react-router'
import { authStyles } from '@/styles/appStyles'
import type { SubmitEvent } from 'react'
import { useEffect, useState } from 'react'
import { initGuestSession } from '@/session/initSession'
import { useAuthStore } from '@/stores/authStore'
import { StorageManager } from '@/stores/storageManager'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import { registerWallet } from '@/lib/registerWallet'

export function GuestLoginPage() {
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)
  const [isSubmitting, setIsSubmitting] = useState(false)

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
    try {
      const { session } = await initGuestSession()

      const { storage } = await StorageManager.initStorageClients(session)
      session.storage = storage

      await storage.ensureUserCollections({ user: session.user })

      // Now that we have somewhere to write _to_, start the history
      await session.storage.addHistoryNewAccount({ user: session.user })
      await session.storage.addHistorySpaceCreated({ user: session.user })

      // Add a "welcome" credential to storage
      await session.storage!.addCredential({ credential: welcomeCredential })
      login(session)
      navigate('/dashboard')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Box component="main" sx={authStyles.page}>
      <Box component="form" onSubmit={handleGuestLogin} sx={authStyles.content}>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          Freewallet
        </Typography>
        <Typography variant="h3" component="h2" sx={authStyles.title}>
          <Box component="span" sx={authStyles.guestIcon}>
            <FaGhost />
          </Box>
          Guest Mode Login
        </Typography>

        <ul>
          <Typography variant="h5" component="li">
            a random login will be created
          </Typography>
          <Typography variant="h5" component="li">
            login and storage will be deleted at end of session
          </Typography>
        </ul>

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
          Guest Mode Log In
        </Button>
      </Box>
    </Box>
  )
}
