import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink } from 'react-router'
import { LanguageSelector } from '@/components/LanguageSelector'
import { landingStyles } from '@/styles/landingStyles'
import { useEffect } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { WAS_SERVER_URL } from '@/app.config'

export function LandingPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  useEffect(() => {
    console.log('Landing page, session:', session)
    console.log('WAS_SERVER_URL:', WAS_SERVER_URL)
  }, [session])

  return (
    <Box component="main" sx={landingStyles.main}>
      <Box sx={landingStyles.content}>
        <Stack
          sx={{
            flexDirection: 'row',
            justifyContent: 'flex-start',
            width: '100%',
            mb: 1
          }}
        >
          <LanguageSelector />
        </Stack>

        <Typography variant="h2" component="h1" sx={landingStyles.title}>
          {t('landing.title')}
        </Typography>

        <Typography variant="h6" component="p" sx={landingStyles.subtitle}>
          <Trans
            i18nKey="landing.subtitle"
            components={{
              vcs: (
                <Link
                  component={RouterLink}
                  to="/docs/vcs"
                  underline="always"
                  sx={landingStyles.link}
                />
              ),
              dids: (
                <Link
                  component={RouterLink}
                  to="/docs/dids"
                  underline="always"
                  sx={landingStyles.link}
                />
              ),
              keys: (
                <Link
                  component={RouterLink}
                  to="/docs/keys"
                  underline="always"
                  sx={landingStyles.link}
                />
              )
            }}
          />
        </Typography>

        <Stack sx={landingStyles.actions}>
          <Button
            variant="contained"
            color="primary"
            size="large"
            sx={landingStyles.button}
            component={RouterLink}
            to="/login"
          >
            {t('landing.logIn')}
          </Button>
          <Button
            variant="outlined"
            color="primary"
            size="large"
            sx={landingStyles.button}
            component={RouterLink}
            to="/signup"
          >
            {t('landing.signUp')}
          </Button>
          <Button
            variant="contained"
            color="secondary"
            size="large"
            startIcon={<FaGhost />}
            sx={{ ...landingStyles.button, ...landingStyles.guestModeButton }}
            component={RouterLink}
            to="/guest-login"
          >
            {t('landing.guestMode')}
          </Button>
        </Stack>
      </Box>
    </Box>
  )
}
