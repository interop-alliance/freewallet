import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink } from 'react-router'
import { LanguageSelector } from '@/components/LanguageSelector'
import { ThemePicker } from '@/components/ThemePicker'
import { useAppTheme } from '@/context/appThemeContext'
import { landingStyles } from '@/styles/landingStyles'

export function LandingPage() {
  const { t } = useTranslation()
  const { themeId } = useAppTheme()

  return (
    <Box component="main" className="fw-page" sx={landingStyles.main}>
      <div className="fw-glow-top" aria-hidden />

      <Box className="fw-frame" sx={{ width: '100%' }}>
        <Box
          className="fw-frame-inner fw-frame-narrow"
          sx={{
            ...landingStyles.content,
            ...(themeId === 'west-coast'
              ? landingStyles.westCoastHeroFrame
              : {})
          }}
        >
          <Box className="fw-hero-card" sx={{ width: '100%' }}>
            <Box
              sx={
                themeId === 'west-coast'
                  ? landingStyles.westCoastHeroCardInner
                  : undefined
              }
            >
              <Box sx={landingStyles.languageBar}>
                <LanguageSelector />
                <ThemePicker />
              </Box>

              <Typography variant="h2" component="h1" sx={landingStyles.title}>
                <span className="fw-grad-text">{t('landing.title')}</span>
              </Typography>

              <Typography
                variant="h6"
                component="p"
                sx={landingStyles.subtitle}
              >
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
                  sx={{
                    ...landingStyles.button,
                    ...landingStyles.guestModeButton
                  }}
                  component={RouterLink}
                  to="/guest-login"
                >
                  {t('landing.guestMode')}
                </Button>
              </Stack>
            </Box>
          </Box>
        </Box>
      </Box>
    </Box>
  )
}
