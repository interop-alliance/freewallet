/**
 * The lobby: the waiting room the signup wizard hands off to while the
 * account-setup ceremony runs. The ceremony itself was started in the
 * wizard's click handler (the passkey path needs the WebAuthn user gesture)
 * and registered in the in-memory setup store, so this page only renders the
 * step feed and performs the navigation the settled run calls for --
 * `/dashboard` on success, `/login` when the credential already had a
 * wallet, and back to the wizard's last step on failure.
 *
 * Mounting with no run in flight (a reload, a direct visit) means the store
 * is empty, and the page routes back to the wizard.
 *
 * This page is the run's one consumer, so it also owns the run's attendance:
 * an unmount before the run settles marks it abandoned, and the settled run
 * then discards its session rather than parking it in the store.
 */
import { useEffect, useRef } from 'react'
import { Box, Typography } from '@mui/material'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { AuthPageHeader } from '@/components/AuthPageHeader'
import { authStyles } from '@/styles/appStyles'
import { usePrfRetryPrompt } from '@/hooks/usePrfRetryPrompt'
import { useAuthStore } from '@/stores/authStore'
import { useSetupStore, type SetupMethod } from '@/stores/setupStore'
import { signupStepPath } from '@/lib/signupSteps'

/**
 * Where a failed run returns the user: the step they must act on. The
 * passphrase path returns to the passphrase field, since a fresh page carries
 * none of what the failed run was given; the passkey path has nothing to
 * re-enter and returns to the last step.
 *
 * @param method {SetupMethod}
 * @returns {string}
 */
function signupRetryPath(method: SetupMethod): string {
  return method === 'passkey'
    ? signupStepPath({ method, step: 'storage' })
    : signupStepPath({ method, step: 'start' })
}

export function LobbyPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)
  const method = useSetupStore(state => state.method)
  const steps = useSetupStore(state => state.steps)
  const result = useSetupStore(state => state.result)
  const clearSetup = useSetupStore(state => state.clearSetup)
  const attendSetup = useSetupStore(state => state.attendSetup)
  const abandonSetup = useSetupStore(state => state.abandonSetup)
  // The passkey ceremony may still ask for a second WebAuthn ceremony while
  // this page is the mounted one, so the consent dialog lives here too.
  const { dialog: prfRetryDialog } = usePrfRetryPrompt()
  // One navigation per visit: clearing the run empties the store, which must
  // not read as "no run in flight" and route back to the wizard.
  const navigated = useRef(false)

  // While this page is mounted the run is attended; leaving before it settles
  // abandons it, so its outcome is discarded instead of parked. Attending on
  // mount is what makes the pairing survive React's double-invoked effects.
  useEffect(() => {
    attendSetup()
    return abandonSetup
  }, [abandonSetup, attendSetup])

  useEffect(() => {
    if (navigated.current) {
      return
    }
    if (!method) {
      navigated.current = true
      void navigate('/signup', { replace: true })
      return
    }
    if (result.kind === 'pending') {
      return
    }
    navigated.current = true
    if (result.kind === 'failed') {
      const { errorKey } = result
      clearSetup()
      void navigate(signupRetryPath(method), {
        replace: true,
        ...(errorKey ? { state: { setupErrorKey: errorKey } } : {})
      })
      return
    }
    const { session, userExists } = result
    clearSetup()
    if (userExists || !session) {
      void navigate('/login', {
        replace: true,
        state: { authMessageKey: 'auth.errors.profileExists' }
      })
      return
    }
    login(session)
    void navigate('/dashboard', { replace: true })
  }, [clearSetup, login, method, navigate, result])

  // Everything already reported, plus the one line currently running.
  const runningIndex = steps.findIndex(step => !step.done)
  const visible = runningIndex === -1 ? steps : steps.slice(0, runningIndex + 1)

  return (
    <Box component="main" className="fw-page" sx={authStyles.page}>
      <AuthPageHeader />
      <Box sx={authStyles.pageContent}>
        <Typography variant="h4" component="h1" sx={authStyles.title}>
          {t('auth.lobby.heading')}
        </Typography>

        <Box sx={authStyles.lobbyTerminal}>
          {visible.map(step => (
            <Box key={step.stage} sx={authStyles.lobbyLine}>
              <Box
                component="span"
                sx={
                  step.done
                    ? authStyles.lobbyLineMarker
                    : authStyles.lobbyLineMarkerRunning
                }
              >
                {step.done ? `[${t('auth.lobby.done')}]` : '[ ]'}
              </Box>
              <Box component="span">{t(`auth.lobby.steps.${step.stage}`)}</Box>
              {!step.done && (
                <Box component="span" sx={authStyles.lobbyCursor}>
                  _
                </Box>
              )}
            </Box>
          ))}
        </Box>

        {prfRetryDialog}
      </Box>
    </Box>
  )
}
