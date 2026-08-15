import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { Link as RouterLink, useNavigate } from 'react-router'
import type { SubmitEvent } from 'react'
import { useState } from 'react'
import { AuthPageHeader } from '@/components/AuthPageHeader'
import { PassphraseStrengthField } from '@/components/PassphraseStrengthField'
import { authStyles } from '@/styles/appStyles'
import { useAuthStore } from '@/stores/authStore'
import { PASSWORD_RULES } from '@/app.config'
import { loginWithPassphrase } from '@/session/initSession'
import {
  locateRecoveryAccount,
  recoverAccountWithCode,
  RecoveryCodeInvalidError,
  RecoveryCodeNotFoundError,
  RecoveryKeyNotCommittedError,
  RecoveryUnavailableError,
  updateRegistryAfterRecovery,
  type RecoveryOutcome
} from '@/session/recovery'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { RecoveryCodeDisplay } from '@/components/RecoveryCodeDisplay'

/**
 * The recovery-code recover page (`/recover`, public) -- the "lost my only
 * client" flow on the roster identity model. The typed code locates the
 * account (its unlock record), a new passphrase is chosen for THIS browser,
 * and the recovery ceremony runs end to end: the code's pre-minted
 * delegation writes the self-enrolling log continuation, the user key comes out
 * of the code's standing roster wrap and is rotated off the spent code, and
 * a replacement code is pushed hard -- the typed code is a spent credential.
 * The final step is an ordinary passphrase login as a freshly enrolled
 * client.
 */
export function RecoverPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)
  const [step, setStep] = useState<'code' | 'passphrase' | 'done'>('code')
  const [busy, setBusy] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [passphraseScore, setPassphraseScore] = useState(0)
  const [outcome, setOutcome] = useState<RecoveryOutcome | null>(null)
  const [replacementSaved, setReplacementSaved] = useState(false)
  /**
   * Maps a recovery failure onto the page's honest error states: a mistyped
   * code, a code that resolves to nothing (never issued, revoked, or spent),
   * a revoked-while-record-survived code, an unreachable server ("could not
   * check", never "no account"), and everything else.
   */
  const errorKeyFor = (err: unknown): string => {
    if (err instanceof RecoveryCodeInvalidError) {
      return 'auth.recover.errors.invalidCode'
    }
    if (err instanceof RecoveryCodeNotFoundError) {
      return 'auth.recover.errors.noMatch'
    }
    if (err instanceof RecoveryKeyNotCommittedError) {
      return 'auth.recover.errors.revoked'
    }
    if (err instanceof RecoveryUnavailableError) {
      return 'auth.recover.errors.unavailable'
    }
    if (isStorageUnreachable(err)) {
      return 'auth.recover.errors.couldNotCheck'
    }
    return 'auth.recover.errors.failed'
  }

  /**
   * Step one: locate the account the code names, without changing anything.
   */
  const handleLocate = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) {
      return
    }
    setBusy(true)
    setErrorKey(null)
    try {
      const data = new FormData(event.currentTarget)
      const typed = (data.get('recovery-code') as string) ?? ''
      await locateRecoveryAccount({ code: typed })
      setCode(typed)
      setStep('passphrase')
    } catch (err) {
      console.warn('Recovery code check failed:', err)
      setErrorKey(errorKeyFor(err))
    } finally {
      setBusy(false)
    }
  }

  /**
   * Step two: run the whole recovery ceremony under the chosen new
   * passphrase. On success the spent code is retired and the replacement
   * code must be saved before logging in.
   */
  const handleRecover = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy || passphrase.length < PASSWORD_RULES.minlength) {
      return
    }
    setBusy(true)
    setErrorKey(null)
    try {
      const recovered = await recoverAccountWithCode({
        code,
        newPassphrase: passphrase
      })
      setOutcome(recovered)
      setStep('done')
    } catch (err) {
      console.error('Recovery failed:', err)
      setErrorKey(errorKeyFor(err))
    } finally {
      setBusy(false)
    }
  }

  /**
   * Step three: an ordinary passphrase login as the freshly enrolled client,
   * then the post-login registry update (drop the spent code's entry, record
   * the replacement's).
   */
  const handleLogin = async () => {
    if (busy || !outcome) {
      return
    }
    setBusy(true)
    setErrorKey(null)
    try {
      const { session } = await loginWithPassphrase({ passphrase })
      if (!session) {
        setErrorKey('auth.recover.errors.loginFailed')
        return
      }
      await session.storageReady
      login(session)
      // Fire-and-forget: the sequencing the two registry updates need lives in
      // `updateRegistryAfterRecovery`, and both halves are best-effort.
      void updateRegistryAfterRecovery({ session, outcome })
      navigate('/dashboard', { replace: true })
    } catch (err) {
      console.error('Recovery login failed:', err)
      setErrorKey('auth.recover.errors.loginFailed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box component="main" className="fw-page" sx={authStyles.page}>
      <AuthPageHeader />
      <Box sx={authStyles.pageContent}>
        <Typography variant="h4" component="h1" sx={authStyles.title}>
          {t('auth.recover.heading')}
        </Typography>

        <Card sx={authStyles.authCard} variant="outlined">
          <CardContent sx={authStyles.authCardContent}>
            {step === 'code' && (
              <Box
                component="form"
                onSubmit={handleLocate}
                sx={authStyles.authCardForm}
              >
                <Typography variant="body1">
                  {t('auth.recover.intro')}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t('auth.recover.noCodeHint')}
                </Typography>

                {errorKey && (
                  <Alert severity="error" sx={authStyles.userMessage}>
                    {t(errorKey)}
                  </Alert>
                )}

                <Typography
                  variant="h5"
                  component="label"
                  htmlFor="recovery-code"
                >
                  {t('auth.recover.codeLabel')}
                </Typography>
                <TextField
                  id="recovery-code"
                  name="recovery-code"
                  autoComplete="off"
                  spellCheck={false}
                  sx={authStyles.input}
                />

                <Button
                  variant="contained"
                  type="submit"
                  loading={busy}
                  sx={authStyles.actionButton}
                >
                  {t('auth.recover.checkCode')}
                </Button>
              </Box>
            )}

            {step === 'passphrase' && (
              <Box
                component="form"
                onSubmit={handleRecover}
                sx={authStyles.authCardForm}
              >
                <Alert severity="success" sx={authStyles.userMessage}>
                  {t('auth.recover.accountFound')}
                </Alert>
                <Typography variant="body2">
                  {t('auth.recover.newPassphraseExplain')}
                </Typography>

                {errorKey && (
                  <Alert severity="error" sx={authStyles.userMessage}>
                    {t(errorKey)}
                  </Alert>
                )}

                <Typography
                  variant="h5"
                  component="label"
                  htmlFor="new-passphrase"
                >
                  {t('auth.recover.newPassphraseLabel')}
                </Typography>
                <TextField
                  id="new-passphrase"
                  name="new-passphrase"
                  type="password"
                  autoComplete="new-password"
                  value={passphrase}
                  onChange={event => setPassphrase(event.target.value)}
                  sx={authStyles.input}
                />
                <PassphraseStrengthField
                  password={passphrase}
                  onChangeScore={setPassphraseScore}
                />

                <Button
                  variant="contained"
                  type="submit"
                  loading={busy}
                  disabled={
                    passphrase.length < PASSWORD_RULES.minlength ||
                    passphraseScore < PASSWORD_RULES.minscore
                  }
                  sx={authStyles.actionButton}
                >
                  {t('auth.recover.submit')}
                </Button>
              </Box>
            )}

            {step === 'done' && outcome && (
              <Stack sx={{ gap: 2 }}>
                <Alert severity="success">{t('auth.recover.recovered')}</Alert>
                <Alert severity="warning">
                  {t('auth.recover.replacementExplain')}
                </Alert>
                <RecoveryCodeDisplay
                  code={outcome.replacementCode}
                  copyLabel={t('auth.recover.copyCode')}
                  testId="replacement-recovery-code"
                />

                {errorKey && (
                  <Alert severity="error" sx={authStyles.userMessage}>
                    {t(errorKey)}
                  </Alert>
                )}

                <Button
                  variant={replacementSaved ? 'outlined' : 'contained'}
                  onClick={() => setReplacementSaved(true)}
                  disabled={replacementSaved}
                >
                  {replacementSaved
                    ? t('auth.recover.replacementSavedDone')
                    : t('auth.recover.replacementSavedButton')}
                </Button>
                <Button
                  variant="contained"
                  onClick={() => void handleLogin()}
                  loading={busy}
                  disabled={!replacementSaved}
                  sx={authStyles.actionButton}
                >
                  {t('auth.recover.login')}
                </Button>
              </Stack>
            )}

            <Typography
              variant="h6"
              component="p"
              sx={authStyles.authFooterText}
            >
              <Link component={RouterLink} to="/login" underline="always">
                {t('auth.recover.backToLogin')}
              </Link>
            </Typography>
          </CardContent>
        </Card>
      </Box>
    </Box>
  )
}
