import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import IconButton from '@mui/material/IconButton'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { MdContentCopy } from 'react-icons/md'
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
import { backfillPassphraseUnlockMethod } from '@/session/unlockMethods'
import {
  formatRecoveryCode,
  locateRecoveryAccount,
  recordRecoveryOutcome,
  recoverAccountWithCode,
  RecoveryCodeInvalidError,
  RecoveryCodeNotFoundError,
  RecoveryKeyNotCommittedError,
  RecoveryUnavailableError,
  type RecoveryOutcome
} from '@/session/recovery'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'

/**
 * The recovery-code recover page (`/recover`, public) -- the "lost my only
 * client" flow on the roster identity model. The typed code locates the
 * account (its unlock record), a new passphrase is chosen for THIS browser,
 * and the recovery ceremony runs end to end: the code's pre-minted
 * delegation writes the self-enrolling log continuation, the PUK comes out
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
  const [accountEmail, setAccountEmail] = useState<string | undefined>()
  const [passphrase, setPassphrase] = useState('')
  const [passphraseScore, setPassphraseScore] = useState(0)
  const [outcome, setOutcome] = useState<RecoveryOutcome | null>(null)
  const [replacementSaved, setReplacementSaved] = useState(false)
  const { copied, copy } = useCopyToClipboard({
    onError: (err: unknown) => {
      console.error('Could not copy the replacement code:', err)
    }
  })

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
      const { email } = await locateRecoveryAccount({ code: typed })
      setCode(typed)
      setAccountEmail(email)
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
      void recordRecoveryOutcome({ session, outcome }).catch(err =>
        console.warn('Could not update the unlock-methods registry:', err)
      )
      void backfillPassphraseUnlockMethod({ session }).catch(err =>
        console.warn('Could not backfill the unlock-methods registry:', err)
      )
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
                  {accountEmail
                    ? t('auth.recover.accountFound', { email: accountEmail })
                    : t('auth.recover.accountFoundNoEmail')}
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
                <Stack direction="row" sx={{ alignItems: 'center', gap: 1 }}>
                  <Typography
                    variant="h6"
                    component="code"
                    data-testid="replacement-recovery-code"
                    sx={{ fontFamily: 'monospace', letterSpacing: 1 }}
                  >
                    {formatRecoveryCode({ code: outcome.replacementCode })}
                  </Typography>
                  <IconButton
                    size="small"
                    aria-label={t('auth.recover.copyCode')}
                    onClick={() =>
                      void copy(
                        formatRecoveryCode({ code: outcome.replacementCode })
                      )
                    }
                  >
                    <MdContentCopy />
                  </IconButton>
                  {copied && (
                    <Typography variant="body2" color="text.secondary">
                      {t('common.copied')}
                    </Typography>
                  )}
                </Stack>

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
