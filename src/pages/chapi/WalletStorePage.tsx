/**
 * CHAPI credential-store popup. Runs inside a CHAPI-managed popup iframe (not
 * the main app shell) when a third-party site calls navigator.credentials.store().
 * Intercepts the CHAPI event, prompts the user to log in with their passphrase,
 * then stores the incoming VC to their wallet on confirmation.
 */
import { useEffect, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { loadOnce } from 'credential-handler-polyfill'
import { receiveCredentialEvent } from 'web-credential-handler'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { MEDIATOR_BASE } from '@/app.config'
import { initSessionFromSecret } from '@/session/initSession'
import type { Session } from '@/types/auth'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { issuerName } from '@/lib/viewMappers/issuerName'
import { chapiStyles } from '@/styles/appStyles'
import { ChapiLoginForm } from './ChapiLoginForm'
import { useTranslation } from 'react-i18next'

type PageState = 'initializing' | 'awaiting-login' | 'confirming' | 'stored'

interface VerifiablePresentation {
  '@context': string[]
  type: string | string[]
  verifiableCredential: IVerifiableCredential | IVerifiableCredential[]
}

interface ChapiStoreEvent {
  credential: { data: VerifiablePresentation }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

export function WalletStorePage() {
  const { t } = useTranslation()
  const [pageState, setPageState] = useState<PageState>('initializing')
  const [chapiEvent, setChapiEvent] = useState<ChapiStoreEvent | null>(null)
  const [vc, setVc] = useState<IVerifiableCredential | null>(null)
  const [vp, setVp] = useState<VerifiablePresentation | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [loginError, setLoginError] = useState<string | null>(null)
  const initialized = useRef(false)

  useEffect(() => {
    if (initialized.current) {
      return
    }
    initialized.current = true

    async function init() {
      await loadOnce(MEDIATOR_BASE + encodeURIComponent(window.location.origin))
      const event = (await receiveCredentialEvent()) as ChapiStoreEvent
      const incomingVp = event.credential.data
      const incomingVc = Array.isArray(incomingVp.verifiableCredential)
        ? incomingVp.verifiableCredential[0]
        : incomingVp.verifiableCredential
      setChapiEvent(event)
      setVp(incomingVp)
      setVc(incomingVc)
      setPageState('awaiting-login')
    }

    init().catch(console.error)
  }, [])

  async function handleLogin(passphrase: string) {
    setLoginError(null)
    const { session: s, userExists } = await initSessionFromSecret({
      secret: passphrase
    })
    if (!userExists) {
      setLoginError(t('chapi.accountNotFound'))
      return
    }
    await s.storage.ensureUserCollections({ user: s.user })
    setSession(s)
    setPageState('confirming')
  }

  async function handleConfirm() {
    if (!session || !vc) {
      return
    }
    await session.storage.addCredential({ credential: vc })
    setPageState('stored')
  }

  function handleCancel() {
    chapiEvent?.respondWith(Promise.resolve(null))
  }

  function handleDone() {
    if (!chapiEvent || !vp) {
      return
    }
    chapiEvent.respondWith(
      Promise.resolve({ dataType: 'VerifiablePresentation', data: vp })
    )
  }

  if (pageState === 'initializing') {
    return (
      <Box sx={{ ...chapiStyles.page, alignItems: 'center' }}>
        <CircularProgress />
      </Box>
    )
  }

  return (
    <Box sx={chapiStyles.page}>
      <Box sx={chapiStyles.card}>
        <Typography variant="h5" sx={{ fontWeight: 600 }}>
          {t('chapi.store.title')}
        </Typography>

        {vc && (
          <Box sx={chapiStyles.credentialSummary}>
            <Typography variant="body2" color="text.secondary">
              {t('common.type')}
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {credentialTitle(vc)}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {t('common.issuer')}
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {issuerName(vc)}
            </Typography>
          </Box>
        )}

        {pageState === 'awaiting-login' && (
          <ChapiLoginForm onSubmit={handleLogin} error={loginError} />
        )}

        {pageState === 'confirming' && (
          <Stack direction="row" spacing={2}>
            <Button
              variant="contained"
              sx={{ textTransform: 'none' }}
              onClick={handleConfirm}
            >
              {t('common.store')}
            </Button>
            <Button
              variant="outlined"
              sx={{ textTransform: 'none' }}
              onClick={handleCancel}
            >
              {t('common.cancel')}
            </Button>
          </Stack>
        )}

        {pageState === 'stored' && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            <Typography variant="body2" color="success.main">
              {t('chapi.store.storedSuccess')}
            </Typography>
            <Button
              variant="contained"
              sx={{ alignSelf: 'flex-start', textTransform: 'none' }}
              onClick={handleDone}
            >
              {t('common.done')}
            </Button>
          </Box>
        )}
      </Box>
    </Box>
  )
}
