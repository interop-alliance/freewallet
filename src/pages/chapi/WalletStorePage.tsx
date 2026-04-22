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
      setLoginError(
        'Account not found. Please create your wallet from the main app first.'
      )
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
          Store Credential
        </Typography>

        {vc && (
          <Box sx={chapiStyles.credentialSummary}>
            <Typography variant="body2" color="text.secondary">
              Type
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {credentialTitle(vc)}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Issuer
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
              Store
            </Button>
            <Button
              variant="outlined"
              sx={{ textTransform: 'none' }}
              onClick={handleCancel}
            >
              Cancel
            </Button>
          </Stack>
        )}

        {pageState === 'stored' && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            <Typography variant="body2" color="success.main">
              Credential stored successfully.
            </Typography>
            <Button
              variant="contained"
              sx={{ alignSelf: 'flex-start', textTransform: 'none' }}
              onClick={handleDone}
            >
              Done
            </Button>
          </Box>
        )}
      </Box>
    </Box>
  )
}
