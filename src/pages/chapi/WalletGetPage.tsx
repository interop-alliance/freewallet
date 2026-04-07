import { useEffect, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Typography from '@mui/material/Typography'
import { loadOnce } from 'credential-handler-polyfill'
import { receiveCredentialEvent } from 'web-credential-handler'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { MEDIATOR } from '@/app.config'
import { initSessionFromSecret } from '@/session/initSession'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { issuerName } from '@/lib/viewMappers/issuerName'
import { chapiStyles } from '@/styles/appStyles'
import type { StoredCredential } from '@/types/credential'
import { ChapiLoginForm } from './ChapiLoginForm'

type PageState = 'initializing' | 'awaiting-login' | 'selecting' | 'done'

interface ChapiGetEvent {
  credentialRequestOrigin: string
  credentialRequestOptions: {
    web: {
      VerifiablePresentation: {
        query:
          | { type: string; credentialQuery?: { reason?: string } }
          | Array<{ type: string; credentialQuery?: { reason?: string } }>
      }
    }
  }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

export function WalletGetPage() {
  const [pageState, setPageState] = useState<PageState>('initializing')
  const [chapiEvent, setChapiEvent] = useState<ChapiGetEvent | null>(null)
  const [requestOrigin, setRequestOrigin] = useState('')
  const [requestReason, setRequestReason] = useState('')
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [loginError, setLoginError] = useState<string | null>(null)
  const initialized = useRef(false)

  useEffect(() => {
    if (initialized.current) {
      return
    }
    initialized.current = true

    async function init() {
      await loadOnce(MEDIATOR)
      const event = (await receiveCredentialEvent()) as ChapiGetEvent
      setChapiEvent(event)
      setRequestOrigin(event.credentialRequestOrigin)

      const vpQuery =
        event.credentialRequestOptions?.web?.VerifiablePresentation?.query
      if (vpQuery) {
        const query = Array.isArray(vpQuery) ? vpQuery[0] : vpQuery
        const reason = query?.credentialQuery?.reason
        if (reason) {
          setRequestReason(reason)
        }
      }

      setPageState('awaiting-login')
    }

    init().catch(console.error)
  }, [])

  async function handleLogin(passphrase: string) {
    setLoginError(null)
    const { session, userExists } = await initSessionFromSecret({
      secret: passphrase
    })
    if (!userExists) {
      setLoginError(
        'Account not found. Please create your wallet from the main app first.'
      )
      return
    }
    await session.storage.ensureUserCollections({ user: session.user })
    const vcs = await session.storage.listCredentials()
    setCredentials(vcs)
    setPageState('selecting')
  }

  function handleShare(vc: IVerifiableCredential) {
    if (!chapiEvent) {
      return
    }
    const vp = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: 'VerifiablePresentation',
      verifiableCredential: vc
    }
    setPageState('done')
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
        <Typography variant="h5" fontWeight={600}>
          Share a Credential
        </Typography>

        <Box>
          <Typography variant="body2" color="text.secondary">
            Requested by
          </Typography>
          <Typography sx={chapiStyles.originChip}>{requestOrigin}</Typography>
        </Box>

        {requestReason && (
          <Typography variant="body2">{requestReason}</Typography>
        )}

        {pageState === 'awaiting-login' && (
          <ChapiLoginForm onSubmit={handleLogin} error={loginError} />
        )}

        {pageState === 'selecting' && (
          <>
            <Typography variant="subtitle1" fontWeight={500}>
              Select a credential to share:
            </Typography>
            {credentials.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                Your wallet is empty.
              </Typography>
            ) : (
              <Box sx={chapiStyles.credentialList}>
                {credentials.map(({ cid, vc }) => (
                  <Box key={cid} sx={chapiStyles.credentialRow}>
                    <Box sx={chapiStyles.credentialInfo}>
                      <Typography variant="body2" fontWeight={500}>
                        {credentialTitle(vc)}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {issuerName(vc)}
                      </Typography>
                    </Box>
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={() => handleShare(vc)}
                    >
                      Share
                    </Button>
                  </Box>
                ))}
              </Box>
            )}
          </>
        )}

        {pageState === 'done' && (
          <Box sx={chapiStyles.doneMessage}>
            <CircularProgress size={20} />
            <Typography variant="body2">Sharing credential…</Typography>
          </Box>
        )}
      </Box>
    </Box>
  )
}
