/**
 * CHAPI credential-get popup. Runs inside a CHAPI-managed popup iframe (not
 * the main app shell) when a third-party site calls navigator.credentials.get().
 * Intercepts and classifies the CHAPI event, prompts the user to log in with
 * their passphrase, then dispatches on what was requested:
 *
 * - `'vc'` -- lists stored VCs and returns the selected one in a VP;
 * - `'didauth'` -- shows a DID Authentication consent screen and returns a
 *   signed VP (holder + auth proof, no credentials);
 * - `'vc+didauth'` -- lists VCs with a DID-Auth notice and returns a signed VP
 *   carrying the selected VC(s) plus the auth proof.
 */
import { useEffect, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { loadOnce } from 'credential-handler-polyfill'
import { receiveCredentialEvent } from 'web-credential-handler'
import { MEDIATOR_BASE } from '@/app.config'
import { initSessionFromSecret } from '@/session/initSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { issuerName } from '@/lib/viewMappers/issuerName'
import { chapiStyles } from '@/styles/appStyles'
import type { Session } from '@/types/auth'
import type { StoredCredential } from '@/types/credential'
import {
  classifyCHAPIGetEvent,
  didAuthMethodSupported,
  domainMatchesOrigin,
  processRequest,
  queriesOf,
  requestKindOf,
  type CHAPIGetEvent,
  type IVerifiableCredential,
  type IVPRDetails,
  type IVPRQuery,
  type WalletRequestKind
} from '@/lib/walletRequest'
import { CHAPILoginForm } from './CHAPILoginForm'
import { useTranslation } from 'react-i18next'

type PageState =
  'initializing' | 'awaiting-login' | 'selecting' | 'blocked' | 'done'

/**
 * Why a request cannot proceed; maps to a `chapi.get.*` message key. Set before
 * login for the two statically-detectable cases, or after a failed compose.
 */
type BlockReason = 'unsupported' | 'domainMismatch' | 'processFailed'

const BLOCK_MESSAGE_KEY: Record<BlockReason, string> = {
  unsupported: 'chapi.get.didAuthUnsupported',
  domainMismatch: 'chapi.get.domainMismatch',
  processFailed: 'chapi.get.processFailed'
}

/**
 * E2E test seam. A CHAPI popup cannot run in an automated browser because
 * `receiveCredentialEvent()` only resolves through the CHAPI mediator
 * handshake, which no test harness performs. In non-production builds only, a
 * Playwright spec may inject a ready-made event on
 * `window.__E2E_CHAPI_GET_EVENT__` (with a `respondWith` that records the
 * payload) to drive this popup deterministically. Returns undefined in
 * production and whenever no event was injected, so the real CHAPI path runs.
 */
function injectedCHAPIGetEvent(): CHAPIGetEvent | undefined {
  if (import.meta.env.MODE === 'production') {
    return undefined
  }
  return (window as unknown as { __E2E_CHAPI_GET_EVENT__?: CHAPIGetEvent })
    .__E2E_CHAPI_GET_EVENT__
}

/**
 * Pulls the first `QueryByExample` reason string (if any) out of a VPR's query
 * set, for display on the share screen.
 */
function reasonFrom(queries: IVPRQuery[]): string {
  for (const query of queries) {
    if (query.type === 'QueryByExample') {
      const reason = query.credentialQuery?.reason
      if (reason) {
        return reason
      }
    }
  }
  return ''
}

export function WalletGetPage() {
  const { t } = useTranslation()
  const [pageState, setPageState] = useState<PageState>('initializing')
  const [chapiEvent, setCHAPIEvent] = useState<CHAPIGetEvent | null>(null)
  const [request, setRequest] = useState<IVPRDetails | null>(null)
  const [requestKind, setRequestKind] = useState<WalletRequestKind>('vc')
  const [requestOrigin, setRequestOrigin] = useState('')
  const [requestReason, setRequestReason] = useState('')
  const [blockReason, setBlockReason] = useState<BlockReason | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [loginError, setLoginError] = useState<string | null>(null)
  const initialized = useRef(false)

  useEffect(() => {
    if (initialized.current) {
      return
    }
    initialized.current = true

    async function init() {
      const injected = injectedCHAPIGetEvent()
      if (!injected) {
        await loadOnce(
          MEDIATOR_BASE + encodeURIComponent(window.location.origin)
        )
      }
      const event =
        injected ?? ((await receiveCredentialEvent()) as CHAPIGetEvent)
      const vpRequest = classifyCHAPIGetEvent(event)
      const details = vpRequest.verifiablePresentationRequest
      const queries = queriesOf(details)
      const origin = event.credentialRequestOrigin
      const kind = requestKindOf(vpRequest)

      setCHAPIEvent(event)
      setRequest(details)
      setRequestOrigin(origin)
      setRequestReason(reasonFrom(queries))
      setRequestKind(kind)

      // When DID Auth is involved the wallet must sign, so reject up front the
      // two cases it can never satisfy: an unsupported DID method, and a domain
      // that does not match the channel origin (VCALM domain-binding).
      if (kind !== 'vc') {
        if (!didAuthMethodSupported(queries)) {
          setBlockReason('unsupported')
          setPageState('blocked')
          return
        }
        if (
          details.domain &&
          !domainMatchesOrigin({ domain: details.domain, origin })
        ) {
          setBlockReason('domainMismatch')
          setPageState('blocked')
          return
        }
      }

      setPageState('awaiting-login')
    }

    init().catch(console.error)
  }, [])

  async function handleLogin(passphrase: string) {
    setLoginError(null)
    try {
      const { session: loggedIn, userExists } = await initSessionFromSecret({
        secret: passphrase
      })
      if (!userExists) {
        setLoginError(t('chapi.accountNotFound'))
        return
      }
      await loggedIn.storage.ensureUserCollections({ user: loggedIn.user })
      const vcs = await loggedIn.storage.listCredentials()
      setSession(loggedIn)
      setCredentials(vcs)
      setPageState('selecting')
    } catch (err) {
      if (isStorageUnreachable(err)) {
        setLoginError(t('chapi.storageUnreachable'))
      } else {
        console.error('CHAPI login failed:', err)
        setLoginError(t('chapi.loginFailed'))
      }
    }
  }

  /**
   * Composes and returns the response VP for the given VC selection (empty for a
   * DID-Auth-only response), delivering it over the CHAPI channel.
   */
  async function respondWithVp(selectedVCs: IVerifiableCredential[]) {
    if (!chapiEvent || !session || !request) {
      return
    }
    setPageState('done')
    try {
      const { verifiablePresentation } = await processRequest({
        request,
        session,
        credentialRequestOrigin: requestOrigin,
        selectedVCs
      })
      chapiEvent.respondWith(
        Promise.resolve(
          verifiablePresentation
            ? {
                dataType: 'VerifiablePresentation',
                data: verifiablePresentation
              }
            : null
        )
      )
    } catch (err) {
      console.error('CHAPI request processing failed:', err)
      setBlockReason('processFailed')
      setPageState('blocked')
    }
  }

  function handleCancel() {
    chapiEvent?.respondWith(Promise.resolve(null))
  }

  if (pageState === 'initializing') {
    return (
      <Box
        className="fw-page"
        sx={{ ...chapiStyles.page, alignItems: 'center' }}
      >
        <CircularProgress />
      </Box>
    )
  }

  const title =
    requestKind === 'didauth'
      ? t('chapi.get.didAuthTitle')
      : t('chapi.get.title')

  return (
    <Box className="fw-page" sx={chapiStyles.page}>
      <Box sx={chapiStyles.card}>
        <Typography variant="h5" sx={{ fontWeight: 600 }}>
          {title}
        </Typography>

        <Box>
          <Typography variant="body2" color="text.secondary">
            {t('chapi.get.requestedBy')}
          </Typography>
          <Typography sx={chapiStyles.originChip}>{requestOrigin}</Typography>
        </Box>

        {requestReason && (
          <Typography variant="body2">{requestReason}</Typography>
        )}

        {pageState === 'blocked' && blockReason && (
          <Stack spacing={2}>
            <Typography variant="body2" color="error.main">
              {t(BLOCK_MESSAGE_KEY[blockReason])}
            </Typography>
            <Button
              variant="outlined"
              sx={{ alignSelf: 'flex-start', textTransform: 'none' }}
              onClick={handleCancel}
            >
              {t('common.cancel')}
            </Button>
          </Stack>
        )}

        {pageState === 'awaiting-login' && (
          <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
        )}

        {pageState === 'selecting' && requestKind === 'didauth' && (
          <Stack spacing={2}>
            <Typography variant="body2">
              {t('chapi.get.didAuthPrompt', { origin: requestOrigin })}
            </Typography>
            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                sx={{ textTransform: 'none' }}
                onClick={() => respondWithVp([])}
              >
                {t('common.continue')}
              </Button>
              <Button
                variant="outlined"
                sx={{ textTransform: 'none' }}
                onClick={handleCancel}
              >
                {t('common.cancel')}
              </Button>
            </Stack>
          </Stack>
        )}

        {pageState === 'selecting' && requestKind !== 'didauth' && (
          <>
            {requestKind === 'vc+didauth' && (
              <Typography variant="body2" color="text.secondary">
                {t('chapi.get.didAuthAlso', { origin: requestOrigin })}
              </Typography>
            )}
            <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
              {t('chapi.get.selectPrompt')}
            </Typography>
            {credentials.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('chapi.get.walletEmpty')}
              </Typography>
            ) : (
              <Box sx={chapiStyles.credentialList}>
                {credentials.map(({ cid, vc }) => (
                  <Box key={cid} sx={chapiStyles.credentialRow}>
                    <Box sx={chapiStyles.credentialInfo}>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        {credentialTitle(vc)}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {issuerName(vc)}
                      </Typography>
                    </Box>
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={() => respondWithVp([vc])}
                    >
                      {t('common.share')}
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
            <Typography variant="body2">{t('chapi.get.sharing')}</Typography>
          </Box>
        )}
      </Box>
    </Box>
  )
}
