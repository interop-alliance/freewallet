/**
 * CHAPI credential-store popup. Runs inside a CHAPI-managed popup iframe (not
 * the main app shell) when a third-party site calls navigator.credentials.store().
 * Intercepts the CHAPI event, prompts the user to log in with their passphrase,
 * then stores every credential the offer carries to their wallet on
 * confirmation. The offer arrives either inline on the event or, when the issuer
 * names a VC API exchange, from that exchange.
 */
import { useEffect, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { loadOnce } from 'credential-handler-polyfill'
import { receiveCredentialEvent } from 'web-credential-handler'
import type {
  IVerifiableCredential,
  IVerifiablePresentation
} from '@interop/data-integrity-core'
import { MEDIATOR_BASE } from '@/app.config'
import { loginWithPassphrase } from '@/session/initSession'
import { persistDelegatedSession } from '@/session/delegatedSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
import type { Session } from '@/types/auth'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { issuerName } from '@/lib/viewMappers/issuerName'
import { chapiStyles } from '@/styles/appStyles'
import {
  classifyCHAPIStoreEvent,
  credentialsOf,
  fetchOfferedPresentation,
  vcApiExchangeUrl,
  type CHAPIStoreEvent
} from '@/lib/walletRequest'
import { CHAPILoginForm } from './CHAPILoginForm'
import { SavedSessionNotice } from './SavedSessionNotice'
import { useTranslation } from 'react-i18next'

type PageState = 'initializing' | 'awaiting-login' | 'confirming' | 'stored'

export function WalletStorePage() {
  const { t } = useTranslation()
  const [pageState, setPageState] = useState<PageState>('initializing')
  const [chapiEvent, setCHAPIEvent] = useState<CHAPIStoreEvent | null>(null)
  // Every credential the offer carries; all are stored on confirmation.
  const [vcs, setVcs] = useState<IVerifiableCredential[]>([])
  const [vp, setVp] = useState<IVerifiablePresentation | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [initError, setInitError] = useState<string | null>(null)
  const [storeError, setStoreError] = useState<string | null>(null)
  // First-party storage factory from the Storage Access API flow (see
  // SavedSessionNotice); a full login persists its delegated session
  // through it so the next popup visit auto-recognizes the user.
  const [firstPartyIdb, setFirstPartyIdb] = useState<IDBFactory | null>(null)
  const initialized = useRef(false)

  useEffect(() => {
    if (initialized.current) {
      return
    }
    initialized.current = true

    async function init() {
      await loadOnce(MEDIATOR_BASE + encodeURIComponent(window.location.origin))
      const event = (await receiveCredentialEvent()) as CHAPIStoreEvent
      const { dataType, data, options } = event.credential ?? {}
      console.log(
        '[CHAPI store] incoming event from %s, dataType: %s, protocols: %s\n%s',
        event.credentialRequestOrigin ?? '(unknown origin)',
        dataType ?? '(none)',
        JSON.stringify(options?.protocols ?? {}),
        JSON.stringify(data, null, 2)
      )

      // An issuer that names a VC API exchange sends an empty payload and keeps
      // the credentials it is offering on the exchange server.
      const exchange = vcApiExchangeUrl({ protocols: options?.protocols })
      const offered = !!data && Object.keys(data).length > 0
      let incomingVp: IVerifiablePresentation
      if (!offered && exchange) {
        console.log('[CHAPI store] fetching the offer from %s', exchange)
        incomingVp = await fetchOfferedPresentation({ exchangeUrl: exchange })
        console.log(
          '[CHAPI store] the exchange offered:\n%s',
          JSON.stringify(incomingVp, null, 2)
        )
      } else {
        incomingVp = classifyCHAPIStoreEvent(event).verifiablePresentation
      }

      const credentials = credentialsOf(incomingVp)
      if (credentials.length === 0) {
        console.warn(
          '[CHAPI store] the offered presentation carries no credential:\n%s',
          JSON.stringify(incomingVp, null, 2)
        )
      }
      setCHAPIEvent(event)
      setVp(incomingVp)
      setVcs(credentials)
      setPageState('awaiting-login')
    }

    init().catch((err: unknown) => {
      console.error('[CHAPI store] could not read the incoming offer:', err)
      setInitError(
        err instanceof Error
          ? err.message
          : 'Could not read the incoming offer.'
      )
    })
  }, [])

  async function handleLogin(passphrase: string) {
    setLoginError(null)
    try {
      // Thread the first-party IndexedDB factory (from the Storage Access API
      // flow) into the keyring lookup so its cache read/write lands in
      // first-party storage rather than the popup's partitioned bucket; fall
      // back to the global factory when no handle is held.
      const { session: s, userExists } = await loginWithPassphrase({
        passphrase,
        idb: firstPartyIdb ?? undefined
      })
      if (!s || !userExists) {
        setLoginError(t('chapi.accountNotFound'))
        return
      }
      await s.storage.ensureUserCollections({
        user: s.user,
        profile: s.profile
      })
      setSession(s)
      setPageState('confirming')
      if (firstPartyIdb) {
        void persistDelegatedSession({ session: s, idb: firstPartyIdb }).catch(
          (err: unknown) => {
            console.warn('Could not persist the delegated session:', err)
          }
        )
      }
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
   * Stores every credential the offer carried. Each is written independently,
   * so a failure part-way through leaves the earlier writes in place; the page
   * says how many were stored rather than reporting a clean success or a clean
   * failure for a run that was neither.
   */
  async function handleConfirm() {
    if (!session || vcs.length === 0) {
      const reason = !session
        ? 'no session is established'
        : 'the offer carried no credential'
      console.error('[CHAPI store] cannot store: %s.', reason)
      setStoreError(`Cannot store: ${reason}.`)
      return
    }
    setStoreError(null)
    let stored = 0
    try {
      for (const credential of vcs) {
        await session.storage.addCredential({ credential })
        stored++
      }
      setPageState('stored')
    } catch (err) {
      console.error(
        '[CHAPI store] addCredential failed after storing %d of %d:',
        stored,
        vcs.length,
        err
      )
      const detail =
        err instanceof Error ? err.message : 'Could not store the credential.'
      setStoreError(
        stored > 0
          ? `Stored ${stored} of ${vcs.length} credentials, then failed: ` +
              `${detail}`
          : detail
      )
    }
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
      <Box
        className="fw-page"
        sx={{ ...chapiStyles.page, alignItems: 'center' }}
      >
        <CircularProgress />
      </Box>
    )
  }

  return (
    <Box className="fw-page" sx={chapiStyles.page}>
      <Box sx={chapiStyles.card}>
        <Typography variant="h5" sx={{ fontWeight: 600 }}>
          {t('chapi.store.title')}
        </Typography>

        {initError && (
          <Typography variant="body2" color="error.main">
            {initError}
          </Typography>
        )}

        {vcs.map((offeredVc, index) => (
          <Box key={offeredVc.id ?? index} sx={chapiStyles.credentialSummary}>
            <Typography variant="body2" color="text.secondary">
              {t('common.type')}
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {credentialTitle(offeredVc)}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {t('common.issuer')}
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {issuerName(offeredVc)}
            </Typography>
          </Box>
        ))}

        {pageState === 'awaiting-login' && (
          <>
            <SavedSessionNotice onFirstPartyStorage={setFirstPartyIdb} />
            <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
          </>
        )}

        {pageState === 'confirming' && (
          <Stack spacing={2}>
            {storeError && (
              <Typography variant="body2" color="error.main">
                {storeError}
              </Typography>
            )}
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
          </Stack>
        )}

        {pageState === 'stored' && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            <Typography variant="body2" color="success.main">
              {t('chapi.store.storedSuccess', { count: vcs.length })}
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
