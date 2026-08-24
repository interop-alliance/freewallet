/**
 * CHAPI credential-store popup. Runs inside a CHAPI-managed popup iframe (not
 * the main app shell) when a third-party site calls navigator.credentials.store().
 * Intercepts the CHAPI event, prompts the user to log in with their passphrase,
 * then stores every credential the offer carries to their wallet on
 * confirmation. The offer arrives either inline on the event or, when the issuer
 * names a VC API exchange, from that exchange -- which may first ask the wallet
 * to authenticate its holder DID, in which case the credentials are collected
 * after login rather than before it. An exchange issuer already holds the
 * credential it delivered, so the popup acknowledges it with an `OutOfBand`
 * CHAPI response; an inline offer gets the stored presentation echoed back.
 */
import { useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
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
import {
  completePopupLogin,
  mapPopupLoginError
} from '@/session/completePopupLogin'
import type { Session } from '@/types/auth'
import { AppKeyRefusedError } from '@interop/wallet-core/request'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { issuerName } from '@/lib/viewMappers/issuerName'
import { chapiStyles } from '@/styles/appStyles'
import { ChapiInitializing } from '@/pages/chapi/ChapiInitializing'
import {
  beginExchange,
  classifyCHAPIStoreEvent,
  classifyRequest,
  collectIssuedPresentation,
  composeVP,
  credentialsOf,
  negotiateCryptosuite,
  queriesOf,
  vcApiExchangeUrl,
  type CHAPIStoreEvent,
  type IVPRDetails
} from '@/lib/walletRequest'
// The exchange client's request param is the shared (spec) VPR shape, narrower
// than Freewallet's local `IVPRDetails` (widened with the App Connect query).
import type { IVPRDetails as ISpecVPRDetails } from '@interop/wallet-core/request'
import { RequestSourcePanel } from './RequestSourcePanel'
import { CHAPILoginForm } from './CHAPILoginForm'
import { useTranslation } from 'react-i18next'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:chapi:store')

type PageState =
  | 'initializing'
  | 'awaiting-login'
  | 'authenticating'
  | 'confirming'
  | 'stored'
  | 'failed'

/**
 * The holder-binding step an issuance exchange may open with: the exchange URL
 * to answer, and the DID-Auth VPR it asked. Held until the user logs in, since
 * signing the answer needs their key.
 */
type PendingDIDAuth = {
  exchangeUrl: string
  request: IVPRDetails
}

/**
 * E2E test seam. A CHAPI popup cannot run in an automated browser because
 * `receiveCredentialEvent()` only resolves through the CHAPI mediator
 * handshake, which no test harness performs. In non-production builds only, a
 * Playwright spec may inject a ready-made event on
 * `window.__E2E_CHAPI_STORE_EVENT__` (with a `respondWith` that records the
 * payload) to drive this popup deterministically. Returns undefined in
 * production and whenever no event was injected, so the real CHAPI path runs.
 */
function injectedCHAPIStoreEvent(): CHAPIStoreEvent | undefined {
  if (import.meta.env.MODE === 'production') {
    return undefined
  }
  return (window as unknown as { __E2E_CHAPI_STORE_EVENT__?: CHAPIStoreEvent })
    .__E2E_CHAPI_STORE_EVENT__
}

export function WalletStorePage() {
  const { t } = useTranslation()
  const [pageState, setPageState] = useState<PageState>('initializing')
  const [chapiEvent, setCHAPIEvent] = useState<CHAPIStoreEvent | null>(null)
  // Every credential the offer carries; all are stored on confirmation.
  const [vcs, setVcs] = useState<IVerifiableCredential[]>([])
  const [vp, setVp] = useState<IVerifiablePresentation | null>(null)
  // True when the offer arrived through a VC API exchange rather than inline on
  // the CHAPI event. Such an issuer received the credential out of band (the
  // wallet POSTed it to the exchange), so it expects an `OutOfBand` response to
  // move on to its own status page; an inline offer expects the stored
  // presentation echoed back instead.
  const [viaExchange, setViaExchange] = useState(false)
  // Set when the issuance exchange opened with a DID-Auth request; answered
  // after login, and the credentials arrive in the reply.
  const [pendingDIDAuth, setPendingDIDAuth] = useState<PendingDIDAuth | null>(
    null
  )
  const [session, setSession] = useState<Session | null>(null)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [initError, setInitError] = useState<string | null>(null)
  const [storeError, setStoreError] = useState<string | null>(null)
  const [storing, setStoring] = useState(false)
  const initialized = useRef(false)

  useEffect(() => {
    if (initialized.current) {
      return
    }
    initialized.current = true

    async function init() {
      const injected = injectedCHAPIStoreEvent()
      if (!injected) {
        await loadOnce(
          MEDIATOR_BASE + encodeURIComponent(window.location.origin)
        )
      }
      const event =
        injected ?? ((await receiveCredentialEvent()) as CHAPIStoreEvent)
      const { dataType, data, options } = event.credential ?? {}
      log.debug('CHAPI store incoming event', {
        origin: event.credentialRequestOrigin ?? '(unknown origin)',
        dataType: dataType ?? '(none)',
        protocols: options?.protocols ?? {}
      })

      // An issuer that names a VC API exchange sends an empty payload and keeps
      // the credentials it is offering on the exchange server.
      const exchange = vcApiExchangeUrl({ protocols: options?.protocols })
      const offered = !!data && Object.keys(data).length > 0
      let incomingVp: IVerifiablePresentation
      if (!offered && exchange) {
        setViaExchange(true)
        log.debug('CHAPI store fetching the offer', { exchange })
        const opening = await beginExchange({ exchangeUrl: exchange })
        log.debug('CHAPI store exchange answered', {
          hasPresentationRequest: !!opening.verifiablePresentationRequest,
          hasPresentation: !!opening.verifiablePresentation
        })

        // Holder binding: the issuer wants a DID-Auth presentation before it
        // hands over the credentials. Signing it needs the user's key, so the
        // exchange is resumed once they have logged in.
        const request = opening.verifiablePresentationRequest
        if (!opening.verifiablePresentation && request) {
          const { didAuth, vcQueries, zcapRequests } = classifyRequest({
            request
          })
          if (!didAuth || vcQueries.length > 0 || zcapRequests.length > 0) {
            throw new Error(
              `The exchange at ${exchange} asked for something other than DID ` +
                'Authentication before offering a credential; such exchanges ' +
                'are not supported.'
            )
          }
          setCHAPIEvent(event)
          setPendingDIDAuth({ exchangeUrl: exchange, request })
          setPageState('awaiting-login')
          return
        }

        if (!opening.verifiablePresentation) {
          throw new Error(
            `The exchange at ${exchange} offered no verifiablePresentation.`
          )
        }
        incomingVp = opening.verifiablePresentation
      } else {
        incomingVp = classifyCHAPIStoreEvent(event).verifiablePresentation
      }

      const credentials = credentialsOf(incomingVp)
      if (credentials.length === 0) {
        log.warn('CHAPI store offered presentation carries no credential')
      }
      setCHAPIEvent(event)
      setVp(incomingVp)
      setVcs(credentials)
      setPageState('awaiting-login')
    }

    init().catch((err: unknown) => {
      log.error('CHAPI store could not read the incoming offer', { err })
      setInitError(
        err instanceof Error
          ? err.message
          : 'Could not read the incoming offer.'
      )
      setPageState('failed')
    })
  }, [])

  async function handleLogin(passphrase: string) {
    setLoginError(null)
    // The shared popup login sequence (keyring resolve in remote-direct mode,
    // account-not-found guard, error mapping) lives in completePopupLogin; only
    // the offer-handling work below is page-specific.
    const result = await completePopupLogin({ passphrase })
    if ('errorKey' in result) {
      setLoginError(t(result.errorKey))
      return
    }
    const popupSession = result.session
    try {
      // Session creation fired `ensureUserCollections` as `session.storageReady`;
      // wait for the collections to be provisioned/opened before storing into
      // them. The popup's background chain (on `session.registryReady`, just
      // the user-key sweep fold in remote-direct mode) is not waited on.
      await popupSession.storageReady
      setSession(popupSession)
      if (pendingDIDAuth) {
        setPageState('authenticating')
        void authenticate({ session: popupSession, pending: pendingDIDAuth })
      } else {
        setPageState('confirming')
      }
    } catch (err) {
      setLoginError(t(mapPopupLoginError(err)))
    }
  }

  /**
   * Answers the issuance exchange's holder-binding step: signs a DID-Auth
   * presentation over the exchange's challenge and trades it for the offered
   * credentials. The `domain` falls back to the exchange's own origin, which is
   * where the answer is POSTed, for issuers that state a challenge but no
   * domain.
   */
  async function authenticate({
    session: loggedIn,
    pending: { exchangeUrl, request }
  }: {
    session: Session
    pending: PendingDIDAuth
  }) {
    try {
      const verifiablePresentation = await composeVP({
        session: loggedIn,
        didAuthRequested: true,
        challenge: request.challenge,
        domain: request.domain ?? new URL(exchangeUrl).origin,
        cryptosuite: negotiateCryptosuite(queriesOf(request))
      })
      log.debug('CHAPI store authenticating to the exchange', {
        holder: verifiablePresentation.holder
      })
      const offeredVp = await collectIssuedPresentation({
        request: request as ISpecVPRDetails,
        exchangeUrl,
        verifiablePresentation
      })
      const credentials = credentialsOf(offeredVp)
      log.debug('CHAPI store exchange offered credentials', {
        count: credentials.length
      })
      if (credentials.length === 0) {
        log.warn('CHAPI store offered presentation carries no credential')
      }
      setVp(offeredVp)
      setVcs(credentials)
      setPageState('confirming')
    } catch (err) {
      log.error('CHAPI store exchange authentication failed', { err })
      setInitError(
        err instanceof Error
          ? err.message
          : 'Could not authenticate to the issuer.'
      )
      setPageState('failed')
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
      log.error('CHAPI store cannot store', { reason })
      setStoreError(`Cannot store: ${reason}.`)
      return
    }
    setStoreError(null)
    setStoring(true)
    let stored = 0
    try {
      for (const credential of vcs) {
        await session.storage.addCredential({ credential, user: session.user })
        stored++
      }
      setPageState('stored')
    } catch (err) {
      log.error('CHAPI store addCredential failed partway through', {
        stored,
        total: vcs.length,
        err
      })
      const detail =
        err instanceof AppKeyRefusedError
          ? t('common.appKeyRefused')
          : err instanceof Error
            ? err.message
            : 'Could not store the credential.'
      setStoreError(
        stored > 0
          ? `Stored ${stored} of ${vcs.length} credentials, then failed: ` +
              `${detail}`
          : detail
      )
    } finally {
      setStoring(false)
    }
  }

  function handleCancel() {
    chapiEvent?.respondWith(Promise.resolve(null))
  }

  function handleDone() {
    if (!chapiEvent || !vp) {
      return
    }
    // An exchange issuer already holds the credential (it was collected over the
    // exchange, not the CHAPI channel), so it wants an `OutOfBand` acknowledgement
    // rather than the presentation echoed back -- anything else reads to it as a
    // failed store. An inline offer, having no other channel, gets the stored
    // presentation returned to it.
    chapiEvent.respondWith(
      Promise.resolve(
        viaExchange
          ? { dataType: 'OutOfBand', data: {} }
          : { dataType: 'VerifiablePresentation', data: vp }
      )
    )
  }

  if (pageState === 'initializing') {
    return <ChapiInitializing />
  }

  return (
    <Box className="fw-page" sx={chapiStyles.page}>
      <Box sx={chapiStyles.card}>
        <Typography variant="h5" sx={{ fontWeight: 600 }}>
          {t('chapi.store.title')}
        </Typography>

        {pageState === 'failed' && (
          <Stack spacing={2}>
            <Alert severity="error">{initError}</Alert>
            <Button
              variant="outlined"
              sx={{ alignSelf: 'flex-start' }}
              onClick={handleCancel}
            >
              {t('common.cancel')}
            </Button>
          </Stack>
        )}

        {pageState === 'authenticating' && (
          <Box sx={chapiStyles.doneMessage}>
            <CircularProgress size={20} />
            <Typography variant="body2">
              {t('chapi.store.authenticating')}
            </Typography>
          </Box>
        )}

        {vcs.map((offeredVc, index) => (
          <Box key={offeredVc.id ?? index} sx={chapiStyles.credentialSummary}>
            <Typography variant="body2" color="text.secondary">
              {t('common.type')}
            </Typography>
            <Typography variant="subtitle2">
              {credentialTitle(offeredVc)}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {t('common.issuer')}
            </Typography>
            <Typography variant="subtitle2">{issuerName(offeredVc)}</Typography>
          </Box>
        ))}

        {pageState === 'awaiting-login' && (
          <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
        )}

        {pageState === 'confirming' && (
          <Stack spacing={2}>
            {storeError && <Alert severity="error">{storeError}</Alert>}
            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                onClick={handleConfirm}
                disabled={storing}
              >
                {t('common.store')}
              </Button>
              <Button
                variant="outlined"
                onClick={handleCancel}
                disabled={storing}
              >
                {t('common.cancel')}
              </Button>
            </Stack>
            <RequestSourcePanel source={vp} />
          </Stack>
        )}

        {pageState === 'stored' && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            <Alert severity="success">
              {t('chapi.store.storedSuccess', { count: vcs.length })}
            </Alert>
            <Button
              variant="contained"
              sx={{ alignSelf: 'flex-start' }}
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
