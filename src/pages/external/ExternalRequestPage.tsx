/**
 * The request page for an interaction URL: a request arriving from outside
 * the app (a CLI agent's `di was request-grant` link by deep link,
 * `/external/request?url=<interaction url>`, or the same URL pasted into the
 * Add Credential box or scanned from a terminal QR) and answered without a
 * CHAPI popup. The `WalletGetPage` shape minus CHAPI: open the exchange behind
 * the interaction URL, classify the VPR, render the storage-access consent
 * panel, delegate through the grant engine, and POST the unsigned zcap-only
 * presentation back to the exchange.
 *
 * The page lives outside `ProtectedRoute` like the popups. A session already
 * live in the app is used directly; otherwise the page runs the ordinary
 * login in place (the same durability decision `/login` makes) and adopts
 * the session app-wide. Everything the entry point refuses -- the exchange
 * states, DID Auth, a `domain`, an `AppConnectQuery`, a delivery endpoint on
 * another origin, a grant class outside the allowlist -- is decided in
 * `src/lib/walletRequest/externalRequest.ts` before consent renders, each
 * with its own copy. The grant is recorded on the Login activity under the
 * fixed `n/a (API request)` origin marker before anything is delivered.
 */
import { useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import {
  RP_ZCAP_TTL_MS,
  RP_ZCAP_WRITE_TTL_MS,
  SHARE_ZCAP_TTL_MS
} from '@/app.config'
import { useAuthStore } from '@/stores/authStore'
import { loginWithPassphrase } from '@/session/initSession'
import { loginErrorKey } from '@/session/loginErrorKey'
import { recordWalletLogin } from '@/session/walletLoginActivity'
import { checkRecoveryHealth } from '@/session/recovery'
import { registerWallet } from '@/lib/registerWallet'
import { showToast } from '@/stores/toastStore'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { chapiStyles } from '@/styles/appStyles'
import type { Session } from '@/types/auth'
import {
  composeAndDeliverResponse,
  existingCollectionsFrom,
  hasZcapStorage,
  resolveGrants,
  WalletResponseFailure,
  type IVPRDetails,
  type ResolvedGrant,
  type WalletRequestProfile
} from '@/lib/walletRequest'
import {
  barredGrants,
  EXTERNAL_REQUEST_ORIGIN,
  ExternalRequestRefusedError,
  interactionUrlFromSearch,
  openExternalRequest,
  precheckExternalRequest,
  type ExternalRequestRefusal
} from '@/lib/walletRequest/externalRequest'
import { ChapiInitializing } from '@/pages/chapi/ChapiInitializing'
import { CHAPILoginForm } from '@/pages/chapi/CHAPILoginForm'
import { RequestSourcePanel } from '@/pages/chapi/RequestSourcePanel'
import { ZcapGrantsPanel } from '@/pages/chapi/ZcapGrantsPanel'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:request:page')

type PageState =
  | 'opening'
  | 'awaiting-login'
  | 'preparing'
  | 'consenting'
  | 'responding'
  | 'delivered'
  | 'blocked'

/**
 * Why the page stopped; maps to an `externalRequest.refusals.*` message key.
 * The entry point's own refusals plus the two post-login blocks the popup
 * shares (no remote storage to delegate against, a failed compose) and the
 * delivery failure, which keeps the composed response for manual delivery.
 */
type BlockReason =
  | ExternalRequestRefusal
  | 'zcapUnavailable'
  | 'processFailed'
  | 'nothingGranted'
  | 'exchangeFailed'

const RP_ZCAP_TTL_DAYS = Math.round(RP_ZCAP_TTL_MS / (24 * 60 * 60 * 1000))
const RP_ZCAP_WRITE_TTL_DAYS = Math.round(
  RP_ZCAP_WRITE_TTL_MS / (24 * 60 * 60 * 1000)
)
const SHARE_ZCAP_TTL_DAYS = Math.round(
  SHARE_ZCAP_TTL_MS / (24 * 60 * 60 * 1000)
)

/**
 * The distinct grantee DIDs a request names, for the requester row. An agent
 * request names one; the row lists each in case a request names several.
 *
 * @param profile {WalletRequestProfile}
 * @returns {string[]}
 */
function requesterDids(profile: WalletRequestProfile): string[] {
  const dids = profile.zcapRequests
    .map(({ controller }) => controller)
    .filter(
      (controller): controller is string => typeof controller === 'string'
    )
  return [...new Set(dids)]
}

export function ExternalRequestPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const liveSession = useAuthStore(state => state.session)
  const adoptSession = useAuthStore(state => state.login)
  const { copied, copy } = useCopyToClipboard()
  const [pageState, setPageState] = useState<PageState>('opening')
  const [blockReason, setBlockReason] = useState<BlockReason | null>(null)
  const [request, setRequest] = useState<IVPRDetails | null>(null)
  const [exchangeUrl, setExchangeUrl] = useState<string | null>(null)
  const [deliveryHost, setDeliveryHost] = useState('')
  const [profile, setProfile] = useState<WalletRequestProfile | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [resolvedGrants, setResolvedGrants] = useState<ResolvedGrant[]>([])
  const [loginError, setLoginError] = useState<string | null>(null)
  // The composed response a failed exchange POST left behind, offered for
  // manual delivery: the Login activity is already recorded, so the grant
  // stands whether or not the requester ever receives it.
  const [undeliveredResponse, setUndeliveredResponse] = useState<string | null>(
    null
  )
  const initialized = useRef(false)

  function block(reason: BlockReason) {
    setBlockReason(reason)
    setPageState('blocked')
  }

  /**
   * Resolves the request's grants against the session's Space and runs the
   * allowlist check, then renders consent. The one post-login refusal the
   * popup also has: no remote Space to delegate against.
   */
  async function prepareConsent({
    loggedIn,
    requestProfile
  }: {
    loggedIn: Session
    requestProfile: WalletRequestProfile
  }) {
    setPageState('preparing')
    await loggedIn.storage.ready()
    await loggedIn.storageReady
    if (!hasZcapStorage(loggedIn) || !loggedIn.storage.spaceUrl) {
      block('zcapUnavailable')
      return
    }
    const grants = resolveGrants({
      zcapRequests: requestProfile.zcapRequests,
      spaceUrl: loggedIn.storage.spaceUrl,
      collections: existingCollectionsFrom(
        await loggedIn.storage.listCollectionPublicStates()
      )
    })
    // The allowlist: the first point a target's class is known is after
    // resolution, so the check runs here, still before consent renders.
    if (barredGrants(grants).length > 0) {
      block('barredGrant')
      return
    }
    setResolvedGrants(grants)
    setPageState('consenting')
  }

  useEffect(() => {
    if (initialized.current) {
      return
    }
    initialized.current = true

    async function init() {
      const url = interactionUrlFromSearch(location.search)
      if (!url) {
        block('invalidLink')
        return
      }
      const opened = await openExternalRequest({ url })
      const checked = precheckExternalRequest({
        request: opened.request,
        exchangeUrl: opened.exchangeUrl
      })
      setRequest(opened.request)
      setExchangeUrl(opened.exchangeUrl)
      setDeliveryHost(checked.deliveryHost)
      setProfile(checked.profile)
      if (liveSession) {
        setSession(liveSession)
        await prepareConsent({
          loggedIn: liveSession,
          requestProfile: checked.profile
        })
        return
      }
      setPageState('awaiting-login')
    }

    init().catch((err: unknown) => {
      if (err instanceof ExternalRequestRefusedError) {
        log.warn('External request refused', { err })
        block(err.refusal)
        return
      }
      log.error('External request initialization failed', { err })
      block('processFailed')
    })
    // Runs once, on the URL the page was opened with.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /**
   * The in-page login for a visit with no live session: the ordinary login
   * (so a non-remembered browser gets the same transient-by-default decision
   * `/login` makes), adopted app-wide so the rest of the app sees it too.
   */
  async function handleLogin(passphrase: string) {
    setLoginError(null)
    if (!profile) {
      return
    }
    let loggedIn: Session
    try {
      const result = await loginWithPassphrase({ passphrase })
      if (!result.session) {
        setLoginError(
          t(
            result.userExists
              ? 'auth.errors.clientNotEnrolled'
              : 'auth.errors.profileNotFound'
          )
        )
        return
      }
      loggedIn = result.session
      await loggedIn.storageReady
    } catch (err) {
      setLoginError(t(loginErrorKey({ err, label: 'External request login' })))
      return
    }
    // The session is adopted app-wide, so the post-login steps `/login` runs
    // follow it here too: the CHAPI handler registration (otherwise never
    // installed for this session), the unlock-methods backfill, the recovery
    // health check, and the could-not-remember warning. All best-effort.
    adoptSession(loggedIn)
    recordWalletLogin({ session: loggedIn })
    void registerWallet()
    if (loggedIn.userKeyPersistFailed) {
      showToast({
        message: t('auth.login.rememberBrowserWarning'),
        severity: 'warning'
      })
    }
    void checkRecoveryHealth({ session: loggedIn })
      .then(flags => {
        if (flags.length > 0) {
          showToast({
            message: t('auth.login.recoveryHealthWarning'),
            severity: 'warning'
          })
        }
      })
      .catch(err => log.warn('Recovery health check failed', { err }))
    setSession(loggedIn)
    try {
      await prepareConsent({ loggedIn, requestProfile: profile })
    } catch (err) {
      // The login form is gone by now, so a failed preparation is a page
      // block, not a login error.
      log.error('External request preparation failed', { err })
      block('processFailed')
    }
  }

  /**
   * Approves the request: the compose / persist-the-Login-activity / deliver
   * sequence runs in `composeAndDeliverResponse`, which POSTs the response to
   * the exchange; there is no second channel here, so a failed delivery
   * offers the composed response for manual delivery instead.
   */
  async function approve() {
    if (!session || !request || !profile || !exchangeUrl) {
      return
    }
    setPageState('responding')
    try {
      const response = await composeAndDeliverResponse({
        request,
        session,
        profile,
        // No requesting origin exists on this entry point; the fixed marker
        // is what the Login activity records and what the Applications
        // listing keys agent rows on.
        requestOrigin: EXTERNAL_REQUEST_ORIGIN,
        selectedVCs: [],
        exchangeUrl
      })
      // An empty compose (every grant turned unsatisfiable at delegation
      // time -- a collection created by another client since consent, say)
      // POSTs nothing, so it must not read as delivered.
      if (!response.verifiablePresentation) {
        block('nothingGranted')
        return
      }
      setPageState('delivered')
    } catch (err) {
      if (err instanceof WalletResponseFailure) {
        if (err.reason === 'exchangeFailed' && err.response) {
          setUndeliveredResponse(JSON.stringify(err.response, null, 2))
        }
        block(
          err.reason === 'zcapUnavailable' || err.reason === 'exchangeFailed'
            ? err.reason
            : 'processFailed'
        )
        return
      }
      log.error('External request processing failed', { err })
      block('processFailed')
    }
  }

  /**
   * Declines the request. The exchange is abandoned rather than notified
   * (the protocol defines no decline message; the exchange expires on its
   * own and the requester's poll reports no response).
   */
  function leave() {
    navigate(session ? '/dashboard' : '/', { replace: true })
  }

  if (pageState === 'opening') {
    return <ChapiInitializing />
  }

  const requesters = profile ? requesterDids(profile) : []

  return (
    <Box className="fw-page" sx={chapiStyles.page}>
      <Box sx={chapiStyles.card}>
        <Typography
          variant="h5"
          sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}
        >
          {t('externalRequest.title')}
        </Typography>

        {profile && (
          <Stack spacing={1}>
            <Box>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {t('externalRequest.requestedBy')}
              </Typography>
              {profile.agent && (
                // Self-declared: the name is whatever the link's author
                // typed, bounded by classification (64 characters, no
                // control characters) and never a substitute for the key.
                <Typography
                  variant="body2"
                  sx={{ fontStyle: 'italic', overflowWrap: 'anywhere' }}
                >
                  {t('externalRequest.agentName', { name: profile.agent.name })}
                </Typography>
              )}
              <Typography variant="caption" color="text.secondary">
                {profile.agent
                  ? t('externalRequest.agentNameNote')
                  : t('externalRequest.requesterNote')}
              </Typography>
              {requesters.map(did => (
                <Typography
                  key={did}
                  variant="body2"
                  sx={{
                    fontFamily: 'monospace',
                    overflowWrap: 'anywhere',
                    mt: 0.5
                  }}
                >
                  {did}
                </Typography>
              ))}
            </Box>
            <Stack
              direction="row"
              spacing={1}
              sx={{ alignItems: 'center', flexWrap: 'wrap' }}
            >
              <Typography variant="body2" color="text.secondary">
                {t('externalRequest.deliveryLabel')}
              </Typography>
              <Chip
                size="small"
                label={deliveryHost}
                sx={chapiStyles.originChip}
              />
            </Stack>
          </Stack>
        )}

        {pageState === 'blocked' && blockReason && (
          <Stack spacing={2}>
            <Alert severity="error">
              {t(`externalRequest.refusals.${blockReason}`)}
            </Alert>
            {undeliveredResponse && (
              <Stack spacing={1}>
                <Typography variant="body2">
                  {t('externalRequest.manualDelivery')}
                </Typography>
                <Box
                  component="pre"
                  sx={{
                    m: 0,
                    p: 1,
                    maxHeight: 240,
                    overflow: 'auto',
                    fontSize: '0.75rem',
                    bgcolor: 'action.hover',
                    borderRadius: 1
                  }}
                >
                  {undeliveredResponse}
                </Box>
                <Button
                  variant="outlined"
                  sx={{ alignSelf: 'flex-start' }}
                  onClick={() => void copy(undeliveredResponse)}
                >
                  {copied ? t('common.copied') : t('common.copy')}
                </Button>
              </Stack>
            )}
            <Button
              variant="outlined"
              sx={{ alignSelf: 'flex-start' }}
              onClick={leave}
            >
              {t('common.close')}
            </Button>
          </Stack>
        )}

        {pageState === 'awaiting-login' && (
          <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
        )}

        {pageState === 'preparing' && (
          <Box sx={chapiStyles.doneMessage}>
            <CircularProgress size={20} />
            <Typography variant="body2">
              {t('externalRequest.preparing')}
            </Typography>
          </Box>
        )}

        {pageState === 'consenting' && (
          <Stack spacing={2}>
            <ZcapGrantsPanel
              grants={resolvedGrants}
              ttlDays={RP_ZCAP_TTL_DAYS}
              writeTtlDays={RP_ZCAP_WRITE_TTL_DAYS}
              shareTtlDays={SHARE_ZCAP_TTL_DAYS}
              revokeNote={t('externalRequest.noRevokeNote')}
            />
            <Typography variant="caption" color="text.secondary">
              {t('externalRequest.exchangeVisibility')}
            </Typography>
            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                onClick={approve}
                disabled={
                  !resolvedGrants.some(({ target }) => target.satisfiable)
                }
              >
                {t('externalRequest.approve')}
              </Button>
              <Button variant="outlined" onClick={leave}>
                {t('common.cancel')}
              </Button>
            </Stack>
            <RequestSourcePanel source={request} />
          </Stack>
        )}

        {pageState === 'responding' && (
          <Box sx={chapiStyles.doneMessage}>
            <CircularProgress size={20} />
            <Typography variant="body2">
              {t('externalRequest.responding')}
            </Typography>
          </Box>
        )}

        {pageState === 'delivered' && (
          <Stack spacing={2}>
            <Alert severity="success">{t('externalRequest.delivered')}</Alert>
            <Button
              variant="outlined"
              sx={{ alignSelf: 'flex-start' }}
              onClick={leave}
            >
              {t('common.close')}
            </Button>
          </Stack>
        )}
      </Box>
    </Box>
  )
}
