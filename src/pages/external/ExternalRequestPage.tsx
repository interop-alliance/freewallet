/**
 * The request page for an interaction URL: a request arriving from outside
 * the app (a CLI agent's `di was request-grant` link by deep link,
 * `/external/request?url=<interaction url>`, or the same URL pasted into the
 * Add Credential box or scanned from a terminal QR) and answered without a
 * CHAPI popup. The `WalletGetPage` shape minus CHAPI: open the exchange behind
 * the interaction URL, classify the VPR, render the storage-access consent
 * panel, delegate through the grant engine, and POST the zcap-only
 * presentation back to the exchange. It is unsigned, except on a connection
 * request, where the wallet's pairwise key toward the agent signs it.
 *
 * The page lives outside `ProtectedRoute` like the popups. A session already
 * live in the app is used directly; otherwise the page runs the ordinary
 * login in place (the same login routing `/login` runs) and adopts
 * the session app-wide. Everything the entry point refuses -- the exchange
 * states, DID Auth, a `domain`, an `AppConnectQuery`, a delivery endpoint on
 * another origin, a grant class outside the allowlist, a plain URL on an
 * encrypted collection the agent cannot read, a grantee that is one of the
 * account's own wallet clients, and a connection request that is unsigned,
 * carries no `challenge`, asks for another write or another descriptor, or
 * meets no trusted `inbox` -- is decided in
 * `src/lib/walletRequest/externalRequest.ts` before consent renders, each
 * with its own copy. The grant is recorded on the agent's `connections`
 * entry, then on a Grant activity under the fixed `n/a (API request)` origin
 * marker, before anything is escrowed or delivered.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useAuthStore } from '@/stores/authStore'
import { loginWithPassphrase } from '@/session/initSession'
import { loginErrorKey } from '@/session/loginErrorKey'
import { useDeadPointerRemoval } from '@/hooks/useDeadPointerRemoval'
import { RemoveSignInDataButton } from '@/components/RemoveSignInDataButton'
import { completeAppLogin } from '@/session/completeAppLogin'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { chapiStyles } from '@/styles/appStyles'
import type { Session } from '@/types/auth'
import {
  composeAndDeliverResponse,
  existingCollectionsFrom,
  grantTtlDays,
  hasZcapStorage,
  isSatisfiable,
  resolveGrants,
  WalletResponseFailure,
  type GrantRequestKind,
  type IVPRDetails,
  type WalletRequestProfile
} from '@/lib/walletRequest'
import {
  barredGrants,
  EXTERNAL_REQUEST_ORIGIN,
  ExternalRequestRefusedError,
  interactionUrlFromSearch,
  namesExistingCollectionByUrl,
  openExternalRequest,
  precheckExternalRequest,
  refuseEnrolledClientController,
  refuseUnattributedServer,
  refuseUntrustedInbox,
  unreadableGrants,
  type ExternalRequestRefusal
} from '@/lib/walletRequest/externalRequest'
import { useAttributedGrants } from '@/hooks/useAttributedGrants'
import { findKnownAgents } from '@/lib/connectedApps'
import { listedClientDids, readDirectoryListing } from '@/session/clients'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { ChapiInitializing } from '@/pages/chapi/ChapiInitializing'
import { CHAPILoginForm } from '@/pages/chapi/CHAPILoginForm'
import { RequestSourcePanel } from '@/pages/chapi/RequestSourcePanel'
import { ZcapGrantsPanel } from '@/pages/chapi/ZcapGrantsPanel'
import { createLogger } from '@/lib/log'
import { wasServiceInfo } from '@/lib/wasService'

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

/**
 * The distinct grantee DIDs a request names, for the requester row. The
 * precheck refuses a request naming more than one, so a rendered row lists
 * exactly one.
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
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const liveSession = useAuthStore(state => state.session)
  const { copied, copy } = useCopyToClipboard()
  const [pageState, setPageState] = useState<PageState>('opening')
  const [blockReason, setBlockReason] = useState<BlockReason | null>(null)
  const [request, setRequest] = useState<IVPRDetails | null>(null)
  const [exchangeUrl, setExchangeUrl] = useState<string | null>(null)
  const [deliveryHost, setDeliveryHost] = useState('')
  const [profile, setProfile] = useState<WalletRequestProfile | null>(null)
  // A connection request (one naming the `#inbox` descriptor) or any other
  // interaction-URL request, as the precheck classed it.
  const [requestKind, setRequestKind] = useState<
    'interaction-url' | 'connection-request'
  >('interaction-url')
  const [session, setSession] = useState<Session | null>(null)
  // The consent screen's grants: the first pass at once, then the pass with
  // the existing collections' attribution read in. A plain URL naming an
  // existing collection waits for that pass instead, before consent.
  const { grants: resolvedGrants, attributeGrants } = useAttributedGrants()
  const [loginError, setLoginError] = useState<string | null>(null)
  // The dead-pointer refusal's removal offer. Reset by every attempt.
  const removal = useDeadPointerRemoval()
  const [loginNotice, setLoginNotice] = useState<string | null>(null)
  // The requester DIDs this account has granted before and not revoked,
  // read off the `connections` directory after consent renders.
  const [knownAgents, setKnownAgents] = useState<
    Map<string, { name?: string; grantedAt?: string }>
  >(new Map())
  // What the mint will actually produce: under a transient session's
  // generation delegation each configured TTL is limited by that parent's
  // life. The panel states the share TTL on a connection request's rows.
  const grantDays = useMemo(
    () => grantTtlDays({ session: session ?? undefined }),
    [session]
  )
  // The composed response a failed exchange POST left behind, offered for
  // manual delivery: the Grant activity is already recorded, so the grant
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
   * popup also has: no remote Space to delegate against. A plain URL naming
   * an existing collection holds consent behind the attribution pass, which
   * reads the key epochs the unreadable-target refusal needs. A connection
   * request also reads the inbox's trust, and is refused when the account
   * has no inbox the wallet would read.
   */
  async function prepareConsent({
    loggedIn,
    requestProfile,
    kind
  }: {
    loggedIn: Session
    requestProfile: WalletRequestProfile
    kind: GrantRequestKind
  }) {
    setPageState('preparing')
    await loggedIn.storage.ready()
    await loggedIn.storageReady
    const spaceUrl = loggedIn.storage.spaceUrl
    if (!hasZcapStorage(loggedIn) || !spaceUrl) {
      block('zcapUnavailable')
      return
    }
    // The existing collections' public state, consulted by grant resolution.
    // The creator of a private collection that already stands is read
    // afterwards, off each collection's own metadata, without holding the
    // consent screen (`useAttributedGrants`) unless the refusal needs it. An interaction-URL grant stamps
    // the agent's did:key (and its self-declared name) on a private
    // collection it provisions, so the same agent's collection reads as its
    // own, and one another party created names that party.
    const resolution = {
      zcapRequests: requestProfile.zcapRequests,
      spaceUrl,
      collections: existingCollectionsFrom(
        await loggedIn.storage.listCollectionPublicStates()
      ),
      requestKind: kind
    }
    const grants = resolveGrants(resolution)
    // The allowlist: the first point a target's class is known is after
    // resolution, so the check runs here, still before consent renders.
    if (barredGrants(grants).length > 0) {
      block('barredGrant')
      return
    }
    // The account log and, on a connection request, the inbox's trust are
    // read together; the refusals below still apply in order. A read that
    // fails fails the preparation closed.
    const [clientDids, inbox] = await Promise.all([
      listedClientDids({ session: loggedIn }),
      kind === 'connection-request' ? loggedIn.storage.readInbox() : undefined
    ])
    // A link naming the did:key of a wallet client the account document lists
    // or ever listed is refused before consent: its grants would land on that
    // client's `connections` entry, where no listing shows them.
    refuseEnrolledClientController({ profile: requestProfile, clientDids })
    // The inbox grant is only worth delegating into an inbox the wallet
    // reads, by the same trust rule the inbox pass reads it under. The inbox
    // pass attributes each message by the server's `createdBy`, so a server
    // that does not advertise recording it is refused too.
    if (inbox !== undefined) {
      refuseUntrustedInbox({ trust: inbox.trust })
      refuseUnattributedServer({ service: await wasServiceInfo() })
    }
    // Best-effort, as on the popup: an unread epoch refuses nothing.
    const attribution = attributeGrants({
      resolution,
      grants,
      storage: loggedIn.storage
    })
    if (
      namesExistingCollectionByUrl({
        grants,
        collections: resolution.collections
      })
    ) {
      // A plain URL on an encrypted collection whose current key epoch does
      // not list the agent would delegate a zcap over ciphertext only.
      if (unreadableGrants(await attribution).length > 0) {
        block('unreadableTarget')
        return
      }
    }
    setPageState('consenting')
    void readKnownAgents({ loggedIn, requestProfile })
  }

  /**
   * Looks up which requester DIDs this account has granted before, for the
   * display-only known-agent hint: one read of the `connections` directory,
   * matched in memory, so the host sees no read at the requester's id. Runs
   * after consent renders and does not hold it. A failed read logs and shows
   * no hint.
   *
   * @param options {object}
   * @param options.loggedIn {Session}
   * @param options.requestProfile {WalletRequestProfile}
   */
  async function readKnownAgents({
    loggedIn,
    requestProfile
  }: {
    loggedIn: Session
    requestProfile: WalletRequestProfile
  }) {
    try {
      const { connections, spaceUrl } = await readDirectoryListing({
        session: loggedIn
      })
      setKnownAgents(
        findKnownAgents({
          connections,
          spaceUrl,
          controllers: requesterDids(requestProfile)
        })
      )
    } catch (err) {
      log.warn('Known-agent lookup failed', { err })
    }
  }

  /**
   * The known-agent hint for one requester DID, or null when this account
   * has no live grant to it.
   *
   * @param did {string}
   * @returns {string | null}
   */
  function knownAgentHint(did: string): string | null {
    const known = knownAgents.get(did)
    if (!known) {
      return null
    }
    if (!known.grantedAt) {
      return t('externalRequest.knownAgentUndated')
    }
    const date = formatDate({
      isoDate: known.grantedAt,
      locale: i18n.language
    })
    if (known.name) {
      return t('externalRequest.knownAgentNamed', { date, name: known.name })
    }
    return t('externalRequest.knownAgent', { date })
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
      const checked = await precheckExternalRequest({
        request: opened.request,
        exchangeUrl: opened.exchangeUrl
      })
      setRequest(opened.request)
      setExchangeUrl(opened.exchangeUrl)
      setDeliveryHost(checked.deliveryHost)
      setProfile(checked.profile)
      setRequestKind(checked.requestKind)
      if (liveSession) {
        setSession(liveSession)
        await prepareConsent({
          loggedIn: liveSession,
          requestProfile: checked.profile,
          kind: checked.requestKind
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
    setLoginNotice(null)
    removal.clear()
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
      // The session is adopted app-wide and stays on this page, so the
      // shared post-login sequence runs without its navigation step.
      await completeAppLogin({ session: loggedIn, t })
    } catch (err) {
      setLoginError(
        t(loginErrorKey({ err, label: 'External request login' }).key)
      )
      removal.offerFrom(err)
      return
    }
    setSession(loggedIn)
    try {
      await prepareConsent({
        loggedIn,
        requestProfile: profile,
        kind: requestKind
      })
    } catch (err) {
      // The login form is gone by now, so a failed preparation is a page
      // block, not a login error.
      if (err instanceof ExternalRequestRefusedError) {
        log.warn('External request refused', { err })
        block(err.refusal)
        return
      }
      log.error('External request preparation failed', { err })
      block('processFailed')
    }
  }

  /**
   * The dead-pointer removal's outcome, as the login form's notice, or on a
   * failed removal (`null`) as its error, beside the offer that stays.
   */
  function handleSignInDataRemoved(
    outcome: { unlockSpaceDeleted: boolean } | null
  ) {
    if (!outcome) {
      setLoginError(t('auth.accountGone.failed'))
      return
    }
    setLoginError(null)
    setLoginNotice(
      t(
        outcome.unlockSpaceDeleted
          ? 'auth.accountGone.removed'
          : 'auth.accountGone.incomplete'
      )
    )
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
        // is what the Grant activity records. The agent's `connections`
        // entry, keyed by its did:key, is what the Applications page lists.
        requestOrigin: EXTERNAL_REQUEST_ORIGIN,
        selectedVCs: [],
        exchangeUrl,
        // The one entry point that grants a standalone capability query.
        delegateStandaloneZcaps: true,
        requestKind
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
              {requesters.map(did => {
                const hint = knownAgentHint(did)
                return (
                  <Box key={did}>
                    <Typography
                      variant="body2"
                      sx={{
                        fontFamily: 'monospace',
                        overflowWrap: 'anywhere',
                        mt: 0.5
                      }}
                    >
                      {did}
                    </Typography>
                    {hint && (
                      // Display-only: naming someone else's DID gains a
                      // requester nothing, since only the key holder can
                      // invoke what is delegated to it.
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: 'block', overflowWrap: 'anywhere' }}
                      >
                        {hint}
                      </Typography>
                    )}
                  </Box>
                )
              })}
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
          <Stack spacing={2}>
            {loginNotice && <Alert severity="info">{loginNotice}</Alert>}
            <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
            <RemoveSignInDataButton
              removal={removal}
              onRemoved={handleSignInDataRemoved}
            />
          </Stack>
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
              ttlDays={grantDays.ttlDays}
              writeTtlDays={grantDays.writeTtlDays}
              shareTtlDays={grantDays.shareTtlDays}
              connectionRequest={requestKind === 'connection-request'}
            />
            <Typography variant="caption" color="text.secondary">
              {t('externalRequest.exchangeVisibility')}
            </Typography>
            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                onClick={approve}
                disabled={
                  !resolvedGrants.some(({ target }) => isSatisfiable(target))
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
