/**
 * CHAPI credential-get popup. Runs inside a CHAPI-managed popup iframe (not
 * the main app shell) when a third-party site calls navigator.credentials.get().
 * Intercepts and classifies the CHAPI event, prompts the user to log in with
 * their passphrase, then shows a single consent screen composed of up to three
 * profile-driven sections:
 *
 * - **DID Authentication** -- a notice that the site is authenticating the
 *   user's DID (the response VP is signed over the request challenge/domain);
 * - **Credential selection** -- the stored VCs matching the request's
 *   QueryByExample queries, including a self-issued Login Credential (username);
 * - **Storage access** -- the WAS capabilities the site is requesting, each
 *   delegated to the site's DID and embedded in the response VP.
 *
 * A single Continue button approves everything shown; Cancel responds `null`.
 *
 * An App Connect request (`profile.appConnect`) replaces the three generic
 * sections with a dedicated app-centric panel: "Connect {app} to storage?",
 * first-run vs returning copy, and the requested collections + access -- one
 * Connect button approves the whole thing (match-or-mint the app key,
 * delegate the grants to its DID, respond in a single round).
 */
import { useEffect, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { loadOnce } from 'credential-handler-polyfill'
import { receiveCredentialEvent } from 'web-credential-handler'
import {
  MEDIATOR_BASE,
  RP_ZCAP_TTL_MS,
  RP_ZCAP_WRITE_TTL_MS
} from '@/app.config'
import {
  completePopupLogin,
  mapPopupLoginError
} from '@/session/completePopupLogin'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { issuerName } from '@/lib/viewMappers/issuerName'
import {
  findLoginCredential,
  loginHandleOf,
  LOGIN_CREDENTIAL_TYPE
} from '@/lib/loginCredential'
import { chapiStyles } from '@/styles/appStyles'
import type { Session } from '@/types/auth'
import type { StoredCredential } from '@/types/credential'
import {
  appConnectZcapRequests,
  classifyRequest,
  credentialQueriesOf,
  deliverPresentation,
  didAuthMethodSupported,
  domainMatchesOrigin,
  hasTypedExample,
  hasZcapStorage,
  isDidAuthOnly,
  processRequest,
  queriesOf,
  requestsCredentialType,
  resolveGrants,
  startExchange,
  vcApiExchangeUrl,
  vcMatchesFor,
  ZcapUnavailableError,
  type CHAPIGetEvent,
  type IVerifiableCredential,
  type IVPRDetails,
  type IVPRQuery,
  type IZcap,
  type ResolvedGrant,
  type WalletRequestProfile,
  type WalletResponse
} from '@/lib/walletRequest'
import { appKeySubjectDid, findAppKeyCredential } from '@/lib/appKey'
import { fetchAppManifest, type AppManifestInfo } from '@/lib/appManifest'
import { ZcapGrantsPanel } from './ZcapGrantsPanel'
import { RequestSourcePanel } from './RequestSourcePanel'
import { CHAPILoginForm } from './CHAPILoginForm'
import { SavedSessionNotice } from './SavedSessionNotice'
import { useTranslation } from 'react-i18next'

type PageState =
  'initializing' | 'awaiting-login' | 'selecting' | 'blocked' | 'done'

/**
 * Why a request cannot proceed; maps to a `chapi.get.*` message key. Set before
 * login for the statically-detectable DID-Auth cases, an unreadable request, or
 * an exchange that could not be opened; after login for a zcap request this
 * wallet cannot back, or a failed compose / delivery.
 */
type BlockReason =
  | 'unsupported'
  | 'domainMismatch'
  | 'zcapUnavailable'
  | 'processFailed'
  | 'malformedRequest'
  | 'exchangeFailed'

const BLOCK_MESSAGE_KEY: Record<BlockReason, string> = {
  unsupported: 'chapi.get.didAuthUnsupported',
  domainMismatch: 'chapi.get.domainMismatch',
  zcapUnavailable: 'chapi.get.zcapUnavailable',
  processFailed: 'chapi.get.processFailed',
  malformedRequest: 'chapi.get.malformedRequest',
  exchangeFailed: 'chapi.get.exchangeFailed'
}

const RP_ZCAP_TTL_DAYS = Math.round(RP_ZCAP_TTL_MS / (24 * 60 * 60 * 1000))
const RP_ZCAP_WRITE_TTL_DAYS = Math.round(
  RP_ZCAP_WRITE_TTL_MS / (24 * 60 * 60 * 1000)
)

const EMPTY_PROFILE: WalletRequestProfile = {
  didAuth: false,
  vcQueries: [],
  zcapRequests: [],
  appConnect: null
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
      for (const { reason } of credentialQueriesOf(query)) {
        if (reason) {
          return reason
        }
      }
    }
  }
  return ''
}

/**
 * Whether a stored credential is a self-issued Login Credential (rendered with
 * a friendly "share your username" label rather than a raw credential card).
 */
function isLoginCredential(credential: StoredCredential): boolean {
  const type = credential.vc.type
  const types = Array.isArray(type) ? type : [type]
  return types.includes(LOGIN_CREDENTIAL_TYPE)
}

export function WalletGetPage() {
  const { t } = useTranslation()
  const [pageState, setPageState] = useState<PageState>('initializing')
  const [chapiEvent, setCHAPIEvent] = useState<CHAPIGetEvent | null>(null)
  const [request, setRequest] = useState<IVPRDetails | null>(null)
  const [profile, setProfile] = useState<WalletRequestProfile>(EMPTY_PROFILE)
  const [requestOrigin, setRequestOrigin] = useState('')
  const [requestReason, setRequestReason] = useState('')
  // Set when the verifier deferred the request to a VC API exchange; the
  // composed presentation is POSTed back there as well as returned over CHAPI.
  const [exchangeUrl, setExchangeUrl] = useState<string | null>(null)
  const [blockReason, setBlockReason] = useState<BlockReason | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  // The credentials offered for sharing (filtered to the request's QBEs when
  // any pins an example type; otherwise all stored credentials).
  const [displayedCredentials, setDisplayedCredentials] = useState<
    StoredCredential[]
  >([])
  const [selectedCids, setSelectedCids] = useState<Set<string>>(new Set())
  const [resolvedGrants, setResolvedGrants] = useState<ResolvedGrant[]>([])
  // App Connect: whether no stored app key matched at login time (the consent
  // copy differs); the authoritative match-or-mint happens at approve time.
  const [appKeyFirstRun, setAppKeyFirstRun] = useState(false)
  // App Connect: the requesting origin's Web App Manifest (logo, description),
  // fetched in the background for the consent screen; display-only garnish.
  const [appManifest, setAppManifest] = useState<AppManifestInfo | null>(null)
  const [loginError, setLoginError] = useState<string | null>(null)
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
      const injected = injectedCHAPIGetEvent()
      if (!injected) {
        await loadOnce(
          MEDIATOR_BASE + encodeURIComponent(window.location.origin)
        )
      }
      const event =
        injected ?? ((await receiveCredentialEvent()) as CHAPIGetEvent)
      const web = event.credentialRequestOptions?.web
      const origin = event.credentialRequestOrigin
      setCHAPIEvent(event)
      setRequestOrigin(origin)

      // A verifier that names a VC API exchange sends an empty VPR body and
      // keeps the real request behind the exchange URL. Open it to retrieve
      // the request the user is actually being asked to answer.
      const exchange = vcApiExchangeUrl({ protocols: web?.protocols })
      let details = web?.VerifiablePresentation
      if (exchange && queriesOf(details ?? {}).length === 0) {
        setExchangeUrl(exchange)
        try {
          details = await startExchange({ exchangeUrl: exchange })
        } catch (err) {
          console.error('Could not open the VC API exchange:', err)
          setBlockReason('exchangeFailed')
          setPageState('blocked')
          return
        }
      }

      const queries = details ? queriesOf(details) : []
      if (!details || queries.length === 0) {
        console.error('CHAPI get event carries no readable request.', web)
        setBlockReason('malformedRequest')
        setPageState('blocked')
        return
      }
      const requestProfile = classifyRequest(details)

      setRequest(details)
      setRequestReason(reasonFrom(queries))
      setProfile(requestProfile)

      // When DID Auth is involved the wallet must sign, so reject up front the
      // two cases it can never satisfy: an unsupported DID method, and a domain
      // that does not match the channel origin (VCALM domain-binding). An
      // exchange-sourced VPR names the verifier's own origin as its `domain`,
      // never the (possibly third-party) host the exchange runs on, so the
      // check is the same either way.
      if (requestProfile.didAuth) {
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

    init().catch((err: unknown) => {
      console.error('CHAPI get initialization failed:', err)
      setBlockReason('malformedRequest')
      setPageState('blocked')
    })
  }, [])

  // App Connect: fetch the requesting origin's app manifest in the background
  // so the consent screen can show the app's logo and description. Best-effort
  // only -- a missing manifest (or no CORS) leaves the screen unchanged.
  useEffect(() => {
    if (!profile.appConnect || !requestOrigin) {
      return
    }
    let cancelled = false
    fetchAppManifest({ origin: requestOrigin })
      .then(info => {
        if (!cancelled && info) {
          setAppManifest(info)
        }
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [profile.appConnect, requestOrigin])

  async function handleLogin(passphrase: string) {
    setLoginError(null)
    // The shared popup login sequence (keyring resolve in remote-direct mode,
    // account-not-found guard, delegated-session persistence, error mapping)
    // lives in completePopupLogin; only the credential-selection work below is
    // page-specific.
    const result = await completePopupLogin({ passphrase, firstPartyIdb })
    if ('errorKey' in result) {
      setLoginError(t(result.errorKey))
      return
    }
    const loggedIn = result.session
    try {
      // Session creation fired `ensureUserCollections` (remote provisioning +
      // did:web round trips) as `session.storageReady`; it and the credential
      // list have no data dependency in remote-direct mode: the standard
      // collections are guaranteed to exist by account signup (a popup login
      // requires an existing account, and signup provisions them), so the list
      // read cannot 404 on a missing collection. Await both together so the
      // consent screen is not gated on provisioning round trips it does not
      // need. In a pathological half-provisioned state the concurrent read can
      // surface an error here -- an accepted trade-off for not re-serializing.
      // When remote-direct routing is NOT in effect (guest / no-WAS fallback),
      // the read targets the local collections `storageReady` initializes, so
      // it must wait for them -- a fast, local-only wait.
      let stored: StoredCredential[]
      if (loggedIn.storage.remoteDirectActive) {
        ;[, stored] = await Promise.all([
          loggedIn.storageReady,
          loggedIn.storage.listCredentials()
        ])
      } else {
        await loggedIn.storageReady
        stored = await loggedIn.storage.listCredentials()
      }

      // A zcap request needs a remote Space to delegate against; a guest or a
      // no-WAS wallet cannot fulfill it. Surface it before the consent screen
      // via the same predicate `processZcaps` guards on (which the eventual
      // delegation would otherwise raise as `ZcapUnavailableError`), so the
      // block does not appear only after the user clicks Continue. An App
      // Connect request's capability queries delegate the same way.
      const wantsGrants =
        profile.zcapRequests.length > 0 ||
        (profile.appConnect?.capabilityQueries.length ?? 0) > 0
      if (wantsGrants && !hasZcapStorage(loggedIn)) {
        setSession(loggedIn)
        setBlockReason('zcapUnavailable')
        setPageState('blocked')
        return
      }

      // App Connect: look up the stored app key for this app + origin, for
      // the first-run vs returning consent copy and the grants preview. The
      // approve-time processing repeats the lookup authoritatively.
      if (profile.appConnect) {
        const existing = findAppKeyCredential({
          credentials: stored,
          credentialType: profile.appConnect.app.credentialType,
          origin: requestOrigin
        })
        setAppKeyFirstRun(!existing)
        if (
          profile.appConnect.capabilityQueries.length > 0 &&
          loggedIn.storage.spaceUrl
        ) {
          setResolvedGrants(
            resolveGrants({
              zcapRequests: appConnectZcapRequests({
                capabilityQueries: profile.appConnect.capabilityQueries,
                // Resolution never reads the controller; on first run the
                // app-key DID does not exist yet.
                controller: existing
                  ? (appKeySubjectDid(existing.vc) ?? '')
                  : ''
              }),
              spaceUrl: loggedIn.storage.spaceUrl
            })
          )
        }
        setSession(loggedIn)
        setPageState('selecting')
        return
      }

      const displayed = hasTypedExample(profile.vcQueries)
        ? vcMatchesFor({ credentials: stored, queries: profile.vcQueries })
        : stored
      setDisplayedCredentials(displayed)

      // Pre-select a matched Login Credential only when the request explicitly
      // asks for one (the login flows); a generic request starts with nothing
      // checked so sharing the username is always a deliberate choice.
      const wantsLogin = requestsCredentialType({
        queries: profile.vcQueries,
        type: LOGIN_CREDENTIAL_TYPE
      })
      const loginMatch = wantsLogin
        ? findLoginCredential({ credentials: displayed })
        : null
      setSelectedCids(new Set(loginMatch ? [loginMatch.cid] : []))

      if (profile.zcapRequests.length > 0 && loggedIn.storage.spaceUrl) {
        setResolvedGrants(
          resolveGrants({
            zcapRequests: profile.zcapRequests,
            spaceUrl: loggedIn.storage.spaceUrl
          })
        )
      }

      setSession(loggedIn)
      setPageState('selecting')
    } catch (err) {
      setLoginError(t(mapPopupLoginError(err)))
    }
  }

  /**
   * Handles a saved (delegated) session recognized by SavedSessionNotice. A
   * delegated session holds no root key (though the session vault envelope
   * may have unlocked its vault), so this fast path deliberately covers only
   * a DID-Auth-*only* request, and only when a KMS-backed did:web is
   * provisioned (the `authentication` key signs without the passphrase). In
   * that case we skip straight to the consent screen; otherwise recognition is
   * cosmetic and the passphrase form stays. Extending the fast path to VC
   * sharing over an unlocked vault is a deliberate non-goal for now.
   */
  function handleRestoredSession(restored: Session) {
    if (isDidAuthOnly(profile) && restored.profile.didWeb) {
      setSession(restored)
      setPageState('selecting')
    }
  }

  function toggleSelected(cid: string) {
    setSelectedCids(prev => {
      const next = new Set(prev)
      if (next.has(cid)) {
        next.delete(cid)
      } else {
        next.add(cid)
      }
      return next
    })
  }

  /**
   * Composes and returns the response VP (selected VCs plus any delegated
   * grants), delivering it over the CHAPI channel -- and, when the request came
   * from a VC API exchange, POSTing it to the exchange as well -- then recording
   * a Login activity when capabilities were granted.
   */
  async function respondAndClose() {
    if (!chapiEvent || !session || !request) {
      return
    }
    setPageState('done')
    const selectedVCs: IVerifiableCredential[] = displayedCredentials
      .filter(({ cid }) => selectedCids.has(cid))
      .map(({ vc }) => vc)

    let verifiablePresentation
    let grantedZcaps: IZcap[]
    let appConnectResult: WalletResponse['appConnect']
    try {
      const response = await processRequest({
        request,
        session,
        credentialRequestOrigin: requestOrigin,
        selectedVCs
      })
      verifiablePresentation = response.verifiablePresentation
      grantedZcaps = response.zcaps ?? []
      appConnectResult = response.appConnect
    } catch (err) {
      // A remote Space that vanished between consent and submit surfaces the
      // same typed error the login-time preflight guards against; map it to the
      // matching block reason rather than the generic processing failure.
      if (err instanceof ZcapUnavailableError) {
        setBlockReason('zcapUnavailable')
      } else {
        console.error('CHAPI request processing failed:', err)
        setBlockReason('processFailed')
      }
      setPageState('blocked')
      return
    }

    // The exchange, not the CHAPI channel, is the verifier's system of record
    // for a VC API request, so a failed delivery is a failed response: report
    // it rather than handing the site a presentation it never received. An
    // empty compose (`{}`) cannot reach this point with an exchange open --
    // Continue is disabled when there is nothing to share -- but if it ever
    // did, skipping the POST is still right: the exchange protocol has no
    // decline message, so an unanswered exchange expires on its own.
    if (exchangeUrl && verifiablePresentation) {
      try {
        // `deliverPresentation` owns the reply inspection (a multi-step reply is
        // an unfinished, hence failed, delivery), the same logic
        // `collectIssuedPresentation` uses for the issuance direction.
        await deliverPresentation({
          request,
          exchangeUrl,
          verifiablePresentation
        })
      } catch (err) {
        console.error(
          'Could not deliver the presentation to the exchange:',
          err
        )
        setBlockReason('exchangeFailed')
        setPageState('blocked')
        return
      }
    }

    // The Login activity is the durable record App Connect revocation re-reads
    // the zcap documents from, so it must be persisted BEFORE the CHAPI
    // response: responding tears the popup down, which aborts an in-flight
    // write and would leave the granted capabilities with no revocation hook.
    try {
      await recordLoginHistory(grantedZcaps, appConnectResult)
    } catch (err) {
      console.error('Could not record the login history entry:', err)
      if (grantedZcaps.length > 0) {
        // Fail closed: the site never receives the capability documents, so
        // the already-signed delegations stay inert rather than unrevocable.
        setBlockReason('processFailed')
        setPageState('blocked')
        return
      }
    }

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
  }

  /**
   * Records the Login activity when the request granted storage capabilities,
   * connected an app, or authenticated the user's DID -- the capabilities
   * `processRequest` actually delegated (threaded out alongside the VP),
   * rather than read back off the composed VP's embedded `zcap` array; for App
   * Connect, also the app name and whether the app key was minted on this
   * connect. Awaited before the CHAPI response goes out (see
   * `respondAndClose`); a failure propagates to the caller, which fails closed
   * when capabilities were granted.
   */
  async function recordLoginHistory(
    zcaps: IZcap[],
    appConnectResult?: WalletResponse['appConnect']
  ): Promise<void> {
    if (
      !session ||
      (!profile.didAuth &&
        profile.zcapRequests.length === 0 &&
        !profile.appConnect)
    ) {
      return
    }
    const grants = zcaps.map(zcap => {
      const allowedAction =
        'allowedAction' in zcap ? zcap.allowedAction : undefined
      return {
        id: zcap.id,
        target: zcap.invocationTarget,
        allowedActions: Array.isArray(allowedAction)
          ? allowedAction
          : allowedAction
            ? [allowedAction]
            : [],
        expires: 'expires' in zcap ? zcap.expires : '',
        // The full delegated capability, kept verbatim alongside the display
        // summary: the WAS revocation endpoint needs the capability document
        // itself, so a later App Connect revocation can retire this grant.
        zcap
      }
    })
    await session.storage.addHistoryLogin({
      user: session.user,
      origin: requestOrigin,
      grants,
      appConnect:
        appConnectResult && profile.appConnect
          ? {
              name: profile.appConnect.app.name,
              firstRun: appConnectResult.firstRun
            }
          : undefined
    })
  }

  /**
   * Declines the request: answers the CHAPI channel with `null` (the
   * VP-Request convention for a user cancel). When the request came from a VC
   * API exchange, the exchange is deliberately abandoned rather than notified:
   * the protocol defines no decline message (no DELETE, no error POST a
   * holder may send), so walking away and letting the exchange's own
   * `expires` reap it is the correct behavior, not an oversight.
   */
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

  const didAuthOnly = isDidAuthOnly(profile)
  const appConnect = profile.appConnect
  // With no DID Auth to sign, no credentials picked, and no satisfiable grant,
  // Continue would compose nothing (processRequest returns `{}`) -- keep it
  // disabled so the only way out of an empty consent screen is Cancel, which
  // answers both CHAPI and any open exchange. An App Connect response always
  // carries the app-key credential, so it always has something to send.
  const nothingToShare =
    !appConnect &&
    !profile.didAuth &&
    selectedCids.size === 0 &&
    !resolvedGrants.some(({ target }) => target.satisfiable)
  const title = appConnect
    ? t('chapi.get.appConnect.title', { appName: appConnect.app.name })
    : profile.zcapRequests.length > 0
      ? t('chapi.get.loginTitle')
      : didAuthOnly
        ? t('chapi.get.didAuthTitle')
        : t('chapi.get.title')

  return (
    <Box className="fw-page" sx={chapiStyles.page}>
      <Box sx={chapiStyles.card}>
        <Typography variant="h5" sx={{ fontWeight: 600 }}>
          {title}
        </Typography>

        <Box>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {t('chapi.get.requestedBy')}
          </Typography>
          {appConnect && (
            <Stack
              direction="row"
              spacing={1}
              sx={{ mt: 0.5, alignItems: 'center' }}
            >
              {appManifest?.iconUrl ? (
                <Box
                  component="img"
                  src={appManifest.iconUrl}
                  alt=""
                  sx={{ width: 32, height: 32, borderRadius: 1 }}
                />
              ) : null}
              <Typography variant="body2" color="text.secondary">
                {t('chapi.get.appConnect.nameLabel')}
              </Typography>
              <Typography variant="body1" sx={{ fontWeight: 500 }}>
                {appConnect.app.name}
              </Typography>
            </Stack>
          )}
          {appConnect ? (
            <Stack
              direction="row"
              spacing={1}
              sx={{ mt: 0.5, alignItems: 'center' }}
            >
              <Typography variant="body2" color="text.secondary">
                {t('chapi.get.appConnect.originLabel')}
              </Typography>
              <Typography sx={chapiStyles.originChip}>
                {requestOrigin}
              </Typography>
            </Stack>
          ) : (
            <Typography sx={chapiStyles.originChip}>{requestOrigin}</Typography>
          )}
          {appConnect && appManifest?.description && (
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ display: 'block', mt: 0.5 }}
            >
              {appManifest.description}
            </Typography>
          )}
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
          <>
            <SavedSessionNotice
              onFirstPartyStorage={setFirstPartyIdb}
              onRestore={handleRestoredSession}
            />
            <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
          </>
        )}

        {pageState === 'selecting' && appConnect && (
          <Stack spacing={2}>
            <Typography variant="body2">
              {t(
                appKeyFirstRun
                  ? 'chapi.get.appConnect.firstRun'
                  : 'chapi.get.appConnect.returning',
                { appName: appConnect.app.name }
              )}
            </Typography>

            {resolvedGrants.length > 0 && (
              <ZcapGrantsPanel
                grants={resolvedGrants}
                ttlDays={RP_ZCAP_TTL_DAYS}
                writeTtlDays={RP_ZCAP_WRITE_TTL_DAYS}
                hideRecipient
                heading={t('chapi.get.appConnect.zcapHeading')}
              />
            )}

            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                sx={{ textTransform: 'none' }}
                onClick={respondAndClose}
              >
                {t('chapi.get.appConnect.connect')}
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

        {pageState === 'selecting' && !appConnect && (
          <Stack spacing={2}>
            {profile.didAuth && (
              <Typography variant="body2" color="text.secondary">
                {t('chapi.get.didAuthPrompt', { origin: requestOrigin })}
              </Typography>
            )}

            {profile.vcQueries.length > 0 && (
              <Stack spacing={1}>
                <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                  {t('chapi.get.selectPrompt')}
                </Typography>
                {displayedCredentials.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">
                    {t('chapi.get.noMatches')}
                  </Typography>
                ) : (
                  <Box sx={chapiStyles.credentialList}>
                    {displayedCredentials.map(credential => {
                      const { cid, vc } = credential
                      const login = isLoginCredential(credential)
                      const primary = login
                        ? t('chapi.get.shareHandle', {
                            username: loginHandleOf(vc) ?? ''
                          })
                        : credentialTitle(vc)
                      return (
                        <Box
                          key={cid}
                          sx={{
                            ...chapiStyles.credentialRow,
                            cursor: 'pointer'
                          }}
                          onClick={() => toggleSelected(cid)}
                        >
                          <Box sx={chapiStyles.credentialInfo}>
                            <Typography
                              variant="body2"
                              sx={{ fontWeight: 500 }}
                            >
                              {primary}
                            </Typography>
                            {!login && (
                              <Typography
                                variant="caption"
                                color="text.secondary"
                              >
                                {issuerName(vc)}
                              </Typography>
                            )}
                          </Box>
                          <Checkbox
                            edge="end"
                            checked={selectedCids.has(cid)}
                            onChange={() => toggleSelected(cid)}
                            onClick={event => event.stopPropagation()}
                          />
                        </Box>
                      )
                    })}
                  </Box>
                )}
              </Stack>
            )}

            {profile.zcapRequests.length > 0 && (
              <ZcapGrantsPanel
                grants={resolvedGrants}
                ttlDays={RP_ZCAP_TTL_DAYS}
                writeTtlDays={RP_ZCAP_WRITE_TTL_DAYS}
              />
            )}

            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                sx={{ textTransform: 'none' }}
                onClick={respondAndClose}
                disabled={nothingToShare}
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

        {pageState === 'selecting' && <RequestSourcePanel source={request} />}

        {pageState === 'done' && (
          <Box sx={chapiStyles.doneMessage}>
            <CircularProgress size={20} />
            <Typography variant="body2">
              {t(
                appConnect
                  ? 'chapi.get.appConnect.connecting'
                  : 'chapi.get.sharing'
              )}
            </Typography>
          </Box>
        )}
      </Box>
    </Box>
  )
}
