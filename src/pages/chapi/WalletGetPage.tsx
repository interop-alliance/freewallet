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
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import Chip from '@mui/material/Chip'
import CircularProgress from '@mui/material/CircularProgress'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemText from '@mui/material/ListItemText'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { loadOnce } from 'credential-handler-polyfill'
import { receiveCredentialEvent } from 'web-credential-handler'
import {
  MEDIATOR_BASE,
  RP_ZCAP_TTL_MS,
  RP_ZCAP_WRITE_TTL_MS,
  SHARE_ZCAP_TTL_MS
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
import { ChapiInitializing } from '@/pages/chapi/ChapiInitializing'
import type { Session } from '@/types/auth'
import type { StoredCredential } from '@/types/credential'
import {
  appConnectZcapRequests,
  classifyRequest,
  composeAndDeliverResponse,
  credentialQueriesOf,
  didAuthMethodSupported,
  domainMatchesOrigin,
  existingCollectionsFrom,
  hasTypedExample,
  hasZcapStorage,
  isDidAuthOnly,
  queriesOf,
  requestsCredentialType,
  resolveGrants,
  startExchange,
  vcApiExchangeUrl,
  vcMatchesFor,
  WalletResponseFailure,
  type CHAPIGetEvent,
  type IVerifiableCredential,
  type IVPRDetails,
  type IVPRQuery,
  type ResolvedGrant,
  type WalletRequestProfile
} from '@/lib/walletRequest'
import {
  appKeySubjectDid,
  findAppKeyCredential
} from '@interop/wallet-core/request'
import { fetchAppManifest, type AppManifestInfo } from '@/lib/appManifest'
import { ZcapGrantsPanel } from './ZcapGrantsPanel'
import { SiteProvidedText } from './SiteProvidedText'
import { RequestSourcePanel } from './RequestSourcePanel'
import { CHAPILoginForm } from './CHAPILoginForm'
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
  | 'appKeysUnreadable'
  | 'processFailed'
  | 'malformedRequest'
  | 'exchangeFailed'

const BLOCK_MESSAGE_KEY: Record<BlockReason, string> = {
  unsupported: 'chapi.get.didAuthUnsupported',
  domainMismatch: 'chapi.get.domainMismatch',
  zcapUnavailable: 'chapi.get.zcapUnavailable',
  appKeysUnreadable: 'chapi.get.appKeysUnreadable',
  processFailed: 'chapi.get.processFailed',
  malformedRequest: 'chapi.get.malformedRequest',
  exchangeFailed: 'chapi.get.exchangeFailed'
}

const RP_ZCAP_TTL_DAYS = Math.round(RP_ZCAP_TTL_MS / (24 * 60 * 60 * 1000))
const RP_ZCAP_WRITE_TTL_DAYS = Math.round(
  RP_ZCAP_WRITE_TTL_MS / (24 * 60 * 60 * 1000)
)
const SHARE_ZCAP_TTL_DAYS = Math.round(
  SHARE_ZCAP_TTL_MS / (24 * 60 * 60 * 1000)
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
 * set, for display on the share screen. The wire value is untrusted: only an
 * actual string is accepted (a non-string would later crash the render).
 */
function reasonFrom(queries: IVPRQuery[]): string {
  for (const query of queries) {
    if (query.type === 'QueryByExample') {
      for (const { reason } of credentialQueriesOf(query)) {
        if (typeof reason === 'string' && reason) {
          return reason
        }
      }
    }
  }
  return ''
}

/**
 * Bounds the requester-supplied app display name: it is interpolated into the
 * consent title, the name row, and the first-run / returning copy, so an
 * unbounded name could dominate the layout and push the trusted consent rows
 * out of view.
 */
const MAX_APP_NAME_CHARS = 64
function clampAppName(name: string): string {
  return name.length > MAX_APP_NAME_CHARS
    ? name.slice(0, MAX_APP_NAME_CHARS) + '...'
    : name
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
  // App Connect: the matched app key's subject DID the consent screen
  // displays (null on first run). Approval pins the delegation to exactly
  // this DID -- the approve-time re-match failing closed on a divergence --
  // so the recipient the user vets is the recipient that is delegated to.
  const [previewedAppKeyDid, setPreviewedAppKeyDid] = useState<string | null>(
    null
  )
  // App Connect: the requesting origin's Web App Manifest (logo, description),
  // fetched in the background for the consent screen; display-only garnish.
  const [appManifest, setAppManifest] = useState<AppManifestInfo | null>(null)
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
      const requestProfile = classifyRequest({ request: details, origin })

      setRequest(details)
      setRequestReason(reasonFrom(queries))
      setProfile(requestProfile)

      // When DID Auth is involved the wallet must sign, so reject up front an
      // unsupported DID method it can never satisfy. An exchange-sourced VPR
      // names the verifier's own origin as its `domain`, never the (possibly
      // third-party) host the exchange runs on, so this stays the same either
      // way.
      if (requestProfile.didAuth && !didAuthMethodSupported(queries)) {
        setBlockReason('unsupported')
        setPageState('blocked')
        return
      }
      // A domain that does not match the channel origin (VCALM domain-binding)
      // can never be satisfied, so reject it before consent. This applies to
      // any request carrying a `domain`, not only DID-Auth ones: a VPR can pin
      // a foreign domain without a DIDAuthentication query, and it deserves the
      // specific domain-mismatch message rather than a generic processing
      // failure surfaced later.
      if (
        details.domain &&
        !domainMatchesOrigin({ domain: details.domain, origin })
      ) {
        setBlockReason('domainMismatch')
        setPageState('blocked')
        return
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
    // account-not-found guard, error mapping) lives in completePopupLogin; only
    // the credential-selection work below is page-specific.
    const result = await completePopupLogin({ passphrase })
    if ('errorKey' in result) {
      setLoginError(t(result.errorKey))
      return
    }
    const loggedIn = result.session
    try {
      // `storage.ready()` resolves when the active backend can serve reads: the
      // local collections being open (guest / no-WAS fallback -- a fast,
      // local-only wait), or nothing at all in the popup's remote-direct mode
      // (reads hit the remote collections directly). Full provisioning (remote
      // Space, did:web) runs as `session.storageReady` in the background; await
      // it too, so the list overlaps those round trips rather than gating on
      // them and a provisioning failure surfaces here rather than as an
      // unhandled rejection. In a pathological half-provisioned state the
      // concurrent read can surface an error here -- an accepted trade-off.
      await loggedIn.storage.ready()
      const [, stored] = await Promise.all([
        loggedIn.storageReady,
        loggedIn.storage.listCredentials()
      ])

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

      // The existing collections' public state, consulted by grant
      // resolution: a public grant that would convert an existing collection
      // resolves unsatisfiable, and a target naming an already-public
      // collection is classed public-collection. Fetched once for the
      // preview; the
      // approve-time delegation re-fetches its own authoritative snapshot.
      const existingCollections = wantsGrants
        ? existingCollectionsFrom(
            await loggedIn.storage.listCollectionPublicStates()
          )
        : existingCollectionsFrom([])

      // App Connect: look up the stored app key for this app + origin, for
      // the first-run vs returning consent copy and the grants preview. The
      // approve-time processing repeats the lookup authoritatively.
      if (profile.appConnect) {
        // Over the dedicated `app-connections` collection, exactly as the
        // approve-time processing matches: app keys never sit among the
        // ordinary credentials listed above.
        const { appKeys, skipped } = await loggedIn.storage.listAppKeys()
        const credentials = appKeys.map(({ vc }) => vc)
        const existing = await findAppKeyCredential({
          credentials,
          appUrl: profile.appConnect.app.appUrl,
          origin: requestOrigin
        })
        // The scan skipped rows this session cannot read and nothing matched,
        // so approval would refuse rather than mint (`AppKeysUnreadableError`).
        // Block here instead of showing first-run "Connect {app}?" copy the
        // user would only see fail after clicking.
        if (
          !existing &&
          (skipped.unknownEpoch > 0 ||
            skipped.noEpochKey > 0 ||
            skipped.undecryptable > 0)
        ) {
          setSession(loggedIn)
          setBlockReason('appKeysUnreadable')
          setPageState('blocked')
          return
        }
        const existingDid = existing ? (appKeySubjectDid(existing) ?? '') : ''
        setAppKeyFirstRun(!existing)
        setPreviewedAppKeyDid(existingDid || null)
        if (
          profile.appConnect.capabilityQueries.length > 0 &&
          loggedIn.storage.spaceUrl
        ) {
          setResolvedGrants(
            resolveGrants({
              zcapRequests: appConnectZcapRequests({
                capabilityQueries: profile.appConnect.capabilityQueries,
                // On first run the app-key DID does not exist yet, so the
                // controller is empty here. Resolution reads it only to
                // validate a share's recipient derivation, and the opt-out
                // below suspends the no-recipient refusal for exactly this
                // case; the approved path re-derives with the real subject DID.
                controller: existingDid
              }),
              spaceUrl: loggedIn.storage.spaceUrl,
              collections: existingCollections,
              allowMissingController: true
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
            spaceUrl: loggedIn.storage.spaceUrl,
            collections: existingCollections
          })
        )
      }

      setSession(loggedIn)
      setPageState('selecting')
    } catch (err) {
      setLoginError(t(mapPopupLoginError(err)))
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
   * Approves the request: the compose / persist-the-Login-activity / deliver
   * sequence runs in `composeAndDeliverResponse` (which owns the ordering that
   * keeps a delegated capability from ever reaching the relying party before
   * its revocation hook exists), and the composed presentation is then
   * returned over the CHAPI channel -- the one leg only this page can perform,
   * since only it holds the CHAPI event.
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
    try {
      const response = await composeAndDeliverResponse({
        request,
        session,
        profile,
        requestOrigin,
        selectedVCs,
        exchangeUrl,
        expectedAppKeyDid: previewedAppKeyDid ?? undefined
      })
      verifiablePresentation = response.verifiablePresentation
    } catch (err) {
      if (err instanceof WalletResponseFailure) {
        setBlockReason(err.reason)
      } else {
        console.error('CHAPI request processing failed:', err)
        setBlockReason('processFailed')
      }
      setPageState('blocked')
      return
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
    return <ChapiInitializing />
  }

  const didAuthOnly = isDidAuthOnly(profile)
  const appConnect = profile.appConnect
  // The requester-supplied display name, bounded once for every place that
  // renders or interpolates it.
  const appName = appConnect ? clampAppName(appConnect.app.name) : ''
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
    ? t('chapi.get.appConnect.title', { appName })
    : profile.zcapRequests.length > 0
      ? t('chapi.get.loginTitle')
      : didAuthOnly
        ? t('chapi.get.didAuthTitle')
        : t('chapi.get.title')

  return (
    <Box className="fw-page" sx={chapiStyles.page}>
      <Box sx={chapiStyles.card}>
        <Typography
          variant="h5"
          sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}
        >
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
              <Typography
                variant="body1"
                sx={{ fontWeight: 500, overflowWrap: 'anywhere' }}
              >
                {appName}
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
              <Chip
                size="small"
                label={requestOrigin}
                sx={chapiStyles.originChip}
              />
            </Stack>
          ) : (
            <Chip
              size="small"
              label={requestOrigin}
              sx={chapiStyles.originChip}
            />
          )}
          {/* The manifest description is fetched from the requesting
              origin's own web-app manifest -- site-authored free text, so it
              gets the same attributed, clamped treatment as a request
              `reason` rather than rendering as wallet copy. */}
          {appConnect && appManifest?.description && (
            <Box sx={{ mt: 0.5 }}>
              <SiteProvidedText
                text={appManifest.description}
                label={t('chapi.get.zcapReasonLabel')}
              />
            </Box>
          )}
        </Box>

        {requestReason && (
          <Box>
            <SiteProvidedText
              text={requestReason}
              label={t('chapi.get.zcapReasonLabel')}
            />
          </Box>
        )}

        {pageState === 'blocked' && blockReason && (
          <Stack spacing={2}>
            <Alert severity="error">{t(BLOCK_MESSAGE_KEY[blockReason])}</Alert>
            <Button
              variant="outlined"
              sx={{ alignSelf: 'flex-start' }}
              onClick={handleCancel}
            >
              {t('common.cancel')}
            </Button>
          </Stack>
        )}

        {pageState === 'awaiting-login' && (
          <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
        )}

        {pageState === 'selecting' && appConnect && (
          <Stack spacing={2}>
            <Typography variant="body2">
              {t(
                appKeyFirstRun
                  ? 'chapi.get.appConnect.firstRun'
                  : 'chapi.get.appConnect.returning',
                { appName }
              )}
            </Typography>

            {resolvedGrants.length > 0 && (
              <ZcapGrantsPanel
                grants={resolvedGrants}
                ttlDays={RP_ZCAP_TTL_DAYS}
                writeTtlDays={RP_ZCAP_WRITE_TTL_DAYS}
                shareTtlDays={SHARE_ZCAP_TTL_DAYS}
                walletMintedRecipient
                heading={t('chapi.get.appConnect.zcapHeading')}
              />
            )}

            <Stack direction="row" spacing={2}>
              <Button variant="contained" onClick={respondAndClose}>
                {t('chapi.get.appConnect.connect')}
              </Button>
              <Button variant="outlined" onClick={handleCancel}>
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
                  <List disablePadding sx={chapiStyles.credentialList}>
                    {displayedCredentials.map(credential => {
                      const { cid, vc } = credential
                      const login = isLoginCredential(credential)
                      const primary = login
                        ? t('chapi.get.shareHandle', {
                            username: loginHandleOf(vc) ?? ''
                          })
                        : credentialTitle(vc)
                      return (
                        <ListItem
                          key={cid}
                          disablePadding
                          sx={chapiStyles.credentialRow}
                          secondaryAction={
                            <Checkbox
                              edge="end"
                              tabIndex={-1}
                              disableRipple
                              checked={selectedCids.has(cid)}
                              onChange={() => toggleSelected(cid)}
                            />
                          }
                        >
                          <ListItemButton
                            dense
                            sx={{ borderRadius: 2 }}
                            onClick={() => toggleSelected(cid)}
                          >
                            <ListItemText
                              primary={primary}
                              secondary={login ? undefined : issuerName(vc)}
                              slotProps={{
                                primary: {
                                  variant: 'subtitle2'
                                },
                                secondary: { variant: 'caption' }
                              }}
                            />
                          </ListItemButton>
                        </ListItem>
                      )
                    })}
                  </List>
                )}
              </Stack>
            )}

            {profile.zcapRequests.length > 0 && (
              <ZcapGrantsPanel
                grants={resolvedGrants}
                ttlDays={RP_ZCAP_TTL_DAYS}
                writeTtlDays={RP_ZCAP_WRITE_TTL_DAYS}
                shareTtlDays={SHARE_ZCAP_TTL_DAYS}
              />
            )}

            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                onClick={respondAndClose}
                disabled={nothingToShare}
              >
                {t('common.continue')}
              </Button>
              <Button variant="outlined" onClick={handleCancel}>
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
