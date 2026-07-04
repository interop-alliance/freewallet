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
import { MEDIATOR_BASE, RP_ZCAP_TTL_MS } from '@/app.config'
import { initSessionFromSecret } from '@/session/initSession'
import { persistDelegatedSession } from '@/session/delegatedSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
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
  classifyRequest,
  didAuthMethodSupported,
  domainMatchesOrigin,
  hasTypedExample,
  processRequest,
  queriesOf,
  resolveGrants,
  vcMatchesFor,
  type CHAPIGetEvent,
  type IVerifiableCredential,
  type IVPRDetails,
  type IVPRQuery,
  type ResolvedGrant,
  type WalletRequestProfile
} from '@/lib/walletRequest'
import { ZcapGrantsPanel } from './ZcapGrantsPanel'
import { CHAPILoginForm } from './CHAPILoginForm'
import { SavedSessionNotice } from './SavedSessionNotice'
import { useTranslation } from 'react-i18next'

type PageState =
  'initializing' | 'awaiting-login' | 'selecting' | 'blocked' | 'done'

/**
 * Why a request cannot proceed; maps to a `chapi.get.*` message key. Set before
 * login for the two statically-detectable DID-Auth cases, after login for a
 * zcap request this wallet cannot back, or after a failed compose.
 */
type BlockReason =
  'unsupported' | 'domainMismatch' | 'zcapUnavailable' | 'processFailed'

const BLOCK_MESSAGE_KEY: Record<BlockReason, string> = {
  unsupported: 'chapi.get.didAuthUnsupported',
  domainMismatch: 'chapi.get.domainMismatch',
  zcapUnavailable: 'chapi.get.zcapUnavailable',
  processFailed: 'chapi.get.processFailed'
}

const RP_ZCAP_TTL_DAYS = Math.round(RP_ZCAP_TTL_MS / (24 * 60 * 60 * 1000))

const EMPTY_PROFILE: WalletRequestProfile = {
  didAuth: false,
  vcQueries: [],
  zcapRequests: []
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
  const [blockReason, setBlockReason] = useState<BlockReason | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  // The credentials offered for sharing (filtered to the request's QBEs when
  // any pins an example type; otherwise all stored credentials).
  const [displayedCredentials, setDisplayedCredentials] = useState<
    StoredCredential[]
  >([])
  const [selectedCids, setSelectedCids] = useState<Set<string>>(new Set())
  const [resolvedGrants, setResolvedGrants] = useState<ResolvedGrant[]>([])
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
      const details =
        event.credentialRequestOptions?.web?.VerifiablePresentation
      if (!details) {
        throw new Error(
          'CHAPI get event is missing a VerifiablePresentation request.'
        )
      }
      const queries = queriesOf(details)
      const origin = event.credentialRequestOrigin
      const requestProfile = classifyRequest(details)

      setCHAPIEvent(event)
      setRequest(details)
      setRequestOrigin(origin)
      setRequestReason(reasonFrom(queries))
      setProfile(requestProfile)

      // When DID Auth is involved the wallet must sign, so reject up front the
      // two cases it can never satisfy: an unsupported DID method, and a domain
      // that does not match the channel origin (VCALM domain-binding).
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

      // A zcap request needs a remote Space to delegate against; a guest or a
      // no-WAS wallet cannot fulfill it. Block before the consent screen.
      if (
        profile.zcapRequests.length > 0 &&
        !loggedIn.storage.hasRemoteStorage
      ) {
        setSession(loggedIn)
        setBlockReason('zcapUnavailable')
        setPageState('blocked')
        return
      }

      const stored = await loggedIn.storage.listCredentials()
      const displayed = hasTypedExample(profile.vcQueries)
        ? vcMatchesFor({ credentials: stored, queries: profile.vcQueries })
        : stored
      setDisplayedCredentials(displayed)

      // Pre-select a matched Login Credential (the common login case).
      const loginMatch = findLoginCredential({ credentials: displayed })
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
      if (firstPartyIdb) {
        void persistDelegatedSession({
          session: loggedIn,
          idb: firstPartyIdb
        }).catch((err: unknown) => {
          console.warn('Could not persist the delegated session:', err)
        })
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
   * grants), delivering it over the CHAPI channel and recording a Login
   * activity when capabilities were granted.
   */
  async function respondAndClose() {
    if (!chapiEvent || !session || !request) {
      return
    }
    setPageState('done')
    const selectedVCs: IVerifiableCredential[] = displayedCredentials
      .filter(({ cid }) => selectedCids.has(cid))
      .map(({ vc }) => vc)
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
      recordLoginHistory(verifiablePresentation)
    } catch (err) {
      console.error('CHAPI request processing failed:', err)
      setBlockReason('processFailed')
      setPageState('blocked')
    }
  }

  /**
   * Fire-and-forget Login-activity record when the request granted storage
   * capabilities or authenticated the user's DID. Reads the granted zcaps back
   * off the response VP (they were embedded during compose).
   */
  function recordLoginHistory(verifiablePresentation: unknown) {
    if (!session || (!profile.didAuth && profile.zcapRequests.length === 0)) {
      return
    }
    const vp = verifiablePresentation as
      | {
          zcap?: Array<{
            id: string
            invocationTarget: string
            allowedAction?: string | string[]
            expires: string
          }>
        }
      | undefined
    const grants = (vp?.zcap ?? []).map(zcap => ({
      id: zcap.id,
      target: zcap.invocationTarget,
      allowedActions: Array.isArray(zcap.allowedAction)
        ? zcap.allowedAction
        : zcap.allowedAction
          ? [zcap.allowedAction]
          : [],
      expires: zcap.expires
    }))
    void session.storage
      .addHistoryLogin({ user: session.user, origin: requestOrigin, grants })
      .catch((err: unknown) => {
        console.warn('Could not record the login history entry:', err)
      })
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

  const isDidAuthOnly =
    profile.didAuth &&
    profile.vcQueries.length === 0 &&
    profile.zcapRequests.length === 0
  const title =
    profile.zcapRequests.length > 0
      ? t('chapi.get.loginTitle')
      : isDidAuthOnly
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
          <>
            <SavedSessionNotice onFirstPartyStorage={setFirstPartyIdb} />
            <CHAPILoginForm onSubmit={handleLogin} error={loginError} />
          </>
        )}

        {pageState === 'selecting' && (
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
              />
            )}

            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                sx={{ textTransform: 'none' }}
                onClick={respondAndClose}
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
