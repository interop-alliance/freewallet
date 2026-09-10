/**
 * The Applications settings section: lists the apps connected through the App
 * Connect flow (one per self-issued app-key credential), each with its origin
 * and connected date. An app whose recorded grants were all signed by a
 * since-disconnected wallet client is marked as needing a reconnect (the
 * current-key-set rule already killed those grants). Clicking a row opens the
 * app detail page; a button on the row revokes access. Revoking removes the
 * app-key credential and records the revocation.
 *
 * The same list carries the connected AGENTS: grantees that answered an
 * interaction-URL request rather than an App Connect popup. An agent row is
 * marked with an Agent chip and titled by the self-declared name the request
 * carried (or by the grantee key when it named none), and it is not clickable
 * -- there is no app key and no detail page behind it. Revoking one revokes
 * its recorded storage grants and records the revocation, which is what takes
 * the row out of the listing.
 */
import { useCallback, useState } from 'react'
import { Link as RouterLink, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdChevronRight } from 'react-icons/md'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Link from '@mui/material/Link'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemButton from '@mui/material/ListItemButton'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { RevokeAppDialog } from '@/components/RevokeAppDialog'
import { useAsyncLoad } from '@/hooks/useAsyncLoad'
import { usePullSettled } from '@/hooks/usePullSettled'
import {
  APP_CONNECTIONS_COLLECTION,
  WALLET_ACTIVITY_COLLECTION
} from '@interop/wallet-core/space'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { dashboardStyles } from '@/styles/appStyles'
import {
  listApplicationsView,
  revokeAgent,
  revokeApplication
} from '@/session/applications'
import {
  deriveGrantsState,
  type AppGrant,
  type ConnectedAgent,
  type ConnectedApp
} from '@/lib/connectedApps'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:applications')

// The collections whose pulls change what this page lists.
const PULLED_COLLECTIONS = [
  APP_CONNECTIONS_COLLECTION,
  WALLET_ACTIVITY_COLLECTION
]

/**
 * The soonest still-future expiry among a row's recorded grants, so the row
 * can say when its access lapses on its own. Undefined when no grant records a
 * parseable future expiry.
 *
 * @param options {object}
 * @param options.grants {AppGrant[]}
 * @returns {string | undefined}   the ISO stamp, verbatim
 */
function nearestExpiry({ grants }: { grants: AppGrant[] }): string | undefined {
  const now = Date.now()
  let soonest: { iso: string; at: number } | undefined
  for (const grant of grants) {
    if (!grant.expires) {
      continue
    }
    const at = new Date(grant.expires).getTime()
    if (!Number.isFinite(at) || at <= now) {
      continue
    }
    if (!soonest || at < soonest.at) {
      soonest = { iso: grant.expires, at }
    }
  }
  return soonest?.iso
}

export function ApplicationsPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)

  const [revokeTarget, setRevokeTarget] = useState<ConnectedApp | null>(null)
  const [revokeAgentTarget, setRevokeAgentTarget] =
    useState<ConnectedAgent | null>(null)
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState(false)
  // Rows the app-key scan had to skip: undecryptable envelopes (purgeable
  // garbage) and rows in a key epoch this session holds no key for (real data,
  // never purged -- an app's only identity lives in this collection).
  const [undecryptableAppKeys, setUndecryptableAppKeys] = useState(0)
  const [noEpochKeyAppKeys, setNoEpochKeyAppKeys] = useState(0)
  // A failed purge shows the same warning a failed load does. It is its own
  // state because the load's error is the hook's, and a successful load
  // clears both.
  const [purgeError, setPurgeError] = useState(false)

  const {
    data: view,
    loading,
    error: loadError,
    reload
  } = useAsyncLoad(
    async ({ isCancelled }) => {
      if (!session) {
        return null
      }
      const listing = await listApplicationsView({ session })
      if (!isCancelled()) {
        setUndecryptableAppKeys(session.storage.undecryptableAppKeys)
        setNoEpochKeyAppKeys(session.storage.noEpochKeyAppKeys)
        setPurgeError(false)
      }
      return listing
    },
    [session],
    {
      enabled: !!session,
      onError: err => {
        log.error('Could not load connected applications', { err })
      }
    }
  )

  // The app rows come from `app-connections` and the grant state (the
  // orphaned marker included) from the Login activities in
  // `wallet-activity`; on a fresh browser either pull can land after the
  // mount read, so re-list when one settles.
  const reloadAfterPull = useCallback(() => {
    reload().catch((err: unknown) => {
      log.error('Could not reload applications after a pull', { err })
    })
  }, [reload])
  usePullSettled({
    collectionIds: PULLED_COLLECTIONS,
    onSettled: reloadAfterPull
  })

  const apps = view?.apps ?? []
  const agents = view?.agents ?? []
  // The account DID and the enrolled clients' signing keys from the verified
  // account log, for the per-row grant-state check; undefined when the check
  // is unavailable.
  const signerCheck = view?.signerCheck

  function openRevokeDialog(app: ConnectedApp) {
    setRevokeError(false)
    setRevokeTarget(app)
  }

  async function handleRevoke() {
    if (!revokeTarget || !session) {
      return
    }
    setRevoking(true)
    setRevokeError(false)
    try {
      const { outcomeKey } = await revokeApplication({
        session,
        app: revokeTarget,
        grantsState: deriveGrantsState({
          grants: revokeTarget.grants,
          signerCheck
        })
      })
      setRevokeTarget(null)
      showToast({ message: t(outcomeKey) })
      await reload()
    } catch (err) {
      log.error('Could not revoke app access', { err })
      setRevokeError(true)
    } finally {
      setRevoking(false)
    }
  }

  async function handleRevokeAgent() {
    if (!revokeAgentTarget || !session) {
      return
    }
    setRevoking(true)
    setRevokeError(false)
    try {
      const { revoked } = await revokeAgent({
        session,
        agent: revokeAgentTarget
      })
      setRevokeAgentTarget(null)
      showToast({
        message:
          revoked > 0
            ? t('applications.revokeAgentSuccess')
            : t('applications.revokeAgentSuccessLegacy')
      })
      await reload()
    } catch (err) {
      log.error('Could not revoke agent access', { err })
      setRevokeError(true)
    } finally {
      setRevoking(false)
    }
  }

  async function handleRemoveUndecryptable() {
    if (!session?.storage) {
      return
    }
    try {
      const removed = await session.storage.purgeUndecryptableAppKeys()
      setUndecryptableAppKeys(session.storage.undecryptableAppKeys)
      showToast({
        message: t('applications.undecryptableAppKeysRemoved', {
          count: removed
        })
      })
    } catch (err) {
      log.error('Could not remove unreadable app connections', { err })
      setPurgeError(true)
    }
  }

  return (
    <DashboardLayout title={t('applications.title')}>
      {loading ? (
        <LoadingSpinner />
      ) : (
        <Stack sx={{ gap: 1, mt: 2 }}>
          {(!!loadError || purgeError) && (
            <Alert severity="warning">{t('applications.loadError')}</Alert>
          )}
          {noEpochKeyAppKeys > 0 && (
            <Alert severity="warning">
              {t('applications.noEpochKeyAppKeys', {
                count: noEpochKeyAppKeys
              })}
            </Alert>
          )}
          {undecryptableAppKeys > 0 && (
            <Alert
              severity="warning"
              action={
                <Button
                  color="inherit"
                  size="small"
                  onClick={handleRemoveUndecryptable}
                >
                  {t('applications.removeUndecryptableAppKeys')}
                </Button>
              }
            >
              {t('applications.undecryptableAppKeys', {
                count: undecryptableAppKeys
              })}
            </Alert>
          )}
          {apps.length === 0 && agents.length === 0 ? (
            <Typography color="text.secondary">
              {t('applications.empty')}
            </Typography>
          ) : (
            <List disablePadding sx={dashboardStyles.applicationsList}>
              {apps.map(app => (
                <ListItem
                  key={app.cid}
                  disablePadding
                  sx={dashboardStyles.applicationsAppCard}
                >
                  <ListItemButton
                    sx={{ p: 0.5, minWidth: 0, borderRadius: 1 }}
                    onClick={() => navigate(`/applications/${app.cid}`)}
                  >
                    <Stack sx={{ gap: 0.5, minWidth: 0 }}>
                      <Stack
                        direction="row"
                        sx={{ gap: 1, alignItems: 'center', flexWrap: 'wrap' }}
                      >
                        <Typography
                          variant="subtitle1"
                          sx={{ fontWeight: 'bold' }}
                        >
                          {app.name}
                        </Typography>
                        {deriveGrantsState({
                          grants: app.grants,
                          signerCheck
                        }) === 'orphaned' && (
                          <Chip
                            size="small"
                            color="warning"
                            label={t('applications.orphanedChip')}
                          />
                        )}
                      </Stack>
                      <Typography
                        variant="body2"
                        sx={dashboardStyles.sharedRecipientDid}
                      >
                        {t('applications.origin')} {app.origin}
                      </Typography>
                    </Stack>
                    <Box
                      sx={dashboardStyles.applicationsRowChevron}
                      aria-hidden
                    >
                      <MdChevronRight />
                    </Box>
                  </ListItemButton>
                  <Stack sx={dashboardStyles.applicationsAppMeta}>
                    <Typography variant="body2" color="text.secondary">
                      {app.connectedAt
                        ? t('applications.connectedOn', {
                            date: formatDate({
                              isoDate: app.connectedAt,
                              locale: i18n.language
                            })
                          })
                        : t('applications.connectedDateUnknown')}
                    </Typography>
                    <Button
                      variant="outlined"
                      size="small"
                      color="error"
                      sx={{ borderRadius: 2 }}
                      onClick={() => openRevokeDialog(app)}
                    >
                      {t('applications.revoke')}
                    </Button>
                  </Stack>
                </ListItem>
              ))}
              {agents.map(agent => {
                const orphaned =
                  deriveGrantsState({
                    grants: agent.grants,
                    signerCheck
                  }) === 'orphaned'
                const fingerprint = t('settings.clients.keyFingerprint', {
                  did: agent.controller
                })
                const expires = nearestExpiry({ grants: agent.grants })
                return (
                  <ListItem
                    key={agent.controller}
                    disablePadding
                    sx={dashboardStyles.applicationsAppCard}
                  >
                    <Stack sx={{ gap: 0.5, minWidth: 0, p: 0.5 }}>
                      <Stack
                        direction="row"
                        sx={{ gap: 1, alignItems: 'center', flexWrap: 'wrap' }}
                      >
                        <Typography
                          variant="subtitle1"
                          sx={{ fontWeight: 'bold', wordBreak: 'break-all' }}
                        >
                          {agent.name ?? fingerprint}
                        </Typography>
                        <Chip
                          size="small"
                          label={t('applications.agentChip')}
                        />
                        {orphaned && (
                          <Chip
                            size="small"
                            color="warning"
                            label={t('applications.orphanedChip')}
                          />
                        )}
                      </Stack>
                      {agent.name !== undefined && (
                        <>
                          <Typography
                            variant="body2"
                            sx={dashboardStyles.sharedRecipientDid}
                          >
                            {fingerprint}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {t('applications.agentNameNote')}
                          </Typography>
                        </>
                      )}
                      <Typography variant="body2" color="text.secondary">
                        {t('applications.agentGrants', {
                          count: agent.grants.length
                        })}
                        {expires
                          ? ` -- ${t('applications.grantExpires', {
                              date: formatDate({
                                isoDate: expires,
                                locale: i18n.language
                              })
                            })}`
                          : ''}
                      </Typography>
                    </Stack>
                    <Stack sx={dashboardStyles.applicationsAppMeta}>
                      <Typography variant="body2" color="text.secondary">
                        {agent.grantedAt
                          ? t('applications.agentGrantedOn', {
                              date: formatDate({
                                isoDate: agent.grantedAt,
                                locale: i18n.language
                              })
                            })
                          : t('applications.agentGrantedDateUnknown')}
                      </Typography>
                      <Button
                        variant="outlined"
                        size="small"
                        color="error"
                        sx={{ borderRadius: 2 }}
                        onClick={() => {
                          setRevokeError(false)
                          setRevokeAgentTarget(agent)
                        }}
                      >
                        {t('applications.revokeAgent')}
                      </Button>
                    </Stack>
                  </ListItem>
                )
              })}
            </List>
          )}
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            {t('applications.clientsCrossPointer')}{' '}
            <Link component={RouterLink} to="/settings">
              {t('applications.clientsCrossPointerLink')}
            </Link>
            .
          </Typography>
        </Stack>
      )}

      <RevokeAppDialog
        open={revokeAgentTarget !== null}
        appName={
          revokeAgentTarget?.name ??
          t('settings.clients.keyFingerprint', {
            did: revokeAgentTarget?.controller ?? ''
          })
        }
        agent
        revoking={revoking}
        error={revokeError}
        onCancel={() => setRevokeAgentTarget(null)}
        onConfirm={handleRevokeAgent}
      />

      <RevokeAppDialog
        open={revokeTarget !== null}
        appName={revokeTarget?.name ?? ''}
        orphaned={
          !!revokeTarget &&
          deriveGrantsState({ grants: revokeTarget.grants, signerCheck }) ===
            'orphaned'
        }
        revoking={revoking}
        error={revokeError}
        onCancel={() => setRevokeTarget(null)}
        onConfirm={handleRevoke}
      />
    </DashboardLayout>
  )
}
