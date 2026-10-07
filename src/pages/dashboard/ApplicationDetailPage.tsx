/**
 * The detail view for one connected party, an app or an agent
 * (`/applications/:resourceId`, keyed by its `connections` entry's resource
 * id): its display name, origin (an app's), DID, connected date (the
 * entry's `firstSeen`), and its storage grants, one card per scope (grantee,
 * target, and actions), newest first. Each card shows the scope's latest
 * record (its target, allowed actions, expiry, and whether it has already
 * lapsed), and the records a renewal or a later consent superseded collapse
 * under it. An agent the owner declined to keep connected shows as declined,
 * with Restore beside Revoke: Restore re-grants its in-scope access as a
 * fresh consent, which clears the decline. A party whose grants were all signed by a
 * since-disconnected wallet client is flagged as orphaned -- those grants
 * stopped verifying with the account-log edit (the current-key-set rule),
 * and reconnecting is the recovery path. Repeats the Applications section's
 * Revoke action; on success it navigates back to the list (the toast
 * survives the navigation). A directory that cannot be listed shows the
 * list page's load warning rather than the not-found text.
 */
import { useState } from 'react'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdArrowBack } from 'react-icons/md'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import Collapse from '@mui/material/Collapse'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { RevokeAppDialog } from '@/components/RevokeAppDialog'
import { getCollectionDisplayName } from '@/components/storage/displayUtils'
import { useAsyncLoad } from '@/hooks/useAsyncLoad'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { dashboardStyles, storageStyles } from '@/styles/appStyles'
import {
  listApplicationsView,
  revokeAgent,
  revokeApplication
} from '@/session/applications'
import {
  deriveGrantsState,
  sharedCollectionIds,
  type AppGrant,
  type ConnectedAgent,
  type ConnectedApp
} from '@/lib/connectedApps'
import { reconnectAgents } from '@/session/agentReconnect'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:applications')

/**
 * A human-readable label for a grant's `invocationTarget`: the last non-empty
 * path segment of the URL (typically the collection name), falling back to the
 * whole target.
 *
 * @param target {string}
 * @returns {string}
 */
function grantTargetLabel(target: string): string {
  if (!target) {
    return ''
  }
  try {
    const { pathname } = new URL(target)
    const segments = pathname.split('/').filter(Boolean)
    return segments[segments.length - 1] ?? target
  } catch {
    const segments = target.split('/').filter(Boolean)
    return segments[segments.length - 1] ?? target
  }
}

/**
 * One grant record's lines: its target label and URL, its allowed actions,
 * and its expiry.
 *
 * @param options {object}
 * @param options.grant {AppGrant}
 * @param options.expired {boolean}
 * @param [options.emphasis] {boolean}   the scope's current record
 */
function GrantSummary({
  grant,
  expired,
  emphasis = false
}: {
  grant: AppGrant
  expired: boolean
  emphasis?: boolean
}) {
  const { t, i18n } = useTranslation()
  return (
    <>
      {emphasis && (
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {grantTargetLabel(grant.target)}
        </Typography>
      )}
      {grant.target && (
        <Typography variant="caption" sx={dashboardStyles.sharedRecipientDid}>
          {grant.target}
        </Typography>
      )}
      <Typography variant="body2" color="text.secondary">
        {t('applications.grantActions', {
          actions:
            grant.allowedActions.join(', ') ||
            t('applications.grantActionsNone')
        })}
      </Typography>
      {grant.expires && (
        <Typography
          variant="body2"
          color={expired ? 'error' : 'text.secondary'}
        >
          {t(
            expired ? 'applications.grantExpired' : 'applications.grantExpires',
            {
              date: formatDate({
                isoDate: grant.expires,
                locale: i18n.language
              })
            }
          )}
        </Typography>
      )}
    </>
  )
}

export function ApplicationDetailPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const { resourceId } = useParams()
  const session = useAuthStore(state => state.session)

  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false)
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const [restoreError, setRestoreError] = useState(false)
  // The scopes whose superseded records are shown, by the current record's
  // capability id.
  const [expanded, setExpanded] = useState<string[]>([])

  const {
    data: view,
    loading,
    error: loadError,
    reload
  } = useAsyncLoad(
    async () => {
      if (!session || !resourceId) {
        return null
      }
      const { apps, agents, signerCheck } = await listApplicationsView({
        session
      })
      return {
        app: apps.find(entry => entry.resourceId === resourceId) ?? null,
        agent: agents.find(entry => entry.resourceId === resourceId) ?? null,
        signerCheck,
        // Captured once when the app loads, so grant expiry is evaluated
        // against a stable timestamp rather than an impure `Date.now()` call
        // during render.
        loadedAt: Date.now()
      }
    },
    [session, resourceId],
    {
      enabled: !!session && !!resourceId,
      onError: err => {
        log.error('Could not load the connected application', { err })
      }
    }
  )

  const app: ConnectedApp | null = view?.app ?? null
  const agent: ConnectedAgent | null = view?.agent ?? null
  // The account DID and the enrolled clients' signing keys from the verified
  // account log, for the grant-state check; undefined when the check is
  // unavailable.
  const signerCheck = view?.signerCheck
  const loadedAt = view?.loadedAt ?? 0

  // What the page shows, the same for an app and an agent: the display name
  // (the shortened DID when the entry names none), the DID, and the grants.
  const party = app
    ? { did: app.subjectDid, name: app.name, grants: app.grants }
    : agent && { did: agent.controller, name: agent.name, grants: agent.grants }
  const partyName = party
    ? (party.name ?? t('settings.clients.keyFingerprint', { did: party.did }))
    : ''
  const connectedAt = app ? app.connectedAt : agent?.connectedAt

  const grantsState = party
    ? deriveGrantsState({ grants: party.grants, signerCheck })
    : 'unknown'

  async function handleRevoke() {
    if (!session || (!app && !agent)) {
      return
    }
    setRevoking(true)
    setRevokeError(false)
    try {
      const { outcomeKey } = app
        ? await revokeApplication({ session, app, grantsState })
        : await revokeAgent({ session, agent: agent! })
      showToast({ message: t(outcomeKey) })
      navigate('/applications')
    } catch (err) {
      log.error('Could not revoke app access', { err })
      setRevokeError(true)
      setRevoking(false)
    }
  }

  /**
   * Restores a declined agent: re-grants its in-scope access as a fresh
   * consent, which clears the decline, and runs the inbox pass that pushes
   * the grants to it.
   */
  async function handleRestore() {
    if (!session || !agent) {
      return
    }
    setRestoring(true)
    setRestoreError(false)
    try {
      const { agents } = await reconnectAgents({
        session,
        dids: [agent.controller]
      })
      if (agents[0]?.outcome === 'restored') {
        showToast({ message: t('applications.restoreSuccess') })
      } else {
        setRestoreError(true)
      }
      await reload()
    } catch (err) {
      log.error('Could not restore the agent', { err })
      setRestoreError(true)
    } finally {
      setRestoring(false)
    }
  }

  function grantExpired(grant: AppGrant): boolean {
    return !!grant.expires && new Date(grant.expires).getTime() <= loadedAt
  }

  return (
    <DashboardLayout
      title={
        party
          ? t('applications.connectionDetailTitle', { name: partyName })
          : t('applications.title')
      }
    >
      <Button
        component={RouterLink}
        to="/applications"
        startIcon={<MdArrowBack />}
        sx={storageStyles.backToStorageButton}
        variant="text"
      >
        {t('applications.back')}
      </Button>
      {loading ? (
        <LoadingSpinner />
      ) : !party ? (
        <Stack sx={{ gap: 2, mt: 1 }}>
          {/* A directory that could not be listed is not a missing party:
              show the same warning the list page does. */}
          {loadError ? (
            <Alert severity="warning">{t('applications.loadError')}</Alert>
          ) : (
            <Typography color="text.secondary">
              {t('applications.notFound')}
            </Typography>
          )}
        </Stack>
      ) : (
        <Stack sx={{ gap: 2, mt: 1 }}>
          {grantsState === 'orphaned' && (
            <Alert severity="warning">
              {t('applications.orphanedNotice', { name: partyName })}
            </Alert>
          )}
          {agent?.declined !== undefined && (
            <Alert severity="info">
              {t('applications.agentDeclinedNotice', {
                date: formatDate({
                  isoDate: agent.declined,
                  locale: i18n.language
                })
              })}
            </Alert>
          )}
          {restoreError && (
            <Alert severity="error">{t('applications.restoreFailed')}</Alert>
          )}
          {app?.origin !== undefined && (
            <Stack
              direction="row"
              sx={{ gap: 1, alignItems: 'baseline', flexWrap: 'wrap' }}
            >
              <Typography variant="subtitle2" color="text.secondary">
                {t('applications.origin')}
              </Typography>
              <Typography
                variant="body2"
                sx={dashboardStyles.sharedRecipientDid}
              >
                {app.origin}
              </Typography>
            </Stack>
          )}

          <Stack
            direction="row"
            sx={{ gap: 1, alignItems: 'baseline', flexWrap: 'wrap' }}
          >
            <Typography variant="subtitle2" color="text.secondary">
              {t('applications.subjectDid')}
            </Typography>
            <Typography variant="body2" sx={dashboardStyles.sharedRecipientDid}>
              {party.did}
            </Typography>
          </Stack>

          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              {t('applications.connected')}
            </Typography>
            <Typography variant="body2">
              {connectedAt
                ? formatDate({
                    isoDate: connectedAt,
                    locale: i18n.language
                  })
                : t('applications.connectedDateUnknown')}
            </Typography>
          </Box>

          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              {t('applications.grants')}
            </Typography>
            {party.grants.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('applications.noGrants')}
              </Typography>
            ) : (
              <Stack sx={{ gap: 1, mt: 1 }}>
                {party.grants.map((grant, index) => (
                  <Card
                    key={grant.id || index}
                    variant="outlined"
                    sx={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 0.5,
                      p: 1.5
                    }}
                  >
                    <GrantSummary
                      grant={grant}
                      expired={grantExpired(grant)}
                      emphasis
                    />
                    {grant.earlier !== undefined && (
                      <>
                        <Button
                          size="small"
                          variant="text"
                          sx={{ alignSelf: 'flex-start', px: 0 }}
                          onClick={() =>
                            setExpanded(
                              expanded.includes(grant.id)
                                ? expanded.filter(id => id !== grant.id)
                                : [...expanded, grant.id]
                            )
                          }
                        >
                          {t('applications.earlierGrants', {
                            count: grant.earlier.length
                          })}
                        </Button>
                        <Collapse in={expanded.includes(grant.id)}>
                          <Stack sx={{ gap: 1, pl: 2 }}>
                            {grant.earlier.map((earlier, earlierIndex) => (
                              <Box key={earlier.id || earlierIndex}>
                                <GrantSummary
                                  grant={earlier}
                                  expired={grantExpired(earlier)}
                                />
                              </Box>
                            ))}
                          </Stack>
                        </Collapse>
                      </>
                    )}
                  </Card>
                ))}
              </Stack>
            )}
          </Box>

          <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
            {agent?.declined !== undefined && (
              <Button
                variant="contained"
                sx={{ borderRadius: 2 }}
                loading={restoring}
                disabled={revoking}
                onClick={() => void handleRestore()}
              >
                {t('applications.restore')}
              </Button>
            )}
            {/* A restore in flight re-records the agent's grants, and a
                revoke beside it would be undone by that write. */}
            <Button
              variant="outlined"
              color="error"
              sx={{ borderRadius: 2 }}
              disabled={restoring}
              onClick={() => {
                setRevokeError(false)
                setRevokeDialogOpen(true)
              }}
            >
              {t(app ? 'applications.revoke' : 'applications.revokeAgent')}
            </Button>
          </Stack>
        </Stack>
      )}

      <RevokeAppDialog
        open={revokeDialogOpen}
        appName={partyName}
        agent={!app && !!agent}
        orphaned={grantsState === 'orphaned'}
        sharedCollections={sharedCollectionIds({
          grants: app?.grants ?? []
        }).map(id => getCollectionDisplayName({ collection: { id }, t }))}
        revoking={revoking}
        error={revokeError}
        onCancel={() => setRevokeDialogOpen(false)}
        onConfirm={handleRevoke}
      />
    </DashboardLayout>
  )
}
