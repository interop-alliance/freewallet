/**
 * The detail view for a single connected application (`/applications/:cid`):
 * its display name, origin, self-issued subject DID, connected date, and the
 * storage grants recorded on the latest connect (each with its target,
 * allowed actions, expiry, and whether it has already lapsed). An app whose
 * recorded grants were all signed by a since-disconnected wallet client is
 * flagged as orphaned -- those grants stopped verifying with the account-log
 * edit (the current-key-set rule), and reconnecting is the recovery path.
 * Repeats the Applications section's Revoke action; on success it navigates
 * back to the list (the toast survives the navigation).
 */
import { useEffect, useState } from 'react'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdArrowBack } from 'react-icons/md'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { RevokeAppDialog } from '@/components/RevokeAppDialog'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { dashboardStyles, storageStyles } from '@/styles/appStyles'
import { listApplicationsView, revokeApplication } from '@/session/applications'
import {
  deriveAppGrantsState,
  type AppGrant,
  type ConnectedApp
} from '@/lib/connectedApps'
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

export function ApplicationDetailPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const { cid } = useParams()
  const session = useAuthStore(state => state.session)

  const [app, setApp] = useState<ConnectedApp | null>(null)
  // The enrolled clients' signing keys from the verified account log, for the
  // grant-state check; undefined when the check is unavailable.
  const [signingKeys, setSigningKeys] = useState<Set<string> | undefined>()
  // Captured once when the app loads, so grant expiry is evaluated against a
  // stable timestamp rather than an impure `Date.now()` call during render.
  const [loadedAt, setLoadedAt] = useState(0)
  const [loading, setLoading] = useState(true)
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false)
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      if (!session || !cid) {
        setLoading(false)
        return
      }
      try {
        const { apps, signingKeys: keys } = await listApplicationsView({
          session
        })
        if (!cancelled) {
          setApp(apps.find(entry => entry.cid === cid) ?? null)
          setSigningKeys(keys)
          setLoadedAt(Date.now())
        }
      } catch (err) {
        log.error('Could not load the connected application', { err })
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [session, cid])

  const grantsState = app
    ? deriveAppGrantsState({ app, currentSigningKeys: signingKeys })
    : 'unknown'

  async function handleRevoke() {
    if (!app || !session) {
      return
    }
    setRevoking(true)
    setRevokeError(false)
    try {
      const { withdrew } = await revokeApplication({
        session,
        app,
        signingKeys
      })
      showToast({
        // What actually happened outranks the row's marker: the revocations
        // are POSTed whatever it says, and a row that derived as orphaned but
        // still had a live chain (a grant minted in a transient session) reads
        // as revoked, not as access that had already ended. `withdrew` spans
        // both stages, so a single app-provisioned collection -- whose pull
        // grant the rotation revokes, leaving the second stage nothing but an
        // already-revoked POST -- still reads as revoked.
        message: withdrew
          ? t('applications.revokeSuccess')
          : grantsState === 'orphaned'
            ? t('applications.revokeSuccessOrphaned')
            : t('applications.revokeSuccessLegacy')
      })
      navigate('/applications')
    } catch (err) {
      log.error('Could not revoke app access', { err })
      setRevokeError(true)
      setRevoking(false)
    }
  }

  function grantExpired(grant: AppGrant): boolean {
    return !!grant.expires && new Date(grant.expires).getTime() <= loadedAt
  }

  return (
    <DashboardLayout
      title={
        app
          ? t('applications.detailTitle', { name: app.name })
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
      ) : !app ? (
        <Stack sx={{ gap: 2, mt: 1 }}>
          <Typography color="text.secondary">
            {t('applications.notFound')}
          </Typography>
        </Stack>
      ) : (
        <Stack sx={{ gap: 2, mt: 1 }}>
          {grantsState === 'orphaned' && (
            <Alert severity="warning">
              {t('applications.orphanedNotice', { name: app.name })}
            </Alert>
          )}
          <Stack
            direction="row"
            sx={{ gap: 1, alignItems: 'baseline', flexWrap: 'wrap' }}
          >
            <Typography variant="subtitle2" color="text.secondary">
              {t('applications.origin')}
            </Typography>
            <Typography variant="body2" sx={dashboardStyles.sharedRecipientDid}>
              {app.origin}
            </Typography>
          </Stack>

          <Stack
            direction="row"
            sx={{ gap: 1, alignItems: 'baseline', flexWrap: 'wrap' }}
          >
            <Typography variant="subtitle2" color="text.secondary">
              {t('applications.subjectDid')}
            </Typography>
            <Typography variant="body2" sx={dashboardStyles.sharedRecipientDid}>
              {app.subjectDid}
            </Typography>
          </Stack>

          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              {t('applications.connected')}
            </Typography>
            <Typography variant="body2">
              {app.connectedAt
                ? formatDate({
                    isoDate: app.connectedAt,
                    locale: i18n.language
                  })
                : t('applications.connectedDateUnknown')}
            </Typography>
          </Box>

          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              {t('applications.grants')}
            </Typography>
            {app.grants.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('applications.noGrants')}
              </Typography>
            ) : (
              <Stack sx={{ gap: 1, mt: 1 }}>
                {app.grants.map((grant, index) => (
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
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {grantTargetLabel(grant.target)}
                    </Typography>
                    {grant.target && (
                      <Typography
                        variant="caption"
                        sx={dashboardStyles.sharedRecipientDid}
                      >
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
                        color={grantExpired(grant) ? 'error' : 'text.secondary'}
                      >
                        {t(
                          grantExpired(grant)
                            ? 'applications.grantExpired'
                            : 'applications.grantExpires',
                          {
                            date: formatDate({
                              isoDate: grant.expires,
                              locale: i18n.language
                            })
                          }
                        )}
                      </Typography>
                    )}
                  </Card>
                ))}
              </Stack>
            )}
          </Box>

          <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
            <Button
              variant="outlined"
              color="error"
              sx={{ borderRadius: 2 }}
              onClick={() => {
                setRevokeError(false)
                setRevokeDialogOpen(true)
              }}
            >
              {t('applications.revoke')}
            </Button>
          </Stack>
        </Stack>
      )}

      <RevokeAppDialog
        open={revokeDialogOpen}
        appName={app?.name ?? ''}
        orphaned={grantsState === 'orphaned'}
        revoking={revoking}
        error={revokeError}
        onCancel={() => setRevokeDialogOpen(false)}
        onConfirm={handleRevoke}
      />
    </DashboardLayout>
  )
}
