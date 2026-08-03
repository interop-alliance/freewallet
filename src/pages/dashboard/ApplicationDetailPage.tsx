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
import { useCallback, useEffect, useState } from 'react'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdArrowBack } from 'react-icons/md'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { dashboardStyles, storageStyles } from '@/styles/appStyles'
import { currentAccountSigningKeys } from '@/session/clients'
import {
  deriveAppGrantsState,
  listConnectedApps,
  revokeAppAccess,
  type AppGrant,
  type ConnectedApp
} from '@/lib/connectedApps'

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
  const [notFound, setNotFound] = useState(false)
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false)
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState(false)

  const fetchApp = useCallback(async () => {
    if (!session?.storage || !cid) {
      return undefined
    }
    const apps = await listConnectedApps({ storage: session.storage })
    return apps.find(entry => entry.cid === cid)
  }, [session, cid])

  // Best-effort: without a promoted account (or with the log unreachable) the
  // state check degrades to "unknown" rather than failing the page.
  const fetchSigningKeys = useCallback(async () => {
    if (!session) {
      return undefined
    }
    try {
      return await currentAccountSigningKeys({ session })
    } catch (err) {
      console.warn(
        'Could not read the account key set for the app detail:',
        err
      )
      return undefined
    }
  }, [session])

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [found, keys] = await Promise.all([
          fetchApp(),
          fetchSigningKeys()
        ])
        if (!cancelled) {
          setApp(found ?? null)
          setSigningKeys(keys)
          setNotFound(!found)
          setLoadedAt(Date.now())
        }
      } catch (err) {
        console.error('Could not load the connected application:', err)
        if (!cancelled) {
          setNotFound(true)
        }
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
  }, [fetchApp, fetchSigningKeys])

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
      const outcome = await revokeAppAccess({
        storage: session.storage,
        user: session.user,
        app,
        grantsState
      })
      showToast({
        message:
          grantsState === 'orphaned'
            ? t('applications.revokeSuccessOrphaned')
            : outcome.revoked > 0
              ? t('applications.revokeSuccess')
              : t('applications.revokeSuccessLegacy')
      })
      navigate('/applications')
    } catch (err) {
      console.error('Could not revoke app access:', err)
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
      ) : notFound || !app ? (
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
                        {grantExpired(grant)
                          ? t('applications.grantExpired', {
                              date: formatDate({
                                isoDate: grant.expires,
                                locale: i18n.language
                              })
                            })
                          : t('applications.grantExpires', {
                              date: formatDate({
                                isoDate: grant.expires,
                                locale: i18n.language
                              })
                            })}
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

      <Dialog
        open={revokeDialogOpen}
        onClose={() => {
          if (!revoking) {
            setRevokeDialogOpen(false)
          }
        }}
      >
        <DialogTitle>{t('applications.revokeTitle')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {grantsState === 'orphaned'
              ? t('applications.revokeConfirmOrphaned', {
                  name: app?.name ?? ''
                })
              : t('applications.revokeConfirm', { name: app?.name ?? '' })}
          </DialogContentText>
          {revokeError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {t('applications.revokeFailed')}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setRevokeDialogOpen(false)}
            disabled={revoking}
          >
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleRevoke}
            loading={revoking}
          >
            {t('applications.revokeConfirmAction')}
          </Button>
        </DialogActions>
      </Dialog>
    </DashboardLayout>
  )
}
