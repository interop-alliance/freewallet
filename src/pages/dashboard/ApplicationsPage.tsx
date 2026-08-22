/**
 * The Applications settings section: lists the apps connected through the App
 * Connect flow (one per self-issued app-key credential), each with its origin
 * and connected date. An app whose recorded grants were all signed by a
 * since-disconnected wallet client is marked as needing a reconnect (the
 * current-key-set rule already killed those grants). Clicking a row opens the
 * app detail page; a button on the row revokes access. Revoking removes the
 * app-key credential and records the revocation.
 */
import { useEffect, useState } from 'react'
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
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { dashboardStyles } from '@/styles/appStyles'
import { listApplicationsView, revokeApplication } from '@/session/applications'
import { deriveAppGrantsState, type ConnectedApp } from '@/lib/connectedApps'

export function ApplicationsPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)

  const [apps, setApps] = useState<ConnectedApp[]>([])
  // The enrolled clients' signing keys from the verified account log, for the
  // per-app grant-state check; undefined when the check is unavailable.
  const [signingKeys, setSigningKeys] = useState<Set<string> | undefined>()
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [revokeTarget, setRevokeTarget] = useState<ConnectedApp | null>(null)
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState(false)
  // Rows the app-key scan had to skip: undecryptable envelopes (purgeable
  // garbage) and rows in a key epoch this session holds no key for (real data,
  // never purged -- an app's only identity lives in this collection).
  const [undecryptableAppKeys, setUndecryptableAppKeys] = useState(0)
  const [noEpochKeyAppKeys, setNoEpochKeyAppKeys] = useState(0)

  useEffect(() => {
    let cancelled = false
    async function load() {
      if (!session) {
        setLoading(false)
        return
      }
      try {
        const { apps: listed, signingKeys: keys } = await listApplicationsView({
          session
        })
        if (!cancelled) {
          setApps(listed)
          setSigningKeys(keys)
          setUndecryptableAppKeys(session.storage.undecryptableAppKeys)
          setNoEpochKeyAppKeys(session.storage.noEpochKeyAppKeys)
          setLoadError(false)
        }
      } catch (err) {
        console.error('Could not load connected applications:', err)
        if (!cancelled) {
          setLoadError(true)
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
  }, [session])

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
      const { grantsState, revoked } = await revokeApplication({
        session,
        app: revokeTarget,
        signingKeys
      })
      setRevokeTarget(null)
      showToast({
        message:
          grantsState === 'orphaned'
            ? t('applications.revokeSuccessOrphaned')
            : revoked > 0
              ? t('applications.revokeSuccess')
              : t('applications.revokeSuccessLegacy')
      })
      try {
        const { apps: listed, signingKeys: keys } = await listApplicationsView({
          session
        })
        setApps(listed)
        setSigningKeys(keys)
        setUndecryptableAppKeys(session.storage.undecryptableAppKeys)
        setNoEpochKeyAppKeys(session.storage.noEpochKeyAppKeys)
        setLoadError(false)
      } catch (err) {
        console.error('Could not reload connected applications:', err)
        setLoadError(true)
      }
    } catch (err) {
      console.error('Could not revoke app access:', err)
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
      console.error('Could not remove unreadable app connections:', err)
      setLoadError(true)
    }
  }

  return (
    <DashboardLayout title={t('applications.title')}>
      {loading ? (
        <LoadingSpinner />
      ) : (
        <Stack sx={{ gap: 1, mt: 2 }}>
          {loadError && (
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
          {apps.length === 0 ? (
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
                        {deriveAppGrantsState({
                          app,
                          currentSigningKeys: signingKeys
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
        open={revokeTarget !== null}
        appName={revokeTarget?.name ?? ''}
        orphaned={
          !!revokeTarget &&
          deriveAppGrantsState({
            app: revokeTarget,
            currentSigningKeys: signingKeys
          }) === 'orphaned'
        }
        revoking={revoking}
        error={revokeError}
        onCancel={() => setRevokeTarget(null)}
        onConfirm={handleRevoke}
      />
    </DashboardLayout>
  )
}
