/**
 * The Applications settings section: lists the apps connected through the App
 * Connect flow (one per self-issued app-key credential), each with its origin
 * and connected date. Clicking a row opens the app detail page; a button on
 * the row revokes access. Revoking removes the app-key credential and records
 * the revocation.
 */
import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdChevronRight } from 'react-icons/md'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemButton from '@mui/material/ListItemButton'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { dashboardStyles } from '@/styles/appStyles'
import {
  listConnectedApps,
  revokeAppAccess,
  type ConnectedApp
} from '@/lib/connectedApps'

export function ApplicationsPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)

  const [apps, setApps] = useState<ConnectedApp[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [revokeTarget, setRevokeTarget] = useState<ConnectedApp | null>(null)
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false)
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState(false)

  const fetchApps = useCallback(async () => {
    if (!session?.storage) {
      return []
    }
    return await listConnectedApps({ storage: session.storage })
  }, [session])

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const list = await fetchApps()
        if (!cancelled) {
          setApps(list)
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
  }, [fetchApps])

  function openRevokeDialog(app: ConnectedApp) {
    setRevokeError(false)
    setRevokeTarget(app)
    setRevokeDialogOpen(true)
  }

  async function handleRevoke() {
    if (!revokeTarget || !session) {
      return
    }
    setRevoking(true)
    setRevokeError(false)
    try {
      const outcome = await revokeAppAccess({
        storage: session.storage,
        user: session.user,
        app: revokeTarget
      })
      setRevokeDialogOpen(false)
      setRevokeTarget(null)
      showToast({
        message:
          outcome.revoked > 0
            ? t('applications.revokeSuccess')
            : t('applications.revokeSuccessLegacy')
      })
      try {
        setApps(await fetchApps())
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

  return (
    <DashboardLayout title={t('applications.title')}>
      {loading ? (
        <LoadingSpinner />
      ) : (
        <Stack sx={{ gap: 1, mt: 2 }}>
          {loadError && (
            <Alert severity="warning">{t('applications.loadError')}</Alert>
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
                      <Typography
                        variant="subtitle1"
                        sx={{ fontWeight: 'bold' }}
                      >
                        {app.name}
                      </Typography>
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
            {t('applications.revokeConfirm', {
              name: revokeTarget?.name ?? ''
            })}
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
