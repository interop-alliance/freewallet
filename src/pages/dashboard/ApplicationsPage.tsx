/**
 * The Applications settings section: lists the apps connected through the App
 * Connect flow (one per self-issued app-key credential), each with its origin
 * and connected date, plus actions to view details or revoke access. Revoking
 * removes the app-key credential and records the revocation; it needs a full
 * (passphrase) session with an unlocked vault, since the app key lives in an
 * encrypted collection and the revocation writes an activity entry. The
 * delegated tier or a locked vault sees the list read-only with a hint.
 */
import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { DATE_FMT } from '@/app.config'
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
  const vaultLocked = session?.storage.vaultLocked ?? true
  // Revoking retires an encrypted credential and writes an activity entry, so
  // it needs a full-tier session with an unlocked vault.
  const canRevoke = session?.tier === 'full' && !vaultLocked

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
      <Typography variant="body2" color="text.secondary">
        {t('applications.subtitle')}
      </Typography>

      {loading ? (
        <LoadingSpinner />
      ) : (
        <Stack sx={{ gap: 1, mt: 2 }}>
          {loadError && (
            <Alert severity="warning">{t('applications.loadError')}</Alert>
          )}
          {!canRevoke && (
            <Typography variant="body2" color="text.secondary">
              {vaultLocked
                ? t('applications.revokeVaultLocked')
                : t('applications.revokeRequiresFullSession')}
            </Typography>
          )}
          {apps.length === 0 ? (
            <Typography color="text.secondary">
              {t('applications.empty')}
            </Typography>
          ) : (
            apps.map(app => (
              <Stack key={app.cid} sx={dashboardStyles.sharedShareRow}>
                <Typography variant="subtitle2">{app.name}</Typography>
                <Typography
                  variant="body2"
                  sx={dashboardStyles.sharedRecipientDid}
                >
                  {app.origin}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {app.connectedAt
                    ? t('applications.connectedOn', {
                        date: new Date(app.connectedAt).toLocaleDateString(
                          i18n.language,
                          DATE_FMT
                        )
                      })
                    : t('applications.connectedDateUnknown')}
                </Typography>
                <Stack
                  direction="row"
                  sx={{ gap: 1, mt: 0.5, flexWrap: 'wrap' }}
                >
                  <Button
                    variant="outlined"
                    size="small"
                    sx={{ textTransform: 'none', borderRadius: 2 }}
                    onClick={() => navigate(`/applications/${app.cid}`)}
                  >
                    {t('applications.details')}
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    color="error"
                    sx={{ textTransform: 'none', borderRadius: 2 }}
                    disabled={!canRevoke}
                    onClick={() => openRevokeDialog(app)}
                  >
                    {t('applications.revoke')}
                  </Button>
                </Stack>
              </Stack>
            ))
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
            sx={{ textTransform: 'none' }}
          >
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            disableElevation
            color="error"
            onClick={handleRevoke}
            disabled={revoking}
            sx={{ textTransform: 'none' }}
          >
            {revoking
              ? t('applications.revoking')
              : t('applications.revokeConfirmAction')}
          </Button>
        </DialogActions>
      </Dialog>
    </DashboardLayout>
  )
}
