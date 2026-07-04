import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Divider from '@mui/material/Divider'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useInfoBox } from '@/hooks/useInfoBox'
import { dashboardStyles } from '@/styles/appStyles'
import { useEffect, useState } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { KMS_SERVER_URL, SYNCED_COLLECTIONS } from '@/app.config'
import { useSyncStatusStore, type SyncStatus } from '@/stores/syncStatusStore'
import {
  findLoginCredential,
  loginHandleOf,
  setLoginHandle
} from '@/lib/loginCredential'

const SYNC_CHIP_COLOR: Record<
  SyncStatus,
  'default' | 'info' | 'success' | 'error'
> = {
  idle: 'default',
  syncing: 'info',
  synced: 'success',
  error: 'error'
}

export function SettingsPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const syncStatuses = useSyncStatusStore(state => state.statuses)
  const { displayInfoBox } = useInfoBox()
  const [deleteError, setDeleteError] = useState(false)
  const hasRemoteStorage = !!session?.storage?.hasRemoteStorage
  // Login handle: a self-issued LoginCredential's preferredUsername. Editable
  // only with a full (passphrase) session -- the delegated tier has no signer
  // and a locked vault, so it cannot issue or read the credential.
  const canEditHandle = session?.tier === 'full'
  const [handle, setHandle] = useState('')
  const [savedHandle, setSavedHandle] = useState('')
  const [handleSaving, setHandleSaving] = useState(false)
  const [handleSaved, setHandleSaved] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function loadHandle() {
      if (!session || !canEditHandle) {
        return
      }
      try {
        const credentials = await session.storage.listCredentials()
        const found = findLoginCredential({ credentials })
        const current = found ? (loginHandleOf(found.vc) ?? '') : ''
        if (!cancelled) {
          setHandle(current)
          setSavedHandle(current)
        }
      } catch (err) {
        console.error('Could not load the login handle:', err)
      }
    }
    void loadHandle()
    return () => {
      cancelled = true
    }
  }, [session, canEditHandle])

  const handleSaveHandle = async () => {
    if (!session) {
      return
    }
    setHandleSaving(true)
    setHandleSaved(false)
    try {
      await setLoginHandle({ session, username: handle })
      setSavedHandle(handle.trim())
      setHandleSaved(true)
    } catch (err) {
      console.error('Could not save the login handle:', err)
    } finally {
      setHandleSaving(false)
    }
  }
  // KMS keystore state: a keystore is provisioned at login whenever a KMS
  // server is configured for a non-guest session (see initSession.ts).
  const kmsConfigured = !!KMS_SERVER_URL && !session?.isGuest
  // A restored (delegated) session carries the keystore id from the
  // persisted record rather than a keystore agent.
  const keystoreId =
    session?.profile?.keystoreAgent?.keystoreId ?? session?.profile?.keystoreId

  const handleDeleteAccount = async () => {
    if (!session) {
      return
    }
    const confirmed = window.confirm(t('settings.deleteConfirm'))
    if (!confirmed) {
      return
    }
    setDeleteError(false)
    try {
      console.log('Wiping user data...')
      await session.storage?.wipeStorage()
    } catch (err) {
      // Do not log the user out if the wipe failed -- surface the error so
      // they know their remote data is still present.
      console.error('Error wiping user data:', err)
      setDeleteError(true)
      return
    }
    window.location.href = '/' // hard reload
    return
  }

  return (
    <DashboardLayout title={t('settings.title')}>
      <Stack sx={{ mt: 4, gap: 4, maxWidth: 640 }}>
        <Stack direction="row" sx={{ alignItems: 'center', gap: 3 }}>
          <Typography variant="h6">{t('settings.vcSection')}</Typography>
          <Button
            variant="outlined"
            size="small"
            sx={{
              textTransform: 'none',
              borderRadius: 2,
              whiteSpace: 'nowrap'
            }}
            onClick={() =>
              displayInfoBox({
                docUrl: 'vcs',
                title: t('settings.vcSection')
              })
            }
          >
            {t('settings.moreInfo')}
          </Button>
        </Stack>

        <Divider />

        <Stack direction="row" sx={dashboardStyles.settingsRow}>
          <Button
            variant="contained"
            disableElevation
            sx={dashboardStyles.deleteAccountButton}
            onClick={handleDeleteAccount}
          >
            {t('settings.deleteAccount')}
          </Button>
          <Typography
            variant="h5"
            component="p"
            sx={dashboardStyles.deleteAccountDescription}
          >
            {t('settings.deleteAccountHint')}
          </Typography>
        </Stack>

        {deleteError && (
          <Alert severity="error">{t('settings.deleteError')}</Alert>
        )}

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.handleSection')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('settings.handleHint')}
          </Typography>
          {canEditHandle ? (
            <>
              <Stack
                direction="row"
                sx={{ alignItems: 'flex-start', gap: 2, mt: 1 }}
              >
                <TextField
                  size="small"
                  label={t('settings.handleLabel')}
                  value={handle}
                  onChange={event => {
                    setHandle(event.target.value)
                    setHandleSaved(false)
                  }}
                  sx={{ minWidth: 260 }}
                />
                <Button
                  variant="contained"
                  disableElevation
                  sx={{ textTransform: 'none', mt: 0.25 }}
                  disabled={handleSaving || handle.trim() === savedHandle}
                  onClick={handleSaveHandle}
                >
                  {handleSaving ? t('common.saving') : t('common.save')}
                </Button>
              </Stack>
              {handleSaved && (
                <Typography variant="body2" color="success.main">
                  {t('settings.handleSaved')}
                </Typography>
              )}
            </>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t('settings.handleRequiresFullSession')}
            </Typography>
          )}
        </Stack>

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.syncSection')}</Typography>
          {hasRemoteStorage ? (
            SYNCED_COLLECTIONS.map(({ id }) => {
              const status = syncStatuses[id] ?? 'idle'
              return (
                <Stack
                  key={id}
                  direction="row"
                  sx={{ alignItems: 'center', gap: 2 }}
                >
                  <Typography variant="body2" sx={{ minWidth: 200 }}>
                    {id}
                  </Typography>
                  <Chip
                    size="small"
                    color={SYNC_CHIP_COLOR[status]}
                    label={t(`settings.syncStatus.${status}`)}
                  />
                </Stack>
              )
            })
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t('settings.syncNone')}
            </Typography>
          )}
        </Stack>

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.kmsSection')}</Typography>
          {kmsConfigured ? (
            <Stack direction="row" sx={{ alignItems: 'center', gap: 2 }}>
              <Typography variant="body2" sx={{ minWidth: 200 }}>
                {t('settings.keystore')}
              </Typography>
              <Chip
                size="small"
                color={keystoreId ? 'success' : 'error'}
                label={
                  keystoreId
                    ? t('settings.keystoreProvisioned')
                    : t('settings.keystoreError')
                }
              />
              {keystoreId && (
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ wordBreak: 'break-all' }}
                >
                  {keystoreId}
                </Typography>
              )}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t('settings.kmsNone')}
            </Typography>
          )}
        </Stack>

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.about')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('settings.version', { version: __APP_VERSION__ })}
          </Typography>
        </Stack>
      </Stack>
    </DashboardLayout>
  )
}
