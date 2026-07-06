import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Divider from '@mui/material/Divider'
import IconButton from '@mui/material/IconButton'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { MdContentCopy } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useInfoBox } from '@/hooks/useInfoBox'
import { getFileUrl } from '@interop/did-method-webvh'
import { rotateWebvhUpdateKey } from '@/lib/didWebvh'
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
  // The published did:web DID (present in both tiers once provisioned) and the
  // world-readable URL its document resolves to.
  const publishedDid = session?.profile?.didWeb?.did
  const publishedDidUrl = session?.storage.publishedDidUrl
  // The published did:webvh DID (Phase 2) and the world-readable URL its log
  // resolves to, derived from the did by the library's canonical mapping
  // (`https://<host>/space/<spaceId>/id/did.jsonl`) -- undefined until the log
  // is provisioned (no did).
  const publishedDidWebvh = session?.profile?.didWebvh?.did
  const publishedDidWebvhLogUrl = publishedDidWebvh
    ? getFileUrl(publishedDidWebvh)
    : undefined
  // Rotating the update key extends the append-only log with the root zcap, so
  // it needs a full (passphrase) session -- the delegated tier has no root key.
  const canRotate = session?.tier === 'full'
  const [copiedDidWebvh, setCopiedDidWebvh] = useState(false)
  const [rotateDialogOpen, setRotateDialogOpen] = useState(false)
  const [rotating, setRotating] = useState(false)
  const [rotateDone, setRotateDone] = useState(false)
  const [rotateError, setRotateError] = useState(false)

  const handleCopyDidWebvh = async () => {
    if (!publishedDidWebvh) {
      return
    }
    try {
      await navigator.clipboard.writeText(publishedDidWebvh)
      setCopiedDidWebvh(true)
      setTimeout(() => setCopiedDidWebvh(false), 1500)
    } catch (err) {
      console.error('Could not copy the did:webvh id:', err)
    }
  }

  const handleRotate = async () => {
    if (!session) {
      return
    }
    setRotateDialogOpen(false)
    setRotating(true)
    setRotateDone(false)
    setRotateError(false)
    try {
      await rotateWebvhUpdateKey({ session })
      setRotateDone(true)
    } catch (err) {
      console.error('Could not rotate the did:webvh update key:', err)
      setRotateError(true)
    } finally {
      setRotating(false)
    }
  }

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
          {kmsConfigured && (
            <Stack
              direction="row"
              sx={{ alignItems: 'center', gap: 2, flexWrap: 'wrap' }}
            >
              <Typography variant="body2" sx={{ minWidth: 200 }}>
                {t('settings.publishedDid')}
              </Typography>
              <Chip
                size="small"
                color={publishedDid ? 'success' : 'default'}
                label={
                  publishedDid
                    ? t('settings.publishedDidProvisioned')
                    : t('settings.publishedDidNone')
                }
              />
              {publishedDid && (
                <Stack sx={{ gap: 0.5 }}>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ wordBreak: 'break-all' }}
                  >
                    {publishedDid}
                  </Typography>
                  {publishedDidUrl && (
                    <Link
                      href={publishedDidUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="body2"
                      sx={{ wordBreak: 'break-all' }}
                    >
                      {publishedDidUrl}
                    </Link>
                  )}
                </Stack>
              )}
            </Stack>
          )}
          {kmsConfigured && (
            <Stack
              direction="row"
              sx={{ alignItems: 'center', gap: 2, flexWrap: 'wrap' }}
            >
              <Typography variant="body2" sx={{ minWidth: 200 }}>
                {t('settings.publishedDidWebvh')}
              </Typography>
              <Chip
                size="small"
                color={publishedDidWebvh ? 'success' : 'default'}
                label={
                  publishedDidWebvh
                    ? t('settings.publishedDidProvisioned')
                    : t('settings.publishedDidNone')
                }
              />
              {publishedDidWebvh && (
                <Stack sx={{ gap: 0.5 }}>
                  <Stack
                    direction="row"
                    sx={{ alignItems: 'center', gap: 0.5 }}
                  >
                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{ wordBreak: 'break-all' }}
                    >
                      {publishedDidWebvh}
                    </Typography>
                    <Tooltip
                      title={
                        copiedDidWebvh ? t('common.copied') : t('common.copy')
                      }
                    >
                      <IconButton
                        size="small"
                        onClick={handleCopyDidWebvh}
                        aria-label={t('common.copy')}
                        sx={{ p: 0.25, flexShrink: 0 }}
                      >
                        <MdContentCopy size={15} />
                      </IconButton>
                    </Tooltip>
                  </Stack>
                  {publishedDidWebvhLogUrl && (
                    <Link
                      href={publishedDidWebvhLogUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="body2"
                      sx={{ wordBreak: 'break-all' }}
                    >
                      {publishedDidWebvhLogUrl}
                    </Link>
                  )}
                </Stack>
              )}
            </Stack>
          )}
          {kmsConfigured && publishedDidWebvh && (
            <Stack sx={{ gap: 0.5, mt: 1 }}>
              <Stack direction="row" sx={{ alignItems: 'center', gap: 2 }}>
                <Button
                  variant="outlined"
                  size="small"
                  sx={{ textTransform: 'none', borderRadius: 2 }}
                  disabled={!canRotate || rotating}
                  onClick={() => {
                    setRotateDone(false)
                    setRotateError(false)
                    setRotateDialogOpen(true)
                  }}
                >
                  {rotating
                    ? t('settings.rotating')
                    : t('settings.rotateUpdateKey')}
                </Button>
                <Typography variant="body2" color="text.secondary">
                  {t('settings.rotateUpdateKeyHint')}
                </Typography>
              </Stack>
              {!canRotate && (
                <Typography variant="body2" color="text.secondary">
                  {t('settings.rotateRequiresFullSession')}
                </Typography>
              )}
              {rotateDone && (
                <Typography variant="body2" color="success.main">
                  {t('settings.rotateSuccess')}
                </Typography>
              )}
              {rotateError && (
                <Alert severity="error">{t('settings.rotateError')}</Alert>
              )}
            </Stack>
          )}
        </Stack>

        <Dialog
          open={rotateDialogOpen}
          onClose={() => setRotateDialogOpen(false)}
        >
          <DialogTitle>{t('settings.rotateConfirmTitle')}</DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('settings.rotateConfirmMessage')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => setRotateDialogOpen(false)}
              sx={{ textTransform: 'none' }}
            >
              {t('common.cancel')}
            </Button>
            <Button
              variant="contained"
              disableElevation
              onClick={handleRotate}
              sx={{ textTransform: 'none' }}
            >
              {t('settings.rotateConfirmAction')}
            </Button>
          </DialogActions>
        </Dialog>

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
