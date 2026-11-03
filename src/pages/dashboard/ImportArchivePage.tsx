/**
 * The archive import page (`/storage/import`): a few words on what an
 * import does, the connected Space's quota, and the file picker. The picker
 * is disabled while a loaded quota says the Space refuses writes, so an
 * over-quota import is refused before the archive is parsed and uploaded
 * rather than by the server after. A quota still loading, or one that failed
 * to load, does not hold the picker: the server refuses an over-quota write
 * on its own, and a stalled quota request must not block the import. The
 * Space section's Import action on the Storage and Settings pages links
 * here.
 */
import { useState } from 'react'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { MdArrowBack } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { Link as RouterLink, useNavigate } from 'react-router'
import { DashboardLayout } from '@/components/DashboardLayout'
import { StorageQuotaCard } from '@/components/storage/StorageQuotaCard'
import { useSpaceQuota } from '@/hooks/useSpaceQuota'
import { importOutcome, importRefusal, parseImportTarFile } from '@/lib/import'
import { createLogger } from '@/lib/log'
import { writesRestricted } from '@/lib/storageQuota'
import { useAuthStore } from '@/stores/authStore'
import { syncController } from '@/stores/syncController'
import { showToast } from '@/stores/toastStore'
import { storageStyles, visuallyHiddenInput } from '@/styles/appStyles'

const log = createLogger('fw:ui:storage')

export function ImportArchivePage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)
  const { status: quotaStatus, reload: reloadQuota } = useSpaceQuota({
    session
  })
  const [isImporting, setIsImporting] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  const importBlocked =
    quotaStatus.kind === 'ready' && writesRestricted(quotaStatus.quota)

  // The route is protected, so the session is live by the time this renders.
  if (!session) {
    return null
  }
  const { storage } = session
  const { hasRemoteStorage } = storage

  const handleImportFile = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) {
      return
    }

    setErrorKey(null)
    setIsImporting(true)
    try {
      const archive = await parseImportTarFile(file)
      const refusal = importRefusal({ archive, hasRemoteStorage })
      if (refusal === 'unrecognized-archive') {
        setErrorKey('storage.importPage.unrecognized')
        return
      }
      if (refusal === 'space-needs-remote') {
        setErrorKey('storage.importSpaceRequiresRemote')
        return
      }

      const spaceSummary = archive.hasSpace
        ? await storage.importSpace({ tarFile: file })
        : undefined
      if (spaceSummary && spaceSummary.resourcesCreated > 0) {
        syncController.reSync()
      }

      const outcome = importOutcome({ archive, spaceSummary })
      if (outcome.kind === 'accept-credentials') {
        navigate('/accept-credentials', {
          state: {
            credentials: outcome.credentials,
            importSummary: outcome.spaceSummary
          }
        })
        return
      }
      if (outcome.kind === 'credentials-only') {
        showToast({
          message: t('storage.importCredentialsOnly', { count: 0 }),
          severity: 'success'
        })
      } else {
        showToast({
          message: t('storage.importSuccess', {
            ...outcome.spaceSummary,
            credentialsNote: outcome.hasCredentials
              ? t('storage.importCredentialsNote', { count: 0 })
              : ''
          }),
          severity: 'success'
        })
      }
      // The Storage page lists the Space's collections on mount, so the
      // imported ones show there with no re-list of its own.
      navigate('/storage')
    } catch (err) {
      log.error('Failed to import space', { err })
      setErrorKey('storage.importError')
    } finally {
      setIsImporting(false)
    }
  }

  return (
    <DashboardLayout title={t('storage.importPage.title')}>
      <Stack sx={{ mt: 3, gap: 3, maxWidth: 640 }}>
        <Button
          component={RouterLink}
          to="/storage"
          startIcon={<MdArrowBack />}
          sx={storageStyles.backToStorageButton}
          variant="text"
        >
          {t('storage.backToCollections')}
        </Button>

        <Typography variant="body1">{t('storage.importPage.intro')}</Typography>

        {hasRemoteStorage && (
          <StorageQuotaCard status={quotaStatus} onRetry={reloadQuota} />
        )}

        {errorKey && <Alert severity="error">{t(errorKey)}</Alert>}

        <Button
          variant="contained"
          component="label"
          loading={isImporting}
          disabled={importBlocked}
          sx={[
            storageStyles.buttonTextLeft,
            storageStyles.buttonSize.topAction
          ]}
        >
          {t('storage.importPage.chooseArchive')}
          <input
            type="file"
            accept={'.tar,application/x-tar'}
            style={visuallyHiddenInput}
            onChange={handleImportFile}
          />
        </Button>
      </Stack>
    </DashboardLayout>
  )
}
