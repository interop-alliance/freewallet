import { useCallback, useEffect, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CollectionsOverview } from '@/components/storage/StorageBrowser'
import { StorageQuotaCard } from '@/components/storage/StorageQuotaCard'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import type { StorageCollection } from '@/lib/storage'
import { quotaViewFromReport, writesRestricted } from '@/lib/storageQuota'
import type { StorageQuotaStatus } from '@/types/storageQuota'
import type { ImportSpaceSummary } from '@/stores/storageManager'
import { parseImportTarFile } from '@/lib/import'

type SaveFilePicker = (options?: {
  suggestedName?: string
  types?: Array<{
    description?: string
    accept?: Record<string, string[]>
  }>
}) => Promise<{
  createWritable: () => Promise<WritableStream>
}>

export const StoragePage = () => {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)
  const [collections, setCollections] = useState<Array<StorageCollection>>([])
  const [collectionsError, setCollectionsError] = useState<string | null>(null)
  const [isLoadingCollections, setIsLoadingCollections] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [isImporting, setIsImporting] = useState(false)
  const [collectionsRefreshKey, setCollectionsRefreshKey] = useState(0)
  const [quotaStatus, setQuotaStatus] = useState<StorageQuotaStatus>({
    kind: 'loading'
  })
  const importInputRef = useRef<HTMLInputElement>(null)

  const loadQuota = useCallback(async () => {
    if (!session?.storage?.hasRemoteStorage) {
      setQuotaStatus({ kind: 'unavailable' })
      return
    }

    setQuotaStatus({ kind: 'loading' })
    try {
      const report = await session.storage.getSpaceQuotas()
      if (!report?.backends.length) {
        setQuotaStatus({ kind: 'unavailable' })
        return
      }

      const quota = quotaViewFromReport(report)
      setQuotaStatus(
        quota ? { kind: 'ready', quota } : { kind: 'unavailable' }
      )
    } catch (error) {
      console.error('Failed to load storage quota:', error)
      setQuotaStatus({
        kind: 'error',
        message: 'Could not load storage usage.'
      })
    }
  }, [session])

  useEffect(() => {
    let cancelled = false

    async function loadCollections() {
      if (!session?.storage?.hasRemoteStorage) {
        setCollections([])
        return
      }

      setIsLoadingCollections(true)
      setCollectionsError(null)
      try {
        const remoteCollections = await session.storage.listCollections()
        if (cancelled) {
          return
        }

        setCollections(remoteCollections)

        const withCounts = await Promise.all(
          remoteCollections.map(async collection => {
            try {
              const items = await session.storage.listCollectionResources({
                collectionUrl: collection.url
              })
              return { ...collection, totalItems: items.length }
            } catch (err) {
              console.warn(
                `Failed to count resources for collection "${collection.id}":`,
                err
              )
              return collection
            }
          })
        )
        if (cancelled) {
          return
        }
        setCollections(withCounts)
      } catch (error) {
        console.error('Failed to list storage collections:', error)
        if (!cancelled) {
          setCollectionsError(t('storage.collectionsLoadError'))
          setCollections([])
        }
      } finally {
        if (!cancelled) {
          setIsLoadingCollections(false)
        }
      }
    }

    if (!session?.storage?.hasRemoteStorage) {
      setCollections([])
      setQuotaStatus({ kind: 'unavailable' })
      return () => {
        cancelled = true
      }
    }

    void Promise.all([loadQuota(), loadCollections()])
    return () => {
      cancelled = true
    }
  }, [session, t, collectionsRefreshKey, loadQuota])

  const handleExportSpace = async () => {
    if (!session?.storage) {
      return
    }
    setIsExporting(true)
    try {
      const spaceId = session.storage.spaceId
      if (!spaceId) {
        throw new Error('Remote space ID is unavailable.')
      }

      const stream = await session.storage.exportSpace()

      const windowWithPicker = window as Window & {
        showSaveFilePicker?: SaveFilePicker
      }
      if (typeof windowWithPicker.showSaveFilePicker !== 'function') {
        throw new Error('Streaming export is not supported in this browser.')
      }

      const fileHandle = await windowWithPicker.showSaveFilePicker({
        suggestedName: `space-${spaceId}.tar`,
        types: [
          {
            description: 'TAR archive',
            accept: { 'application/x-tar': ['.tar'] }
          }
        ]
      })

      const writable = await fileHandle.createWritable()
      await stream.pipeTo(writable)
    } catch (error) {
      if ((error as DOMException).name === 'AbortError') {
        return
      }
      console.error('Failed to export space:', error)
      window.alert(t('storage.exportError'))
    } finally {
      setIsExporting(false)
    }
  }

  const handleImportClick = () => {
    if (!isImporting) {
      importInputRef.current?.click()
    }
  }

  const handleImportFile = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file || !session?.storage) {
      return
    }

    setIsImporting(true)
    try {
      const { hasSpace, hasCredentials, credentials } =
        await parseImportTarFile(file)

      if (!hasSpace && !hasCredentials) {
        throw new Error('Unrecognized archive.')
      }

      let spaceSummary: ImportSpaceSummary | undefined
      if (hasSpace) {
        if (!session.storage.hasRemoteStorage) {
          throw new Error(t('storage.importSpaceRequiresRemote'))
        }
        spaceSummary = await session.storage.importSpace({ tarFile: file })
        setCollectionsRefreshKey(key => key + 1)
      }

      if (credentials.length > 0) {
        navigate('/accept-credentials', {
          state: { credentials, importSummary: spaceSummary }
        })
        return
      }

      const credentialsNote = hasCredentials
        ? t('storage.importCredentialsNote', { count: credentials.length })
        : ''

      if (spaceSummary) {
        window.alert(
          t('storage.importSuccess', { ...spaceSummary, credentialsNote })
        )
        return
      }

      if (hasCredentials) {
        window.alert(
          t('storage.importCredentialsOnly', { count: credentials.length })
        )
      }
    } catch (error) {
      console.error('Failed to import space:', error)
      window.alert(t('storage.importError'))
    } finally {
      setIsImporting(false)
    }
  }

  const importBlocked =
    quotaStatus.kind === 'ready' && writesRestricted(quotaStatus.quota)

  return (
    <DashboardLayout title={t('storage.title')}>
      <Paper variant="outlined" sx={storageStyles.storageToolbar}>
        <Stack
          direction={{ xs: 'column', md: 'row' }}
          spacing={2}
          sx={storageStyles.connectedRow}
        >
          <Stack spacing={0.5} sx={{ minWidth: 0, flexGrow: 1 }}>
            <Typography variant="h6" sx={storageStyles.connectedLabel}>
              {t('storage.spaceConnected')}
            </Typography>
            <Typography variant="body2" sx={storageStyles.connectedLink}>
              {session?.storage.spaceUrl || t('storage.noRemoteSpace')}
            </Typography>
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <Button
              variant="outlined"
              onClick={handleImportClick}
              disabled={isImporting || importBlocked}
              sx={[
                storageStyles.buttonTextLeft,
                storageStyles.buttonSize.topAction
              ]}
            >
              {isImporting ? t('storage.importing') : t('storage.importSpace')}
            </Button>
            <Button
              variant="contained"
              onClick={handleExportSpace}
              disabled={isExporting || !session?.storage?.hasRemoteStorage}
              sx={[
                storageStyles.buttonTextLeft,
                storageStyles.buttonSize.topAction
              ]}
            >
              {isExporting ? t('storage.exporting') : t('storage.exportSpace')}
            </Button>
          </Stack>
          <input
            ref={importInputRef}
            type="file"
            accept={'.tar,application/x-tar'}
            hidden
            onChange={handleImportFile}
          />
        </Stack>
      </Paper>

      {session?.storage?.hasRemoteStorage && (
        <StorageQuotaCard
          status={quotaStatus}
          collections={collections}
          onRetry={loadQuota}
        />
      )}

      <Box sx={storageStyles.sectionHeader}>
        <Typography variant="h4" sx={storageStyles.sectionHeading}>
          {t('storage.collections')}
        </Typography>
      </Box>

      <Box sx={storageStyles.collectionsWrap}>
        {isLoadingCollections && (
          <Typography variant="body1" sx={storageStyles.statusText}>
            {t('storage.loadingCollections')}
          </Typography>
        )}
        {collectionsError && (
          <Typography variant="body1" sx={storageStyles.errorText}>
            {collectionsError}
          </Typography>
        )}
        {!isLoadingCollections && !collectionsError && (
          <CollectionsOverview collections={collections} />
        )}
      </Box>
    </DashboardLayout>
  )
}
