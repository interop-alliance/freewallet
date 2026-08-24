import { useCallback, useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CollectionSharesDialog } from '@/components/storage/CollectionSharesDialog'
import { CollectionsOverview } from '@/components/storage/StorageBrowser'
import { StorageQuotaCard } from '@/components/storage/StorageQuotaCard'
import { getCollectionDisplayName } from '@/components/storage/displayUtils'
import { useAuthStore } from '@/stores/authStore'
import { useSyncStatusStore } from '@/stores/syncStatusStore'
import { showToast } from '@/stores/toastStore'
import { storageStyles } from '@/styles/appStyles'
import type { StorageCollection } from '@/lib/storage'
import { quotaViewFromReport, writesRestricted } from '@/lib/storageQuota'
import type { StorageQuotaStatus } from '@/types/storageQuota'
import type { ImportSpaceSummary } from '@/stores/storageManager'
import { parseImportTarFile } from '@/lib/import'
import { listSharedCollections, type CollectionShare } from '@/session/shares'
import { SYNCED_COLLECTIONS } from '@/app.config'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:storage')

/**
 * Visually-hidden style for the file input wrapped by the import Button
 * (`component="label"`); keeps the native input accessible while the Button
 * provides the visible affordance.
 */
const visuallyHiddenInput: React.CSSProperties = {
  clip: 'rect(0 0 0 0)',
  clipPath: 'inset(50%)',
  height: 1,
  overflow: 'hidden',
  position: 'absolute',
  bottom: 0,
  left: 0,
  whiteSpace: 'nowrap',
  width: 1
}

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
  const [sharesByCollection, setSharesByCollection] = useState<
    Record<string, CollectionShare[]>
  >({})
  const [sharesRefreshKey, setSharesRefreshKey] = useState(0)
  const [sharesDialogCollectionId, setSharesDialogCollectionId] = useState<
    string | null
  >(null)
  const [quotaStatus, setQuotaStatus] = useState<StorageQuotaStatus>({
    kind: 'loading'
  })
  const hasRemoteStorage = Boolean(session?.storage?.hasRemoteStorage)
  const syncStatuses = useSyncStatusStore(state => state.statuses)

  const loadQuota = useCallback(async () => {
    if (!hasRemoteStorage || !session?.storage) {
      return
    }

    try {
      const report = await session.storage.getSpaceQuotas()
      if (!report?.backends.length) {
        setQuotaStatus({ kind: 'unavailable' })
        return
      }

      const quota = quotaViewFromReport(report)
      setQuotaStatus(quota ? { kind: 'ready', quota } : { kind: 'unavailable' })
    } catch (error) {
      log.error('Failed to load storage quota', { err: error })
      setQuotaStatus({ kind: 'error' })
    }
  }, [hasRemoteStorage, session])

  const handleRetryQuota = useCallback(() => {
    setQuotaStatus({ kind: 'loading' })
    void loadQuota()
  }, [loadQuota])

  useEffect(() => {
    if (!hasRemoteStorage || !session?.storage) {
      return
    }

    let cancelled = false
    const storage = session.storage

    async function loadCollections() {
      try {
        const remoteCollections = await storage.listCollections()
        if (cancelled) {
          return
        }

        setCollections(remoteCollections)

        const withCounts = await Promise.all(
          remoteCollections.map(async collection => {
            try {
              const items = await storage.listCollectionResources({
                collectionUrl: collection.url
              })
              return { ...collection, totalItems: items.length }
            } catch (err) {
              log.warn('Failed to count resources for collection', {
                collectionId: collection.id,
                err
              })
              return collection
            }
          })
        )
        if (cancelled) {
          return
        }
        setCollections(withCounts)
      } catch (error) {
        log.error('Failed to list storage collections', { err: error })
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

    void (async () => {
      await Promise.resolve()
      if (cancelled) {
        return
      }

      setIsLoadingCollections(true)
      setCollectionsError(null)
      await Promise.all([loadQuota(), loadCollections()])
    })()

    return () => {
      cancelled = true
    }
  }, [hasRemoteStorage, session, t, collectionsRefreshKey, loadQuota])

  // The reader rosters behind each collection row's "Shared" chip. A failure
  // is non-blocking: the chips simply do not appear, and the storage listing
  // itself stays usable.
  useEffect(() => {
    if (!hasRemoteStorage || !session) {
      return
    }

    let cancelled = false
    const activeSession = session

    async function loadShares() {
      try {
        const record = await listSharedCollections({ session: activeSession })
        if (!cancelled) {
          setSharesByCollection(record)
        }
      } catch (err) {
        log.error('Could not load the collection shares', { err })
        if (!cancelled) {
          setSharesByCollection({})
        }
      }
    }

    void loadShares()

    return () => {
      cancelled = true
    }
  }, [hasRemoteStorage, session, sharesRefreshKey])

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
      log.error('Failed to export space', { err: error })
      showToast({ message: t('storage.exportError'), severity: 'error' })
    } finally {
      setIsExporting(false)
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
        showToast({
          message: t('storage.importSuccess', {
            ...spaceSummary,
            credentialsNote
          }),
          severity: 'success'
        })
        return
      }

      if (hasCredentials) {
        showToast({
          message: t('storage.importCredentialsOnly', {
            count: credentials.length
          }),
          severity: 'success'
        })
      }
    } catch (error) {
      log.error('Failed to import space', { err: error })
      showToast({ message: t('storage.importError'), severity: 'error' })
    } finally {
      setIsImporting(false)
    }
  }

  const sharesDialogCollection = collections.find(
    collection => collection.id === sharesDialogCollectionId
  )
  const sharesDialogCollectionName = sharesDialogCollection
    ? getCollectionDisplayName({ collection: sharesDialogCollection, t })
    : (sharesDialogCollectionId ?? '')

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
              variant="contained"
              onClick={handleExportSpace}
              loading={isExporting}
              disabled={!hasRemoteStorage}
              sx={[
                storageStyles.buttonTextLeft,
                storageStyles.buttonSize.topAction
              ]}
            >
              {t('storage.exportSpace')}
            </Button>
            <Button
              variant="outlined"
              component="label"
              loading={isImporting}
              disabled={importBlocked}
              sx={[
                storageStyles.buttonTextLeft,
                storageStyles.buttonSize.topAction
              ]}
            >
              {t('storage.importSpace')}
              <input
                type="file"
                accept={'.tar,application/x-tar'}
                style={visuallyHiddenInput}
                onChange={handleImportFile}
              />
            </Button>
          </Stack>
        </Stack>
      </Paper>

      {hasRemoteStorage && (
        <StorageQuotaCard status={quotaStatus} onRetry={handleRetryQuota} />
      )}

      <Box sx={storageStyles.collectionsWrap}>
        {hasRemoteStorage && isLoadingCollections && (
          <Stack spacing={1.5} aria-busy="true">
            {[0, 1, 2].map(row => (
              <Skeleton key={row} variant="rounded" height={72} />
            ))}
          </Stack>
        )}
        {collectionsError && <Alert severity="error">{collectionsError}</Alert>}
        {hasRemoteStorage && !isLoadingCollections && !collectionsError && (
          <CollectionsOverview
            collections={collections}
            usageByCollection={
              quotaStatus.kind === 'ready'
                ? quotaStatus.quota.usageByCollection
                : undefined
            }
            syncStatuses={Object.fromEntries(
              SYNCED_COLLECTIONS.map(({ id }) => [
                id,
                syncStatuses[id] ?? 'idle'
              ])
            )}
            sharesByCollection={sharesByCollection}
            onShowShares={setSharesDialogCollectionId}
          />
        )}
      </Box>

      {session && sharesDialogCollectionId && (
        <CollectionSharesDialog
          session={session}
          collectionId={sharesDialogCollectionId}
          collectionName={sharesDialogCollectionName}
          shares={sharesByCollection[sharesDialogCollectionId] ?? []}
          onClose={() => setSharesDialogCollectionId(null)}
          onRemoved={() => setSharesRefreshKey(key => key + 1)}
        />
      )}
    </DashboardLayout>
  )
}
