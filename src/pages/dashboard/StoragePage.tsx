import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CollectionsOverview } from '@/components/storage/StorageBrowser'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import type { StorageCollection } from '@/lib/storage'

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
  const session = useAuthStore(state => state.session)
  const [collections, setCollections] = useState<Array<StorageCollection>>([])
  const [collectionsError, setCollectionsError] = useState<string | null>(null)
  const [isLoadingCollections, setIsLoadingCollections] = useState(false)
  const [isExporting, setIsExporting] = useState(false)

  useEffect(() => {
    let cancelled = false

    async function loadCollections() {
      if (!session?.storage?.remoteStore) {
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

    loadCollections()
    return () => {
      cancelled = true
    }
  }, [session, t])

  const handleExportSpace = async () => {
    if (!session?.storage) {
      return
    }
    setIsExporting(true)
    try {
      const spaceId = session.storage.remoteStore?.spaceId
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
              {session?.storage.remoteStore?.spaceUrl ||
                t('storage.noRemoteSpace')}
            </Typography>
          </Stack>
          <Button
            variant="contained"
            onClick={handleExportSpace}
            disabled={isExporting || !session?.storage?.remoteStore}
            sx={[
              storageStyles.buttonTextLeft,
              storageStyles.buttonSize.topAction
            ]}
          >
            {isExporting ? t('storage.exporting') : t('storage.exportSpace')}
          </Button>
        </Stack>
      </Paper>

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
