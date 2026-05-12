import { DashboardLayout } from '@/components/DashboardLayout'
import { getBackends, type StorageCollection } from '@/lib/storage'
import { Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import { MdStorage } from 'react-icons/md'
import { FcGoogle } from 'react-icons/fc'
import { useEffect, useState } from 'react'

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
  const session = useAuthStore(state => state.session)
  const backends = getBackends()
  const [collections, setCollections] = useState<Array<StorageCollection>>([])
  const [collectionsError, setCollectionsError] = useState<string | null>(null)
  const [isLoadingCollections, setIsLoadingCollections] = useState(false)
  const [isExporting, setIsExporting] = useState(false)

  useEffect(() => {
    async function loadCollections() {
      if (!session?.storage?.remoteStore) {
        setCollections([])
        return
      }

      setIsLoadingCollections(true)
      setCollectionsError(null)
      try {
        const remoteCollections = await session.storage.listCollections()
        setCollections(remoteCollections)
      } catch (error) {
        console.error('Failed to list storage collections:', error)
        setCollectionsError('Could not load storage collections.')
        setCollections([])
      } finally {
        setIsLoadingCollections(false)
      }
    }

    loadCollections()
  }, [session])

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

      // Ask user where to save — streams directly, no buffering
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
      await stream.pipeTo(writable) // chunks go disk
    } catch (error) {
      if ((error as DOMException).name === 'AbortError') {
        return
      } // user cancelled picker
      console.error('Failed to export space:', error)
      window.alert('Could not export space. Please try again.')
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <DashboardLayout title="Storage">
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        spacing={2}
        sx={storageStyles.connectedRow}
      >
        <Typography variant="h6" sx={storageStyles.connectedLabel}>
          Space(connected):
        </Typography>
        <Typography variant="body1" sx={storageStyles.connectedLink}>
          {session?.storage.remoteStore?.spaceUrl}
        </Typography>

        <Button
          variant="outlined"
          sx={[
            storageStyles.buttonTextLeft,
            storageStyles.buttonSize.topAction
          ]}
        >
          View Details
        </Button>
        <Button
          variant="contained"
          onClick={handleExportSpace}
          disabled={isExporting || !session?.storage?.remoteStore}
          sx={[
            storageStyles.buttonTextLeft,
            storageStyles.buttonSize.topAction
          ]}
        >
          {isExporting ? 'Exporting...' : 'Export Space'}
        </Button>
      </Stack>

      <Typography variant="h4" sx={storageStyles.sectionHeading}>
        Backends
      </Typography>
      <Stack
        direction={{ xs: 'column', lg: 'row' }}
        spacing={2}
        sx={storageStyles.backendRow}
      >
        {backends.map(backend => (
          <Paper
            key={backend.id}
            variant="outlined"
            sx={storageStyles.backendCard(backend.enabled === false)}
          >
            <Box sx={storageStyles.backendHeaderRow}>
              {backend.id === 'google-drive' ? (
                <Box component={FcGoogle} sx={storageStyles.backendIcon} />
              ) : (
                <Box component="span" sx={storageStyles.backendIcon}>
                  <MdStorage />
                </Box>
              )}
              <Typography variant="h5" sx={storageStyles.backendTitle}>
                {backend.displayName}
              </Typography>
            </Box>
            <Typography
              variant="h6"
              color="text.secondary"
              sx={storageStyles.backendDescription(
                backend.comingSoon === true,
                backend.enabled === false
              )}
            >
              {backend.description}
            </Typography>
          </Paper>
        ))}

        <Box sx={storageStyles.connectBackendWrap}>
          <Button
            variant="outlined"
            sx={[
              storageStyles.buttonTextLeft,
              storageStyles.buttonSize.connectBackend
            ]}
          >
            (+) Connect Backend
          </Button>
        </Box>
      </Stack>

      <Typography variant="h4" sx={storageStyles.sectionHeading}>
        Collections
      </Typography>
      <Stack spacing={3} sx={storageStyles.collectionsWrap}>
        {isLoadingCollections && (
          <Typography variant="body1" color="text.secondary">
            Loading collections...
          </Typography>
        )}
        {collectionsError && (
          <Typography variant="body1" color="error">
            {collectionsError}
          </Typography>
        )}
        {collections.map(collection => {
          return (
            <Stack key={collection.id} spacing={1.25}>
              <Typography variant="body1" sx={storageStyles.collectionItem}>
                {collection.id}
              </Typography>

              <Stack
                direction="row"
                spacing={2}
                sx={storageStyles.collectionMetaRow}
              >
                <Box sx={storageStyles.collectionDetailsSlot}>
                  <Button
                    variant="outlined"
                    size="small"
                    sx={[
                      storageStyles.buttonTextLeft,
                      storageStyles.buttonSize.collectionDetails
                    ]}
                  >
                    View Details
                  </Button>
                </Box>

                <Typography variant="h6" color="text.secondary">
                  Backend: Default (WAS)
                </Typography>
              </Stack>
            </Stack>
          )
        })}
      </Stack>
    </DashboardLayout>
  )
}
