import { DashboardLayout } from '@/components/DashboardLayout'
import { getBackends, getCollections } from '@/lib/storage'
import { Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import { MdStorage } from 'react-icons/md'
import { FcGoogle } from 'react-icons/fc'

export const StoragePage = () => {
  const session = useAuthStore(state => state.session)
  const backends = getBackends()
  const collections = getCollections()

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
          sx={{
            ...storageStyles.buttonTextLeft,
            ...storageStyles.buttonSize.topAction
          }}
        >
          View Details
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
                <FcGoogle style={{ fontSize: 32 }} />
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
            sx={{
              ...storageStyles.buttonTextLeft,
              ...storageStyles.buttonSize.connectBackend
            }}
          >
            (+) Connect Backend
          </Button>
        </Box>
      </Stack>

      <Typography variant="h4" sx={storageStyles.sectionHeading}>
        Collections
      </Typography>
      <Stack spacing={3} sx={storageStyles.collectionsWrap}>
        {collections.map(collection => {
          return (
            <Stack key={collection.id} spacing={1.25}>
              <Button
                variant="outlined"
                sx={{
                  ...storageStyles.buttonTextLeft,
                  alignSelf: 'flex-start',
                  ...storageStyles.buttonSize.collectionLabel
                }}
              >
                {collection.displayName}
              </Button>

              <Stack
                direction="row"
                spacing={2}
                sx={storageStyles.collectionMetaRow}
              >
                <Box sx={storageStyles.collectionDetailsSlot}>
                  <Button
                    variant="outlined"
                    size="small"
                    sx={{
                      ...storageStyles.buttonTextLeft,
                      ...storageStyles.buttonSize.collectionDetails
                    }}
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
