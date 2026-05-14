import { Box, Card, CardActionArea, Stack, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdFolder, MdFolderOpen } from 'react-icons/md'
import type { StorageCollection } from '@/lib/storage'
import { storageStyles } from '@/styles/appStyles'
import { getCollectionDisplayName } from './displayUtils'
import { StorageEmptyState } from './EmptyState'

interface CollectionsOverviewProps {
  collections: StorageCollection[]
  backendName?: string
}

export function CollectionsOverview({
  collections,
  backendName
}: CollectionsOverviewProps) {
  const { t } = useTranslation()

  if (collections.length === 0) {
    return (
      <StorageEmptyState
        icon={<MdFolderOpen />}
        title={t('storage.emptyCollectionsTitle')}
        description={t('storage.emptyCollectionsDescription')}
      />
    )
  }

  const resolvedBackend = backendName ?? t('storage.collectionBackend')

  return (
    <Box sx={storageStyles.collectionsList} role="list">
      {collections.map(collection => (
        <CollectionFolderCard
          key={collection.id}
          collection={collection}
          backendName={resolvedBackend}
        />
      ))}
    </Box>
  )
}

interface CollectionFolderCardProps {
  collection: StorageCollection
  backendName: string
}

function CollectionFolderCard({
  collection,
  backendName
}: CollectionFolderCardProps) {
  const { t } = useTranslation()
  const displayName = getCollectionDisplayName(collection)
  const total = collection.totalItems ?? 0
  const targetPath = `/storage/collections/${encodeURIComponent(collection.id)}`

  return (
    <Card
      role="listitem"
      variant="outlined"
      sx={storageStyles.folderCard}
      aria-label={displayName}
    >
      <CardActionArea
        component={RouterLink}
        to={targetPath}
        sx={storageStyles.folderCardAction}
      >
        <Stack
          direction="row"
          spacing={1.5}
          sx={storageStyles.folderCardHeader}
        >
          <Box sx={storageStyles.folderIcon} aria-hidden>
            <MdFolder />
          </Box>
          <Stack spacing={0.25} sx={storageStyles.folderCardBody}>
            <Typography variant="subtitle1" sx={storageStyles.folderName}>
              {displayName}
            </Typography>
            <Typography variant="caption" sx={storageStyles.folderMeta}>
              {backendName}
            </Typography>
          </Stack>
        </Stack>
        <Typography
          variant="body2"
          component="span"
          sx={storageStyles.folderCount}
        >
          {t('storage.resourceCount', { count: total })}
        </Typography>
      </CardActionArea>
    </Card>
  )
}
