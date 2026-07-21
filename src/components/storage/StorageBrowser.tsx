import { Box, Card, CardActionArea, Stack, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdFolder, MdFolderOpen } from 'react-icons/md'
import type { StorageCollection } from '@/lib/storage'
import { storageStyles } from '@/styles/appStyles'
import { getCollectionDisplayName, groupCollections } from './displayUtils'
import { PublicAccessIcon } from './PublicAccessIcon'
import { EncryptedAccessIcon } from './EncryptedAccessIcon'
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
  const { contents, app, system } = groupCollections({ collections })

  return (
    <Stack spacing={3}>
      <CollectionGroup
        title={t('storage.groupWalletContents')}
        collections={contents}
        backendName={resolvedBackend}
      />
      {app.length > 0 && (
        <CollectionGroup
          title={t('storage.groupAppCollections')}
          description={t('storage.groupAppCollectionsDescription')}
          collections={app}
          backendName={resolvedBackend}
        />
      )}
      <CollectionGroup
        title={t('storage.groupSystemCollections')}
        collections={system}
        backendName={resolvedBackend}
        muted
      />
    </Stack>
  )
}

/**
 * One titled category of collection folder cards. `muted` renders the group in
 * the secondary text color -- the Wallet System Collections cue that these are
 * wallet plumbing the user is not expected to edit by hand.
 */
function CollectionGroup({
  title,
  description,
  collections,
  backendName,
  muted = false
}: {
  title: string
  description?: string
  collections: StorageCollection[]
  backendName: string
  muted?: boolean
}) {
  if (collections.length === 0) {
    return null
  }
  return (
    <Box>
      <Typography
        variant="subtitle1"
        sx={
          muted
            ? storageStyles.collectionGroupHeadingMuted
            : storageStyles.collectionGroupHeading
        }
      >
        {title}
      </Typography>
      {description && (
        <Typography variant="body2" sx={storageStyles.collectionGroupNote}>
          {description}
        </Typography>
      )}
      <Box sx={storageStyles.collectionsList} role="list">
        {collections.map(collection => (
          <CollectionFolderCard
            key={collection.id}
            collection={collection}
            backendName={backendName}
            muted={muted}
          />
        ))}
      </Box>
    </Box>
  )
}

interface CollectionFolderCardProps {
  collection: StorageCollection
  backendName: string
  muted?: boolean
}

function CollectionFolderCard({
  collection,
  backendName,
  muted = false
}: CollectionFolderCardProps) {
  const { t } = useTranslation()
  const displayName = getCollectionDisplayName(collection)
  const total = collection.totalItems ?? 0
  const targetPath = `/storage/collections/${encodeURIComponent(collection.id)}`

  return (
    <Card
      role="listitem"
      variant="outlined"
      sx={muted ? storageStyles.systemFolderCard : storageStyles.folderCard}
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
            <Typography
              variant="subtitle1"
              sx={
                muted
                  ? { ...storageStyles.folderName, color: 'text.secondary' }
                  : storageStyles.folderName
              }
            >
              {displayName}
            </Typography>
            <Typography
              variant="caption"
              sx={storageStyles.folderMeta}
              component="div"
            >
              {backendName}
              {collection.isPublic && (
                <Box component="span" sx={storageStyles.folderMetaPublic}>
                  {' · '}
                  <PublicAccessIcon />
                </Box>
              )}
              {collection.isEncrypted && (
                <Box component="span" sx={storageStyles.folderMetaEncrypted}>
                  {' · '}
                  <EncryptedAccessIcon />
                </Box>
              )}
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
