import {
  Box,
  List,
  ListItem,
  ListItemButton,
  Stack,
  Typography
} from '@mui/material'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdFolder, MdFolderOpen, MdSettings } from 'react-icons/md'
import type { StorageCollection } from '@/lib/storage'
import { formatBytes } from '@/lib/formatBytes'
import { storageStyles } from '@/styles/appStyles'
import { getCollectionDisplayName, groupCollections } from './displayUtils'
import { PublicAccessIcon } from './PublicAccessIcon'
import { EncryptedAccessIcon } from './EncryptedAccessIcon'
import { StorageEmptyState } from './EmptyState'

interface CollectionsOverviewProps {
  collections: StorageCollection[]
  usageByCollection?: Map<string, number>
}

export function CollectionsOverview({
  collections,
  usageByCollection
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

  const { contents, app, system } = groupCollections({ collections, t })

  return (
    <Stack spacing={3}>
      <CollectionGroup
        title={t('storage.groupWalletContents')}
        collections={contents}
        usageByCollection={usageByCollection}
      />
      {app.length > 0 && (
        <CollectionGroup
          title={t('storage.groupAppCollections')}
          description={t('storage.groupAppCollectionsDescription')}
          collections={app}
          usageByCollection={usageByCollection}
        />
      )}
      <CollectionGroup
        title={t('storage.groupSystemCollections')}
        collections={system}
        usageByCollection={usageByCollection}
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
  usageByCollection,
  muted = false
}: {
  title: string
  description?: string
  collections: StorageCollection[]
  usageByCollection?: Map<string, number>
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
      <List disablePadding sx={storageStyles.collectionsList}>
        {collections.map(collection => (
          <CollectionFolderCard
            key={collection.id}
            collection={collection}
            usageBytes={usageByCollection?.get(collection.id)}
            muted={muted}
          />
        ))}
      </List>
    </Box>
  )
}

interface CollectionFolderCardProps {
  collection: StorageCollection
  usageBytes?: number
  muted?: boolean
}

function CollectionFolderCard({
  collection,
  usageBytes,
  muted = false
}: CollectionFolderCardProps) {
  const { t } = useTranslation()
  const displayName = getCollectionDisplayName(collection, t)
  const total = collection.totalItems ?? 0
  const targetPath = `/storage/collections/${encodeURIComponent(collection.id)}`

  return (
    <ListItem disablePadding divider>
      <ListItemButton
        component={RouterLink}
        to={targetPath}
        sx={muted ? storageStyles.systemFolderCard : storageStyles.folderCard}
      >
        <Stack
          direction="row"
          spacing={1.5}
          sx={storageStyles.folderCardHeader}
        >
          <Box sx={storageStyles.folderIcon} aria-hidden>
            <MdFolder />
            {muted && (
              <Box component="span" sx={storageStyles.systemFolderIconBadge}>
                <MdSettings />
              </Box>
            )}
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
              {displayName !== collection.id && (
                <Box component="code" sx={storageStyles.folderId}>
                  {' '}
                  ({collection.id})
                </Box>
              )}
            </Typography>
            {(collection.isPublic || collection.isEncrypted) && (
              <Typography
                variant="caption"
                sx={storageStyles.folderMeta}
                component="div"
              >
                {collection.isPublic && (
                  <Box component="span" sx={storageStyles.folderMetaPublic}>
                    <PublicAccessIcon />
                  </Box>
                )}
                {collection.isEncrypted && (
                  <Box component="span" sx={storageStyles.folderMetaEncrypted}>
                    {collection.isPublic && ' · '}
                    <EncryptedAccessIcon />
                  </Box>
                )}
              </Typography>
            )}
          </Stack>
        </Stack>
        <Typography
          variant="body2"
          component="span"
          sx={storageStyles.folderCount}
        >
          {t('storage.resourceCount', { count: total })}
        </Typography>
        {usageBytes != null && (
          <Typography
            variant="body2"
            component="span"
            sx={storageStyles.folderUsage}
          >
            {formatBytes(usageBytes)}
          </Typography>
        )}
      </ListItemButton>
    </ListItem>
  )
}
