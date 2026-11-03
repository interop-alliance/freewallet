import { useMemo, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CollectionSharesDialog } from '@/components/storage/CollectionSharesDialog'
import { SpaceSection } from '@/components/storage/SpaceSection'
import { CollectionsOverview } from '@/components/storage/StorageBrowser'
import { StorageQuotaCard } from '@/components/storage/StorageQuotaCard'
import { getCollectionDisplayName } from '@/components/storage/displayUtils'
import { useAsyncLoad } from '@/hooks/useAsyncLoad'
import { useSpaceQuota } from '@/hooks/useSpaceQuota'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import type { StorageCollection } from '@/lib/storage'
import { useStorageListings } from '@/hooks/useStorageListings'
import { attributeCollectionsToApps } from '@/lib/collectionAttribution'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:storage')

export const StoragePage = () => {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const [loadedCollections, setLoadedCollections] = useState<
    Array<StorageCollection>
  >([])
  const [sharesDialogCollectionId, setSharesDialogCollectionId] = useState<
    string | null
  >(null)
  const hasRemoteStorage = Boolean(session?.storage?.hasRemoteStorage)

  const { status: quotaStatus, reload: reloadQuota } = useSpaceQuota({
    session
  })

  // The listing lands in two stages: the bare collections first, then the same
  // list with each collection's resource count.
  const {
    loading: isLoadingCollections,
    error: collectionsError,
    reload: reloadCollections
  } = useAsyncLoad(
    async ({ isCancelled }) => {
      const storage = session?.storage
      if (!hasRemoteStorage || !storage) {
        return
      }

      const remoteCollections = await storage.listCollections()
      if (isCancelled()) {
        return
      }

      setLoadedCollections(remoteCollections)

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
      if (isCancelled()) {
        return
      }
      setLoadedCollections(withCounts)
    },
    [hasRemoteStorage, session],
    {
      enabled: hasRemoteStorage && Boolean(session?.storage),
      onError: err => {
        log.error('Failed to list storage collections', { err })
      }
    }
  )

  const collections = useMemo(
    () => (collectionsError ? [] : loadedCollections),
    [collectionsError, loadedCollections]
  )
  // The collection listing's failure copy, derived as an i18n KEY and
  // translated at render: keeping the translated string here would put `t` in
  // the load's dependencies, so a language switch would refetch the whole
  // listing.
  const collectionsErrorKey = collectionsError
    ? 'storage.collectionsLoadError'
    : null

  // The reader rosters behind each collection row's "Shared" chip and the
  // creating applications behind its "Created by" line, over one read of the
  // activity history.
  const {
    sharesByCollection,
    creators,
    reload: reloadShares
  } = useStorageListings({ session, collections })

  const creatorsByCollection = useMemo(
    () => attributeCollectionsToApps({ collections, creators }),
    [creators, collections]
  )

  const sharesDialogCollection = collections.find(
    collection => collection.id === sharesDialogCollectionId
  )
  const sharesDialogCollectionName = sharesDialogCollection
    ? getCollectionDisplayName({ collection: sharesDialogCollection, t })
    : (sharesDialogCollectionId ?? '')

  return (
    <DashboardLayout title={t('storage.title')}>
      <Stack sx={{ mt: 3, gap: 3 }}>
        <SpaceSection
          session={session}
          onImported={() => {
            void reloadCollections()
            reloadQuota()
          }}
        />

        {hasRemoteStorage && (
          <StorageQuotaCard status={quotaStatus} onRetry={reloadQuota} />
        )}

        <Box sx={storageStyles.collectionsWrap}>
          {hasRemoteStorage && isLoadingCollections && (
            <Stack spacing={1.5} aria-busy="true">
              {[0, 1, 2].map(row => (
                <Skeleton key={row} variant="rounded" height={72} />
              ))}
            </Stack>
          )}
          {collectionsErrorKey && (
            <Alert severity="error">{t(collectionsErrorKey)}</Alert>
          )}
          {hasRemoteStorage &&
            !isLoadingCollections &&
            !collectionsErrorKey && (
              <CollectionsOverview
                collections={collections}
                usageByCollection={
                  quotaStatus.kind === 'ready'
                    ? quotaStatus.quota.usageByCollection
                    : undefined
                }
                sharesByCollection={sharesByCollection}
                creatorsByCollection={creatorsByCollection}
                onShowShares={setSharesDialogCollectionId}
              />
            )}
        </Box>
      </Stack>

      {session && sharesDialogCollectionId && (
        <CollectionSharesDialog
          session={session}
          collectionId={sharesDialogCollectionId}
          collectionName={sharesDialogCollectionName}
          shares={sharesByCollection[sharesDialogCollectionId] ?? []}
          onClose={() => setSharesDialogCollectionId(null)}
          onRemoved={() => {
            void reloadShares()
          }}
        />
      )}
    </DashboardLayout>
  )
}
