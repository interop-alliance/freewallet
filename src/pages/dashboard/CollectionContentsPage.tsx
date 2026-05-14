import { useEffect, useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdArrowBack, MdFolder, MdFolderOpen } from 'react-icons/md'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import { ResourceTable } from '@/components/storage/ResourceTable'
import { StorageEmptyState } from '@/components/storage/EmptyState'
import { getCollectionDisplayName } from '@/components/storage/displayUtils'

export function CollectionContentsPage() {
  const { t } = useTranslation()
  const { collectionId: rawCollectionId } = useParams<{
    collectionId: string
  }>()
  const collectionId = rawCollectionId
    ? decodeURIComponent(rawCollectionId)
    : undefined

  const session = useAuthStore(state => state.session)
  const storage = session?.storage

  const [collection, setCollection] = useState<StorageCollection | null>(null)
  const [resources, setResources] = useState<StorageResource[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      if (!storage?.remoteStore || !collectionId) {
        setCollection(null)
        setResources([])
        return
      }
      setIsLoading(true)
      setErrorKey(null)
      try {
        const collections = await storage.listCollections()
        if (cancelled) {
          return
        }

        const match = collections.find(c => c.id === collectionId) ?? null
        setCollection(match)

        if (!match) {
          setResources([])
          setErrorKey('storage.collectionNotFound')
          return
        }

        const items = await storage.listCollectionResources({
          collectionUrl: match.url
        })
        if (cancelled) {
          return
        }
        setResources(items)
      } catch (error) {
        console.error('Failed to load collection contents:', error)
        if (!cancelled) {
          setErrorKey('storage.resourcesLoadError')
          setResources([])
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [storage, collectionId])

  const displayName = useMemo(() => {
    if (!collection) {
      return t('storage.collectionContentsTitle')
    }
    return getCollectionDisplayName(collection)
  }, [collection, t])

  const subtitle = useMemo(() => {
    if (!collection) {
      return ''
    }
    return t('storage.collectionContentsDescription', {
      backend: t('storage.collectionBackend'),
      count: collection.totalItems ?? resources.length
    })
  }, [collection, resources.length, t])

  return (
    <DashboardLayout title={t('storage.title')}>
      <Box sx={storageStyles.contentsWrap}>
        <Button
          component={RouterLink}
          to="/storage"
          startIcon={<MdArrowBack />}
          sx={storageStyles.backToStorageButton}
          variant="text"
        >
          {t('storage.backToCollections')}
        </Button>

        <Stack
          direction="row"
          spacing={1.5}
          sx={storageStyles.contentsTitleRow}
        >
          <Box sx={storageStyles.contentsTitleIcon} aria-hidden>
            <MdFolder />
          </Box>
          <Stack spacing={0.25} sx={{ minWidth: 0 }}>
            <Typography variant="h5" sx={storageStyles.contentsTitle}>
              {displayName}
            </Typography>
            {subtitle && (
              <Typography variant="body2" sx={storageStyles.contentsSubtitle}>
                {subtitle}
              </Typography>
            )}
          </Stack>
        </Stack>

        <Box sx={storageStyles.contentsBody}>
          {isLoading && (
            <Typography variant="body1" sx={storageStyles.statusText}>
              {t('storage.loadingResources')}
            </Typography>
          )}

          {!isLoading && errorKey && (
            <Typography variant="body1" sx={storageStyles.errorText}>
              {t(errorKey)}
            </Typography>
          )}

          {!isLoading && !errorKey && collection && resources.length === 0 && (
            <StorageEmptyState
              icon={<MdFolderOpen />}
              title={t('storage.emptyResourcesTitle')}
              description={t('storage.emptyResourcesDescription')}
            />
          )}

          {!isLoading && !errorKey && resources.length > 0 && (
            <ResourceTable resources={resources} />
          )}
        </Box>
      </Box>
    </DashboardLayout>
  )
}
