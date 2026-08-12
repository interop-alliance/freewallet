import { useCallback, useEffect, useMemo, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import IconButton from '@mui/material/IconButton'
import Paper from '@mui/material/Paper'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import {
  MdArrowBack,
  MdClose,
  MdContentCopy,
  MdDeleteOutline,
  MdDownload,
  MdFolder,
  MdFolderOpen
} from 'react-icons/md'
import { DashboardLayout } from '@/components/DashboardLayout'
import { JsonHighlight } from '@/components/JsonHighlight'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { storageStyles } from '@/styles/appStyles'
import {
  credentialDetailCardStyles,
  credentialDetailStyles
} from '@/styles/credentialStyles'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { Json } from '@/lib/sync'
import {
  isVerifiableCredentialData,
  type FetchedCollectionResource
} from '@/lib/storageResource'
import { extensionFromMime } from '@/lib/extensionFromMime'
import { downloadBlob } from '@/lib/downloadBlob'
import { ResourceTable } from '@/components/storage/ResourceTable'
import {
  EncryptedAccessIcon,
  PublicAccessIcon
} from '@/components/storage/AccessIcon'
import { StorageEmptyState } from '@/components/storage/EmptyState'
import { SourceViewToggle } from '@/components/storage/SourceViewToggle'
import {
  decryptResourceBody,
  useResourceSourceCopy
} from '@/components/storage/useResourceSource'
import {
  getCollectionDisplayName,
  getResourceDisplayName
} from '@/components/storage/displayUtils'

export function CollectionContentsPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
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

  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deletingCollection, setDeletingCollection] = useState(false)
  const [deleteCollectionError, setDeleteCollectionError] = useState(false)

  const [selectedResource, setSelectedResource] =
    useState<StorageResource | null>(null)
  const [resourcePayload, setResourcePayload] =
    useState<FetchedCollectionResource | null>(null)
  // The decrypted document behind an EDV envelope resource (null when the
  // resource is plaintext or could not be decrypted), and which of the two
  // views the snippet dialog shows.
  const [decryptedData, setDecryptedData] = useState<Json | null>(null)
  const [resourceView, setResourceView] = useState<'decrypted' | 'envelope'>(
    'decrypted'
  )
  const [resourceLoading, setResourceLoading] = useState(false)
  const [resourceError, setResourceError] = useState<string | null>(null)
  const {
    copied: snippetCopied,
    copy: copySnippet,
    reset: resetSnippetCopied
  } = useResourceSourceCopy()

  const clearResourcePreview = useCallback(() => {
    setSelectedResource(null)
    setResourcePayload(null)
    setDecryptedData(null)
    setResourceError(null)
    setResourceLoading(false)
    resetSnippetCopied()
  }, [resetSnippetCopied])

  const [previousCollectionId, setPreviousCollectionId] = useState(collectionId)
  if (previousCollectionId !== collectionId) {
    setPreviousCollectionId(collectionId)
    clearResourcePreview()
  }

  useEffect(() => {
    let cancelled = false

    async function load() {
      if (!storage?.hasRemoteStorage || !collectionId) {
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

        const match =
          collections.find(collection => collection.id === collectionId) ?? null
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

  const handleResourceOpen = useCallback(
    async (resource: StorageResource) => {
      if (!storage?.hasRemoteStorage) {
        return
      }
      clearResourcePreview()
      setSelectedResource(resource)
      setResourceLoading(true)
      try {
        const body = await storage.fetchCollectionResource(resource)
        const decrypted = await decryptResourceBody({
          storage,
          collectionId,
          body
        })
        if (
          body.kind === 'json' &&
          isVerifiableCredentialData(decrypted ?? body.data) &&
          collectionId
        ) {
          navigate(
            `/storage/collections/${encodeURIComponent(collectionId)}/resources/${encodeURIComponent(resource.id)}`
          )
          return
        }
        setResourcePayload(body)
        setDecryptedData(decrypted ?? null)
        setResourceView(decrypted !== undefined ? 'decrypted' : 'envelope')
      } catch (err) {
        console.error('Failed to load resource:', err)
        setResourceError(t('storage.resourceLoadError'))
        setResourcePayload(null)
      } finally {
        setResourceLoading(false)
      }
    },
    [clearResourcePreview, collectionId, navigate, storage, t]
  )

  const snippetText = useMemo(() => {
    if (!resourcePayload) {
      return ''
    }
    if (resourcePayload.kind === 'json') {
      const shown =
        decryptedData !== null && resourceView === 'decrypted'
          ? decryptedData
          : resourcePayload.data
      return JSON.stringify(shown, null, 2)
    }
    if (resourcePayload.kind === 'text') {
      return resourcePayload.text
    }
    return ''
  }, [decryptedData, resourcePayload, resourceView])

  const snippetDialogOpen =
    Boolean(selectedResource) &&
    !resourceLoading &&
    !resourceError &&
    Boolean(snippetText)

  const handleCopySnippet = useCallback(async () => {
    if (!snippetText) {
      return
    }
    await copySnippet(snippetText)
  }, [copySnippet, snippetText])

  const handleDownloadResource = useCallback(() => {
    if (!resourcePayload || !collectionId) {
      return
    }
    const base = `${collectionId}-${selectedResource?.id ?? 'file'}`
    let blob: Blob
    let fname: string
    if (resourcePayload.kind === 'binary') {
      blob = resourcePayload.blob
      fname = /\.[a-z0-9]{1,12}$/i.test(base)
        ? base
        : `${base}.${extensionFromMime(resourcePayload.contentType)}`
    } else if (resourcePayload.kind === 'json') {
      blob = new Blob([snippetText], { type: 'application/json' })
      fname = /\.json$/i.test(base) ? base : `${base}.json`
    } else {
      return
    }
    downloadBlob({ blob, filename: fname })
  }, [collectionId, resourcePayload, selectedResource?.id, snippetText])

  const handleDeleteCollection = useCallback(async () => {
    if (!storage?.hasRemoteStorage || !collectionId) {
      return
    }
    setDeleteCollectionError(false)
    setDeletingCollection(true)
    try {
      await storage.deleteCollection({ id: collectionId })
      showToast({ message: t('storage.collectionDeleted') })
      navigate('/storage')
    } catch (err) {
      console.error('Failed to delete collection:', err)
      setDeleteCollectionError(true)
      setDeletingCollection(false)
      return
    } finally {
      setDeletingCollection(false)
      setDeleteDialogOpen(false)
    }
  }, [collectionId, navigate, storage, t])

  const resourcePreviewTitle = selectedResource
    ? getResourceDisplayName(selectedResource)
    : ''

  const folderDisplayName = useMemo(() => {
    if (!collection) {
      return t('storage.collectionContentsTitle')
    }
    return getCollectionDisplayName({ collection, t })
  }, [collection, t])

  const subtitle = useMemo(() => {
    if (!collection) {
      return ''
    }
    return t('storage.collectionContentsDescription', {
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
          <Stack spacing={0.25} sx={{ minWidth: 0, flex: 1 }}>
            <Typography variant="h5" sx={storageStyles.contentsTitle}>
              {folderDisplayName}
            </Typography>
            {subtitle && (
              <Typography
                variant="body2"
                sx={storageStyles.contentsSubtitle}
                component="div"
              >
                {subtitle}
                {collection?.isPublic && (
                  <Box component="span" sx={storageStyles.folderMetaInline}>
                    {' · '}
                    <PublicAccessIcon />
                  </Box>
                )}
                {collection?.isEncrypted && (
                  <Box component="span" sx={storageStyles.folderMetaInline}>
                    {' · '}
                    <EncryptedAccessIcon />
                  </Box>
                )}
              </Typography>
            )}
          </Stack>
          {collection && (
            <Button
              size="small"
              variant="outlined"
              startIcon={<MdDeleteOutline size={18} />}
              onClick={() => setDeleteDialogOpen(true)}
              sx={{
                ...credentialDetailCardStyles.deleteButton,
                flexShrink: 0,
                alignSelf: 'center'
              }}
            >
              {t('storage.deleteCollection')}
            </Button>
          )}
        </Stack>

        <Box sx={storageStyles.contentsBody}>
          {deleteCollectionError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {t('storage.deleteCollectionError')}
            </Alert>
          )}

          {isLoading && (
            <Stack spacing={1.5} aria-busy="true">
              {[0, 1, 2, 3].map(row => (
                <Skeleton key={row} variant="rounded" height={56} />
              ))}
            </Stack>
          )}

          {!isLoading && errorKey && (
            <Alert severity="error">{t(errorKey)}</Alert>
          )}

          {!isLoading && !errorKey && collection && resources.length === 0 && (
            <StorageEmptyState
              icon={<MdFolderOpen />}
              title={t('storage.emptyResourcesTitle')}
              description={t('storage.emptyResourcesDescription')}
            />
          )}

          {!isLoading && !errorKey && resources.length > 0 && collectionId && (
            <ResourceTable
              resources={resources}
              selectedResourceId={selectedResource?.id ?? null}
              onResourceOpen={handleResourceOpen}
            />
          )}

          {selectedResource && resourceLoading && (
            <Typography
              variant="body2"
              sx={{ ...storageStyles.statusText, mt: 2 }}
            >
              {t('storage.loadingResource')}
            </Typography>
          )}

          {selectedResource && resourceError && (
            <Typography
              variant="body2"
              sx={{ ...storageStyles.errorText, mt: 2 }}
            >
              {resourceError}
            </Typography>
          )}

          {resourcePayload?.kind === 'binary' &&
            !resourceLoading &&
            selectedResource && (
              <Paper variant="outlined" sx={{ mt: 3, p: 2, maxWidth: 480 }}>
                <Stack spacing={2}>
                  <Typography variant="h6">
                    {getResourceDisplayName(selectedResource)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {resourcePayload.contentType}
                  </Typography>
                  <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
                    <Button
                      variant="contained"
                      startIcon={<MdDownload />}
                      onClick={handleDownloadResource}
                    >
                      {t('storage.download')}
                    </Button>
                    <Button variant="text" onClick={clearResourcePreview}>
                      {t('storage.backToFiles')}
                    </Button>
                  </Stack>
                </Stack>
              </Paper>
            )}
        </Box>

        <Dialog
          open={snippetDialogOpen}
          onClose={clearResourcePreview}
          fullWidth
          maxWidth="lg"
          scroll="paper"
        >
          <DialogTitle
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              pr: 1,
              py: 1.5
            }}
          >
            <Typography
              variant="subtitle1"
              component="span"
              sx={{
                flex: 1,
                minWidth: 0,
                fontWeight: 600,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap'
              }}
            >
              {resourcePreviewTitle || t('storage.resourceTitle')}
            </Typography>
            {decryptedData !== null && (
              <SourceViewToggle
                value={resourceView}
                onChange={setResourceView}
                sx={{ flexShrink: 0 }}
              />
            )}
            {resourcePayload?.kind === 'json' && (
              <Button
                size="small"
                variant="outlined"
                startIcon={<MdDownload />}
                onClick={handleDownloadResource}
                sx={{ flexShrink: 0 }}
                aria-label={t('storage.download')}
              >
                {t('storage.download')}
              </Button>
            )}
            <Button
              size="small"
              variant="outlined"
              startIcon={<MdContentCopy />}
              onClick={() => {
                void handleCopySnippet()
              }}
              sx={{ flexShrink: 0 }}
              aria-label={t('storage.copySnippet')}
            >
              {snippetCopied ? t('storage.copied') : t('storage.copySnippet')}
            </Button>
            <IconButton
              aria-label={t('common.close')}
              size="small"
              onClick={clearResourcePreview}
              sx={{ flexShrink: 0 }}
            >
              <MdClose />
            </IconButton>
          </DialogTitle>
          <DialogContent dividers sx={{ bgcolor: 'grey.900' }}>
            <JsonHighlight
              code={snippetText}
              sx={credentialDetailStyles.codeBlock}
            />
          </DialogContent>
        </Dialog>

        <Dialog
          open={deleteDialogOpen}
          onClose={() => {
            if (!deletingCollection) {
              setDeleteDialogOpen(false)
            }
          }}
        >
          <DialogTitle>{t('storage.deleteCollectionConfirmTitle')}</DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('storage.deleteCollectionConfirm', {
                name: folderDisplayName,
                count: collection?.totalItems ?? resources.length
              })}
            </DialogContentText>
          </DialogContent>
          <DialogActions sx={{ gap: 1, px: 3, pb: 2 }}>
            <Button
              onClick={() => setDeleteDialogOpen(false)}
              disabled={deletingCollection}
            >
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() => void handleDeleteCollection()}
              color="error"
              variant="contained"
              disabled={deletingCollection}
            >
              {t('storage.deleteCollection')}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </DashboardLayout>
  )
}
