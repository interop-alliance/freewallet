import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import IconButton from '@mui/material/IconButton'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import {
  MdArrowBack,
  MdClose,
  MdContentCopy,
  MdDownload,
  MdFolder,
  MdFolderOpen
} from 'react-icons/md'
import { reset as microlightReset } from 'microlight'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import {
  isVerifiableCredentialData,
  type FetchedCollectionResource
} from '@/lib/storageResource'
import { extensionFromMime } from '@/lib/extensionFromMime'
import { ResourceTable } from '@/components/storage/ResourceTable'
import { StorageEmptyState } from '@/components/storage/EmptyState'
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

  const [selectedResource, setSelectedResource] =
    useState<StorageResource | null>(null)
  const [resourcePayload, setResourcePayload] =
    useState<FetchedCollectionResource | null>(null)
  const [resourceLoading, setResourceLoading] = useState(false)
  const [resourceError, setResourceError] = useState<string | null>(null)
  const [snippetCopied, setSnippetCopied] = useState(false)

  const copyResetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearResourcePreview = useCallback(() => {
    setSelectedResource(null)
    setResourcePayload(null)
    setResourceError(null)
    setResourceLoading(false)
    setSnippetCopied(false)
    if (copyResetTimerRef.current) {
      clearTimeout(copyResetTimerRef.current)
      copyResetTimerRef.current = null
    }
  }, [])

  useEffect(() => {
    return () => {
      if (copyResetTimerRef.current) {
        clearTimeout(copyResetTimerRef.current)
      }
    }
  }, [])

  useEffect(() => {
    clearResourcePreview()
  }, [collectionId, clearResourcePreview])

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

  const handleResourceOpen = useCallback(
    async (resource: StorageResource) => {
      if (!storage?.remoteStore) {
        return
      }
      setSelectedResource(resource)
      setResourcePayload(null)
      setResourceError(null)
      setResourceLoading(true)
      setSnippetCopied(false)
      try {
        const body = await storage.fetchCollectionResource(resource)
        if (
          body.kind === 'json' &&
          isVerifiableCredentialData(body.data) &&
          collectionId
        ) {
          navigate(
            `/storage/collections/${encodeURIComponent(collectionId)}/resources/${encodeURIComponent(resource.id)}`
          )
          return
        }
        setResourcePayload(body)
      } catch (e) {
        console.error('Failed to load resource:', e)
        setResourceError(t('storage.resourceLoadError'))
        setResourcePayload(null)
      } finally {
        setResourceLoading(false)
      }
    },
    [collectionId, navigate, storage, t]
  )

  const snippetText = useMemo(() => {
    if (!resourcePayload) {
      return ''
    }
    if (resourcePayload.kind === 'json') {
      return JSON.stringify(resourcePayload.data, null, 2)
    }
    if (resourcePayload.kind === 'text') {
      return resourcePayload.text
    }
    return ''
  }, [resourcePayload])

  const snippetDialogOpen =
    Boolean(selectedResource) &&
    !resourceLoading &&
    !resourceError &&
    Boolean(snippetText)

  useEffect(() => {
    if (!snippetDialogOpen || !snippetText) {
      return
    }
    requestAnimationFrame(() => {
      microlightReset()
    })
  }, [snippetDialogOpen, snippetText])

  useEffect(() => {
    if (!snippetDialogOpen) {
      setSnippetCopied(false)
      if (copyResetTimerRef.current) {
        clearTimeout(copyResetTimerRef.current)
        copyResetTimerRef.current = null
      }
    }
  }, [snippetDialogOpen])

  const handleCopySnippet = useCallback(async () => {
    if (!snippetText) {
      return
    }
    const markCopied = () => {
      setSnippetCopied(true)
      if (copyResetTimerRef.current) {
        clearTimeout(copyResetTimerRef.current)
      }
      copyResetTimerRef.current = setTimeout(() => {
        setSnippetCopied(false)
        copyResetTimerRef.current = null
      }, 2000)
    }
    try {
      await navigator.clipboard.writeText(snippetText)
      markCopied()
      return
    } catch {
      /* fall through */
    }
    try {
      const ta = document.createElement('textarea')
      ta.value = snippetText
      ta.setAttribute('readonly', '')
      ta.style.position = 'fixed'
      ta.style.left = '-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      markCopied()
    } catch (err) {
      console.warn('Copy to clipboard failed:', err)
    }
  }, [snippetText])

  const handleDownloadBinary = useCallback(() => {
    if (
      !resourcePayload ||
      resourcePayload.kind !== 'binary' ||
      !collectionId
    ) {
      return
    }
    const base = `${collectionId}-${selectedResource?.id ?? 'file'}`
    const fname = /\.[a-z0-9]{1,12}$/i.test(base)
      ? base
      : `${base}.${extensionFromMime(resourcePayload.contentType)}`
    const blobUrl = URL.createObjectURL(resourcePayload.blob)
    const a = document.createElement('a')
    a.href = blobUrl
    a.download = fname
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(blobUrl)
  }, [collectionId, resourcePayload, selectedResource?.id])

  const resourcePreviewTitle = selectedResource
    ? getResourceDisplayName(selectedResource)
    : ''

  const folderDisplayName = useMemo(() => {
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
              {folderDisplayName}
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
                      onClick={handleDownloadBinary}
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
            <Button
              size="small"
              variant="outlined"
              startIcon={<MdContentCopy />}
              onClick={() => {
                void handleCopySnippet()
              }}
              sx={{ flexShrink: 0, textTransform: 'none' }}
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
          <DialogContent dividers sx={{ bgcolor: '#0b0f14' }}>
            <Box
              component="pre"
              sx={credentialDetailStyles.codeBlock}
              className="microlight"
            >
              {snippetText}
            </Box>
          </DialogContent>
        </Dialog>
      </Box>
    </DashboardLayout>
  )
}
