import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import {
  MdArrowBack,
  MdContentCopy,
  MdDeleteOutline,
  MdDownload
} from 'react-icons/md'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { JsonHighlight } from '@/components/JsonHighlight'
import { DeleteCredentialDialog } from '@/components/credentialDetails/DeleteCredentialDialog'
import { useCredentialDelete } from '@/hooks/useCredentialDelete'
import { useAsyncLoad } from '@/hooks/useAsyncLoad'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import type { StorageResource } from '@/lib/storage'
import {
  isVerifiableCredentialData,
  type FetchedCollectionResource
} from '@/lib/storageResource'
import { getResourceDisplayName } from '@/components/storage/displayUtils'
import { PublicAccessIcon } from '@/components/storage/AccessIcon'
import { SourceViewToggle } from '@/components/storage/SourceViewToggle'
import { MetadataCard } from '@/components/storage/MetadataCard'
import {
  decryptResourceBody,
  useResourceSourceCopy
} from '@/components/storage/useResourceSource'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { cidFrom } from '@interop/was-client/sync'
import { downloadBlob } from '@/lib/downloadBlob'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:storage')

// The Resource Metadata members this card labels, in display order; anything
// else the server sends follows them under its own key.
const RESOURCE_META_FIELDS = [
  'contentType',
  'size',
  'createdAt',
  'updatedAt',
  'createdBy',
  'epoch',
  'etag'
]

/**
 * The resource preview shell shared by this page's two branches (a Verifiable
 * Credential body and any other JSON/text body): the resource id heading, the
 * titled card with its public marker and action buttons, and the source view
 * beneath it. The branches differ only in the description line and in which
 * actions they offer.
 *
 * @param options {object}
 * @param options.resourceId {string}
 * @param options.title {string}   the display title inside the card
 * @param options.isPublic {boolean}   whether to show the public-access marker
 * @param [options.description] {string}
 * @param options.actions {ReactNode}   the card's action buttons
 * @param options.metadata {ReactNode}   the lazy metadata card
 * @param options.sourceToggle {ReactNode}   the decrypted/envelope switch
 * @param options.sourceText {string}   the code block's contents
 * @returns {JSX.Element}
 */
function ResourcePreview({
  resourceId,
  title,
  isPublic,
  description,
  actions,
  metadata,
  sourceToggle,
  sourceText
}: {
  resourceId: string
  title: string
  isPublic: boolean
  description?: string
  actions: ReactNode
  metadata: ReactNode
  sourceToggle: ReactNode
  sourceText: string
}) {
  return (
    <>
      <Typography
        variant="h5"
        component="h2"
        sx={storageStyles.resourceDetailId}
      >
        {resourceId}
      </Typography>

      <Paper variant="outlined" sx={storageStyles.vcPreviewCard}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={2}
          sx={storageStyles.vcPreviewCardInner}
        >
          <Box sx={storageStyles.vcPreviewMain}>
            <Typography variant="h6" sx={storageStyles.vcPreviewTitle}>
              {title}
            </Typography>
            {isPublic && (
              <Box sx={storageStyles.vcPreviewPublicMeta}>
                <PublicAccessIcon />
              </Box>
            )}
            {description ? (
              <Typography
                variant="body2"
                color="text.secondary"
                sx={storageStyles.vcPreviewDescription}
              >
                {description}
              </Typography>
            ) : null}
          </Box>

          <Stack
            direction="row"
            spacing={1}
            sx={storageStyles.vcPreviewActions}
          >
            {actions}
          </Stack>
        </Stack>
      </Paper>

      {metadata}

      {sourceToggle}
      <JsonHighlight code={sourceText} sx={credentialDetailStyles.codeBlock} />
    </>
  )
}

export function CollectionResourcePage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { collectionId: rawCollectionId, resourceId: rawResourceId } =
    useParams<{
      collectionId: string
      resourceId: string
    }>()
  const collectionId = rawCollectionId
    ? decodeURIComponent(rawCollectionId)
    : undefined
  const resourceId = rawResourceId
    ? decodeURIComponent(rawResourceId)
    : undefined

  const session = useAuthStore(state => state.session)
  const storage = session?.storage

  // Which source view the code block shows. The stored EDV envelope source
  // that backs the alternate view (null for plaintext resources) comes off the
  // load below.
  const [sourceView, setSourceView] = useState<'decrypted' | 'envelope'>(
    'decrypted'
  )

  const { copied, copy, reset: resetCopied } = useResourceSourceCopy()

  const resourceAvailable = Boolean(
    storage?.hasRemoteStorage && collectionId && resourceId
  )

  // One load resolves the matched resource, its viewable body, the stored EDV
  // envelope source behind that body when the resource is encrypted, and the
  // failure copy's i18n key when the resource cannot be shown. A run that was
  // superseded resolves null, and its result is dropped.
  const {
    data: loaded,
    loading: isLoading,
    error: loadError
  } = useAsyncLoad(
    async ({
      isCancelled
    }): Promise<{
      resource: StorageResource | null
      payload: FetchedCollectionResource | null
      envelopeText: string | null
      errorKey: string | null
    } | null> => {
      if (!storage?.hasRemoteStorage || !collectionId || !resourceId) {
        return null
      }

      resetCopied()

      const collections = await storage.listCollections()
      if (isCancelled()) {
        return null
      }

      const matchCollection =
        collections.find(collection => collection.id === collectionId) ?? null

      if (!matchCollection) {
        return {
          resource: null,
          payload: null,
          envelopeText: null,
          errorKey: 'storage.collectionNotFound'
        }
      }

      const items = await storage.listCollectionResources({
        collectionUrl: matchCollection.url
      })
      if (isCancelled()) {
        return null
      }

      const matchResource = items.find(item => item.id === resourceId) ?? null

      if (!matchResource) {
        return {
          resource: null,
          payload: null,
          envelopeText: null,
          errorKey: 'storage.resourceNotFound'
        }
      }

      const body = await storage.fetchCollectionResource(matchResource)
      if (isCancelled()) {
        return null
      }

      // The envelope source is kept around for the alternate view.
      const decrypted = await decryptResourceBody({
        storage,
        collectionId,
        body
      })
      if (isCancelled()) {
        return null
      }

      if (body.kind === 'json') {
        const data = decrypted ?? body.data
        setSourceView('decrypted')
        return {
          resource: matchResource,
          payload: { kind: 'json', data },
          envelopeText:
            decrypted !== undefined ? JSON.stringify(body.data, null, 2) : null,
          errorKey: null
        }
      }
      if (body.kind === 'text') {
        return {
          resource: matchResource,
          payload: { kind: 'text', text: body.text },
          envelopeText: null,
          errorKey: null
        }
      }
      // A binary body has no inline JSON/text rendering here.
      return {
        resource: matchResource,
        payload: null,
        envelopeText: null,
        errorKey: 'storage.resourceNotViewable'
      }
    },
    [storage, collectionId, resourceId, resetCopied],
    {
      enabled: resourceAvailable,
      onError: err => {
        log.error('Failed to load collection resource', { err })
      }
    }
  )

  const resource = loaded?.resource ?? null
  const payload = loaded?.payload ?? null
  const envelopeText = loaded?.envelopeText ?? null
  const errorKey = !resourceAvailable
    ? 'storage.resourceNotFound'
    : loadError
      ? 'storage.resourceLoadError'
      : (loaded?.errorKey ?? null)

  // A Verifiable Credential body renders the rich credential card; any other
  // JSON (or text) body renders the generic viewer. `vc` is null in the latter
  // case, which drives the branch.
  const vc = useMemo<IVerifiableCredential | null>(() => {
    if (payload?.kind !== 'json' || !isVerifiableCredentialData(payload.data)) {
      return null
    }
    return payload.data as IVerifiableCredential
  }, [payload])

  // The content-addressed cid is a pure, synchronous hash of the decrypted VC,
  // so it derives straight from `vc` rather than living in state behind an
  // effect.
  const credentialCid = useMemo<string | null>(() => {
    if (!vc) {
      return null
    }
    try {
      return cidFrom({ doc: vc as object })
    } catch (err: unknown) {
      log.error('Error computing credential CID', { err })
      return null
    }
  }, [vc])

  const collectionPath = collectionId
    ? `/storage/collections/${encodeURIComponent(collectionId)}`
    : '/storage'

  const {
    deleteError,
    deleteDialogOpen,
    deleting,
    requestDelete,
    runDelete,
    cancelDelete
  } = useCredentialDelete({
    session: session ?? null,
    cid: credentialCid ?? undefined,
    title: vc ? credentialTitle(vc) : undefined,
    onSuccess: () => navigate(collectionPath)
  })

  const jsonText = useMemo(() => {
    if (payload?.kind === 'json') {
      return JSON.stringify(payload.data, null, 2)
    }
    if (payload?.kind === 'text') {
      return payload.text
    }
    return ''
  }, [payload])

  const shownSourceText =
    sourceView === 'envelope' && envelopeText !== null ? envelopeText : jsonText

  const displayTitle = useMemo(() => {
    if (vc) {
      return credentialTitle(vc)
    }
    if (resource) {
      return getResourceDisplayName(resource)
    }
    return ''
  }, [resource, vc])

  const description = useMemo(() => {
    if (!vc) {
      return ''
    }
    return getDisplayFields(vc).credentialDescription ?? ''
  }, [vc])

  const handleDownload = useCallback(() => {
    if (!shownSourceText || !resourceId) {
      return
    }
    const blob = new Blob([shownSourceText], { type: 'application/json' })
    downloadBlob({ blob, filename: `${resourceId}.json` })
  }, [shownSourceText, resourceId])

  const handleCopy = useCallback(async () => {
    if (!shownSourceText) {
      return
    }
    await copy(shownSourceText)
  }, [copy, shownSourceText])

  const handleDelete = useCallback(async () => {
    if (!credentialCid) {
      return
    }
    await requestDelete()
  }, [credentialCid, requestDelete])

  const credentialDetailHref = credentialCid
    ? `/credential/${encodeURIComponent(credentialCid)}`
    : null

  const resourceUrl = resource?.url ?? null
  const fetchResourceMeta = useCallback(async () => {
    if (!storage || !resourceUrl || !collectionId) {
      return { meta: null, encrypted: false }
    }
    const [meta, encrypted] = await Promise.all([
      storage.fetchResourceMeta({ url: resourceUrl }),
      storage.isCollectionEncrypted({ collectionId })
    ])
    return { meta, encrypted }
  }, [storage, resourceUrl, collectionId])

  const metadata = resourceUrl ? (
    <MetadataCard
      key={resourceUrl}
      fetchMeta={fetchResourceMeta}
      fieldOrder={RESOURCE_META_FIELDS}
    />
  ) : null

  const sourceToggle = envelopeText !== null && (
    <SourceViewToggle
      value={sourceView}
      onChange={setSourceView}
      sx={{ mb: 1 }}
    />
  )

  return (
    <DashboardLayout title={t('storage.title')}>
      <Box sx={storageStyles.resourceDetailWrap}>
        <Button
          component={RouterLink}
          to={collectionPath}
          startIcon={<MdArrowBack />}
          sx={storageStyles.backToStorageButton}
          variant="text"
        >
          {t('storage.backToCollection')}
        </Button>

        {isLoading && <LoadingSpinner />}

        {!isLoading && errorKey && (
          <Alert severity="error">{t(errorKey)}</Alert>
        )}

        {!isLoading && !errorKey && resource && vc && (
          <>
            {deleteError && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {deleteError}
              </Alert>
            )}

            <ResourcePreview
              resourceId={resource.id}
              title={displayTitle}
              isPublic={!!resource.isPublic}
              description={description}
              metadata={metadata}
              sourceToggle={sourceToggle}
              sourceText={shownSourceText}
              actions={
                <>
                  {credentialDetailHref ? (
                    <Button
                      variant="outlined"
                      component={RouterLink}
                      to={credentialDetailHref}
                      sx={storageStyles.vcPreviewActionButton}
                    >
                      {t('storage.viewDetails')}
                    </Button>
                  ) : null}
                  <Button
                    variant="contained"
                    startIcon={<MdDownload />}
                    onClick={handleDownload}
                    sx={storageStyles.vcPreviewActionButton}
                  >
                    {t('storage.download')}
                  </Button>
                  <Button
                    variant="outlined"
                    color="error"
                    startIcon={<MdDeleteOutline />}
                    onClick={() => {
                      void handleDelete()
                    }}
                    sx={storageStyles.vcPreviewActionButton}
                  >
                    {t('storage.deleteResource')}
                  </Button>
                </>
              }
            />
          </>
        )}

        {!isLoading && !errorKey && resource && !vc && payload && (
          <ResourcePreview
            resourceId={resource.id}
            title={displayTitle}
            isPublic={!!resource.isPublic}
            metadata={metadata}
            sourceToggle={sourceToggle}
            sourceText={shownSourceText}
            actions={
              <>
                <Button
                  variant="outlined"
                  startIcon={<MdContentCopy />}
                  onClick={() => {
                    void handleCopy()
                  }}
                  sx={storageStyles.vcPreviewActionButton}
                >
                  {copied ? t('storage.copied') : t('storage.copySnippet')}
                </Button>
                <Button
                  variant="contained"
                  startIcon={<MdDownload />}
                  onClick={handleDownload}
                  sx={storageStyles.vcPreviewActionButton}
                >
                  {t('storage.download')}
                </Button>
              </>
            }
          />
        )}
      </Box>

      <DeleteCredentialDialog
        open={deleteDialogOpen}
        busy={deleting}
        onKeepPublic={() => void runDelete({ alsoRemovePublic: false })}
        onDeleteAll={() => void runDelete({ alsoRemovePublic: true })}
        onCancel={cancelDelete}
      />
    </DashboardLayout>
  )
}
