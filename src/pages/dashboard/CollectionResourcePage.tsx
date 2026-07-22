import { useCallback, useEffect, useMemo, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import ToggleButton from '@mui/material/ToggleButton'
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdArrowBack, MdDeleteOutline, MdDownload } from 'react-icons/md'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { JsonHighlight } from '@/components/JsonHighlight'
import { DeleteCredentialDialog } from '@/components/credentialDetails/DeleteCredentialDialog'
import { useCredentialDelete } from '@/hooks/useCredentialDelete'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import type { StorageResource } from '@/lib/storage'
import type { Json } from '@/lib/sync'
import {
  isVerifiableCredentialData,
  type FetchedCollectionResource
} from '@/lib/storageResource'
import { getResourceDisplayName } from '@/components/storage/displayUtils'
import { PublicAccessIcon } from '@/components/storage/PublicAccessIcon'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { cidFrom } from '@interop/was-client/sync'
import { downloadBlob } from '@/lib/downloadBlob'

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

  const [resource, setResource] = useState<StorageResource | null>(null)
  const [payload, setPayload] = useState<FetchedCollectionResource | null>(null)
  // The stored EDV envelope source when this resource is encrypted (null for
  // plaintext resources), and which source view the code block shows.
  const [envelopeText, setEnvelopeText] = useState<string | null>(null)
  const [sourceView, setSourceView] = useState<'decrypted' | 'envelope'>(
    'decrypted'
  )
  const [isLoading, setIsLoading] = useState(true)
  const [errorKey, setErrorKey] = useState<string | null>(null)

  const vc = useMemo(() => {
    if (payload?.kind !== 'json') {
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
      console.error('Error computing credential CID:', err)
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
    onSuccess: () => navigate(collectionPath)
  })

  useEffect(() => {
    let cancelled = false

    async function load() {
      if (!storage?.hasRemoteStorage || !collectionId || !resourceId) {
        setErrorKey('storage.resourceNotFound')
        setIsLoading(false)
        return
      }

      setIsLoading(true)
      setErrorKey(null)

      try {
        const collections = await storage.listCollections()
        if (cancelled) {
          return
        }

        const matchCollection =
          collections.find(c => c.id === collectionId) ?? null

        if (!matchCollection) {
          setErrorKey('storage.collectionNotFound')
          return
        }

        const items = await storage.listCollectionResources({
          collectionUrl: matchCollection.url
        })
        if (cancelled) {
          return
        }

        const matchResource = items.find(r => r.id === resourceId) ?? null
        setResource(matchResource)

        if (!matchResource) {
          setErrorKey('storage.resourceNotFound')
          return
        }

        const body = await storage.fetchCollectionResource(matchResource)
        if (cancelled) {
          return
        }

        // An encrypted-collection resource arrives as an EDV envelope; with
        // an unlocked vault, recover the credential behind it and keep the
        // envelope source around for the alternate view.
        const decrypted =
          body.kind === 'json'
            ? await storage.decryptCollectionResource({
                collectionId,
                data: body.data as Json
              })
            : undefined
        if (cancelled) {
          return
        }
        const data = decrypted ?? (body.kind === 'json' ? body.data : null)

        if (body.kind !== 'json' || !isVerifiableCredentialData(data)) {
          setErrorKey('storage.resourceNotVerifiableCredential')
          setPayload(null)
          setEnvelopeText(null)
          return
        }

        setPayload({ kind: 'json', data })
        setEnvelopeText(
          decrypted !== undefined ? JSON.stringify(body.data, null, 2) : null
        )
        setSourceView('decrypted')
      } catch (err) {
        console.error('Failed to load collection resource:', err)
        if (!cancelled) {
          setErrorKey('storage.resourceLoadError')
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [storage, collectionId, resourceId])

  const jsonText = useMemo(() => {
    if (payload?.kind !== 'json') {
      return ''
    }
    return JSON.stringify(payload.data, null, 2)
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

  const handleDelete = useCallback(async () => {
    if (!credentialCid) {
      return
    }
    await requestDelete()
  }, [credentialCid, requestDelete])

  const credentialDetailHref = credentialCid
    ? `/credential/${encodeURIComponent(credentialCid)}`
    : null

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
                {t('credential.deleteError')}
              </Alert>
            )}

            <Typography
              variant="h5"
              component="h2"
              sx={storageStyles.resourceDetailId}
            >
              {resource.id}
            </Typography>

            <Paper variant="outlined" sx={storageStyles.vcPreviewCard}>
              <Stack
                direction={{ xs: 'column', sm: 'row' }}
                spacing={2}
                sx={storageStyles.vcPreviewCardInner}
              >
                <Box sx={storageStyles.vcPreviewMain}>
                  <Typography variant="h6" sx={storageStyles.vcPreviewTitle}>
                    {displayTitle}
                  </Typography>
                  {resource.isPublic && (
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
                </Stack>
              </Stack>
            </Paper>

            {envelopeText !== null && (
              <ToggleButtonGroup
                size="small"
                exclusive
                value={sourceView}
                onChange={(_event, view: 'decrypted' | 'envelope' | null) => {
                  if (view) {
                    setSourceView(view)
                  }
                }}
                sx={{ mb: 1 }}
              >
                <ToggleButton value="decrypted">
                  {t('storage.viewDecrypted')}
                </ToggleButton>
                <ToggleButton value="envelope">
                  {t('storage.viewEnvelope')}
                </ToggleButton>
              </ToggleButtonGroup>
            )}
            <JsonHighlight
              code={shownSourceText}
              sx={credentialDetailStyles.codeBlock}
            />
          </>
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
