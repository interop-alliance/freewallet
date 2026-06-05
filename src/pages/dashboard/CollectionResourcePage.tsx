import { useCallback, useEffect, useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { MdArrowBack, MdDeleteOutline, MdDownload } from 'react-icons/md'
import { reset as microlightReset } from 'microlight'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useAuthStore } from '@/stores/authStore'
import { storageStyles } from '@/styles/appStyles'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import type { StorageResource } from '@/lib/storage'
import {
  isVerifiableCredentialData,
  type FetchedCollectionResource
} from '@/lib/storageResource'
import { getResourceDisplayName } from '@/components/storage/displayUtils'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { cidFrom } from '@/lib/cidFrom'

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
  const [isLoading, setIsLoading] = useState(true)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  const [credentialCid, setCredentialCid] = useState<string | null>(null)

  const collectionPath = collectionId
    ? `/storage/collections/${encodeURIComponent(collectionId)}`
    : '/storage'

  useEffect(() => {
    let cancelled = false

    async function load() {
      if (!storage?.remoteStore || !collectionId || !resourceId) {
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

        if (body.kind !== 'json' || !isVerifiableCredentialData(body.data)) {
          setErrorKey('storage.resourceNotVerifiableCredential')
          setPayload(null)
          return
        }

        setPayload(body)
      } catch (e) {
        console.error('Failed to load collection resource:', e)
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

  const vc = useMemo(() => {
    if (payload?.kind !== 'json') {
      return null
    }
    return payload.data as IVerifiableCredential
  }, [payload])

  const [previousVc, setPreviousVc] = useState(vc)
  if (previousVc !== vc) {
    setPreviousVc(vc)
    setCredentialCid(null)
  }

  useEffect(() => {
    if (!vc) {
      return
    }
    let cancelled = false
    void cidFrom({ doc: vc as object })
      .then(cid => {
        if (!cancelled) {
          setCredentialCid(cid)
        }
      })
      .catch((err: unknown) => {
        console.error('Error computing credential CID:', err)
      })
    return () => {
      cancelled = true
    }
  }, [vc])

  const jsonText = useMemo(() => {
    if (payload?.kind !== 'json') {
      return ''
    }
    return JSON.stringify(payload.data, null, 2)
  }, [payload])

  useEffect(() => {
    if (!jsonText) {
      return
    }
    requestAnimationFrame(() => {
      microlightReset()
    })
  }, [jsonText])

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
    if (!jsonText || !resourceId) {
      return
    }
    const blob = new Blob([jsonText], { type: 'application/json' })
    const blobUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = blobUrl
    a.download = `${resourceId}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(blobUrl)
  }, [jsonText, resourceId])

  const handleDelete = useCallback(async () => {
    if (!storage || !resource) {
      return
    }
    try {
      await storage.deleteCollectionResource(resource)
      navigate(collectionPath)
    } catch (e) {
      console.error('Failed to delete resource:', e)
      window.alert(t('storage.deleteResourceError'))
    }
  }, [collectionPath, navigate, resource, storage, t])

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

        {isLoading && (
          <Typography variant="body1" sx={storageStyles.statusText}>
            {t('storage.loadingResource')}
          </Typography>
        )}

        {!isLoading && errorKey && (
          <Typography variant="body1" sx={storageStyles.errorText}>
            {t(errorKey)}
          </Typography>
        )}

        {!isLoading && !errorKey && resource && vc && (
          <>
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

            <Box
              component="pre"
              className="microlight"
              sx={credentialDetailStyles.codeBlock}
            >
              {jsonText}
            </Box>
          </>
        )}
      </Box>
    </DashboardLayout>
  )
}
