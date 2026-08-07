import { useEffect, useMemo, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useLocation, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { IssuerAvatar } from '@/components/credentialDetails/IssuerAvatar'
import { IssuerInfo } from '@/components/credentialDetails/IssuerInfo'
import { useAuthStore } from '@/stores/authStore'
import { useVerification } from '@/hooks/useVerification'
import { getIssuerDetails } from '@/lib/viewMappers/issuerName'
import {
  isRecognizedIssuer,
  type IssuerRegistryInfo,
  type MatchingIssuerEntry
} from '@/lib/viewMappers/issuerRegistryInfo'
import { issuerDetailStyles as sx } from '@/styles/credentialStyles'
import { NotFoundPage } from '@/pages/NotFoundPage'
import type { IVerifiableCredential } from '@interop/data-integrity-core'

function imageUriFrom(img?: string | { id?: string }): string | undefined {
  if (!img) {
    return undefined
  }
  if (typeof img === 'string') {
    return img
  }
  return typeof img.id === 'string' ? img.id : undefined
}

function IssuerLink({
  url,
  label,
  disabled
}: {
  url?: string
  label?: string
  disabled: boolean
}) {
  const { t } = useTranslation()
  if (!url) {
    return (
      <Typography variant="body2" color="text.secondary">
        {t('issuer.none')}
      </Typography>
    )
  }
  if (disabled) {
    return (
      <Typography variant="body2" color="text.disabled">
        {label || url}
      </Typography>
    )
  }
  return (
    <Link href={url} target="_blank" rel="noopener" variant="body2">
      {label || url}
    </Link>
  )
}

function RegistryIssuerBlock({
  entry,
  urlsDisabled,
  fallbackImage
}: {
  entry: MatchingIssuerEntry
  urlsDisabled: boolean
  fallbackImage?: string
}) {
  const { t } = useTranslation()
  const registryName =
    entry.registry?.federation_entity?.organization_name ??
    t('issuer.unknownRegistry')
  const governanceUrl = entry.registry?.federation_entity?.policy_uri
  const legalName = entry.issuer?.institution_additional_information?.legal_name
  const issuerEntity = entry.issuer?.federation_entity ?? {}
  const issuerImageUri =
    imageUriFrom(issuerEntity.logo_uri) || fallbackImage || undefined

  return (
    <Box sx={sx.registryBlock}>
      <Typography variant="subtitle2" sx={sx.registryTitle}>
        {registryName}
        {governanceUrl && (
          <>
            {' '}
            {urlsDisabled ? (
              <Typography
                component="span"
                variant="body2"
                color="text.disabled"
              >
                ({t('issuer.governanceInfo')})
              </Typography>
            ) : (
              <Link
                href={governanceUrl}
                target="_blank"
                rel="noopener"
                variant="body2"
              >
                ({t('issuer.governanceInfo')})
              </Link>
            )}
          </>
        )}
      </Typography>

      <IssuerAvatar
        src={issuerImageUri}
        alt={issuerEntity.organization_name || t('issuer.unknown')}
        sx={sx.registryAvatar}
      />

      <Stack spacing={1.5}>
        <Box>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={sx.fieldLabel}
          >
            {t('issuer.name')}
          </Typography>
          <Typography variant="body2">
            {issuerEntity.organization_name || t('common.na')}
          </Typography>
        </Box>

        {legalName && (
          <Box>
            <Typography
              variant="caption"
              color="text.secondary"
              sx={sx.fieldLabel}
            >
              {t('issuer.legalName')}
            </Typography>
            <Typography variant="body2">{legalName}</Typography>
          </Box>
        )}

        <Box>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={sx.fieldLabel}
          >
            {t('issuer.url')}
          </Typography>
          <IssuerLink url={issuerEntity.homepage_uri} disabled={urlsDisabled} />
        </Box>

        {entry.issuer?.credential_registry_entity?.ce_url && (
          <Box>
            <Typography
              variant="caption"
              color="text.secondary"
              sx={sx.fieldLabel}
            >
              {t('issuer.ctidUrl')}
            </Typography>
            <IssuerLink
              url={entry.issuer.credential_registry_entity.ce_url}
              disabled={urlsDisabled}
            />
          </Box>
        )}
      </Stack>
    </Box>
  )
}

export function IssuerDetailPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const { cid } = useParams()
  const location = useLocation()
  const locationState = location.state as {
    issuerRegistry?: IssuerRegistryInfo | null
  } | null
  const cachedRegistry =
    locationState && 'issuerRegistry' in locationState
      ? (locationState.issuerRegistry ?? null)
      : undefined
  const skipVerify = cachedRegistry !== undefined
  const [vc, setVc] = useState<IVerifiableCredential | null>(null)
  const [isNotFound, setIsNotFound] = useState(false)
  const [loadError, setLoadError] = useState(false)
  const verification = useVerification(vc, { runOnMount: !skipVerify })
  const issuerRegistry = skipVerify
    ? cachedRegistry
    : verification.issuerRegistry
  const registryLoading = skipVerify ? false : verification.loading
  const urlsDisabled = !isRecognizedIssuer(issuerRegistry)
  const matchingIssuers = issuerRegistry?.matchingIssuers ?? []
  const credentialIssuerImage = vc ? getIssuerDetails(vc.issuer).image : ''
  const issuerName = useMemo(() => {
    if (!vc) {
      return t('issuer.detailTitle')
    }
    return getIssuerDetails(vc.issuer).name || t('issuer.detailTitle')
  }, [vc, t])

  useEffect(() => {
    if (!session || !cid) {
      return
    }
    session.storage
      ?.loadCredential({ cid })
      .then(credential => {
        if (!credential) {
          setIsNotFound(true)
          setVc(null)
          return
        }
        setIsNotFound(false)
        setLoadError(false)
        setVc(credential)
      })
      .catch((err: unknown) => {
        console.error('Error loading credential:', err)
        setLoadError(true)
      })
  }, [cid, session])

  if (!cid || isNotFound) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout title={issuerName}>
      <Box sx={sx.wrapper}>
        {loadError ? (
          <Alert severity="error">{t('credential.loadError')}</Alert>
        ) : !vc ? (
          <LoadingSpinner />
        ) : (
          <Stack spacing={2}>
            {urlsDisabled && !registryLoading && (
              <Alert severity="warning">
                {t('issuer.linksDisabledWarning')}
              </Alert>
            )}

            {matchingIssuers.length > 0 ? (
              matchingIssuers.map((entry, index) => (
                <RegistryIssuerBlock
                  key={index}
                  entry={entry}
                  urlsDisabled={urlsDisabled}
                  fallbackImage={credentialIssuerImage || undefined}
                />
              ))
            ) : (
              <IssuerInfo
                issuer={vc.issuer}
                issuerRegistry={issuerRegistry}
                registryLoading={registryLoading}
                urlsDisabled={urlsDisabled}
              />
            )}
          </Stack>
        )}
      </Box>
    </DashboardLayout>
  )
}
