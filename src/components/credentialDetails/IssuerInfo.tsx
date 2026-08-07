import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Link from '@mui/material/Link'
import Button from '@mui/material/Button'
import { Link as RouterLink } from 'react-router'
import { IssuerAvatar } from '@/components/credentialDetails/IssuerAvatar'
import { getIssuerDetails } from '@/lib/viewMappers/issuerName'
import {
  getRegistryNames,
  isRecognizedIssuer,
  type IssuerRegistryInfo
} from '@/lib/viewMappers/issuerRegistryInfo'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { issuerInfoStyles as sx } from '@/styles/credentialStyles'
import { useTranslation } from 'react-i18next'

export function IssuerInfo({
  issuer,
  cid,
  issuerRegistry = null,
  registryLoading = false,
  urlsDisabled = false
}: {
  issuer: IVerifiableCredential['issuer']
  cid?: string
  issuerRegistry?: IssuerRegistryInfo | null
  registryLoading?: boolean
  urlsDisabled?: boolean
}) {
  const { t } = useTranslation()
  const details = getIssuerDetails(issuer)
  const hasName = !!details.name
  const recognized = isRecognizedIssuer(issuerRegistry)
  const registryCount = getRegistryNames(
    issuerRegistry?.matchingIssuers ?? []
  ).length

  return (
    <Box>
      <Typography variant="overline" sx={sx.header}>
        {t('common.issuer')}
      </Typography>
      <Box sx={sx.row}>
        <IssuerAvatar
          src={details.image || undefined}
          alt={details.name || t('issuer.unknown')}
          sx={sx.avatar}
        />

        <Box sx={sx.infoWrapper}>
          {hasName && (
            <Typography variant="body2" sx={sx.name}>
              {details.name}
            </Typography>
          )}

          {details.url &&
            (urlsDisabled ? (
              <Typography
                variant="caption"
                color="text.disabled"
                sx={sx.urlLink}
              >
                {details.url}
              </Typography>
            ) : (
              <Link
                href={details.url}
                target="_blank"
                rel="noopener"
                variant="caption"
                sx={sx.urlLink}
              >
                {details.url}
              </Link>
            ))}

          <Typography
            variant="caption"
            color="text.secondary"
            sx={sx.registryStatus}
          >
            {registryLoading
              ? t('common.verifying')
              : recognized
                ? t('issuer.foundInRegistries', { count: registryCount })
                : t('issuer.unrecognized')}
          </Typography>

          {cid && details.id && (
            <Button
              component={RouterLink}
              to={`/credential/${cid}/issuer`}
              state={{ issuerRegistry }}
              size="small"
              variant="outlined"
              sx={sx.detailButton}
            >
              {t('issuer.viewDetail')}
            </Button>
          )}
        </Box>
      </Box>
    </Box>
  )
}
