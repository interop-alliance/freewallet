import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { MdPublic } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { storageStyles } from '@/styles/appStyles'

/**
 * Icon + label for use on a metadata/subtitle line (e.g. "Default (WAS) ·
 * Public Readable").
 */
export function PublicAccessIcon() {
  const { t } = useTranslation()
  const label = t('storage.publicAccess')

  return (
    <Box
      component="span"
      sx={storageStyles.publicAccessMeta}
      aria-label={label}
    >
      <Box component="span" sx={storageStyles.publicAccessMetaIcon} aria-hidden>
        <MdPublic size={14} />
      </Box>
      <Typography
        component="span"
        variant="caption"
        sx={storageStyles.publicAccessMetaLabel}
      >
        {label}
      </Typography>
    </Box>
  )
}
