import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { MdLock } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { storageStyles } from '@/styles/appStyles'

/** Icon + label for use on a metadata/subtitle line (e.g. "Default (WAS) · Encrypted"). */
export function EncryptedAccessIcon() {
  const { t } = useTranslation()
  const label = t('storage.encrypted')

  return (
    <Box
      component="span"
      sx={storageStyles.encryptedAccessMeta}
      aria-label={label}
    >
      <Box
        component="span"
        sx={storageStyles.encryptedAccessMetaIcon}
        aria-hidden
      >
        <MdLock size={14} />
      </Box>
      <Typography
        component="span"
        variant="caption"
        sx={storageStyles.encryptedAccessMetaLabel}
      >
        {label}
      </Typography>
    </Box>
  )
}
