/**
 * The access markers shown on a storage metadata/subtitle line (e.g. "Default
 * (WAS) · Public Readable", "... · Encrypted"). Both are the same icon + label
 * pill, differing only in icon, label, and colour.
 */
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { MdLock, MdPublic } from 'react-icons/md'
import type { IconType } from 'react-icons'
import { useTranslation } from 'react-i18next'
import { storageStyles } from '@/styles/appStyles'

/**
 * Renders one access marker.
 *
 * @param options {object}
 * @param options.icon {IconType}   the marker's icon component
 * @param options.label {string}   the marker's text, also its accessible name
 * @param options.color {string}   the MUI palette colour for icon and label
 * @returns {JSX.Element}
 */
function AccessIcon({
  icon: Icon,
  label,
  color
}: {
  icon: IconType
  label: string
  color: string
}) {
  return (
    <Box
      component="span"
      sx={{ ...storageStyles.accessMeta, color }}
      aria-label={label}
    >
      <Box component="span" sx={storageStyles.accessMetaIcon} aria-hidden>
        <Icon size={14} />
      </Box>
      <Typography
        component="span"
        variant="caption"
        sx={storageStyles.accessMetaLabel}
      >
        {label}
      </Typography>
    </Box>
  )
}

/**
 * The "Public Readable" marker.
 *
 * @returns {JSX.Element}
 */
export function PublicAccessIcon() {
  const { t } = useTranslation()

  return (
    <AccessIcon
      icon={MdPublic}
      label={t('storage.publicAccess')}
      color="success.main"
    />
  )
}

/**
 * The "Encrypted" marker.
 *
 * @returns {JSX.Element}
 */
export function EncryptedAccessIcon() {
  const { t } = useTranslation()

  return (
    <AccessIcon
      icon={MdLock}
      label={t('storage.encrypted')}
      color="info.main"
    />
  )
}
