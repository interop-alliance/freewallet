import { useState } from 'react'
import {
  Box,
  Button,
  CircularProgress,
  IconButton,
  Link,
  Stack,
  Tooltip,
  type SxProps
} from '@mui/material'
import {
  MdAddLink,
  MdContentCopy,
  MdDeleteOutline,
  MdLinkOff,
  MdPublic
} from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { credentialDetailCardStyles as sx } from '@/styles/credentialStyles'
import type {
  CredentialDetailActions,
  CredentialShareActions
} from '@/types/credentialActions'

/**
 * The public-link toggle button: "Create public link" when the credential is
 * private, "Remove public link" when it is shared.
 */
function ShareButton({ share }: { share: CredentialShareActions }) {
  const { t } = useTranslation()

  let icon = <MdAddLink size={18} />
  if (share.busy) {
    icon = <CircularProgress size={16} />
  } else if (share.isShared) {
    icon = <MdLinkOff size={18} />
  }

  let label = t('credential.createPublicLink')
  let buttonSx: SxProps = sx.shareButton
  if (share.isShared) {
    label = t('credential.removePublicLink')
    buttonSx = sx.shareActiveButton
  }

  return (
    <Button
      size="small"
      variant="outlined"
      disabled={share.busy}
      onClick={share.toggle}
      startIcon={icon}
      sx={buttonSx}
    >
      {label}
    </Button>
  )
}

/**
 * Action cluster for a credential: the public-link toggle (when sharing is
 * available) followed by the delete button.
 */
export function CredentialActions({
  actions,
  containerSx
}: {
  actions: CredentialDetailActions
  containerSx: object
}) {
  const { t } = useTranslation()
  const { onDelete, share } = actions

  if (!share && !onDelete) {
    return null
  }

  return (
    <Stack direction="row" spacing={1} sx={containerSx}>
      {share && <ShareButton share={share} />}
      {onDelete && (
        <Button
          size="small"
          variant="outlined"
          onClick={onDelete}
          startIcon={<MdDeleteOutline size={18} />}
          sx={sx.deleteButton}
        >
          {t('credential.delete')}
        </Button>
      )}
    </Stack>
  )
}

/**
 * Inline display of a credential's active public link, with a copy button.
 */
export function PublicLinkDisplay({ url }: { url: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(url)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      console.error('Could not copy public link:', err)
    }
  }

  return (
    <Box sx={sx.publicLinkBox}>
      <Box component="span" sx={sx.publicLinkIcon}>
        <MdPublic size={18} />
      </Box>
      <Link
        href={url}
        target="_blank"
        rel="noopener"
        variant="caption"
        sx={sx.publicLinkUrl}
      >
        {url}
      </Link>
      <Tooltip title={copied ? t('credential.linkCopied') : t('common.copy')}>
        <IconButton
          size="small"
          onClick={handleCopy}
          aria-label={t('common.copy')}
        >
          <MdContentCopy size={16} />
        </IconButton>
      </Tooltip>
    </Box>
  )
}
