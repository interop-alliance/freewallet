import { useState } from 'react'
import {
  Box,
  Button,
  CircularProgress,
  IconButton,
  Link,
  Stack,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
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
 * private, "Remove public link" when it is shared. On small screens only the
 * icon is shown; the label appears from `sm` up.
 */
function ShareButton({ share }: { share: CredentialShareActions }) {
  const { t } = useTranslation()
  const theme = useTheme()
  const compact = useMediaQuery(theme.breakpoints.down('sm'))

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
    <Tooltip title={compact ? label : ''}>
      <Button
        size="small"
        variant="outlined"
        disabled={share.busy}
        onClick={share.toggle}
        startIcon={icon}
        aria-label={label}
        sx={{
          ...buttonSx,
          minWidth: { xs: 36, sm: 'auto' },
          px: { xs: 1, sm: 1.5 },
          '& .MuiButton-startIcon': { mr: { xs: 0, sm: 1 }, ml: { xs: 0, sm: -0.5 } }
        }}
      >
        <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
          {label}
        </Box>
      </Button>
    </Tooltip>
  )
}

/**
 * Action cluster for a credential: on desktop the shared link sits to the
 * left of the buttons; on mobile the buttons are on top and the link below.
 */
export function CredentialActions({
  actions,
  containerSx
}: {
  actions: CredentialDetailActions
  containerSx?: object
}) {
  const { t } = useTranslation()
  const theme = useTheme()
  const compact = useMediaQuery(theme.breakpoints.down('sm'))
  const { onDelete, share } = actions
  const publicLink = share?.publicLink
  const deleteLabel = t('credential.delete')

  if (!share && !onDelete && !publicLink) {
    return null
  }

  return (
    <Stack sx={{ ...sx.actionsCluster, ...containerSx }}>
      {(share || onDelete) && (
        <Stack direction="row" spacing={1} sx={sx.actionButtonsRow}>
          {share && <ShareButton share={share} />}
          {onDelete && (
            <Tooltip title={compact ? deleteLabel : ''}>
              <Button
                size="small"
                variant="outlined"
                onClick={onDelete}
                startIcon={<MdDeleteOutline size={18} />}
                aria-label={deleteLabel}
                sx={{
                  ...sx.deleteButton,
                  minWidth: { xs: 36, sm: 'auto' },
                  px: { xs: 1, sm: 1.5 },
                  '& .MuiButton-startIcon': {
                    mr: { xs: 0, sm: 1 },
                    ml: { xs: 0, sm: -0.5 }
                  }
                }}
              >
                <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                  {deleteLabel}
                </Box>
              </Button>
            </Tooltip>
          )}
        </Stack>
      )}
      {publicLink && <PublicLinkDisplay url={publicLink} />}
    </Stack>
  )
}

function truncateUrl(url: string, maxLength: number): string {
  if (url.length <= maxLength) {
    return url
  }
  return `${url.slice(0, maxLength)}...`
}

/**
 * Compact display of a credential's active public link, with a copy button.
 */
export function PublicLinkDisplay({ url }: { url: string }) {
  const { t } = useTranslation()
  const theme = useTheme()
  const isSmall = useMediaQuery(theme.breakpoints.down('sm'))
  const isMedium = useMediaQuery(theme.breakpoints.down('md'))
  const [copied, setCopied] = useState(false)

  let maxLength = 32
  if (isSmall) {
    maxLength = 16
  } else if (isMedium) {
    maxLength = 24
  }
  const displayUrl = truncateUrl(url, maxLength)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(url)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      console.error('Could not copy public link:', err)
    }
  }

  const copyTooltip = copied ? t('credential.linkCopied') : t('common.copy')

  return (
    <Box sx={{ ...sx.publicLinkBox, ...sx.publicLinkOrder }}>
      <Box component="span" sx={sx.publicLinkIcon}>
        <MdPublic size={16} />
      </Box>
      <Typography
        component="span"
        sx={{ ...sx.publicLinkLabel, display: { xs: 'none', sm: 'inline' } }}
      >
        {t('credential.sharedTo')}
      </Typography>
      <Tooltip title={url}>
        <Link
          href={url}
          target="_blank"
          rel="noopener"
          underline="hover"
          sx={sx.publicLinkUrl}
        >
          {displayUrl}
        </Link>
      </Tooltip>
      <Tooltip title={copyTooltip}>
        <IconButton
          size="small"
          onClick={handleCopy}
          aria-label={t('common.copy')}
          sx={{ p: 0.25, flexShrink: 0 }}
        >
          <MdContentCopy size={15} />
        </IconButton>
      </Tooltip>
    </Box>
  )
}
