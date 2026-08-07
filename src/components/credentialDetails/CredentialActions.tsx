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
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { credentialDetailCardStyles as sx } from '@/styles/credentialStyles'
import type {
  CredentialDetailActions,
  CredentialShareActions
} from '@/types/credentialActions'

/**
 * One credential action button: icon-only below `sm` (the label moving into a
 * tooltip), icon plus label from `sm` up. Both the public-link toggle and the
 * delete action render through this so their responsive treatment stays
 * identical.
 *
 * @param options {object}
 * @param options.label {string}   the button's label and accessible name
 * @param options.icon {ReactNode}   the start icon
 * @param options.buttonSx {SxProps}   the action's own styling
 * @param options.onClick {Function}
 * @param [options.disabled] {boolean}
 * @returns {JSX.Element}
 */
function ActionButton({
  label,
  icon,
  buttonSx,
  onClick,
  disabled
}: {
  label: string
  icon: ReactNode
  buttonSx: SxProps
  onClick?: () => void
  disabled?: boolean
}) {
  const theme = useTheme()
  const compact = useMediaQuery(theme.breakpoints.down('sm'))

  return (
    <Tooltip title={compact ? label : ''}>
      <Button
        size="small"
        variant="outlined"
        disabled={disabled}
        onClick={onClick}
        startIcon={icon}
        aria-label={label}
        sx={{
          ...buttonSx,
          minWidth: { xs: 36, sm: 'auto' },
          px: { xs: 1, sm: 1.5 },
          '& .MuiButton-startIcon': {
            mr: { xs: 0, sm: 1 },
            ml: { xs: 0, sm: -0.5 }
          }
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
 * The public-link toggle button: "Create public link" when the credential is
 * private, "Remove public link" when it is shared. On small screens only the
 * icon is shown; the label appears from `sm` up.
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
    <ActionButton
      label={label}
      icon={icon}
      buttonSx={buttonSx}
      onClick={share.toggle}
      disabled={share.busy}
    />
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
            <ActionButton
              label={deleteLabel}
              icon={<MdDeleteOutline size={18} />}
              buttonSx={sx.deleteButton}
              onClick={onDelete}
            />
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
function PublicLinkDisplay({ url }: { url: string }) {
  const { t } = useTranslation()
  const theme = useTheme()
  const isSmall = useMediaQuery(theme.breakpoints.down('sm'))
  const isMedium = useMediaQuery(theme.breakpoints.down('md'))
  const { copied, copy } = useCopyToClipboard({
    onError: (err: unknown) => {
      console.error('Could not copy public link:', err)
    }
  })

  let maxLength = 32
  if (isSmall) {
    maxLength = 16
  } else if (isMedium) {
    maxLength = 24
  }
  const displayUrl = truncateUrl(url, maxLength)

  async function handleCopy() {
    await copy(url)
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
