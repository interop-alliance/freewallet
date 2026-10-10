import Button from '@mui/material/Button'
import type { SxProps, Theme } from '@mui/material/styles'
import { useTranslation } from 'react-i18next'
import type { useDeadPointerRemoval } from '@/hooks/useDeadPointerRemoval'

/**
 * The dead-pointer prompt's accept button: removes this credential's
 * sign-in data (its unlock Space, root-invoked under its own unlock
 * identity, and its unlock-local state) through the refusal's own closure,
 * then hands the outcome to the page. Renders nothing while no offer
 * stands.
 */
export function RemoveSignInDataButton({
  removal,
  onRemoved,
  sx
}: {
  removal: ReturnType<typeof useDeadPointerRemoval>
  onRemoved: (outcome: { unlockSpaceDeleted: boolean } | null) => void
  sx?: SxProps<Theme>
}) {
  const { t } = useTranslation()
  if (!removal.deadPointer) {
    return null
  }
  return (
    <Button
      variant="outlined"
      color="error"
      onClick={() => void removal.remove().then(onRemoved)}
      loading={removal.busy}
      sx={sx}
      data-testid="remove-sign-in-data-button"
    >
      {t('auth.accountGone.button')}
    </Button>
  )
}
