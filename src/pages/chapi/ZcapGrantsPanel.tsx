/**
 * The "Storage access" section of the CHAPI login consent screen: one row per
 * requested capability, showing the relying party's reason, a human-readable
 * target, the actions to be granted, and the expiry. Encrypted standard
 * collections get a ciphertext note; whole-Space grants get a warning banner
 * and an explicit read-only label; unsatisfiable grants render greyed with a
 * "cannot fulfill" note. Display-only -- approval is the single Continue button
 * on the parent page.
 */
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import type { ResolvedGrant } from '@/lib/walletRequest'

/**
 * A human-readable label for a resolved grant's target.
 */
function targetLabel(
  grant: ResolvedGrant,
  t: (key: string, opts?: Record<string, unknown>) => string
): string {
  const { target } = grant
  if (target.wholeSpace) {
    return t('chapi.get.zcapTarget.space')
  }
  if (target.collectionId) {
    return t('chapi.get.zcapTarget.collection', { name: target.collectionId })
  }
  if (target.invocationTarget) {
    try {
      return new URL(target.invocationTarget).pathname
    } catch {
      return target.invocationTarget
    }
  }
  return ''
}

export function ZcapGrantsPanel({
  grants,
  ttlDays
}: {
  grants: ResolvedGrant[]
  ttlDays: number
}) {
  const { t } = useTranslation()

  return (
    <Stack spacing={1}>
      <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
        {t('chapi.get.zcapHeading')}
      </Typography>
      {grants.map((grant, index) => {
        const { target, allowedActions, descriptor } = grant
        const satisfiable = target.satisfiable
        return (
          <Box
            key={descriptor.referenceId ?? index}
            sx={{
              p: 1.5,
              border: 1,
              borderColor: target.wholeSpace ? 'warning.main' : 'divider',
              borderRadius: 2,
              opacity: satisfiable ? 1 : 0.6
            }}
          >
            {descriptor.reason && (
              <Typography variant="body2" sx={{ mb: 0.5 }}>
                {descriptor.reason}
              </Typography>
            )}

            {satisfiable ? (
              <>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  {targetLabel(grant, t)}
                </Typography>

                <Stack
                  direction="row"
                  spacing={0.5}
                  sx={{ flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}
                >
                  {allowedActions.map(action => (
                    <Chip key={action} size="small" label={action} />
                  ))}
                </Stack>

                {target.wholeSpace && (
                  <Typography
                    variant="caption"
                    color="warning.main"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapSpaceWarning')}{' '}
                    {t('chapi.get.zcapReadOnlyNote')}
                  </Typography>
                )}

                {target.encrypted && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapEncryptedNote')}
                  </Typography>
                )}

                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mt: 0.5 }}
                >
                  {t('chapi.get.zcapExpiry', { days: ttlDays })}
                </Typography>
              </>
            ) : (
              <Typography variant="body2" color="text.secondary">
                {t('chapi.get.zcapCannotFulfill')}
              </Typography>
            )}
          </Box>
        )
      })}
    </Stack>
  )
}
