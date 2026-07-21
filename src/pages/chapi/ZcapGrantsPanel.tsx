/**
 * The "Storage access" section of the CHAPI login consent screen: one row per
 * requested capability, showing the relying party's reason, the recipient DID
 * the capability is delegated to, a human-readable target, the actions to be
 * granted, and the expiry. Encrypted standard collections get a ciphertext
 * note; whole-Space grants get a warning banner and an explicit read-only
 * label; write grants get a warning banner, the warning border, and the
 * shorter write expiry; public-collection grants get a warning banner stating
 * anyone on the web can read the collection (and, being plaintext, never a
 * ciphertext note); unsatisfiable grants render greyed with a "cannot
 * fulfill" note. Because the RP-supplied `reason` is attacker-controlled free
 * text, the recipient DID is rendered separately with its own label and a
 * monospace style so it cannot be spoofed by the reason. Display-only --
 * approval is the single Continue button on the parent page.
 */
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import type { ResolvedGrant } from '@/lib/walletRequest'

/**
 * A human-readable label for a resolved grant's target. A collection target
 * renders its id as a distinct monospace badge so it stands out from the
 * surrounding copy; the other targets stay plain text.
 */
function targetLabel(
  grant: ResolvedGrant,
  t: (key: string, opts?: Record<string, unknown>) => string
) {
  const { target } = grant
  if (target.wholeSpace) {
    return t('chapi.get.zcapTarget.space')
  }
  if (target.collectionId) {
    return (
      <>
        {t('chapi.get.zcapTarget.collection')}{' '}
        <Chip
          component="span"
          size="small"
          label={target.collectionId}
          sx={{ fontFamily: 'monospace' }}
        />
      </>
    )
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
  ttlDays,
  writeTtlDays,
  hideRecipient = false,
  heading
}: {
  grants: ResolvedGrant[]
  ttlDays: number
  writeTtlDays: number
  // App Connect consent hides the recipient DID rows: the recipient is the
  // app's own (possibly not-yet-minted) key, not a DID the user could vet.
  hideRecipient?: boolean
  // Overrides the default "Storage access" section heading (App Connect uses
  // app-centric phrasing).
  heading?: string
}) {
  const { t } = useTranslation()

  return (
    <Stack spacing={1}>
      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
        {heading ?? t('chapi.get.zcapHeading')}
      </Typography>
      {grants.map((grant, index) => {
        const { target, allowedActions, descriptor, write } = grant
        const satisfiable = target.satisfiable
        // Warning border for whole-Space, public-collection, and write grants.
        const highlight = target.wholeSpace || target.isPublic || write
        return (
          <Box
            key={descriptor.referenceId ?? index}
            sx={{
              p: 1.5,
              border: 1,
              borderColor: highlight ? 'warning.main' : 'divider',
              borderRadius: 2,
              opacity: satisfiable ? 1 : 0.6
            }}
          >
            {descriptor.reason && (
              <Typography variant="body2" sx={{ mb: 0.5 }}>
                {descriptor.reason}
              </Typography>
            )}

            {!hideRecipient && (
              <>
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mb: 0.5 }}
                >
                  {t('chapi.get.zcapRecipient')}
                </Typography>
                <Typography
                  variant="caption"
                  component="div"
                  sx={{
                    fontFamily: 'monospace',
                    wordBreak: 'break-all',
                    mb: 0.5
                  }}
                >
                  {descriptor.controller}
                </Typography>
              </>
            )}

            {satisfiable ? (
              <>
                <Typography variant="subtitle2">
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

                {target.isPublic && (
                  <Typography
                    variant="caption"
                    color="warning.main"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapPublicWarning')}
                  </Typography>
                )}

                {write && (
                  <Typography
                    variant="caption"
                    color="warning.main"
                    sx={{ display: 'block', mt: 0.5 }}
                  >
                    {t('chapi.get.zcapWriteWarning')}
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
                  {t('chapi.get.zcapExpiry', {
                    days: write ? writeTtlDays : ttlDays
                  })}{' '}
                  {t('chapi.get.zcapRevokeNote')}
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
