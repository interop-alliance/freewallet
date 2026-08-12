/**
 * The inviter's consent panel for the wallet-onboarding ceremony, rendered
 * inside the invite card once the other wallet's response parses: it leads
 * with the new client's key fingerprint (the point-to-point comparison the
 * whole ceremony rests on), states plainly that the wallet becomes a full
 * peer of the account, and only then offers the approval that runs the
 * enrollment.
 *
 * Approving is idempotent -- the shared ceremony resumes from durable state --
 * so a failure here is reported as "approve again" rather than as a dead end.
 */
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  enrollmentClientDid,
  type EnrollmentRequest
} from '@interop/wallet-core/enrollment'
import type { Session } from '@/types/auth'
import { approveEnrollment } from '@/lib/enrollment'

export function OnboardConsentPanel({
  session,
  consent,
  onApproved,
  onCancel
}: {
  session: Session
  consent: { request: EnrollmentRequest; label?: string }
  onApproved: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const [label, setLabel] = useState(consent.label ?? '')
  const [approving, setApproving] = useState(false)
  const [approveError, setApproveError] = useState(false)

  /**
   * Runs the enrollment ceremony for the response the other wallet posted,
   * saving the chosen label once it lands.
   */
  const handleApprove = async () => {
    if (approving) {
      return
    }
    setApproving(true)
    setApproveError(false)
    try {
      await approveEnrollment({ request: consent.request, session, label })
      onApproved()
    } catch (err) {
      console.error('Onboarding the new wallet client failed:', err)
      setApproveError(true)
    } finally {
      setApproving(false)
    }
  }

  return (
    <Stack data-testid="onboard-consent-panel" sx={{ gap: 1.5 }}>
      <Typography
        variant="body2"
        color="text.secondary"
        sx={{ wordBreak: 'break-all', fontFamily: 'monospace' }}
      >
        {t('settings.onboardFingerprint', {
          did: enrollmentClientDid({ request: consent.request })
        })}
      </Typography>

      <Alert severity="warning">{t('settings.onboardFullPeer')}</Alert>

      <Typography variant="body2" color="text.secondary">
        {t('settings.onboardDisconnectCeiling')}
      </Typography>

      <TextField
        fullWidth
        size="small"
        label={t('settings.clients.nameLabel')}
        value={label}
        onChange={event => setLabel(event.target.value)}
        slotProps={{
          htmlInput: { 'data-testid': 'onboard-label-input' }
        }}
      />

      {approveError && (
        <Alert severity="error">{t('settings.onboardApproveError')}</Alert>
      )}

      <Stack direction="row" sx={{ gap: 1 }}>
        <Button size="small" disabled={approving} onClick={onCancel}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="contained"
          size="small"
          sx={{ borderRadius: 2 }}
          loading={approving}
          onClick={() => void handleApprove()}
        >
          {t('settings.enrollConfirmAction')}
        </Button>
      </Stack>
    </Stack>
  )
}
