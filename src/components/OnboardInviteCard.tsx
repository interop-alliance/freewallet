/**
 * The inviter's onboarding invite card, shown in place under Settings >
 * Connected wallets: it creates an ephemeral exchange carrying a
 * `WalletOnboardingQuery`, shows the resulting interaction URL as a QR code
 * (and as copyable text), counts the invite down, and polls the exchange for
 * the other wallet's response.
 *
 * Every run is per-instance: one `AbortController` in a ref cancels the poll
 * on cancel, on unmount, on expiry, and before a regenerated invite starts.
 * Once a response arrives it is parsed here and handed to
 * `OnboardConsentPanel`, which owns the fingerprint comparison, the consent
 * copy, and the approval; a response that does not parse ends the invite with
 * "generate a new code" rather than a partial render.
 */
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { QRCodeSVG } from 'qrcode.react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { composeWalletOnboardingRequest } from '@interop/wallet-core/request'
import {
  parseOnboardingResponse,
  type EnrollmentRequest
} from '@interop/wallet-core/enrollment'
import type { Session } from '@/types/auth'
import { enrolledClientContext } from '@/session/enrolledContext'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { OnboardConsentPanel } from '@/components/OnboardConsentPanel'
import {
  createOnboardingExchange,
  OnboardingExchangeGoneError,
  ONBOARDING_INVITE_TTL_MS,
  pollOnboardingExchange
} from '@/lib/onboardingInvite'

/**
 * Where the card is in the invite's life: creating the exchange, offering a
 * live code, expired (server-gone or the countdown ran out), the other
 * wallet's response in hand, a response that could not be read, or a failed
 * create.
 */
type InvitePhase =
  'creating' | 'live' | 'expired' | 'received' | 'invalid' | 'error'

/**
 * Formats a remaining duration as `m:ss` for the countdown line.
 *
 * @param options {object}
 * @param options.remainingMs {number}
 * @returns {string}
 */
function formatRemaining({ remainingMs }: { remainingMs: number }): string {
  const totalSeconds = Math.max(0, Math.ceil(remainingMs / 1000))
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes}:${String(seconds).padStart(2, '0')}`
}

export function OnboardInviteCard({
  session,
  onApproved,
  onCancel
}: {
  session: Session
  onApproved: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const [phase, setPhase] = useState<InvitePhase>('creating')
  const [interactionUrl, setInteractionUrl] = useState('')
  const [deadline, setDeadline] = useState(0)
  const [remainingMs, setRemainingMs] = useState(ONBOARDING_INVITE_TTL_MS)
  // What the consent panel renders, once a response parses.
  const [consent, setConsent] = useState<{
    request: EnrollmentRequest
    label?: string
  } | null>(null)
  // Bumping this re-runs the create-and-poll effect with a fresh exchange.
  const [attempt, setAttempt] = useState(0)
  const abortRef = useRef<AbortController | null>(null)
  const { copied, copy } = useCopyToClipboard()

  useEffect(() => {
    const controller = new AbortController()
    abortRef.current = controller
    let cancelled = false

    /**
     * Creates the exchange, then polls it until the other wallet responds.
     */
    async function inviteAnotherWallet() {
      setPhase('creating')
      setInteractionUrl('')
      setConsent(null)
      setRemainingMs(ONBOARDING_INVITE_TTL_MS)
      let exchangeUrl: string
      try {
        const context = enrolledClientContext({ session })
        if (!context) {
          throw new Error(
            'Onboarding another wallet requires an enrolled client on a ' +
              'configured storage server.'
          )
        }
        const created = await createOnboardingExchange({
          serverUrl: context.remoteStore.storageServerUrl,
          request: composeWalletOnboardingRequest({
            pointer: context.pointer,
            controller: context.controller
          })
        })
        if (cancelled) {
          return
        }
        exchangeUrl = created.exchangeUrl
        setInteractionUrl(created.interactionUrl)
        setDeadline(Date.now() + ONBOARDING_INVITE_TTL_MS)
        setPhase('live')
      } catch (err) {
        console.error('Could not create the wallet onboarding invite:', err)
        if (!cancelled) {
          setPhase('error')
        }
        return
      }
      try {
        const response = await pollOnboardingExchange({
          exchangeUrl,
          signal: controller.signal
        })
        if (cancelled) {
          return
        }
        // A malformed envelope has one remedy -- a fresh code -- so it ends
        // the invite in its own phase rather than half-rendering a consent
        // screen.
        try {
          const parsed = parseOnboardingResponse({ body: response })
          setConsent({ request: parsed.request, label: parsed.label })
          setPhase('received')
        } catch (err) {
          console.warn("Could not read the other wallet's response:", err)
          setPhase('invalid')
        }
      } catch (err) {
        if (cancelled || controller.signal.aborted) {
          return
        }
        if (err instanceof OnboardingExchangeGoneError) {
          setPhase('expired')
          return
        }
        console.error('Polling the wallet onboarding invite failed:', err)
        setPhase('error')
      }
    }

    void inviteAnotherWallet()

    return () => {
      cancelled = true
      controller.abort(new Error('The wallet onboarding invite was closed.'))
    }
  }, [attempt, session])

  // The countdown, running only while a code is on offer. Reaching zero ends
  // the poll -- the server's own exchange TTL is longer, so an expired card
  // is always the safe side of it.
  useEffect(() => {
    if (phase !== 'live') {
      return
    }
    function tick() {
      const remaining = Math.max(0, deadline - Date.now())
      setRemainingMs(remaining)
      if (remaining === 0) {
        abortRef.current?.abort(
          new Error('The wallet onboarding invite expired.')
        )
        setPhase('expired')
      }
    }
    tick()
    const timer = setInterval(tick, 1000)
    return () => clearInterval(timer)
  }, [phase, deadline])

  return (
    <Card
      variant="outlined"
      data-testid="onboard-invite-card"
      sx={{
        display: 'flex',
        flexDirection: 'column',
        gap: 1,
        p: 2,
        mt: 1
      }}
    >
      <Typography variant="subtitle1">
        {phase === 'received'
          ? t('settings.onboardConsentTitle')
          : t('settings.onboardCardTitle')}
      </Typography>

      {phase === 'creating' && (
        <Stack direction="row" sx={{ alignItems: 'center', gap: 1 }}>
          <CircularProgress size={18} />
          <Typography variant="body2" color="text.secondary">
            {t('settings.onboardCreating')}
          </Typography>
        </Stack>
      )}

      {phase === 'error' && (
        <Alert severity="error">{t('settings.onboardCreateError')}</Alert>
      )}

      {phase === 'expired' && (
        <Alert severity="warning">{t('settings.onboardExpired')}</Alert>
      )}

      {phase === 'invalid' && (
        <Alert severity="error">{t('settings.onboardInvalidResponse')}</Alert>
      )}

      {phase === 'received' && consent && (
        <OnboardConsentPanel
          session={session}
          consent={consent}
          onApproved={onApproved}
          onCancel={onCancel}
        />
      )}

      {phase === 'live' && (
        <>
          <Typography variant="body2" color="text.secondary">
            {t('settings.onboardInstructions')}
          </Typography>
          {/* The QR keeps a white ground so it scans in dark mode too. */}
          <Box
            sx={{
              alignSelf: 'flex-start',
              bgcolor: '#fff',
              p: 1,
              borderRadius: 1,
              lineHeight: 0
            }}
          >
            <QRCodeSVG value={interactionUrl} size={200} marginSize={2} />
          </Box>
          <Typography variant="body2" color="text.secondary">
            {t('settings.onboardUrlLabel')}
          </Typography>
          <Typography
            variant="body2"
            data-testid="onboard-invite-url"
            sx={{ wordBreak: 'break-all', fontFamily: 'monospace' }}
          >
            {interactionUrl}
          </Typography>
          <Button
            variant="outlined"
            size="small"
            sx={{ borderRadius: 2, alignSelf: 'flex-start' }}
            onClick={() => void copy(interactionUrl)}
          >
            {copied
              ? t('settings.onboardCopied')
              : t('settings.onboardCopyUrl')}
          </Button>
          <Typography variant="body2" color="text.secondary">
            {t('settings.onboardCountdown', {
              time: formatRemaining({ remainingMs })
            })}
          </Typography>
        </>
      )}

      {/* In `received` the consent panel owns the actions. */}
      {phase !== 'received' && (
        <Stack direction="row" sx={{ gap: 1, mt: 1 }}>
          {(phase === 'expired' ||
            phase === 'error' ||
            phase === 'invalid') && (
            <Button
              variant="contained"
              size="small"
              sx={{ borderRadius: 2 }}
              onClick={() => {
                setConsent(null)
                setAttempt(current => current + 1)
              }}
            >
              {t('settings.onboardGenerateNew')}
            </Button>
          )}
          <Button size="small" onClick={onCancel}>
            {t('common.cancel')}
          </Button>
        </Stack>
      )}
    </Card>
  )
}
