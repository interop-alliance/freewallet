/**
 * Settings section for recovery codes: lists the account's issued
 * codes from the unlock-methods registry, generates a new code inside a
 * confirm-once dialog (nothing is durable until "I saved this code" -- only
 * the confirm runs the issuance ceremony), revokes codes (a REAL revocation:
 * the document entry, the roster wrap, and the unlock Space all go, so the
 * code resolves to nothing afterwards), and surfaces the recovery health
 * check's delegation-rot warnings.
 */
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { MdDeleteOutline } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { useEffect, useState } from 'react'
import type { Session } from '@/types/auth'
import type { RecoveryCodeUnlockMethod } from '@/session/unlockMethods'
import {
  canIssueRecoveryCode,
  checkRecoveryHealth,
  generateRecoveryCode,
  issueRecoveryCode,
  listRecoveryCodeEntries,
  revokeRecoveryCode,
  type RecoveryHealthFlag
} from '@/session/recovery'
import { RecoveryCodeDisplay } from '@/components/RecoveryCodeDisplay'
import { formatDate } from '@/lib/viewMappers/formatDate'

export function RecoveryCodesSection({ session }: { session: Session }) {
  const { t, i18n } = useTranslation()
  const canManage = canIssueRecoveryCode({ session })
  const [entries, setEntries] = useState<RecoveryCodeUnlockMethod[] | null>(
    null
  )
  const [healthFlags, setHealthFlags] = useState<RecoveryHealthFlag[]>([])
  const [pendingCode, setPendingCode] = useState<string | null>(null)
  const [label, setLabel] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const [revokingKid, setRevokingKid] = useState<string | null>(null)
  const [errorKey, setErrorKey] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      const loaded = await listRecoveryCodeEntries({ session })
      if (cancelled) {
        return
      }
      setEntries(loaded)
      if (loaded.length > 0) {
        try {
          const flags = await checkRecoveryHealth({
            session,
            entries: loaded
          })
          if (!cancelled) {
            setHealthFlags(flags)
          }
        } catch (err) {
          console.warn('Recovery health check failed:', err)
        }
      }
    }

    void initialLoad()
    return () => {
      cancelled = true
    }
  }, [session])

  const handleGenerate = () => {
    setErrorKey(null)
    setLabel(
      t('settings.recovery.defaultLabel', {
        number: (entries?.length ?? 0) + 1
      })
    )
    // In-memory only: closing the dialog without confirming discards the
    // code and binds nothing.
    setPendingCode(generateRecoveryCode())
  }

  /**
   * Runs the issuance ceremony for the displayed code. Only now does the
   * code become usable.
   */
  const handleConfirm = async () => {
    if (!pendingCode || isSaving) {
      return
    }
    setIsSaving(true)
    setErrorKey(null)
    try {
      await issueRecoveryCode({
        session,
        code: pendingCode,
        label: label.trim() || t('settings.recovery.unlabeled')
      })
      setPendingCode(null)
      setEntries(await listRecoveryCodeEntries({ session }))
    } catch (err) {
      console.error('Could not issue the recovery code:', err)
      setErrorKey('settings.recovery.saveError')
    } finally {
      setIsSaving(false)
    }
  }

  const handleRevoke = async (entry: RecoveryCodeUnlockMethod) => {
    if (revokingKid) {
      return
    }
    if (!window.confirm(t('settings.recovery.removeConfirm'))) {
      return
    }
    setRevokingKid(entry.recoveryKid)
    setErrorKey(null)
    try {
      await revokeRecoveryCode({ session, entry })
      setEntries(await listRecoveryCodeEntries({ session }))
      setHealthFlags(flags =>
        flags.filter(flag => flag.entry.recoveryKid !== entry.recoveryKid)
      )
    } catch (err) {
      console.error('Could not revoke the recovery code:', err)
      setErrorKey('settings.recovery.revokeError')
    } finally {
      setRevokingKid(null)
    }
  }

  const flaggedKids = new Set(healthFlags.map(flag => flag.entry.recoveryKid))

  return (
    <Stack sx={{ gap: 1 }}>
      <Typography variant="h6">{t('settings.recovery.section')}</Typography>
      <Typography variant="body2" color="text.secondary">
        {t('settings.recovery.intro')}
      </Typography>

      {!canManage && (
        <Typography variant="body2" color="text.secondary">
          {t('settings.recovery.requiresEnrolledClient')}
        </Typography>
      )}

      {entries !== null && entries.length > 0 && (
        <Stack sx={{ gap: 0.5 }}>
          {entries.map(entry => (
            <Stack
              key={entry.recoveryKid}
              direction="row"
              sx={{ alignItems: 'center', gap: 2 }}
            >
              <Typography variant="body2" sx={{ minWidth: 200 }}>
                {entry.label || t('settings.recovery.unlabeled')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {formatDate({
                  isoDate: entry.createdAt,
                  locale: i18n.language
                })}
              </Typography>
              {flaggedKids.has(entry.recoveryKid) && (
                <Chip
                  size="small"
                  color="warning"
                  label={t('settings.recovery.healthFlagged')}
                />
              )}
              <IconButton
                size="small"
                aria-label={t('settings.recovery.remove')}
                disabled={!canManage || revokingKid !== null}
                onClick={() => void handleRevoke(entry)}
              >
                <MdDeleteOutline />
              </IconButton>
            </Stack>
          ))}
        </Stack>
      )}
      {entries !== null && entries.length === 0 && canManage && (
        <Typography variant="body2" color="text.secondary">
          {t('settings.recovery.none')}
        </Typography>
      )}

      {healthFlags.length > 0 && (
        <Alert severity="warning">{t('settings.recovery.healthWarning')}</Alert>
      )}

      {errorKey && <Alert severity="error">{t(errorKey)}</Alert>}

      <Stack direction="row" sx={{ alignItems: 'center', gap: 2, mt: 1 }}>
        <Button
          variant="outlined"
          size="small"
          sx={{ textTransform: 'none', borderRadius: 2, whiteSpace: 'nowrap' }}
          disabled={!canManage || entries === null}
          onClick={handleGenerate}
        >
          {t('settings.recovery.generate')}
        </Button>
      </Stack>

      <Dialog
        open={pendingCode !== null}
        onClose={() => !isSaving && setPendingCode(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>{t('settings.recovery.dialogTitle')}</DialogTitle>
        <DialogContent>
          <Stack sx={{ gap: 2, mt: 1 }}>
            <Alert severity="warning">{t('settings.recovery.shownOnce')}</Alert>
            {pendingCode && (
              <RecoveryCodeDisplay
                code={pendingCode}
                copyLabel={t('settings.recovery.copy')}
              />
            )}
            <TextField
              label={t('settings.recovery.labelField')}
              value={label}
              onChange={event => setLabel(event.target.value)}
              size="small"
            />
            <Typography variant="body2" color="text.secondary">
              {t('settings.recovery.codePowerHint')}
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button disabled={isSaving} onClick={() => setPendingCode(null)}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            loading={isSaving}
            onClick={() => void handleConfirm()}
          >
            {t('settings.recovery.confirmSaved')}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}
