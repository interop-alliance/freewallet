/**
 * The backup-export dialog behind the Storage page's export action: the two
 * bundle modes, the run's progress, and the file save.
 *
 * Every export establishes a fresh backup credential and packs its secret
 * in the bundle, so the file plus that secret carries everything a restore
 * login needs (that login is not built yet). The mode decides how the secret
 * travels. Password-protected, the
 * default, seals it under an export passphrase chosen here, which never has
 * to match the wallet passphrase. Unprotected, it travels in the clear, which
 * makes the file a bearer credential: whoever holds it signs in to the
 * account.
 *
 * The export passphrase seals that one file, and no more. The bundle still
 * carries every unlock Space archive and the account Space's user key
 * roster, so a holder of the file can guess the wallet passphrase offline
 * and open the account without the export passphrase at all. The file's
 * bound is therefore the weaker of the two secrets, which the dialog's copy
 * says rather than implying the export passphrase alone protects it. No
 * minimum length or strength is required of either here.
 *
 * The export-passphrase fields carry `autoComplete="off"` and no name a
 * password manager matches, for the same reason the content-migration
 * dialog's do: the one saved entry for this origin is this account's
 * passphrase, and a manager invited to overwrite it with an export
 * passphrase would lock the user out. Nothing here logs either secret, and
 * the state holding them is dropped on every exit path the run takes, not
 * just on a successful one.
 *
 * Where the file goes is asked first, before the ceremony starts, since the
 * export's first stage establishes a backup credential into the account: a
 * save picker the user dismisses then costs no credential and no run. A browser without the
 * File System Access API has no picker to open, so there the finished bundle
 * is buffered into a Blob and downloaded as before.
 */
import { useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import FormControl from '@mui/material/FormControl'
import FormControlLabel from '@mui/material/FormControlLabel'
import FormLabel from '@mui/material/FormLabel'
import LinearProgress from '@mui/material/LinearProgress'
import Radio from '@mui/material/Radio'
import RadioGroup from '@mui/material/RadioGroup'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { createLogger } from '@/lib/log'
import { pickSaveFile, saveStreamAsBlob } from '@/lib/saveStream'
import { formatDate } from '@/lib/viewMappers/formatDate'
import {
  backupExportCancelled,
  backupExportErrorKey,
  backupExportErrorLabel,
  exportBackup,
  type BackupExportProgress
} from '@/session/backupExport'
import { showToast } from '@/stores/toastStore'
import type { Session } from '@/types/auth'

const log = createLogger('fw:ui:storage')

/**
 * Which mode the form is on: the packed code sealed under an export
 * passphrase, or packed in the clear.
 */
type BackupMode = 'protected' | 'unprotected'

/**
 * A date as `YYYY-MM-DD`, for the file name. The code's label formats the
 * same day through the shared `DATE_FMT`, as every other minted
 * unlock-method label does.
 *
 * @param now {Date}
 * @returns {string}
 */
function fileDate(now: Date): string {
  // The local calendar date, not the UTC one: a user west of UTC late in the
  // evening would otherwise see tomorrow's date on the file.
  const month = String(now.getMonth() + 1).padStart(2, '0')
  const day = String(now.getDate()).padStart(2, '0')
  return `${now.getFullYear()}-${month}-${day}`
}

/**
 * Renders the mode choice, the run, and the save.
 *
 * @param options {object}
 * @param options.session {Session}   the account being backed up
 * @param options.onClose {Function}   closes the dialog
 * @returns {JSX.Element}
 */
export function BackupExportDialog({
  session,
  onClose
}: {
  session: Session
  onClose: () => void
}) {
  const { t, i18n } = useTranslation()
  const [mode, setMode] = useState<BackupMode>('protected')
  const [exportPassphrase, setExportPassphrase] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<BackupExportProgress | null>(null)
  const [error, setError] = useState<{ key: string; label?: string } | null>(
    null
  )
  const abortRef = useRef<AbortController | null>(null)

  const mismatch =
    mode === 'protected' &&
    confirmation.length > 0 &&
    confirmation !== exportPassphrase
  const runnable =
    !running &&
    (mode === 'unprotected' ||
      (exportPassphrase.length > 0 && confirmation === exportPassphrase))

  /**
   * The failure the dialog renders, with the refused entry's label where the
   * message names one.
   *
   * @param err {unknown}
   * @returns {void}
   */
  function showError(err: unknown): void {
    const label = backupExportErrorLabel(err)
    setError({ key: backupExportErrorKey(err), ...(label ? { label } : {}) })
  }

  const handleRun = async () => {
    const now = new Date()
    const fileName = `wallet-backup-${fileDate(now)}.tar`
    // Where the file goes is asked BEFORE the ceremony runs, and outside the
    // try that renders the run's failures: the export establishes a backup
    // credential, and a picker the user dismisses should cost neither that
    // credential nor the run, and should leave the form exactly as it was -- no message, and
    // both passphrase fields kept. A browser with no picker answers nothing
    // here and takes the Blob download below instead.
    let target
    try {
      target = await pickSaveFile({ fileName })
    } catch (err) {
      if (backupExportCancelled(err)) {
        return
      }
      log.error('Could not open the save picker', { err })
      showError(err)
      return
    }
    const controller = new AbortController()
    abortRef.current = controller
    setProgress(null)
    setError(null)
    setRunning(true)
    try {
      const stream = await exportBackup({
        session,
        credentialLabel: t('storage.backup.credentialLabel', {
          date: formatDate({
            isoDate: now.toISOString(),
            locale: i18n.language
          })
        }),
        ...(mode === 'protected' ? { exportPassphrase } : {}),
        signal: controller.signal,
        onProgress: setProgress
      })
      if (target) {
        await target.write(stream)
      } else {
        await saveStreamAsBlob({ stream, fileName })
      }
      showToast({ message: t('storage.backup.success') })
      onClose()
    } catch (err) {
      // A cancelled run renders too: past the establishment it has left a
      // backup credential standing, and the cancelled message is what says
      // so.
      if (!backupExportCancelled(err)) {
        log.error('Could not export a backup bundle', { err })
      }
      showError(err)
    } finally {
      // Neither secret outlives the attempt, whichever way it ended.
      setExportPassphrase('')
      setConfirmation('')
      abortRef.current = null
      setRunning(false)
    }
  }

  const handleCancel = () => {
    abortRef.current?.abort()
  }

  /**
   * The running line: which stage, and for an export which Space of how
   * many.
   *
   * @returns {string}
   */
  function progressText(): string {
    if (!progress || progress.stage === 'establishing-credential') {
      return t('storage.backup.progress.establishingCredential')
    }
    if (progress.stage === 'packing') {
      return t('storage.backup.progress.packing')
    }
    return t('storage.backup.progress.exportingSpace', {
      index: progress.index ?? 1,
      total: progress.total ?? 1
    })
  }

  return (
    <Dialog
      open
      onClose={running ? undefined : onClose}
      fullWidth
      maxWidth="sm"
    >
      <DialogTitle>{t('storage.backup.title')}</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2}>
          <Typography variant="body2">{t('storage.backup.intro')}</Typography>

          <FormControl disabled={running}>
            <FormLabel>{t('storage.backup.modeLegend')}</FormLabel>
            <RadioGroup
              value={mode}
              onChange={event => setMode(event.target.value as BackupMode)}
            >
              <FormControlLabel
                value="protected"
                control={<Radio />}
                label={t('storage.backup.modes.protected')}
              />
              <FormControlLabel
                value="unprotected"
                control={<Radio />}
                label={t('storage.backup.modes.unprotected')}
              />
            </RadioGroup>
          </FormControl>

          {mode === 'protected' && (
            <Stack spacing={2}>
              <TextField
                type="password"
                label={t('storage.backup.passphraseLabel')}
                value={exportPassphrase}
                onChange={event => setExportPassphrase(event.target.value)}
                disabled={running}
                autoComplete="off"
                helperText={t('storage.backup.passphraseHelp')}
              />
              <TextField
                type="password"
                label={t('storage.backup.confirmLabel')}
                value={confirmation}
                onChange={event => setConfirmation(event.target.value)}
                disabled={running}
                autoComplete="off"
                error={mismatch}
                {...(mismatch
                  ? { helperText: t('storage.backup.passphraseMismatch') }
                  : {})}
              />
            </Stack>
          )}

          {mode === 'unprotected' && (
            <Alert severity="warning">
              {t('storage.backup.unprotectedWarning')}
            </Alert>
          )}

          <Typography variant="body2" color="text.secondary">
            {t('storage.backup.credentialNote')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('storage.backup.removalNote')}
          </Typography>

          {running && (
            <Stack spacing={1}>
              <LinearProgress />
              <Typography variant="body2">{progressText()}</Typography>
            </Stack>
          )}

          {error && (
            <Alert severity="error">
              {t(error.key, { ...(error.label ? { label: error.label } : {}) })}
            </Alert>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        {running ? (
          <Button onClick={handleCancel}>{t('storage.backup.cancel')}</Button>
        ) : (
          <Button onClick={onClose}>{t('storage.backup.close')}</Button>
        )}
        <Button variant="contained" onClick={handleRun} disabled={!runnable}>
          {t('storage.backup.run')}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
