/**
 * The content-migration dialog behind the Storage page's "Import from another
 * wallet" action: a backup file, the one secret that opens it, and the report
 * the walk leaves behind.
 *
 * It offers every session kind, a guest and a no-WAS deployment included --
 * `migrateContent` writes through the session's own import methods, so
 * there is nothing here to gate on remote storage. The three secret inputs
 * are the ones the walk accepts: the old wallet's passphrase, a recovery
 * code typed in, or the code the backup itself carries, unsealed with the
 * export passphrase where one was used. There is no passkey input, since evaluating
 * a passkey needs the old account's sealed unlock registry.
 *
 * The secret fields carry `autoComplete="off"` and no name a password manager
 * matches: the one saved entry for this origin is THIS account's passphrase,
 * and a manager invited to overwrite it with the old wallet's would lock the
 * user out of the account they just imported into. Nothing here logs a secret,
 * and the state holding it is dropped when the dialog closes.
 */
import { useCallback, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import Divider from '@mui/material/Divider'
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
import type { MigrationSecret } from '@interop/wallet-backup'
import { getCollectionDisplayName } from '@/components/storage/displayUtils'
import { contentMigrationCauseKey } from '@/lib/contentMigrationCauseKey'
import { formatBytes } from '@/lib/formatBytes'
import { createLogger } from '@/lib/log'
import {
  contentMigrationErrorKey,
  migrateContent,
  type ContentMigrationResult
} from '@/session/contentMigration'
import { showToast } from '@/stores/toastStore'
import { visuallyHiddenInput } from '@/styles/appStyles'
import type { Session } from '@/types/auth'

const log = createLogger('fw:ui:storage')

/**
 * The report's per-collection count buckets, in the order they render.
 */
const REPORT_BUCKETS = [
  'accepted',
  'skipped',
  'conflicting',
  'failed',
  'unopenable'
] as const

/**
 * The lines under "What does not migrate", in the order they render.
 */
const NOT_MIGRATED_KEYS = [
  'storage.migration.notMigratedDid',
  'storage.migration.notMigratedGrants',
  'storage.migration.notMigratedShares',
  'storage.migration.notMigratedPublicLinks'
]

/**
 * Which of the three secret inputs the form is showing.
 */
type SecretKind = 'passphrase' | 'recoveryCode' | 'packedCredential'

/**
 * How often the per-collection counters are pushed into React state. The walk
 * reports every Resource and a large bundle carries thousands, so the counts
 * accumulate in a ref and land on screen at this interval instead.
 */
const PROGRESS_FLUSH_MS = 200

/**
 * Renders the import form, the run, and the report.
 *
 * @param options {object}
 * @param options.session {Session}   the account imported INTO
 * @param options.onClose {Function}   closes the dialog
 * @param options.onImported {Function}   called once a run has written
 *   Resources, so the page can re-list what it shows
 * @returns {JSX.Element}
 */
export function ContentMigrationDialog({
  session,
  onClose,
  onImported
}: {
  session: Session
  onClose: () => void
  onImported: () => void
}) {
  const { t } = useTranslation()
  const [file, setFile] = useState<File | null>(null)
  const [secretKind, setSecretKind] = useState<SecretKind>('passphrase')
  const [passphrase, setPassphrase] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
  const [exportPassphrase, setExportPassphrase] = useState('')
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<Record<string, number>>({})
  const [result, setResult] = useState<ContentMigrationResult | null>(null)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const countsRef = useRef<Map<string, number>>(new Map())
  const flushedAtRef = useRef(0)

  /**
   * The display name of one migrated collection: the wallet's canonical
   * name for a standard collection, the raw id for any other, an app
   * collection included.
   *
   * @param collectionId {string}
   * @returns {string}
   */
  const collectionLabel = useCallback(
    (collectionId: string): string =>
      getCollectionDisplayName({ collection: { id: collectionId }, t }),
    [t]
  )

  /**
   * One cause name from the report as a sentence.
   *
   * @param cause {string}
   * @returns {string}
   */
  const causeText = useCallback(
    (cause: string): string => {
      const { key, name } = contentMigrationCauseKey(cause)
      return name ? t(key, { name }) : t(key)
    },
    [t]
  )

  const handleFile = (event: React.ChangeEvent<HTMLInputElement>) => {
    const picked = event.target.files?.[0] ?? null
    event.target.value = ''
    setFile(picked)
    setErrorKey(null)
    setResult(null)
  }

  /**
   * The secret the form currently stands for.
   *
   * @returns {MigrationSecret}
   */
  function secretFromForm(): MigrationSecret {
    if (secretKind === 'recoveryCode') {
      return { recoveryCode }
    }
    if (secretKind === 'packedCredential') {
      // An empty field is the plain packed credential: the export was written
      // without a password, so there is nothing to unseal it with.
      return {
        packedCredential: exportPassphrase ? { exportPassphrase } : {}
      }
    }
    return { passphrase }
  }

  const handleRun = async () => {
    if (!file) {
      return
    }
    const controller = new AbortController()
    abortRef.current = controller
    countsRef.current = new Map()
    flushedAtRef.current = 0
    setProgress({})
    setResult(null)
    setErrorKey(null)
    setRunning(true)
    try {
      const migrationResult = await migrateContent({
        session,
        bundle: file.stream(),
        secret: secretFromForm(),
        bundleBytes: file.size,
        signal: controller.signal,
        onProgress: ({ collectionId }) => {
          const counts = countsRef.current
          counts.set(collectionId, (counts.get(collectionId) ?? 0) + 1)
          const now = Date.now()
          if (now - flushedAtRef.current < PROGRESS_FLUSH_MS) {
            return
          }
          flushedAtRef.current = now
          setProgress(Object.fromEntries(counts))
        }
      })
      setProgress(Object.fromEntries(countsRef.current))
      setResult(migrationResult)
      setPassphrase('')
      setRecoveryCode('')
      setExportPassphrase('')
      showToast({ message: t('storage.migration.success') })
    } catch (err) {
      log.error('Could not import content from a backup', { err })
      setErrorKey(contentMigrationErrorKey(err))
    } finally {
      abortRef.current = null
      setRunning(false)
      // An aborted or refused run may still have written Resources before it
      // stopped, so the page re-lists either way.
      onImported()
    }
  }

  const handleCancel = () => {
    abortRef.current?.abort()
  }

  const progressRows = Object.entries(progress)

  return (
    <Dialog
      open
      onClose={running ? undefined : onClose}
      fullWidth
      maxWidth="sm"
    >
      <DialogTitle>{t('storage.migration.title')}</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2}>
          <Typography variant="body2">
            {t('storage.migration.intro')}
          </Typography>

          <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
            <Button variant="outlined" component="label" disabled={running}>
              {file
                ? t('storage.migration.changeFile')
                : t('storage.migration.chooseFile')}
              <input
                type="file"
                accept=".tar,application/x-tar"
                style={visuallyHiddenInput}
                onChange={handleFile}
              />
            </Button>
            {file && (
              <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                {t('storage.migration.selectedFile', {
                  name: file.name,
                  size: formatBytes(file.size)
                })}
              </Typography>
            )}
          </Stack>

          <FormControl disabled={running}>
            <FormLabel>{t('storage.migration.secretLegend')}</FormLabel>
            <RadioGroup
              value={secretKind}
              onChange={event =>
                setSecretKind(event.target.value as SecretKind)
              }
            >
              <FormControlLabel
                value="passphrase"
                control={<Radio />}
                label={t('storage.migration.secretKinds.passphrase')}
              />
              <FormControlLabel
                value="recoveryCode"
                control={<Radio />}
                label={t('storage.migration.secretKinds.recoveryCode')}
              />
              <FormControlLabel
                value="packedCredential"
                control={<Radio />}
                label={t('storage.migration.secretKinds.packedCredential')}
              />
            </RadioGroup>
          </FormControl>

          {secretKind === 'passphrase' && (
            <TextField
              type="password"
              label={t('storage.migration.passphraseLabel')}
              value={passphrase}
              onChange={event => setPassphrase(event.target.value)}
              disabled={running}
              autoComplete="off"
              helperText={t('storage.migration.recoveryCodeHint')}
            />
          )}
          {secretKind === 'recoveryCode' && (
            <TextField
              type="password"
              label={t('storage.migration.recoveryCodeLabel')}
              value={recoveryCode}
              onChange={event => setRecoveryCode(event.target.value)}
              disabled={running}
              autoComplete="off"
            />
          )}
          {secretKind === 'packedCredential' && (
            <TextField
              type="password"
              label={t('storage.migration.exportPassphraseLabel')}
              value={exportPassphrase}
              onChange={event => setExportPassphrase(event.target.value)}
              disabled={running}
              autoComplete="off"
              helperText={t('storage.migration.exportPassphraseHelp')}
            />
          )}

          <Divider />

          <Stack spacing={0.5}>
            <Typography variant="subtitle2">
              {t('storage.migration.notMigratedTitle')}
            </Typography>
            {NOT_MIGRATED_KEYS.map(key => (
              <Typography key={key} variant="body2" color="text.secondary">
                {t(key)}
              </Typography>
            ))}
            {!session.storage.canProvisionAppCollections && (
              <Typography variant="body2" color="text.secondary">
                {t('storage.migration.notMigratedAppCollections')}
              </Typography>
            )}
            {!session.storage.hasRemoteStorage && (
              <Typography variant="body2" color="text.secondary">
                {t('storage.migration.notMigratedLocalOnly')}
              </Typography>
            )}
          </Stack>

          {running && (
            <Stack spacing={1}>
              <LinearProgress />
              <Typography variant="body2">
                {t('storage.migration.running')}
              </Typography>
              {progressRows.length > 0 && (
                <Stack spacing={0.25}>
                  <Typography variant="subtitle2">
                    {t('storage.migration.progressTitle')}
                  </Typography>
                  {progressRows.map(([collectionId, count]) => (
                    <Typography key={collectionId} variant="body2">
                      {t('storage.migration.progressRow', {
                        collection: collectionLabel(collectionId),
                        count
                      })}
                    </Typography>
                  ))}
                </Stack>
              )}
            </Stack>
          )}

          {errorKey && <Alert severity="error">{t(errorKey)}</Alert>}

          {result && (
            <Stack spacing={1.5}>
              <Divider />
              <Typography variant="subtitle2">
                {t('storage.migration.reportTitle')}
              </Typography>
              {result.quotaWarning && (
                <Alert severity="warning">
                  {t('storage.migration.quotaWarning', {
                    bundleSize: formatBytes(result.quotaWarning.bundleBytes),
                    freeSize: formatBytes(result.quotaWarning.freeBytes)
                  })}
                </Alert>
              )}
              {!result.replicaInSync && (
                <Alert severity="info">
                  {t('storage.migration.replicaOutOfSync')}
                </Alert>
              )}
              {result.report.stoppedAt && (
                <Alert severity="warning">
                  {t('storage.migration.stoppedAt', {
                    collection: collectionLabel(
                      result.report.stoppedAt.collectionId
                    ),
                    cause: causeText(result.report.stoppedAt.cause)
                  })}
                </Alert>
              )}
              {Object.entries(result.report.collections).map(
                ([collectionId, counts]) => (
                  <Stack key={collectionId} spacing={0.25}>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {collectionLabel(collectionId)}
                    </Typography>
                    {REPORT_BUCKETS.map(bucket => (
                      <Typography
                        key={bucket}
                        variant="body2"
                        color="text.secondary"
                      >
                        {t(`storage.migration.buckets.${bucket}`, {
                          count: counts[bucket]
                        })}
                      </Typography>
                    ))}
                    {Object.entries(counts.unopenableCauses ?? {}).map(
                      ([cause, count]) => (
                        <Typography
                          key={cause}
                          variant="body2"
                          color="text.secondary"
                        >
                          {`${causeText(cause)} (${count})`}
                        </Typography>
                      )
                    )}
                    {counts.stoppedBy && (
                      <Typography variant="body2" color="text.secondary">
                        {t('storage.migration.collectionStoppedBy', {
                          cause: causeText(counts.stoppedBy)
                        })}
                      </Typography>
                    )}
                  </Stack>
                )
              )}
              {Object.keys(result.report.notMigrated).length > 0 && (
                <Stack spacing={0.25}>
                  <Typography variant="subtitle2">
                    {t('storage.migration.notMigratedCollectionsTitle')}
                  </Typography>
                  {Object.entries(result.report.notMigrated).map(
                    ([collectionId, count]) => (
                      <Typography
                        key={collectionId}
                        variant="body2"
                        color="text.secondary"
                      >
                        {t('storage.migration.notMigratedCollectionRow', {
                          collection: collectionLabel(collectionId),
                          count
                        })}
                      </Typography>
                    )
                  )}
                </Stack>
              )}
            </Stack>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        {running ? (
          <Button onClick={handleCancel}>
            {t('storage.migration.cancel')}
          </Button>
        ) : (
          <Button onClick={onClose}>{t('storage.migration.close')}</Button>
        )}
        <Button
          variant="contained"
          onClick={handleRun}
          disabled={!file || running}
        >
          {t('storage.migration.run')}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
