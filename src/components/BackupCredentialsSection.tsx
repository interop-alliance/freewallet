/**
 * Settings section for backup credentials: lists the standing credentials
 * the account's backup exports established, one per bundle written, and
 * removes one (a real removal: the document entry, the roster wrap, and the
 * unlock Space all go, so the bundle that packed it no longer signs in).
 * Nothing is created here; a credential is minted only by the Storage
 * page's export. No last-method guard is needed: the credential this session
 * entered on always stands beside a backup credential, so removing one never
 * leaves the account with no unlock method.
 */
import Alert from '@mui/material/Alert'
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { MdDeleteOutline } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { useState } from 'react'
import type { Session } from '@/types/auth'
import type { BackupCredentialUnlockMethod } from '@/session/unlockMethods'
import {
  listBackupCredentialEntries,
  removeAccountBackupCredential
} from '@/session/backupCredential'
import { showToast } from '@/stores/toastStore'
import { useAsyncLoad } from '@/hooks/useAsyncLoad'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:backup-credentials')

/**
 * The Backup credentials panel.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.registryRepairing] {boolean}   Settings is mending the
 *   unlock-methods registry; removing a backup credential waits
 */
export function BackupCredentialsSection({
  session,
  registryRepairing = false
}: {
  session: Session
  registryRepairing?: boolean
}) {
  const { t, i18n } = useTranslation()
  const [removingSpaceId, setRemovingSpaceId] = useState<string | null>(null)
  const [errorKey, setErrorKey] = useState<string | null>(null)

  const { data: entries, reload } = useAsyncLoad(async () => {
    // Wait out the login-time registry passes first, so a mid-repair
    // registry is not read as "no backups".
    await session.registryReady
    return await listBackupCredentialEntries({ session })
  }, [session])

  const handleRemove = async (entry: BackupCredentialUnlockMethod) => {
    if (removingSpaceId) {
      return
    }
    if (!window.confirm(t('settings.backupCredentials.removeConfirm'))) {
      return
    }
    setRemovingSpaceId(entry.unlockSpaceId)
    setErrorKey(null)
    try {
      await removeAccountBackupCredential({ session, entry })
      showToast({ message: t('settings.backupCredentials.removed') })
      await reload()
    } catch (err) {
      log.error('Could not remove the backup credential', { err })
      setErrorKey(
        (err as { name?: string }).name === 'ActingCredentialRemovalError'
          ? 'settings.backupCredentials.actingCredential'
          : 'settings.backupCredentials.revokeError'
      )
    } finally {
      setRemovingSpaceId(null)
    }
  }

  return (
    <Stack sx={{ gap: 1 }}>
      <Typography variant="h6">
        {t('settings.backupCredentials.section')}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {t('settings.backupCredentials.intro')}
      </Typography>

      {entries !== undefined && entries.length > 0 && (
        <Stack sx={{ gap: 0.5 }}>
          {entries.map(entry => (
            <Stack
              key={entry.unlockSpaceId}
              direction="row"
              sx={{ alignItems: 'center', gap: 2 }}
            >
              <Typography variant="body2" sx={{ minWidth: 200 }}>
                {entry.label}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {formatDate({
                  isoDate: entry.createdAt,
                  locale: i18n.language
                })}
              </Typography>
              <IconButton
                size="small"
                aria-label={t('settings.backupCredentials.remove')}
                disabled={removingSpaceId !== null || registryRepairing}
                onClick={() => void handleRemove(entry)}
              >
                <MdDeleteOutline />
              </IconButton>
            </Stack>
          ))}
        </Stack>
      )}
      {entries !== undefined && entries.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          {t('settings.backupCredentials.none')}
        </Typography>
      )}
      {errorKey && <Alert severity="error">{t(errorKey)}</Alert>}
    </Stack>
  )
}
