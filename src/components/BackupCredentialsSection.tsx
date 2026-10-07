/**
 * Settings section for backup credentials: lists the standing credentials
 * the account's backup exports established, one per bundle written, and
 * removes one (a real removal: the document entry, the roster wrap, and the
 * unlock Space all go, so the bundle that packed it no longer signs in).
 * Nothing is created here; a credential is minted only by the Storage
 * page's export. No last-method guard is needed: the credential this session
 * entered on always stands beside a backup credential, so removing one never
 * leaves the account with no unlock method.
 *
 * The removal strikes the credential's ladder VM. Its confirmation dialog
 * lists the connected agents holding a grant that VM signed, each ticked by
 * default; an unticked agent is marked declined. Once the removal resolves,
 * the ticked agents are restored and the Settings inbox pass runs.
 */
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
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
import { GenerationDelegationRenewalError } from '@/session/annexReach'
import { retiredCredentialWithdrawnKeys } from '@/session/credentialRotation'
import { useAgentReconnect } from '@/hooks/useAgentReconnect'
import {
  AgentReconnectList,
  AgentReconnectNotice
} from '@/components/AgentReconnectList'
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

  // The entry the confirm dialog is open on.
  const [pending, setPending] = useState<BackupCredentialUnlockMethod | null>(
    null
  )
  // The connected agents holding a grant the removed credential's ladder VM
  // signed, listed in the dialog.
  const agents = useAgentReconnect({
    session,
    withdrawn: pending
      ? {
          key: pending.unlockSpaceId,
          keys: () =>
            retiredCredentialWithdrawnKeys({ session, entry: pending })
        }
      : null
  })

  /**
   * Runs the removal, then marks the unticked agents declined, restores the
   * ticked agents, and runs the inbox pass. A failed removal declines
   * nothing.
   *
   * @param entry {BackupCredentialUnlockMethod}
   * @returns {Promise<void>}
   */
  const runRemove = async (entry: BackupCredentialUnlockMethod) => {
    if (removingSpaceId) {
      return
    }
    setRemovingSpaceId(entry.unlockSpaceId)
    setErrorKey(null)
    try {
      await agents.runCeremony(() =>
        removeAccountBackupCredential({ session, entry })
      )
      setPending(null)
      showToast({ message: t('settings.backupCredentials.removed') })
      await reload()
    } catch (err) {
      log.error('Could not remove the backup credential', { err })
      setPending(null)
      if ((err as { name?: string }).name === 'ActingCredentialRemovalError') {
        setErrorKey('settings.backupCredentials.actingCredential')
      } else if (err instanceof GenerationDelegationRenewalError) {
        // Refused before the strike: the backup credential still stands.
        setErrorKey('settings.backupCredentials.removeRefusedRenewal')
      } else {
        setErrorKey('settings.backupCredentials.revokeError')
      }
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
                onClick={() => setPending(entry)}
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
      <AgentReconnectNotice state={agents.state} />

      <Dialog
        open={pending !== null}
        onClose={() => {
          if (!removingSpaceId) {
            setPending(null)
          }
        }}
        fullWidth
      >
        <DialogContent>
          <DialogContentText>
            {t('settings.backupCredentials.removeConfirm')}
          </DialogContentText>
          <AgentReconnectList
            agents={agents.agents}
            mode="tick"
            isTicked={agents.isTicked}
            onToggle={agents.toggle}
            disabled={removingSpaceId !== null}
          />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setPending(null)}
            disabled={removingSpaceId !== null}
          >
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            color="error"
            loading={removingSpaceId !== null}
            disabled={registryRepairing || agents.loading}
            onClick={() => {
              if (pending) {
                void runRemove(pending)
              }
            }}
          >
            {t('settings.backupCredentials.remove')}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}
