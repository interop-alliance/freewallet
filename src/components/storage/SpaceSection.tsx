/**
 * The Space section: the connected Space's URL and the three account-data
 * actions beside it (backup export, archive import, content migration), with
 * the two dialogs behind the export and the migration. The import action
 * links to the Import page, which gates on the quota before the file picker.
 * The Storage page renders the section as its toolbar and the Settings page
 * renders it above Delete Account.
 */
import { useState } from 'react'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { Link as RouterLink } from 'react-router'
import { BackupExportDialog } from '@/components/storage/BackupExportDialog'
import { ContentMigrationDialog } from '@/components/storage/ContentMigrationDialog'
import { syncController } from '@/stores/syncController'
import { storageStyles } from '@/styles/appStyles'
import { canExportBackup } from '@/session/backupExport'
import type { Session } from '@/types/auth'

/**
 * @param options {object}
 * @param options.session {Session | null}
 * @param [options.registryRepairing] {boolean}   Settings is mending the
 *   unlock-methods registry; the backup export, which establishes a backup
 *   credential there, waits
 * @param [options.onImported] {Function}   Called once a content migration
 *   has landed, so a host that lists the Space's contents can re-list them.
 *   Replication is nudged to re-pull before the callback runs.
 */
export function SpaceSection({
  session,
  registryRepairing = false,
  onImported
}: {
  session: Session | null
  registryRepairing?: boolean
  onImported?: () => void
}) {
  const { t } = useTranslation()
  const [backupOpen, setBackupOpen] = useState(false)
  const [migrationOpen, setMigrationOpen] = useState(false)
  const backupOffered = Boolean(session && canExportBackup({ session }))

  const handleImported = () => {
    syncController.reSync()
    onImported?.()
  }

  return (
    <>
      <Paper variant="outlined" sx={storageStyles.spaceSection}>
        <Stack
          direction={{ xs: 'column', md: 'row' }}
          spacing={2}
          sx={storageStyles.connectedRow}
        >
          <Stack spacing={0.5} sx={{ minWidth: 0, flexGrow: 1 }}>
            <Typography variant="h6" sx={storageStyles.connectedLabel}>
              {t('storage.spaceConnected')}
            </Typography>
            <Typography variant="body2" sx={storageStyles.connectedLink}>
              {session?.storage.spaceUrl || t('storage.noRemoteSpace')}
            </Typography>
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <Button
              variant="contained"
              onClick={() => setBackupOpen(true)}
              disabled={!backupOffered || registryRepairing}
              sx={[
                storageStyles.buttonTextLeft,
                storageStyles.buttonSize.topAction
              ]}
            >
              {t('storage.exportSpace')}
            </Button>
            <Button
              variant="outlined"
              component={RouterLink}
              to="/storage/import"
              sx={[
                storageStyles.buttonTextLeft,
                storageStyles.buttonSize.topAction
              ]}
            >
              {t('storage.importSpace')}
            </Button>
            <Button
              variant="outlined"
              onClick={() => setMigrationOpen(true)}
              disabled={!session}
              sx={[
                storageStyles.buttonTextLeft,
                storageStyles.buttonSize.topAction
              ]}
            >
              {t('storage.migration.action')}
            </Button>
          </Stack>
        </Stack>
      </Paper>

      {session && backupOpen && (
        <BackupExportDialog
          session={session}
          onClose={() => setBackupOpen(false)}
        />
      )}

      {session && migrationOpen && (
        <ContentMigrationDialog
          session={session}
          onClose={() => setMigrationOpen(false)}
          onImported={handleImported}
        />
      )}
    </>
  )
}
