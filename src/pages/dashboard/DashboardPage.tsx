import { useState, useEffect, useCallback } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import Button from '@mui/material/Button'
import {
  MdAddCircleOutline,
  MdClose,
  MdQrCodeScanner,
  MdSync
} from 'react-icons/md'
import { Link as RouterLink, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { FuseOptionKey } from 'fuse.js'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { loadPasskeySafetyNotice } from '@/lib/sessionKey'
import { syncController } from '@/stores/syncController'
import { flattenSearchValues } from '@/lib/searchValues'
import { useSearch } from '@/hooks/useSearch'
import { dashboardStyles } from '@/styles/appStyles'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialCard } from '@/components/CredentialCard'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { SearchField } from '@/components/SearchField'
import { ScanCredentialQrDialog } from '@/components/ScanCredentialQrDialog'
import type { StoredCredential } from '@/types/credential'

// Declared outside the component so this array is the same object on every
// render; useSearch's index is memoized on it, so a fresh array each render
// would rebuild the index on every keystroke. The one `getFn` key pulls out
// every value in the credential instead of naming fields one by one, so
// search covers the whole credential; `proof` is skipped since it's a
// cryptographic signature, not something a user would search for.
const CREDENTIAL_SEARCH_KEYS: FuseOptionKey<StoredCredential>[] = [
  {
    name: 'vcFields',
    getFn: item => flattenSearchValues(item.vc, ['proof'])
  }
]

export function DashboardPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [scanQrOpen, setScanQrOpen] = useState(false)
  const [loadError, setLoadError] = useState(false)
  // Rows the vault is unlocked for but that still would not decrypt (corrupted
  // or written under a mismatched KAK). Skipped by the list read; surfaced here
  // so the user can see and clear them rather than one poisoned row hanging the
  // page.
  const [undecryptableCount, setUndecryptableCount] = useState(0)
  // The passkey-only safety notice: present when this wallet was created with a
  // single passkey and no second unlock method has been added yet. Drives a
  // recurring "add a second login method" prompt.
  const [passkeySafetyNotice, setPasskeySafetyNotice] = useState<{
    backupEligibility: boolean
    backupState: boolean
    createdAt: string
  } | null>(null)

  const {
    query,
    setQuery,
    results: searchedCredentials
  } = useSearch({ items: credentials, keys: CREDENTIAL_SEARCH_KEYS })

  const handleQrCredentialsReady = useCallback(
    (resolved: IVerifiableCredential[]) => {
      setScanQrOpen(false)
      navigate('/accept-credentials', { state: { credentials: resolved } })
    },
    [navigate]
  )

  // `isStale` lets the mount effect drop a read whose effect was cleaned up;
  // the imperative refreshes never cancel and pass nothing.
  const loadCredentials = useCallback(
    async (isStale?: () => boolean) => {
      if (!session?.storage) {
        throw new Error('Storage not initialized')
      }
      const vcs = await session.storage.listCredentials()
      if (isStale?.()) {
        return
      }
      setCredentials(vcs)
      setUndecryptableCount(session.storage.undecryptableCredentials)
      setLoadError(false)
    },
    [session]
  )

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      try {
        await loadCredentials(() => cancelled)
      } catch (err) {
        // A failed read must not leave the page spinning forever.
        console.error('Could not load credentials:', err)
        if (!cancelled) {
          setLoadError(true)
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }
    initialLoad()

    // clean up effect
    return () => {
      cancelled = true
    }
  }, [session, loadCredentials])

  useEffect(() => {
    let cancelled = false
    async function loadNotice() {
      if (!session || session.isGuest) {
        return
      }
      try {
        const notice = await loadPasskeySafetyNotice({
          controller: session.user.id
        })
        if (!cancelled) {
          setPasskeySafetyNotice(notice)
        }
      } catch (err) {
        console.error('Could not load the passkey-safety notice:', err)
      }
    }
    void loadNotice()
    return () => {
      cancelled = true
    }
  }, [session])

  async function handleSync() {
    setSyncing(true)
    try {
      // Kick an immediate replication cycle (no-op for guests / no remote);
      // pulled changes land in the local replica in the background.
      syncController.reSync()
      await loadCredentials()
    } catch (err) {
      console.error('Could not refresh credentials:', err)
      setLoadError(true)
    } finally {
      // Always release the Sync button, even on a failed refresh.
      setSyncing(false)
    }
  }

  async function handleRemoveUndecryptable() {
    if (!session?.storage) {
      return
    }
    try {
      const removed = session.storage.undecryptableCredentials
      await session.storage.purgeUndecryptableCredentials()
      await loadCredentials()
      showToast({
        message: t('dashboard.undecryptableRemoved', { count: removed })
      })
    } catch (err) {
      console.error('Could not remove undecryptable credentials:', err)
      setLoadError(true)
    }
  }

  return (
    <DashboardLayout title={t('dashboard.title')}>
      <Stack
        direction="row"
        spacing={2}
        sx={dashboardStyles.dashboardCredentialActions}
      >
        <Button
          variant="outlined"
          component={RouterLink}
          to="/add-credential"
          startIcon={<MdAddCircleOutline size={20} />}
          sx={dashboardStyles.addCredentialLink}
        >
          {t('dashboard.addCredential')}
        </Button>
        <Button
          variant="outlined"
          startIcon={<MdQrCodeScanner size={20} />}
          sx={dashboardStyles.addCredentialLink}
          onClick={() => setScanQrOpen(true)}
        >
          {t('dashboard.scanQr.button')}
        </Button>
      </Stack>

      <ScanCredentialQrDialog
        open={scanQrOpen}
        onClose={() => setScanQrOpen(false)}
        onCredentialsReady={handleQrCredentialsReady}
      />

      {loadError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {t('dashboard.loadError')}
        </Alert>
      )}

      {undecryptableCount > 0 && (
        <Alert
          severity="warning"
          sx={{ mb: 2 }}
          action={
            <Button
              color="inherit"
              size="small"
              onClick={handleRemoveUndecryptable}
            >
              {t('dashboard.removeUndecryptable')}
            </Button>
          }
        >
          {t('dashboard.undecryptable', { count: undecryptableCount })}
        </Alert>
      )}

      {passkeySafetyNotice && (
        <Alert
          severity={passkeySafetyNotice.backupState ? 'info' : 'warning'}
          sx={{ mb: 2 }}
          // The action carries its own close button (an `action` prop replaces
          // the Alert's built-in `onClose` icon). Dismissing clears only the
          // component state -- the notice record is left in place, so the
          // prompt recurs on the next visit until a second unlock method
          // resolves it.
          action={
            <Stack direction="row" sx={{ alignItems: 'center', gap: 0.5 }}>
              <Button
                component={RouterLink}
                to="/settings"
                color="inherit"
                size="small"
              >
                {t('dashboard.passkeySafety.action')}
              </Button>
              <IconButton
                color="inherit"
                size="small"
                aria-label={t('common.close')}
                onClick={() => setPasskeySafetyNotice(null)}
              >
                <MdClose size={18} />
              </IconButton>
            </Stack>
          }
        >
          {passkeySafetyNotice.backupState
            ? t('dashboard.passkeySafety.synced')
            : t('dashboard.passkeySafety.notSynced')}
        </Alert>
      )}

      <Box sx={dashboardStyles.credentialsSection}>
        <Stack sx={dashboardStyles.credentialsHeadingRow}>
          <Typography variant="h5" sx={dashboardStyles.credentialsHeading}>
            {t('dashboard.credentialsHeading')}
          </Typography>
          <Button
            variant="outlined"
            size="small"
            onClick={handleSync}
            disabled={syncing}
            startIcon={
              <MdSync size={16} style={dashboardStyles.syncIcon(syncing)} />
            }
            sx={dashboardStyles.syncButton}
          >
            {t('common.sync')}
          </Button>
        </Stack>
        {!loading && credentials.length > 0 && (
          <SearchField
            value={query}
            onChange={setQuery}
            placeholder={t('dashboard.searchPlaceholder')}
            sx={{ mt: 2 }}
          />
        )}
        {loading ? (
          <LoadingSpinner />
        ) : searchedCredentials.length === 0 && credentials.length > 0 ? (
          <Typography color="text.secondary" sx={{ mt: 3 }}>
            {t('dashboard.noResults')}
          </Typography>
        ) : (
          <Box sx={dashboardStyles.credentialsGrid}>
            {searchedCredentials.map(({ cid, vc }) => (
              <CredentialCard key={cid} cid={cid} credential={vc} />
            ))}
          </Box>
        )}
      </Box>
    </DashboardLayout>
  )
}
