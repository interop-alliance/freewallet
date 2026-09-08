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
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { syncController } from '@/stores/syncController'
import { usePullSettled } from '@/hooks/usePullSettled'
import { PRIVATE_CREDENTIALS_COLLECTION } from '@interop/wallet-core/space'
import { flattenSearchValues } from '@/lib/searchValues'
import { useAsyncLoad } from '@/hooks/useAsyncLoad'
import { useSearch } from '@/hooks/useSearch'
import { dashboardStyles } from '@/styles/appStyles'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialCard } from '@/components/CredentialCard'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { SearchField } from '@/components/SearchField'
import { ScanCredentialQrDialog } from '@/components/ScanCredentialQrDialog'
import type { WalletInputOutcome } from '@/lib/resolveWalletInput'
import { externalRequestPath } from '@/lib/walletRequest/externalRequest'
import type { StoredCredential } from '@/types/credential'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:dashboard')

// The collections whose pulls change what this page lists.
const PULLED_COLLECTIONS = [PRIVATE_CREDENTIALS_COLLECTION]

// Declared outside the component so this array is the same object on every
// render; useSearch's index is memoized on it, so a fresh array each render
// would rebuild the index on every keystroke. The one `getFn` key pulls out
// every value in the credential instead of naming fields one by one, so
// search covers the whole credential; `proof` is skipped since it's a
// cryptographic signature, not something a user would search for.
const CREDENTIAL_SEARCH_KEYS: FuseOptionKey<StoredCredential>[] = [
  {
    name: 'vcFields',
    getFn: item =>
      flattenSearchValues({ root: item.vc, excludeKeys: ['proof'] })
  }
]

export function DashboardPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [syncing, setSyncing] = useState(false)
  const [scanQrOpen, setScanQrOpen] = useState(false)
  // Covers a failed load and a failed purge alike; a successful load clears it.
  const [loadError, setLoadError] = useState(false)
  // Rows the vault is unlocked for but that still would not decrypt (corrupted
  // or written under a mismatched KAK). Skipped by the list read; surfaced here
  // so the user can see and clear them rather than one poisoned row hanging the
  // page.
  const [undecryptableCount, setUndecryptableCount] = useState(0)
  // Dismissing the passkey-safety notice hides it for this visit only.
  const [noticeDismissed, setNoticeDismissed] = useState(false)
  const seedReady = session?.welcomeSeedReady

  const {
    query,
    setQuery,
    results: searchedCredentials
  } = useSearch({ items: credentials, keys: CREDENTIAL_SEARCH_KEYS })

  const handleQrResolved = useCallback(
    (outcome: WalletInputOutcome) => {
      setScanQrOpen(false)
      if (outcome.kind === 'interaction-url') {
        navigate(externalRequestPath({ url: outcome.url }))
        return
      }
      navigate('/accept-credentials', {
        state: { credentials: outcome.credentials }
      })
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

  // Timing mark: paired with the signup and login submit marks to measure
  // how long reaching the dashboard takes.
  useEffect(() => {
    log.info('Dashboard rendered', { at: new Date().toISOString() })
  }, [])

  const { loading, reload } = useAsyncLoad(
    ({ isCancelled }) => loadCredentials(isCancelled),
    [loadCredentials],
    {
      enabled: Boolean(session?.storage),
      // A failed read must not leave the page spinning forever.
      onError: err => {
        log.error('Could not load credentials', { err })
        setLoadError(true)
      }
    }
  )

  // Background replication lands rows after the mount read (on a fresh
  // browser the first pull of `private-credentials` completes moments after
  // the dashboard rendered its empty list), so re-read when that pull
  // settles.
  const reloadAfterPull = useCallback(() => {
    loadCredentials().catch((err: unknown) => {
      log.error('Could not reload credentials after a pull', { err })
    })
  }, [loadCredentials])
  usePullSettled({
    collectionIds: PULLED_COLLECTIONS,
    onSettled: reloadAfterPull
  })

  // The credential-anchored signup seeds its welcome content behind the
  // dashboard navigation; while its promise is pending an indicator shows in
  // place of the empty state, and the list reloads when it settles.
  const { loading: seeding } = useAsyncLoad(
    async ({ isCancelled }) => {
      // Never rejects: the seeding helper is best-effort throughout.
      await seedReady
      if (isCancelled()) {
        return
      }
      await loadCredentials(isCancelled)
    },
    [seedReady, loadCredentials],
    {
      enabled: Boolean(seedReady),
      // The initial load's error handling owns the loadError banner; a
      // failed reload here just leaves the current (empty) list standing.
      onError: err => {
        log.error('Could not reload credentials after the welcome seed', {
          err
        })
      }
    }
  )

  // The passkey-only safety notice: present when this wallet was created with a
  // single passkey and no second unlock method has been added yet. Drives a
  // recurring "add a second login method" prompt.
  const { data: loadedNotice } = useAsyncLoad(
    async () => {
      if (!session || session.isGuest) {
        return null
      }
      return session.profile.persistence.passkeyNotices.load({
        controller: session.user.id
      })
    },
    [session],
    {
      onError: err => {
        log.error('Could not load the passkey-safety notice', { err })
      }
    }
  )
  const passkeySafetyNotice = noticeDismissed ? null : (loadedNotice ?? null)

  async function handleSync() {
    setSyncing(true)
    try {
      // Kick an immediate replication cycle (no-op for guests / no remote);
      // pulled changes land in the local replica in the background.
      syncController.reSync()
      await reload()
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
      log.error('Could not remove undecryptable credentials', { err })
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
        onResolved={handleQrResolved}
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
                onClick={() => setNoticeDismissed(true)}
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
        ) : seeding && credentials.length === 0 ? (
          <Box sx={{ mt: 3 }}>
            <LoadingSpinner />
            <Typography
              variant="body2"
              color="text.secondary"
              align="center"
              sx={{ mt: 1 }}
            >
              {t('dashboard.seedingWelcome')}
            </Typography>
          </Box>
        ) : credentials.length === 0 && !loadError ? (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
            {t('dashboard.empty')}
          </Typography>
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
