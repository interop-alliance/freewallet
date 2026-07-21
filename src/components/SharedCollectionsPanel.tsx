/**
 * "Shared collections" settings panel. For each encrypted standard collection
 * (the `WALLET_STANDARD_COLLECTIONS` entries carrying an `encryption` marker),
 * it lists the readers the collection is currently shared with -- their
 * controller DID (or key id), the grant's expiry, and a "Remove access" action.
 *
 * Removing access is one indivisible operation with two honest halves:
 * `unshareCollection` rotates the collection's key epoch (so resources written
 * afterwards are unreadable to the removed reader) and revokes its storage
 * authorization (so the server stops serving it ciphertext). Neither half claws
 * back data the reader already fetched -- the confirmation dialog says so
 * plainly. Un-sharing rewrites the Collection Description and revokes with the
 * root key, so it needs a full (passphrase) session; the delegated tier sees
 * the list read-only with a re-login prompt.
 *
 * There is deliberately no "add share" flow here: how an app publishes its
 * recipient key is an open design question, so this panel only lists and
 * removes.
 */
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { DATE_FMT, WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { dashboardStyles } from '@/styles/appStyles'
import { showToast } from '@/stores/toastStore'
import type { Session } from '@/types/auth'

/**
 * One reader a collection is shared with, as returned by
 * `StorageManager.listCollectionShares`.
 */
type CollectionShare = {
  recipientId: string
  controller?: string
  expires?: string
}

// The encrypted standard collections -- the only ones that can be shared.
const ENCRYPTED_COLLECTIONS = WALLET_STANDARD_COLLECTIONS.filter(
  ({ encryption }) => encryption
)

/**
 * Renders the shared-collections settings section for the current session.
 *
 * @param options {object}
 * @param options.session {Session}   the logged-in session
 * @returns {JSX.Element}
 */
export function SharedCollectionsPanel({ session }: { session: Session }) {
  const { t, i18n } = useTranslation()
  const hasRemoteStorage = session.storage.hasRemoteStorage
  const vaultLocked = session.storage.vaultLocked
  // Un-sharing rewrites the Collection Description and revokes zcaps with the
  // root key, so it needs a full (passphrase) session -- the delegated tier's
  // read-only Space zcaps cannot rotate the epoch.
  const canManageShares = session.tier === 'full'

  const [sharesByCollection, setSharesByCollection] = useState<
    Record<string, CollectionShare[]>
  >({})
  const [loadError, setLoadError] = useState(false)
  const [removeTarget, setRemoveTarget] = useState<{
    collectionId: string
    recipientId: string
  } | null>(null)
  const [removeDialogOpen, setRemoveDialogOpen] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState(false)

  // Fetches every encrypted collection's current reader roster, keyed by WAS
  // collection id. Pure (no state writes) so callers own their own setState --
  // the mount effect below guards against a stale write, the remove handler
  // just refreshes.
  const fetchShares = useCallback(async () => {
    const entries = await Promise.all(
      ENCRYPTED_COLLECTIONS.map(
        async ({ id }) =>
          [
            id,
            await session.storage.listCollectionShares({ collectionId: id })
          ] as const
      )
    )
    return Object.fromEntries(entries) as Record<string, CollectionShare[]>
  }, [session])

  // Load the rosters on mount. Skipped without a remote store (nothing is
  // shared) or with a locked vault (the owner key can't be resolved to filter
  // itself out of the roster, so the list is unreliable).
  useEffect(() => {
    if (!hasRemoteStorage || vaultLocked) {
      return
    }
    let cancelled = false
    async function load() {
      try {
        const record = await fetchShares()
        if (!cancelled) {
          setSharesByCollection(record)
          setLoadError(false)
        }
      } catch (err) {
        console.error('Could not load the collection shares:', err)
        if (!cancelled) {
          setLoadError(true)
        }
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [fetchShares, hasRemoteStorage, vaultLocked])

  const openRemoveDialog = (target: {
    collectionId: string
    recipientId: string
  }) => {
    setRemoveError(false)
    setRemoveTarget(target)
    setRemoveDialogOpen(true)
  }

  const handleRemoveAccess = async () => {
    if (!removeTarget) {
      return
    }
    setRemoving(true)
    setRemoveError(false)
    try {
      await session.storage.unshareCollection({
        profile: session.profile,
        user: session.user,
        collectionId: removeTarget.collectionId,
        recipientId: removeTarget.recipientId
      })
      setRemoveDialogOpen(false)
      setRemoveTarget(null)
      showToast({ message: t('settings.sharedRemoved') })
      try {
        setSharesByCollection(await fetchShares())
        setLoadError(false)
      } catch (err) {
        console.error('Could not reload the collection shares:', err)
        setLoadError(true)
      }
    } catch (err) {
      console.error('Could not remove collection access:', err)
      setRemoveError(true)
    } finally {
      setRemoving(false)
    }
  }

  return (
    <Stack sx={{ gap: 1 }}>
      <Typography variant="h6">{t('settings.sharedSection')}</Typography>
      <Typography variant="body2" color="text.secondary">
        {t('settings.sharedSectionHint')}
      </Typography>

      {!hasRemoteStorage ? (
        <Typography variant="body2" color="text.secondary">
          {t('settings.sharedRequiresRemote')}
        </Typography>
      ) : vaultLocked ? (
        <Typography variant="body2" color="text.secondary">
          {t('settings.sharedVaultLocked')}
        </Typography>
      ) : (
        <>
          {loadError && (
            <Alert severity="warning">{t('settings.sharedLoadError')}</Alert>
          )}
          {!canManageShares && (
            <Typography variant="body2" color="text.secondary">
              {t('settings.sharedRequiresFullSession')}
            </Typography>
          )}
          {ENCRYPTED_COLLECTIONS.map(({ id, name }) => {
            const shares = sharesByCollection[id] ?? []
            const collectionName = t(`storage.collectionNames.${id}`, {
              defaultValue: name
            })
            return (
              <Stack key={id} sx={{ gap: 1, mt: 1 }}>
                <Typography variant="subtitle2">{collectionName}</Typography>
                {shares.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">
                    {t('settings.sharedNothingForCollection')}
                  </Typography>
                ) : (
                  shares.map(share => (
                    <Stack
                      key={share.recipientId}
                      sx={dashboardStyles.sharedShareRow}
                    >
                      <Typography
                        variant="body2"
                        sx={dashboardStyles.sharedRecipientDid}
                      >
                        {share.controller ?? share.recipientId}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {share.expires
                          ? t('settings.sharedExpires', {
                              date: new Date(share.expires).toLocaleDateString(
                                i18n.language,
                                DATE_FMT
                              )
                            })
                          : t('settings.sharedExpiryUnknown')}
                      </Typography>
                      <Button
                        variant="outlined"
                        size="small"
                        color="error"
                        sx={{
                          textTransform: 'none',
                          borderRadius: 2,
                          alignSelf: 'flex-start'
                        }}
                        disabled={!canManageShares}
                        onClick={() =>
                          openRemoveDialog({
                            collectionId: id,
                            recipientId: share.recipientId
                          })
                        }
                      >
                        {t('settings.sharedRemove')}
                      </Button>
                    </Stack>
                  ))
                )}
              </Stack>
            )
          })}
        </>
      )}

      <Dialog
        open={removeDialogOpen}
        onClose={() => {
          if (!removing) {
            setRemoveDialogOpen(false)
          }
        }}
      >
        <DialogTitle>{t('settings.sharedRemoveTitle')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('settings.sharedRemoveConfirm')}
          </DialogContentText>
          {removeError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {t('settings.sharedRemoveFailed')}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setRemoveDialogOpen(false)}
            disabled={removing}
            sx={{ textTransform: 'none' }}
          >
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            disableElevation
            color="error"
            onClick={handleRemoveAccess}
            disabled={removing}
            sx={{ textTransform: 'none' }}
          >
            {removing
              ? t('settings.sharedRemoving')
              : t('settings.sharedRemoveConfirmAction')}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}
