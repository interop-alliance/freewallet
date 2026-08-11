/**
 * "Shared collections" settings panel. For each encrypted standard collection
 * (the `WALLET_STANDARD_COLLECTIONS` entries carrying an `encryption` descriptor),
 * it lists the readers the collection is currently shared with -- their
 * controller DID (or key id), the grant's expiry, and a "Remove access" action.
 *
 * Removing access is one indivisible operation with two honest halves:
 * `unshareCollection` rotates the collection's key epoch (so resources written
 * afterwards are unreadable to the removed reader) and revokes its storage
 * authorization (so the server stops serving it ciphertext). Neither half claws
 * back data the reader already fetched -- the confirmation dialog says so
 * plainly.
 *
 * There is deliberately no "add share" action here. A share is initiated from
 * the consent screen of a `https://w3id.org/byoe#shared-wallet-collection` capability request (a
 * connected app asking, over CHAPI, to read and decrypt one of these
 * collections); this panel is where the resulting grant is reviewed and
 * removed.
 */
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatDate } from '@/lib/viewMappers/formatDate'
import {
  listSharedCollections,
  removeCollectionShare,
  SHAREABLE_COLLECTIONS,
  type CollectionShare
} from '@/session/shares'
import { dashboardStyles } from '@/styles/appStyles'
import { showToast } from '@/stores/toastStore'
import type { Session } from '@/types/auth'

/**
 * A connected app reader's label: its name paired with its origin ("Text
 * Editor (app.example)"). The name is app-supplied display text, so it is
 * never shown without the origin that actually identifies the app. Only called
 * for a share that recorded an `appName`; readers without one show their
 * controller DID alone.
 *
 * @param share {CollectionShare}
 * @returns {string}
 */
function appLabel(share: CollectionShare): string {
  return share.appOrigin
    ? `${share.appName} (${hostOf(share.appOrigin)})`
    : (share.appName ?? '')
}

/**
 * The host of an origin URL, for a compact label. Falls back to the raw string
 * when it does not parse.
 *
 * @param origin {string}
 * @returns {string}
 */
function hostOf(origin: string): string {
  try {
    return new URL(origin).host
  } catch {
    return origin
  }
}

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

  const [sharesByCollection, setSharesByCollection] = useState<
    Record<string, CollectionShare[]>
  >({})
  const [loadError, setLoadError] = useState(false)
  const [removeTarget, setRemoveTarget] = useState<{
    collectionId: string
    recipientId: string
  } | null>(null)
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState(false)

  // Load the rosters on mount. Skipped without a remote store (nothing is
  // shared).
  useEffect(() => {
    if (!hasRemoteStorage) {
      return
    }
    let cancelled = false
    async function load() {
      try {
        const record = await listSharedCollections({ session })
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
  }, [session, hasRemoteStorage])

  const openRemoveDialog = (target: {
    collectionId: string
    recipientId: string
  }) => {
    setRemoveError(false)
    setRemoveTarget(target)
  }

  const handleRemoveAccess = async () => {
    if (!removeTarget) {
      return
    }
    setRemoving(true)
    setRemoveError(false)
    try {
      await removeCollectionShare({
        session,
        collectionId: removeTarget.collectionId,
        recipientId: removeTarget.recipientId
      })
      setRemoveTarget(null)
      showToast({ message: t('settings.sharedRemoved') })
      try {
        setSharesByCollection(await listSharedCollections({ session }))
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
      ) : (
        <>
          {loadError && (
            <Alert severity="warning">{t('settings.sharedLoadError')}</Alert>
          )}
          {SHAREABLE_COLLECTIONS.map(({ id, name }) => {
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
                    <Card
                      key={share.recipientId}
                      variant="outlined"
                      sx={{
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 0.5,
                        p: 1.5
                      }}
                    >
                      {share.appName && (
                        <Typography variant="subtitle2">
                          {appLabel(share)}
                        </Typography>
                      )}
                      <Typography
                        variant="body2"
                        sx={dashboardStyles.sharedRecipientDid}
                      >
                        {share.controller ?? share.recipientId}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {share.expires
                          ? t('settings.sharedExpires', {
                              date: formatDate({
                                isoDate: share.expires,
                                locale: i18n.language
                              })
                            })
                          : t('settings.sharedExpiryUnknown')}
                      </Typography>
                      <Button
                        variant="outlined"
                        size="small"
                        color="error"
                        sx={{
                          borderRadius: 2,
                          alignSelf: 'flex-start'
                        }}
                        onClick={() =>
                          openRemoveDialog({
                            collectionId: id,
                            recipientId: share.recipientId
                          })
                        }
                      >
                        {t('settings.sharedRemove')}
                      </Button>
                    </Card>
                  ))
                )}
              </Stack>
            )
          })}
        </>
      )}

      <Dialog
        open={removeTarget !== null}
        onClose={() => {
          if (!removing) {
            setRemoveTarget(null)
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
          <Button onClick={() => setRemoveTarget(null)} disabled={removing}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleRemoveAccess}
            disabled={removing}
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
