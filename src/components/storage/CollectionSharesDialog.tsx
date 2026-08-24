/**
 * The shares dialog behind a collection row's "Shared" chip in the Storage
 * collection list. For one encrypted collection it lists the readers it is
 * currently shared with -- their controller DID (or key id), the grant's
 * expiry, and a "Remove access" action.
 *
 * Removing access is one indivisible operation with two honest halves:
 * `unshareCollection` rotates the collection's key epoch (so resources written
 * afterwards are unreadable to the removed reader) and revokes its storage
 * authorization (so the server stops serving it ciphertext). Neither half claws
 * back data the reader already fetched -- the confirmation dialog says so
 * plainly.
 *
 * There is deliberately no "add share" action here. A share is initiated from
 * the consent screen of a `https://w3id.org/byoe#shared-wallet-collection`
 * capability request (a connected app asking, over CHAPI, to read and decrypt
 * one of these collections); this dialog is where the resulting grant is
 * reviewed and removed.
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
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { removeCollectionShare, type CollectionShare } from '@/session/shares'
import { showToast } from '@/stores/toastStore'
import { dashboardStyles, storageStyles } from '@/styles/appStyles'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:storage')

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
 * Renders one collection's readers and the removal ceremony.
 *
 * @param options {object}
 * @param options.session {Session}          the logged-in session
 * @param options.collectionId {string}      the WAS collection id
 * @param options.collectionName {string}    its display name, for the title
 * @param options.shares {CollectionShare[]} the collection's current readers
 * @param options.onClose {Function}         closes the dialog
 * @param options.onRemoved {Function}       reloads the page's share data
 * @returns {JSX.Element}
 */
export function CollectionSharesDialog({
  session,
  collectionId,
  collectionName,
  shares,
  onClose,
  onRemoved
}: {
  session: Session
  collectionId: string
  collectionName: string
  shares: CollectionShare[]
  onClose: () => void
  onRemoved: () => void
}) {
  const { t, i18n } = useTranslation()
  const [removeTarget, setRemoveTarget] = useState<string | null>(null)
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState(false)

  const handleRemoveAccess = async () => {
    if (!removeTarget) {
      return
    }
    setRemoving(true)
    setRemoveError(false)
    try {
      await removeCollectionShare({
        session,
        collectionId,
        recipientId: removeTarget
      })
      setRemoveTarget(null)
      showToast({ message: t('storage.sharedRemoved') })
      onRemoved()
    } catch (err) {
      log.error('Could not remove collection access', { err })
      setRemoveError(true)
    } finally {
      setRemoving(false)
    }
  }

  return (
    <>
      <Dialog open onClose={onClose} fullWidth maxWidth="sm">
        <DialogTitle>{collectionName}</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            {t('storage.sharedDialogHint')}
          </DialogContentText>
          <Stack sx={{ gap: 1 }}>
            {shares.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('storage.sharedNothingForCollection')}
              </Typography>
            ) : (
              shares.map(share => (
                <Card
                  key={share.recipientId}
                  variant="outlined"
                  sx={storageStyles.sharedReaderCard}
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
                      ? t('storage.sharedExpires', {
                          date: formatDate({
                            isoDate: share.expires,
                            locale: i18n.language
                          })
                        })
                      : t('storage.sharedExpiryUnknown')}
                  </Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    color="error"
                    sx={storageStyles.sharedRemoveButton}
                    onClick={() => {
                      setRemoveError(false)
                      setRemoveTarget(share.recipientId)
                    }}
                  >
                    {t('storage.sharedRemove')}
                  </Button>
                </Card>
              ))
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>{t('common.close')}</Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={removeTarget !== null}
        onClose={() => {
          if (!removing) {
            setRemoveTarget(null)
          }
        }}
      >
        <DialogTitle>{t('storage.sharedRemoveTitle')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('storage.sharedRemoveConfirm')}
          </DialogContentText>
          {removeError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {t('storage.sharedRemoveFailed')}
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
              ? t('storage.sharedRemoving')
              : t('storage.sharedRemoveConfirmAction')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  )
}
