import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { showToast } from '@/stores/toastStore'
import { PublicCopyRetractionError } from '@/stores/storageManager'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:delete')

/**
 * Shared delete flow for credentials that may have a public link. When the
 * credential is shared, opens a confirmation dialog; otherwise deletes
 * immediately.
 *
 * Ordering (public copy retracted first, and blocking when it is live) lives in
 * `StorageManager.deleteCredential`, so every caller gets it; this hook only
 * passes the user's "keep the public copy" choice through and renders the
 * refusal. `deleteError` is the message to show, or `null`.
 */
export function useCredentialDelete({
  session,
  cid,
  title,
  onSuccess
}: {
  session: Session | null
  cid?: string
  title?: string
  onSuccess: () => void
}) {
  const { t } = useTranslation()
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  /**
   * The one delete path. `keepPublicCopy` is the deliberate retention choice
   * (only ever true from the dialog's "keep public copy" button); every other
   * entry leaves it false, so the storage layer retracts a public copy it finds
   * even when the pre-dialog `isShared` check said there was none.
   */
  const performDelete = useCallback(
    async ({
      keepPublicCopy,
      removedPublic
    }: {
      keepPublicCopy: boolean
      removedPublic: boolean
    }) => {
      if (!session || !cid) {
        return
      }
      setDeleteError(null)
      setDeleting(true)
      try {
        await session.storage.deleteCredential({ cid, keepPublicCopy })
        await session.storage.addHistoryCredentialDeleted({
          cid,
          title: title ?? cid,
          user: session.user
        })
      } catch (err) {
        log.error('Error deleting credential', { err })
        setDeleteError(
          err instanceof PublicCopyRetractionError
            ? t('credential.deletePublicRetractError')
            : t('credential.deleteError')
        )
        setDeleting(false)
        setDeleteDialogOpen(false)
        return
      }
      setDeleteDialogOpen(false)
      // Posted to the global toast store rather than local state: onSuccess
      // navigates away from this page, so only a store-backed message survives
      // to be shown on the page the user lands on.
      showToast({
        message: removedPublic
          ? t('credential.deletedWithPublic')
          : t('credential.deleted')
      })
      onSuccess()
    },
    [session, cid, title, onSuccess, t]
  )

  const runDelete = useCallback(
    async ({ alsoRemovePublic }: { alsoRemovePublic: boolean }) =>
      await performDelete({
        keepPublicCopy: !alsoRemovePublic,
        removedPublic: alsoRemovePublic
      }),
    [performDelete]
  )

  const requestDelete = useCallback(async () => {
    if (!session || !cid) {
      return
    }
    const shared = await session.storage.isShared({ cid })
    if (shared) {
      setDeleteDialogOpen(true)
    } else {
      await performDelete({ keepPublicCopy: false, removedPublic: false })
    }
  }, [session, cid, performDelete])

  const cancelDelete = useCallback(() => {
    setDeleteDialogOpen(false)
  }, [])

  return {
    deleteError,
    deleteDialogOpen,
    deleting,
    requestDelete,
    runDelete,
    cancelDelete
  }
}
