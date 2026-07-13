import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { showToast } from '@/stores/toastStore'
import type { Session } from '@/types/auth'

/**
 * Shared delete flow for credentials that may have a public link. When the
 * credential is shared, opens a confirmation dialog; otherwise deletes
 * immediately.
 */
export function useCredentialDelete({
  session,
  cid,
  onSuccess
}: {
  session: Session | null
  cid?: string
  onSuccess: () => void
}) {
  const { t } = useTranslation()
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState(false)

  const runDelete = useCallback(
    async ({ alsoRemovePublic }: { alsoRemovePublic: boolean }) => {
      if (!session || !cid) {
        return
      }
      setDeleteError(false)
      setDeleting(true)
      try {
        await session.storage.deleteCredential({ cid })
        if (alsoRemovePublic) {
          await session.storage.removePublicLink({ cid })
        }
        await session.storage.addHistoryCredentialDeleted({
          cid,
          user: session.user
        })
      } catch (err) {
        console.error('Error deleting credential:', err)
        setDeleteError(true)
        setDeleting(false)
        setDeleteDialogOpen(false)
        return
      }
      setDeleteDialogOpen(false)
      // Posted to the global toast store rather than local state: onSuccess
      // navigates away from this page, so only a store-backed message survives
      // to be shown on the page the user lands on.
      showToast({
        message: alsoRemovePublic
          ? t('credential.deletedWithPublic')
          : t('credential.deleted')
      })
      onSuccess()
    },
    [session, cid, onSuccess, t]
  )

  const requestDelete = useCallback(async () => {
    if (!session || !cid) {
      return
    }
    const shared = await session.storage.isShared({ cid })
    if (shared) {
      setDeleteDialogOpen(true)
    } else {
      await runDelete({ alsoRemovePublic: false })
    }
  }, [session, cid, runDelete])

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
