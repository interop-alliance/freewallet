import { useCallback, useEffect, useState } from 'react'
import type { Session } from '@/types/auth'
import type { CredentialShareActions } from '@/types/credentialActions'

export function useCredentialPublicLink({
  cid,
  session
}: {
  cid?: string
  session: Session | null
}) {
  const [isShared, setIsShared] = useState(false)
  const [publicLink, setPublicLink] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(false)

  const canShare = !!session?.storage.canShare

  useEffect(() => {
    if (!session || !cid || !canShare) {
      return
    }
    session.storage
      .isShared({ cid })
      .then(shared => {
        setIsShared(shared)
        setPublicLink(
          shared ? (session.storage.publicLinkUrl({ cid }) ?? null) : null
        )
      })
      .catch((err: unknown) => {
        console.error('Error checking public link status:', err)
      })
  }, [canShare, cid, session])

  const create = useCallback(async () => {
    if (!session || !cid) {
      return
    }
    setBusy(true)
    setError(false)
    try {
      const url = await session.storage.createPublicLink({ cid })
      setPublicLink(url)
      setIsShared(true)
      await session.storage.addHistoryCredentialShared({
        cid,
        user: session.user
      })
    } catch (err) {
      console.error('Error creating public link:', err)
      setError(true)
    } finally {
      setBusy(false)
    }
  }, [cid, session])

  const remove = useCallback(async () => {
    if (!session || !cid) {
      return
    }
    setBusy(true)
    setError(false)
    try {
      await session.storage.removePublicLink({ cid })
      setPublicLink(null)
      setIsShared(false)
      await session.storage.addHistoryCredentialUnshared({
        cid,
        user: session.user
      })
    } catch (err) {
      console.error('Error removing public link:', err)
      setError(true)
    } finally {
      setBusy(false)
    }
  }, [cid, session])

  const toggle = useCallback(() => {
    if (isShared) {
      void remove()
    } else {
      void create()
    }
  }, [create, isShared, remove])

  const share: CredentialShareActions | undefined = canShare
    ? { isShared, publicLink, busy, toggle }
    : undefined

  return { share, error }
}
