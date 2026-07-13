import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { showToast } from '@/stores/toastStore'
import { cidFrom } from '@/lib/cidFrom'
import type { Session } from '@/types/auth'
import type { CredentialShareActions } from '@/types/credentialActions'

/**
 * Drives a credential's public-link (sharing) state. Sharing is
 * content-addressed: the public copy is keyed by the credential's cid (a hash
 * of its content), computed here from the decrypted VC -- not by the opaque EDV
 * id the encrypted `private-credentials` collection uses for routing.
 */
export function useCredentialPublicLink({
  credential,
  session
}: {
  credential?: IVerifiableCredential
  session: Session | null
}) {
  const { t } = useTranslation()
  const [cid, setCid] = useState<string | null>(null)
  const [isShared, setIsShared] = useState(false)
  const [publicLink, setPublicLink] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(false)

  const canShare = !!session?.storage.canShare

  useEffect(() => {
    if (!credential) {
      return
    }
    let cancelled = false
    cidFrom({ doc: credential })
      .then(contentCid => {
        if (!cancelled) {
          setCid(contentCid)
        }
      })
      .catch((err: unknown) => {
        console.error('Error computing credential cid:', err)
      })
    return () => {
      cancelled = true
    }
  }, [credential])

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
    if (!session || !cid || !credential) {
      return
    }
    setBusy(true)
    setError(false)
    try {
      const url = await session.storage.createPublicLink({ credential })
      setPublicLink(url)
      setIsShared(true)
      await session.storage.addHistoryCredentialShared({
        cid,
        user: session.user
      })
      showToast({ message: t('credential.publicLinkCreated') })
    } catch (err) {
      console.error('Error creating public link:', err)
      setError(true)
    } finally {
      setBusy(false)
    }
  }, [cid, credential, session, t])

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
      showToast({ message: t('credential.publicLinkRemoved') })
    } catch (err) {
      console.error('Error removing public link:', err)
      setError(true)
    } finally {
      setBusy(false)
    }
  }, [cid, session, t])

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
