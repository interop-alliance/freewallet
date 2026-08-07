import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { showToast } from '@/stores/toastStore'
import { cidFrom } from '@interop/was-client/sync'
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
  const [isShared, setIsShared] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(false)

  const canShare = !!session?.storage.canShare

  // The cid is a pure, synchronous hash of the decrypted VC, so it derives
  // straight from `credential` rather than living in state behind an effect.
  const cid = useMemo<string | null>(() => {
    if (!credential) {
      return null
    }
    try {
      return cidFrom({ doc: credential })
    } catch (err: unknown) {
      console.error('Error computing credential cid:', err)
      return null
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
      await session.storage.createPublicLink({ credential })
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

  // The public copy's URL is a pure function of the cid, so it derives from the
  // shared flag rather than being tracked alongside it.
  const publicLink =
    isShared && cid ? (session?.storage.publicLinkUrl({ cid }) ?? null) : null

  const share: CredentialShareActions | undefined = canShare
    ? { isShared, publicLink, busy, toggle }
    : undefined

  return { share, error }
}
