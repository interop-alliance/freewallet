import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import Chip from '@mui/material/Chip'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Divider from '@mui/material/Divider'
import IconButton from '@mui/material/IconButton'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { MdContentCopy, MdEdit } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { base64urlnopad } from '@scure/base'
import type { IZcap } from '@interop/data-integrity-core'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useInfoBox } from '@/hooks/useInfoBox'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { getFileUrl } from '@interop/did-method-webvh'
import { isWebvhDid, rotateWebvhUpdateKey } from '@interop/wallet-core/webvh'
import {
  bindPassphrase,
  changePassphrase,
  deleteKeyring,
  unlockManagementGrantee,
  verifyPassphrase,
  WrongPassphraseError
} from '@/session/keyring'
import {
  adoptPassphraseRebind,
  backfillPassphraseUnlockMethod,
  canRevokeWithoutCeremony,
  enrollPasskey,
  getUnlockMethods,
  putUnlockMethods,
  revokeUnlockMethod,
  revokeUnlockMethodByCeremony,
  type PasskeyUnlockMethod,
  type PassphraseUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import {
  PasskeyCancelledError,
  PasskeyDuplicateError,
  PasskeyPrfUnsupportedError,
  passkeySupported
} from '@/lib/passkey'
import { deletePasskeySafetyNotice } from '@/lib/sessionKey'
import { PassphraseStrengthField } from '@/components/PassphraseStrengthField'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { RecoveryCodesSection } from '@/components/RecoveryCodesSection'
import { EnrolledClientsSection } from '@/components/EnrolledClientsSection'
import { SharedCollectionsPanel } from '@/components/SharedCollectionsPanel'
import { dashboardStyles } from '@/styles/appStyles'
import { type ReactNode, useEffect, useRef, useState } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import {
  DATE_FMT,
  KMS_SERVER_URL,
  PASSWORD_RULES,
  SYNCED_COLLECTIONS
} from '@/app.config'
import { useSyncStatusStore, type SyncStatus } from '@/stores/syncStatusStore'
import {
  findLoginCredential,
  loginHandleOf,
  setLoginHandle
} from '@/lib/loginCredential'

const SYNC_CHIP_COLOR: Record<
  SyncStatus,
  'default' | 'info' | 'success' | 'error'
> = {
  idle: 'default',
  syncing: 'info',
  synced: 'success',
  error: 'error'
}

/**
 * A single label/value settings row: a fixed-width label column and a value
 * column, laid out on a two-column grid (stacking on narrow screens) so the
 * labels align without hand-tuned widths.
 */
function SettingRow({
  label,
  children
}: {
  label: string
  children: ReactNode
}) {
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: { xs: '1fr', sm: '200px 1fr' },
        alignItems: 'center',
        columnGap: 2,
        rowGap: 0.5
      }}
    >
      <Typography variant="body2">{label}</Typography>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 2,
          flexWrap: 'wrap',
          minWidth: 0
        }}
      >
        {children}
      </Box>
    </Box>
  )
}

export function SettingsPage() {
  const { t, i18n } = useTranslation()
  const session = useAuthStore(state => state.session)
  const logout = useAuthStore(state => state.logout)
  const syncStatuses = useSyncStatusStore(state => state.statuses)
  const { displayInfoBox } = useInfoBox()
  const [deleteError, setDeleteError] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deletePassphrase, setDeletePassphrase] = useState('')
  const [deletePassphraseIncorrect, setDeletePassphraseIncorrect] =
    useState(false)
  const [deleting, setDeleting] = useState(false)
  const hasRemoteStorage = !!session?.storage?.hasRemoteStorage
  const [handle, setHandle] = useState('')
  const [savedHandle, setSavedHandle] = useState('')
  const [handleSaving, setHandleSaving] = useState(false)
  const [handleSaved, setHandleSaved] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function loadHandle() {
      if (!session) {
        return
      }
      try {
        const credentials = await session.storage.listCredentials()
        const found = findLoginCredential({ credentials })
        const current = found ? (loginHandleOf(found.vc) ?? '') : ''
        if (!cancelled) {
          setHandle(current)
          setSavedHandle(current)
        }
      } catch (err) {
        console.error('Could not load the login handle:', err)
      }
    }
    void loadHandle()
    return () => {
      cancelled = true
    }
  }, [session])

  const handleSaveHandle = async () => {
    if (!session) {
      return
    }
    setHandleSaving(true)
    setHandleSaved(false)
    try {
      await setLoginHandle({ session, username: handle })
      setSavedHandle(handle.trim())
      setHandleSaved(true)
    } catch (err) {
      console.error('Could not save the login handle:', err)
    } finally {
      setHandleSaving(false)
    }
  }
  // Passphrase keyring (keyring v2) state. The whole section is shown for
  // non-guest sessions; changing the passphrase re-binds this client's key
  // set under a new unlock identity, so it needs the client seed in memory.
  const keyringSectionVisible = !session?.isGuest
  const canChangePassphrase = !!session?.profile?.clientSeed
  const [oldPassphrase, setOldPassphrase] = useState('')
  const [newPassphrase, setNewPassphrase] = useState('')
  const [newPassphraseScore, setNewPassphraseScore] = useState(0)
  const [changingPassphrase, setChangingPassphrase] = useState(false)
  // `null` = not yet run; a boolean carries the last change's
  // `oldPassphraseRetired` so the success copy can differ.
  const [passphraseChangeSuccess, setPassphraseChangeSuccess] = useState<
    boolean | null
  >(null)
  const [passphraseChangeError, setPassphraseChangeError] = useState<
    'incorrect' | 'failed' | null
  >(null)
  const newPassphraseLengthPassed =
    newPassphrase.length >= PASSWORD_RULES.minlength
  const newPassphraseValid =
    newPassphraseLengthPassed && newPassphraseScore >= PASSWORD_RULES.minscore

  const handleChangePassphrase = async () => {
    const profile = session?.profile
    const seed = profile?.clientSeed
    if (!session || !profile || !seed) {
      return
    }
    setChangingPassphrase(true)
    setPassphraseChangeSuccess(null)
    setPassphraseChangeError(null)
    try {
      // The keyring record is bound under the ACCOUNT controller (the first
      // client's did:key) -- on an enrolled second client it differs from this
      // client's `user.id`, so verification must match against it.
      const {
        oldPassphraseRetired,
        unlockSpaceId,
        manageCapability,
        persistClientKeys
      } = await changePassphrase({
        clientSeed: seed,
        controller: profile.accountController ?? session.user.id,
        oldPassphrase,
        newPassphrase,
        puk: profile.puk,
        webvhUpdateKeys: profile.clientWebvhKeys
      })
      // The rebind retired the unlock identity this session logged in under:
      // swap the live profile onto the new one, so later re-wraps (rolled
      // update-key seeds, a rotated PUK) hit the new client-key record and the
      // registry backfill never repoints at the deleted unlock Space.
      adoptPassphraseRebind({
        session,
        unlockSpaceId,
        manageCapability,
        persistClientKeys
      })
      setOldPassphrase('')
      setNewPassphrase('')
      setPassphraseChangeSuccess(oldPassphraseRetired)
      // The passphrase now lives in a new unlock Space; point the registry's
      // passphrase entry at it (fire-and-forget -- the change itself succeeded).
      void updatePassphraseEntry({ unlockSpaceId, manageCapability })
    } catch (err) {
      if (err instanceof WrongPassphraseError) {
        setPassphraseChangeError('incorrect')
      } else {
        console.error('Could not change the passphrase:', err)
        setPassphraseChangeError('failed')
      }
    } finally {
      setChangingPassphrase(false)
    }
  }

  // Repoints the registry's passphrase entry at the unlock Space a passphrase
  // change (or bind) produced, preserving the entry's original creation date.
  // Best-effort: the passphrase change itself has already succeeded.
  const updatePassphraseEntry = async ({
    unlockSpaceId,
    manageCapability
  }: {
    unlockSpaceId: string
    manageCapability?: IZcap
  }) => {
    if (!session) {
      return
    }
    try {
      const current = await getUnlockMethods({ session })
      if (!current) {
        return
      }
      const existing = current.methods.find(
        (method): method is PassphraseUnlockMethod =>
          method.type === 'passphrase'
      )
      const entry: PassphraseUnlockMethod = {
        type: 'passphrase',
        createdAt: existing?.createdAt ?? new Date().toISOString(),
        unlockSpaceId,
        manageCapability
      }
      const methods = existing
        ? current.methods.map(method =>
            method.type === 'passphrase' ? entry : method
          )
        : [...current.methods, entry]
      const updated: UnlockMethodsRecord = { ...current, methods }
      await putUnlockMethods({ session, record: updated })
      setUnlockRegistry(updated)
    } catch (err) {
      console.warn('Could not update the passphrase unlock-method entry:', err)
    }
  }
  // Passkeys (keyring v2 unlock methods). The section is shown only where
  // WebAuthn exists; adding a passkey binds this client's in-memory key set
  // under the passkey's PRF-derived unlock identity, so it needs the seed
  // present.
  const passkeysSupported = passkeySupported()
  const canAddPasskey = !!session?.profile?.clientSeed
  const [addingPasskey, setAddingPasskey] = useState(false)
  const [passkeyError, setPasskeyError] = useState<
    'duplicate' | 'unsupported' | 'failed' | null
  >(null)
  // The unlock-methods registry: how this account can be unlocked (the
  // passphrase entry plus one entry per passkey). Loaded once the passkeys
  // section is usable (full tier + data seed), refreshed after every mutation.
  // `null` = no registry yet (or a load failure); `registryLoaded` records that
  // a load attempt has finished so the UI can distinguish "unknown" from
  // "known empty".
  const [unlockRegistry, setUnlockRegistry] =
    useState<UnlockMethodsRecord | null>(null)
  const [registryLoaded, setRegistryLoaded] = useState(false)
  const [registryLoadError, setRegistryLoadError] = useState(false)
  // Inline passkey-label editing: one row edits at a time, keyed by the
  // passkey's credentialId.
  const [editingCredentialId, setEditingCredentialId] = useState<string | null>(
    null
  )
  const [labelDraft, setLabelDraft] = useState('')
  const [labelSaving, setLabelSaving] = useState(false)
  // Remove-passkey confirm dialog state.
  const [removeTarget, setRemoveTarget] = useState<PasskeyUnlockMethod | null>(
    null
  )
  const [removeDialogOpen, setRemoveDialogOpen] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState(false)
  const passkeyEntries = (unlockRegistry?.methods ?? []).filter(
    (method): method is PasskeyUnlockMethod => method.type === 'passkey'
  )
  const hasPassphraseEntry = !!unlockRegistry?.methods.some(
    method => method.type === 'passphrase'
  )
  // The registry has at most one unlock method left -- removing it would leave
  // the wallet unrecoverable after logout, so Settings refuses the removal.
  const isLastUnlockMethod = (unlockRegistry?.methods.length ?? 0) <= 1
  const removeNeedsCeremony = removeTarget
    ? !canRevokeWithoutCeremony(removeTarget)
    : false
  // Positively knowing this account has no passphrase method (registry loaded,
  // present, no passphrase entry, and the session did not log in via a
  // passphrase) is what lets us hide the change-passphrase form and offer to
  // add one instead. When the registry is unknown we keep showing change (the
  // legacy-account default).
  const knownNoPassphrase =
    registryLoaded &&
    !!unlockRegistry &&
    !hasPassphraseEntry &&
    session?.profile?.unlockMethod?.type !== 'passphrase'
  const canAddPassphrase = knownNoPassphrase && !!session?.profile?.clientSeed

  // Refreshes the registry from the source of truth after a mutation (not the
  // cancellable mount load below).
  const reloadRegistry = async () => {
    if (!session) {
      return
    }
    try {
      const record = await getUnlockMethods({ session })
      setUnlockRegistry(record)
      setRegistryLoaded(true)
      setRegistryLoadError(false)
    } catch (err) {
      console.warn('Could not refresh the unlock methods:', err)
      setRegistryLoadError(true)
    }
  }
  // PRF-retry consent dialog: some authenticators evaluate the WebAuthn PRF
  // only during a second (assertion) ceremony. `registerPasskey` calls
  // `promptForPrfRetry` when that is needed; the promise resolves on the user's
  // choice in the dialog below.
  const [prfRetryOpen, setPrfRetryOpen] = useState(false)
  const prfRetryResolve = useRef<((consented: boolean) => void) | null>(null)

  const promptForPrfRetry = (): Promise<boolean> => {
    setPrfRetryOpen(true)
    return new Promise<boolean>(resolve => {
      prfRetryResolve.current = resolve
    })
  }

  const resolvePrfRetry = (consented: boolean) => {
    setPrfRetryOpen(false)
    prfRetryResolve.current?.(consented)
    prfRetryResolve.current = null
  }

  const handleAddPasskey = async () => {
    const profile = session?.profile
    const seed = profile?.clientSeed
    if (!session || !profile || !seed) {
      return
    }
    setAddingPasskey(true)
    setPasskeyError(null)
    try {
      // Reuse the registry already loaded into state (it may already carry the
      // backfilled passphrase entry) so the new passkey shares the one
      // wallet-wide user handle and excludes any authenticator already holding
      // a passkey for this wallet. Fall back to a fresh registry when none has
      // been written yet.
      const registry: UnlockMethodsRecord = unlockRegistry ?? {
        version: 1,
        userHandle: base64urlnopad.encode(
          crypto.getRandomValues(new Uint8Array(16))
        ),
        methods: []
      }
      const excludeCredentialIds = registry.methods
        .filter(
          (method): method is PasskeyUnlockMethod => method.type === 'passkey'
        )
        .map(method => base64urlnopad.decode(method.credentialId))
      const userName =
        session.user.email ??
        `Freewallet ${new Date().toLocaleDateString(i18n.language, DATE_FMT)}`

      // Run the ceremony, bind this client's key set under the passkey's
      // unlock identity, and build the registry entry. Delegating management
      // to the account identity lets Settings later revoke this passkey
      // without a tap on the (possibly lost) authenticator -- from any
      // enrolled client, since a promoted account's grant names the
      // did:webvh. The record still binds under the account controller (the
      // FIRST client's did:key) -- on an enrolled second client it differs
      // from this client's `user.id`.
      const accountController = profile.accountController ?? session.user.id
      const { entry } = await enrollPasskey({
        clientSeed: seed,
        puk: profile.puk,
        webvhUpdateKeys: profile.clientWebvhKeys,
        pointer: profile.accountPointer,
        controller: accountController,
        userHandle: base64urlnopad.decode(registry.userHandle),
        userName,
        locale: i18n.language,
        email: session.user.email,
        excludeCredentialIds,
        delegateManagementTo: unlockManagementGrantee({
          pointer: profile.accountPointer,
          controller: accountController
        }),
        promptForPrfRetry
      })

      const updated: UnlockMethodsRecord = {
        ...registry,
        methods: [...registry.methods, entry]
      }
      try {
        await putUnlockMethods({ session, record: updated })
      } catch (err) {
        // The passkey is already bound and will log in; only the registry
        // listing entry failed to persist.
        console.error('Could not record the new passkey in the registry:', err)
        setPasskeyError('failed')
        return
      }
      setUnlockRegistry(updated)
      // The account now has a second unlock method, so the dashboard's
      // passkey-only safety prompt is resolved. Non-fatal.
      if (updated.methods.length > 1) {
        try {
          await deletePasskeySafetyNotice({ controller: session.user.id })
        } catch (err) {
          console.warn('Could not clear the passkey-safety notice:', err)
        }
      }
      showToast({ message: t('settings.passkeyAdded') })
      await reloadRegistry()
    } catch (err) {
      if (err instanceof PasskeyCancelledError) {
        // The user dismissed the ceremony (or declined the PRF retry): silent.
      } else if (err instanceof PasskeyDuplicateError) {
        setPasskeyError('duplicate')
      } else if (err instanceof PasskeyPrfUnsupportedError) {
        setPasskeyError('unsupported')
      } else {
        console.error('Could not add a passkey:', err)
        setPasskeyError('failed')
      }
    } finally {
      setAddingPasskey(false)
    }
  }
  // Saves an edited passkey label back to the registry.
  const handleSaveLabel = async (entry: PasskeyUnlockMethod) => {
    if (!session || !unlockRegistry) {
      return
    }
    const trimmed = labelDraft.trim()
    if (!trimmed || trimmed === entry.label) {
      setEditingCredentialId(null)
      return
    }
    setLabelSaving(true)
    try {
      const updated: UnlockMethodsRecord = {
        ...unlockRegistry,
        methods: unlockRegistry.methods.map(method =>
          method.type === 'passkey' &&
          method.credentialId === entry.credentialId
            ? { ...method, label: trimmed }
            : method
        )
      }
      await putUnlockMethods({ session, record: updated })
      setUnlockRegistry(updated)
      setEditingCredentialId(null)
      showToast({ message: t('settings.passkeyLabelSaved') })
      await reloadRegistry()
    } catch (err) {
      console.error('Could not rename the passkey:', err)
      setPasskeyError('failed')
    } finally {
      setLabelSaving(false)
    }
  }

  const openRemoveDialog = (entry: PasskeyUnlockMethod) => {
    setRemoveError(false)
    setRemoveTarget(entry)
    setRemoveDialogOpen(true)
  }

  // Removes a passkey: tap-free via its management zcap when present, else a
  // WebAuthn ceremony against that passkey (legacy entries). Both paths also
  // drop the registry entry itself.
  const handleRemovePasskey = async () => {
    const entry = removeTarget
    if (!session || !entry) {
      return
    }
    setRemoving(true)
    setRemoveError(false)
    try {
      if (canRevokeWithoutCeremony(entry)) {
        await revokeUnlockMethod({ session, entry })
      } else {
        await revokeUnlockMethodByCeremony({ session, entry })
      }
      setRemoveDialogOpen(false)
      setRemoveTarget(null)
      showToast({ message: t('settings.passkeyRemoved') })
      await reloadRegistry()
    } catch (err) {
      if (err instanceof PasskeyCancelledError) {
        // The user dismissed the confirming ceremony: silent close.
        setRemoveDialogOpen(false)
        setRemoveTarget(null)
      } else {
        console.error('Could not remove the passkey:', err)
        setRemoveError(true)
      }
    } finally {
      setRemoving(false)
    }
  }
  // "Add a passphrase" for passkey-only accounts (see 2.8): binds this
  // client's key set under a passphrase unlock identity and appends a
  // passphrase registry entry.
  const [addPassphrase, setAddPassphrase] = useState('')
  const [addPassphraseScore, setAddPassphraseScore] = useState(0)
  const [addingPassphrase, setAddingPassphrase] = useState(false)
  const [addPassphraseSuccess, setAddPassphraseSuccess] = useState(false)
  const [addPassphraseError, setAddPassphraseError] = useState(false)
  const addPassphraseLengthPassed =
    addPassphrase.length >= PASSWORD_RULES.minlength
  const addPassphraseValid =
    addPassphraseLengthPassed && addPassphraseScore >= PASSWORD_RULES.minscore

  const handleAddPassphrase = async () => {
    const seed = session?.profile?.clientSeed
    if (!session || !seed) {
      return
    }
    setAddingPassphrase(true)
    setAddPassphraseError(false)
    setAddPassphraseSuccess(false)
    try {
      // Bind under the ACCOUNT controller -- the first client's did:key,
      // which differs from this client's `user.id` on an enrolled second
      // client. Management is delegated to the account identity (the
      // did:webvh on a promoted account), so any enrolled client can later
      // revoke this method.
      const accountController =
        session.profile.accountController ?? session.user.id
      const { unlockSpaceId, manageCapability } = await bindPassphrase({
        clientSeed: seed,
        controller: accountController,
        passphrase: addPassphrase,
        email: session.user.email,
        puk: session.profile.puk,
        webvhUpdateKeys: session.profile.clientWebvhKeys,
        pointer: session.profile.accountPointer,
        delegateManagementTo: unlockManagementGrantee({
          pointer: session.profile.accountPointer,
          controller: accountController
        })
      })
      const base: UnlockMethodsRecord = unlockRegistry ?? {
        version: 1,
        userHandle: base64urlnopad.encode(
          crypto.getRandomValues(new Uint8Array(16))
        ),
        methods: []
      }
      const entry: PassphraseUnlockMethod = {
        type: 'passphrase',
        createdAt: new Date().toISOString(),
        unlockSpaceId,
        manageCapability
      }
      const updated: UnlockMethodsRecord = {
        ...base,
        methods: [...base.methods, entry]
      }
      await putUnlockMethods({ session, record: updated })
      setUnlockRegistry(updated)
      // The account now has a passphrase backup, so the passkey-only safety
      // prompt is resolved. Best-effort.
      try {
        await deletePasskeySafetyNotice({ controller: session.user.id })
      } catch (err) {
        console.warn('Could not clear the passkey-safety notice:', err)
      }
      setAddPassphrase('')
      setAddPassphraseSuccess(true)
      showToast({ message: t('settings.passphraseAdded') })
      await reloadRegistry()
    } catch (err) {
      console.error('Could not add a passphrase:', err)
      setAddPassphraseError(true)
    } finally {
      setAddingPassphrase(false)
    }
  }
  // On the first render of a usable passkeys section, lazily create/repair the
  // passphrase entry (the registry's backfill point) and hold the registry in
  // state. A backfill failure falls back to a plain read; a read failure shows
  // a non-blocking load error but leaves the rest of the section working.
  useEffect(() => {
    if (!session || !canAddPasskey) {
      return
    }
    let cancelled = false
    async function loadRegistry() {
      if (!session) {
        return
      }
      try {
        const record = await backfillPassphraseUnlockMethod({
          session,
          createIfMissing: true
        })
        if (!cancelled) {
          setUnlockRegistry(record)
          setRegistryLoaded(true)
          setRegistryLoadError(false)
        }
      } catch (err) {
        console.warn('Could not backfill the unlock methods; reading:', err)
        try {
          const fallback = await getUnlockMethods({ session })
          if (!cancelled) {
            setUnlockRegistry(fallback)
            setRegistryLoaded(true)
            setRegistryLoadError(false)
          }
        } catch (readErr) {
          console.error('Could not load the unlock methods:', readErr)
          if (!cancelled) {
            setRegistryLoaded(true)
            setRegistryLoadError(true)
          }
        }
      }
    }
    void loadRegistry()
    return () => {
      cancelled = true
    }
  }, [session, canAddPasskey])
  // KMS keystore state: a keystore is provisioned at login whenever a KMS
  // server is configured for a non-guest session (see initSession.ts).
  const kmsConfigured = !!KMS_SERVER_URL && !session?.isGuest
  const keystoreId = session?.profile?.keystoreAgent?.keystoreId
  // The published did:web DID (present once provisioned) and the world-readable
  // URL its document resolves to.
  const publishedDid = session?.profile?.didWeb?.did
  const publishedDidUrl = session?.storage.publishedDidUrl
  // The published did:webvh DID (Phase 2) and the world-readable URL its log
  // resolves to, derived from the did by the library's canonical mapping
  // (`https://<host>/space/<spaceId>/id/did.jsonl`) -- undefined until the log
  // is provisioned (no did).
  const publishedDidWebvh = session?.profile?.didWebvh?.did
  const publishedDidWebvhLogUrl = publishedDidWebvh
    ? getFileUrl(publishedDidWebvh)
    : undefined
  const { copied: copiedDidWebvh, copy: copyDidWebvh } = useCopyToClipboard({
    onError: (err: unknown) => {
      console.error('Could not copy the did:webvh id:', err)
    }
  })
  const [rotateDialogOpen, setRotateDialogOpen] = useState(false)
  const [rotating, setRotating] = useState(false)
  const [rotateDone, setRotateDone] = useState(false)
  const [rotateError, setRotateError] = useState(false)

  const handleCopyDidWebvh = async () => {
    if (!publishedDidWebvh) {
      return
    }
    await copyDidWebvh(publishedDidWebvh)
  }

  const handleRotate = async () => {
    const remoteStore = session?.storage.remoteStore
    const updateKeys = session?.profile.clientWebvhKeys
    const persistClientKeys = session?.profile.persistClientKeys
    if (!session || !remoteStore || !updateKeys || !persistClientKeys) {
      return
    }
    setRotateDialogOpen(false)
    setRotating(true)
    setRotateDone(false)
    setRotateError(false)
    try {
      // Per-client self-rotation with the client-held seeds: every changed
      // seed set is persisted into the wrapped client-key record (and the
      // in-memory profile) before and after the log extends, so a crash
      // mid-rotation resumes from durable state.
      await rotateWebvhUpdateKey({
        idStore: remoteStore.webvhIdStore(),
        updateKeys,
        persistUpdateKeys: async next => {
          await persistClientKeys({ webvhUpdateKeys: next })
          session.profile.clientWebvhKeys = next
        }
      })
      setRotateDone(true)
    } catch (err) {
      console.error('Could not rotate the did:webvh update key:', err)
      setRotateError(true)
    } finally {
      setRotating(false)
    }
  }

  const openDeleteDialog = () => {
    setDeleteError(false)
    setDeletePassphrase('')
    setDeletePassphraseIncorrect(false)
    setDeleteDialogOpen(true)
  }

  const handleDeleteAccount = async () => {
    if (!session) {
      return
    }
    const isGuest = !!session.isGuest
    setDeleteError(false)
    setDeletePassphraseIncorrect(false)
    setDeleting(true)
    try {
      // (a) Confirm the passphrase before wiping anything -- a wrong passphrase
      // must not delete data. Guests have no keyring, so this is skipped.
      if (!isGuest) {
        try {
          // Match against the ACCOUNT controller the keyring record was bound
          // under (differs from `user.id` on an enrolled second client).
          await verifyPassphrase({
            controller: session.profile.accountController ?? session.user.id,
            passphrase: deletePassphrase
          })
        } catch (err) {
          if (err instanceof WrongPassphraseError) {
            setDeletePassphraseIncorrect(true)
            return
          }
          // Any other failure (e.g. the remote is unreachable) is a generic
          // delete failure -- do not touch the user's data.
          console.error('Could not verify the passphrase for deletion:', err)
          setDeleteError(true)
          setDeleteDialogOpen(false)
          return
        }
      }
      // (b) Wipe the data Space and the local replica. On failure keep the old
      // semantics: surface the error, do not log out (the data is still there).
      try {
        console.log('Wiping user data...')
        await session.storage?.wipeStorage()
      } catch (err) {
        console.error('Error wiping user data:', err)
        setDeleteError(true)
        setDeleteDialogOpen(false)
        return
      }
      // (c) Retire the passphrase keyring only after a successful wipe -- if the
      // keyring died first and the wipe then failed, the data Space would be
      // orphaned unrecoverably. Non-fatal: the data is already gone, so a
      // leftover record is only a hygiene residue. Guests have no keyring.
      if (!isGuest) {
        try {
          const { unlockSpaceDeleted } = await deleteKeyring({
            passphrase: deletePassphrase
          })
          if (!unlockSpaceDeleted) {
            console.warn(
              'Could not delete the unlock Space during account deletion.'
            )
          }
        } catch (err) {
          console.warn('Could not retire the passphrase keyring:', err)
        }
        // Best-effort cleanup of the local passkey-safety notice for hygiene.
        try {
          await deletePasskeySafetyNotice({ controller: session.user.id })
        } catch (err) {
          console.warn('Could not delete the passkey-safety notice:', err)
        }
      }
      // (d) Clear the session, then (e) hard-reload to the landing page.
      await logout()
      window.location.href = '/'
    } finally {
      setDeleting(false)
    }
  }

  return (
    <DashboardLayout title={t('settings.title')}>
      <Stack sx={{ mt: 4, gap: 4, maxWidth: 640 }}>
        <Stack direction="row" sx={{ alignItems: 'center', gap: 3 }}>
          <Typography variant="h6">{t('settings.vcSection')}</Typography>
          <Button
            variant="outlined"
            size="small"
            sx={{
              borderRadius: 2,
              whiteSpace: 'nowrap'
            }}
            onClick={() =>
              displayInfoBox({
                docUrl: 'vcs',
                title: t('settings.vcSection')
              })
            }
          >
            {t('settings.moreInfo')}
          </Button>
        </Stack>

        <Divider />

        <Stack direction="row" sx={dashboardStyles.settingsRow}>
          <Button variant="contained" color="error" onClick={openDeleteDialog}>
            {t('settings.deleteAccount')}
          </Button>
          <Typography
            variant="body1"
            sx={dashboardStyles.deleteAccountDescription}
          >
            {t('settings.deleteAccountHint')}
          </Typography>
        </Stack>

        {deleteError && (
          <Alert severity="error">{t('settings.deleteError')}</Alert>
        )}

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.handleSection')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('settings.handleHint')}
          </Typography>
          <Stack
            direction="row"
            sx={{ alignItems: 'flex-start', gap: 2, mt: 1 }}
          >
            <TextField
              size="small"
              label={t('settings.handleLabel')}
              value={handle}
              onChange={event => {
                setHandle(event.target.value)
                setHandleSaved(false)
              }}
              sx={{ minWidth: 260 }}
            />
            <Button
              variant="contained"
              sx={{ mt: 0.25 }}
              loading={handleSaving}
              disabled={handle.trim() === savedHandle}
              onClick={handleSaveHandle}
            >
              {t('common.save')}
            </Button>
          </Stack>
          {handleSaved && (
            <Typography variant="body2" color="success.main">
              {t('settings.handleSaved')}
            </Typography>
          )}
        </Stack>

        {keyringSectionVisible && (
          <>
            <Divider />

            <Stack sx={{ gap: 1 }}>
              <Typography variant="h6">
                {t('settings.passphraseSection')}
              </Typography>

              {knownNoPassphrase ? (
                <>
                  <Typography variant="body2" color="text.secondary">
                    {t('settings.addPassphraseHint')}
                  </Typography>
                  {canAddPassphrase ? (
                    <Stack sx={{ gap: 1.5, mt: 1, maxWidth: 360 }}>
                      <TextField
                        size="small"
                        type="password"
                        label={t('settings.newPassphrase')}
                        autoComplete="new-password"
                        value={addPassphrase}
                        onChange={event => {
                          setAddPassphrase(event.target.value)
                          setAddPassphraseSuccess(false)
                          setAddPassphraseError(false)
                        }}
                      />
                      <PassphraseStrengthField
                        password={addPassphrase}
                        onChangeScore={setAddPassphraseScore}
                      />
                      <Button
                        variant="contained"
                        sx={{ alignSelf: 'flex-start' }}
                        loading={addingPassphrase}
                        disabled={!addPassphraseValid}
                        onClick={handleAddPassphrase}
                      >
                        {t('settings.addPassphrase')}
                      </Button>
                      {addPassphraseSuccess && (
                        <Typography variant="body2" color="success.main">
                          {t('settings.passphraseAddedHint')}
                        </Typography>
                      )}
                      {addPassphraseError && (
                        <Alert severity="error">
                          {t('settings.addPassphraseFailed')}
                        </Alert>
                      )}
                    </Stack>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      {t('settings.passphraseRequiresFullSession')}
                    </Typography>
                  )}
                </>
              ) : canChangePassphrase ? (
                <Stack sx={{ gap: 1.5, mt: 1, maxWidth: 360 }}>
                  <TextField
                    size="small"
                    type="password"
                    label={t('settings.currentPassphrase')}
                    autoComplete="current-password"
                    value={oldPassphrase}
                    onChange={event => {
                      setOldPassphrase(event.target.value)
                      setPassphraseChangeSuccess(null)
                      setPassphraseChangeError(null)
                    }}
                  />
                  <TextField
                    size="small"
                    type="password"
                    label={t('settings.newPassphrase')}
                    autoComplete="new-password"
                    value={newPassphrase}
                    onChange={event => {
                      setNewPassphrase(event.target.value)
                      setPassphraseChangeSuccess(null)
                      setPassphraseChangeError(null)
                    }}
                  />
                  <PassphraseStrengthField
                    password={newPassphrase}
                    onChangeScore={setNewPassphraseScore}
                  />
                  <Button
                    variant="contained"
                    sx={{ alignSelf: 'flex-start' }}
                    disabled={
                      changingPassphrase ||
                      oldPassphrase.length === 0 ||
                      !newPassphraseValid
                    }
                    onClick={handleChangePassphrase}
                  >
                    {changingPassphrase
                      ? t('settings.changingPassphrase')
                      : t('settings.changePassphrase')}
                  </Button>
                  {passphraseChangeSuccess !== null && (
                    <Typography variant="body2" color="success.main">
                      {passphraseChangeSuccess
                        ? t('settings.passphraseChanged')
                        : t('settings.passphraseChangedNotRetired')}
                    </Typography>
                  )}
                  {passphraseChangeError && (
                    <Alert severity="error">
                      {passphraseChangeError === 'incorrect'
                        ? t('settings.passphraseIncorrect')
                        : t('settings.passphraseChangeFailed')}
                    </Alert>
                  )}
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  {t('settings.passphraseRequiresFullSession')}
                </Typography>
              )}
            </Stack>
          </>
        )}

        {passkeysSupported && (
          <>
            <Divider />

            <Stack sx={{ gap: 1 }}>
              <Typography variant="h6">
                {t('settings.passkeysSection')}
              </Typography>

              {canAddPasskey ? (
                <Stack sx={{ gap: 2, mt: 1, alignItems: 'flex-start' }}>
                  {registryLoadError && (
                    <Alert severity="warning" sx={{ alignSelf: 'stretch' }}>
                      {t('settings.passkeyLoadError')}
                    </Alert>
                  )}
                  {passkeyEntries.length > 0 && (
                    <Stack sx={{ gap: 1.5, alignSelf: 'stretch' }}>
                      {passkeyEntries.map(entry => {
                        const editing =
                          editingCredentialId === entry.credentialId
                        const synced =
                          entry.backupEligibility && entry.backupState
                        const chipColor: 'success' | 'default' | 'warning' =
                          synced
                            ? 'success'
                            : entry.backupEligibility
                              ? 'default'
                              : 'warning'
                        const chipLabel = synced
                          ? t('settings.passkeySyncSynced')
                          : entry.backupEligibility
                            ? t('settings.passkeySyncAvailable')
                            : t('settings.passkeySyncNone')
                        return (
                          <Card
                            key={entry.credentialId}
                            variant="outlined"
                            sx={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: 0.5,
                              p: 1.5
                            }}
                          >
                            <Stack
                              direction="row"
                              sx={{
                                alignItems: 'center',
                                gap: 1,
                                flexWrap: 'wrap'
                              }}
                            >
                              {editing ? (
                                <>
                                  <TextField
                                    size="small"
                                    label={t('settings.passkeyNameLabel')}
                                    value={labelDraft}
                                    onChange={event =>
                                      setLabelDraft(event.target.value)
                                    }
                                    sx={{ minWidth: 220 }}
                                  />
                                  <Button
                                    variant="contained"
                                    size="small"
                                    loading={labelSaving}
                                    disabled={labelDraft.trim().length === 0}
                                    onClick={() => handleSaveLabel(entry)}
                                  >
                                    {t('common.save')}
                                  </Button>
                                  <Button
                                    size="small"
                                    disabled={labelSaving}
                                    onClick={() => setEditingCredentialId(null)}
                                  >
                                    {t('common.cancel')}
                                  </Button>
                                </>
                              ) : (
                                <>
                                  <Typography variant="body1">
                                    {entry.label}
                                  </Typography>
                                  <Tooltip title={t('common.edit')}>
                                    <IconButton
                                      size="small"
                                      aria-label={t('common.edit')}
                                      onClick={() => {
                                        setLabelDraft(entry.label)
                                        setEditingCredentialId(
                                          entry.credentialId
                                        )
                                      }}
                                      sx={{ p: 0.25 }}
                                    >
                                      <MdEdit size={15} />
                                    </IconButton>
                                  </Tooltip>
                                  <Chip
                                    size="small"
                                    color={chipColor}
                                    label={chipLabel}
                                  />
                                </>
                              )}
                            </Stack>
                            <Typography variant="body2" color="text.secondary">
                              {t('settings.passkeyCreatedOn', {
                                date: formatDate({
                                  isoDate: entry.createdAt,
                                  locale: i18n.language
                                })
                              })}
                            </Typography>
                            <Button
                              variant="outlined"
                              size="small"
                              color="error"
                              sx={{
                                borderRadius: 2,
                                alignSelf: 'flex-start'
                              }}
                              disabled={isLastUnlockMethod}
                              onClick={() => openRemoveDialog(entry)}
                            >
                              {t('settings.passkeyRemove')}
                            </Button>
                          </Card>
                        )
                      })}
                    </Stack>
                  )}
                  {isLastUnlockMethod && passkeyEntries.length > 0 && (
                    <Typography variant="body2" color="text.secondary">
                      {t('settings.passkeyLastMethod')}
                    </Typography>
                  )}
                  {passkeyEntries.some(
                    entry => !(entry.backupEligibility && entry.backupState)
                  ) && (
                    <Typography variant="body2" color="text.secondary">
                      {t('settings.passkeyNotSyncedHint')}
                    </Typography>
                  )}
                  <Button
                    variant="contained"
                    loading={addingPasskey}
                    onClick={handleAddPasskey}
                  >
                    {t('settings.addPasskey')}
                  </Button>
                  {passkeyError && (
                    <Alert severity="error">
                      {passkeyError === 'duplicate'
                        ? t('settings.passkeyDuplicate')
                        : passkeyError === 'unsupported'
                          ? t('settings.passkeyPrfUnsupported')
                          : t('settings.passkeyAddFailed')}
                    </Alert>
                  )}
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  {t('settings.passkeysRequiresFullSession')}
                </Typography>
              )}
            </Stack>
          </>
        )}

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.syncSection')}</Typography>
          {hasRemoteStorage ? (
            SYNCED_COLLECTIONS.map(({ id }) => {
              const status = syncStatuses[id] ?? 'idle'
              return (
                <SettingRow key={id} label={id}>
                  <Chip
                    size="small"
                    color={SYNC_CHIP_COLOR[status]}
                    label={t(`settings.syncStatus.${status}`)}
                  />
                </SettingRow>
              )
            })
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t('settings.syncNone')}
            </Typography>
          )}
        </Stack>

        {session && !session.isGuest && (
          <>
            <Divider />
            {hasRemoteStorage &&
              !isWebvhDid(session.profile.accountPointer?.did) && (
                <Alert severity="info">{t('settings.unpromotedAccount')}</Alert>
              )}
            <EnrolledClientsSection session={session} />
            <Divider />
            <RecoveryCodesSection session={session} />
          </>
        )}

        {session && (
          <>
            <Divider />
            <SharedCollectionsPanel session={session} />
          </>
        )}

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.kmsSection')}</Typography>
          {kmsConfigured ? (
            <SettingRow label={t('settings.keystore')}>
              <Chip
                size="small"
                color={keystoreId ? 'success' : 'error'}
                label={
                  keystoreId
                    ? t('settings.keystoreProvisioned')
                    : t('settings.keystoreError')
                }
              />
              {keystoreId && (
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ wordBreak: 'break-all' }}
                >
                  {keystoreId}
                </Typography>
              )}
            </SettingRow>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t('settings.kmsNone')}
            </Typography>
          )}
          {kmsConfigured && (
            <SettingRow label={t('settings.publishedDid')}>
              <Chip
                size="small"
                color={publishedDid ? 'success' : 'default'}
                label={
                  publishedDid
                    ? t('settings.publishedDidProvisioned')
                    : t('settings.publishedDidNone')
                }
              />
              {publishedDid && (
                <Stack sx={{ gap: 0.5 }}>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ wordBreak: 'break-all' }}
                  >
                    {publishedDid}
                  </Typography>
                  {publishedDidUrl && (
                    <Link
                      href={publishedDidUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="body2"
                      sx={{ wordBreak: 'break-all' }}
                    >
                      {publishedDidUrl}
                    </Link>
                  )}
                </Stack>
              )}
            </SettingRow>
          )}
          {kmsConfigured && (
            <SettingRow label={t('settings.publishedDidWebvh')}>
              <Chip
                size="small"
                color={publishedDidWebvh ? 'success' : 'default'}
                label={
                  publishedDidWebvh
                    ? t('settings.publishedDidProvisioned')
                    : t('settings.publishedDidNone')
                }
              />
              {publishedDidWebvh && (
                <Stack sx={{ gap: 0.5 }}>
                  <Stack
                    direction="row"
                    sx={{ alignItems: 'center', gap: 0.5 }}
                  >
                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{ wordBreak: 'break-all' }}
                    >
                      {publishedDidWebvh}
                    </Typography>
                    <Tooltip
                      title={
                        copiedDidWebvh ? t('common.copied') : t('common.copy')
                      }
                    >
                      <IconButton
                        size="small"
                        onClick={handleCopyDidWebvh}
                        aria-label={t('common.copy')}
                        sx={{ p: 0.25, flexShrink: 0 }}
                      >
                        <MdContentCopy size={15} />
                      </IconButton>
                    </Tooltip>
                  </Stack>
                  {publishedDidWebvhLogUrl && (
                    <Link
                      href={publishedDidWebvhLogUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="body2"
                      sx={{ wordBreak: 'break-all' }}
                    >
                      {publishedDidWebvhLogUrl}
                    </Link>
                  )}
                </Stack>
              )}
            </SettingRow>
          )}
          {publishedDidWebvh && (
            <Stack sx={{ gap: 0.5, mt: 1 }}>
              <Stack direction="row" sx={{ alignItems: 'center', gap: 2 }}>
                <Button
                  variant="outlined"
                  size="small"
                  sx={{ borderRadius: 2, px: 2, py: 1 }}
                  disabled={
                    rotating ||
                    !session?.profile.clientWebvhKeys ||
                    !session?.profile.persistClientKeys
                  }
                  onClick={() => {
                    setRotateDone(false)
                    setRotateError(false)
                    setRotateDialogOpen(true)
                  }}
                >
                  {rotating
                    ? t('settings.rotating')
                    : t('settings.rotateUpdateKey')}
                </Button>
                <Typography variant="body2" color="text.secondary">
                  {t('settings.rotateUpdateKeyHint')}
                </Typography>
              </Stack>
              {rotateDone && (
                <Typography variant="body2" color="success.main">
                  {t('settings.rotateSuccess')}
                </Typography>
              )}
              {rotateError && (
                <Alert severity="error">{t('settings.rotateError')}</Alert>
              )}
            </Stack>
          )}
        </Stack>

        <Dialog
          open={deleteDialogOpen}
          onClose={() => {
            if (!deleting) {
              setDeleteDialogOpen(false)
            }
          }}
        >
          <DialogTitle>{t('settings.deleteConfirmTitle')}</DialogTitle>
          <DialogContent>
            <DialogContentText>{t('settings.deleteConfirm')}</DialogContentText>
            {!session?.isGuest && (
              <TextField
                fullWidth
                size="small"
                type="password"
                label={t('settings.deletePassphraseLabel')}
                autoComplete="current-password"
                value={deletePassphrase}
                onChange={event => {
                  setDeletePassphrase(event.target.value)
                  setDeletePassphraseIncorrect(false)
                }}
                sx={{ mt: 2 }}
              />
            )}
            {deletePassphraseIncorrect && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {t('settings.deletePassphraseIncorrect')}
              </Alert>
            )}
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => setDeleteDialogOpen(false)}
              disabled={deleting}
            >
              {t('common.cancel')}
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleDeleteAccount}
              loading={deleting}
              disabled={!session?.isGuest && deletePassphrase.length === 0}
            >
              {t('settings.deleteConfirmAction')}
            </Button>
          </DialogActions>
        </Dialog>

        <Dialog
          open={removeDialogOpen}
          onClose={() => {
            if (!removing) {
              setRemoveDialogOpen(false)
            }
          }}
        >
          <DialogTitle>{t('settings.passkeyRemoveTitle')}</DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('settings.passkeyRemoveConfirm')}
              {removeNeedsCeremony
                ? ` ${t('settings.passkeyRemoveCeremonyNote')}`
                : ''}
            </DialogContentText>
            {removeError && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {t('settings.passkeyRemoveFailed')}
              </Alert>
            )}
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => setRemoveDialogOpen(false)}
              disabled={removing}
            >
              {t('common.cancel')}
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleRemovePasskey}
              disabled={removing}
            >
              {removing
                ? t('settings.passkeyRemoving')
                : t('settings.passkeyRemoveConfirmAction')}
            </Button>
          </DialogActions>
        </Dialog>

        <Dialog open={prfRetryOpen} onClose={() => resolvePrfRetry(false)}>
          <DialogTitle>{t('settings.passkeyRetryTitle')}</DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('settings.passkeyRetryMessage')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => resolvePrfRetry(false)}>
              {t('settings.passkeyRetryCancel')}
            </Button>
            <Button variant="contained" onClick={() => resolvePrfRetry(true)}>
              {t('settings.passkeyRetryConfirm')}
            </Button>
          </DialogActions>
        </Dialog>

        <Dialog
          open={rotateDialogOpen}
          onClose={() => setRotateDialogOpen(false)}
        >
          <DialogTitle>{t('settings.rotateConfirmTitle')}</DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('settings.rotateConfirmMessage')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setRotateDialogOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button variant="contained" onClick={handleRotate}>
              {t('settings.rotateConfirmAction')}
            </Button>
          </DialogActions>
        </Dialog>

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.about')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('settings.version', { version: __APP_VERSION__ })}
          </Typography>
        </Stack>
      </Stack>
    </DashboardLayout>
  )
}
