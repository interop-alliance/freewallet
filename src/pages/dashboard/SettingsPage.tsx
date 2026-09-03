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
import { DashboardLayout } from '@/components/DashboardLayout'
import { useInfoBox } from '@/hooks/useInfoBox'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { usePrfRetryPrompt } from '@/hooks/usePrfRetryPrompt'
import { getFileUrl } from '@interop/did-method-webvh'
import { isWebvhDid, relationIds } from '@interop/wallet-core/webvh'
import { didWebFromSpace } from '@/lib/didWeb'
import { WrongPassphraseError } from '@/session/keyring'
import { peekVerifiedAccountLog } from '@/session/verifiedLog'
import {
  canRevokeWithoutCeremony,
  getUnlockMethods,
  UnlockRegistryStaleSealError,
  type PasskeyUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import {
  addAccountPasskey,
  addAccountPassphrase,
  changeAccountPassphrase,
  PasskeyNotEstablishedError,
  PendingPassphraseRetirementError,
  SamePassphraseError,
  accountDeletionRefusalKey,
  deleteAccount,
  loadUnlockRegistry,
  readLoginHandle,
  removeAccountPasskey,
  renameAccountPasskey,
  rotateAccountUpdateKey
} from '@/session/accountSettings'
import {
  PasskeyCancelledError,
  PasskeyDuplicateError,
  PasskeyPrfUnsupportedError,
  passkeySupported
} from '@/lib/passkey'
import { forgetBrowserWalletData } from '@/session/forget'
import { PassphraseStrengthField } from '@/components/PassphraseStrengthField'
import { formatDate } from '@/lib/viewMappers/formatDate'
import { RecoveryCodesSection } from '@/components/RecoveryCodesSection'
import { EnrolledClientsSection } from '@/components/EnrolledClientsSection'
import { dashboardStyles } from '@/styles/appStyles'
import { type ReactNode, useEffect, useState } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { DATE_FMT, KMS_SERVER_URL, PASSWORD_RULES } from '@/app.config'
import { setLoginHandle } from '@/lib/loginCredential'
import { createLogger } from '@/lib/log'

/**
 * The i18n suffix for one deletion phase: the ceremony's kebab phase names
 * map onto the camelCase copy keys under `settings.deletePhase`.
 *
 * @param phase {string}
 * @returns {string}
 */
function deletePhaseKey(phase: string): string {
  return phase.replace(/-([a-z])/g, (_match, letter: string) =>
    letter.toUpperCase()
  )
}

const log = createLogger('fw:ui:settings')

/**
 * Whether an account document publishes a verification method under
 * `authentication` that it does not also publish under
 * `capabilityInvocation`. That is the KMS-held key and nothing else: every
 * enrolled client's signing key is published under both relations, and the
 * ladder VM under neither.
 *
 * @param options {object}
 * @param options.doc {object}   the verified account document
 * @returns {boolean}
 */
function publishesAuthenticationOnlyKey({
  doc
}: {
  doc: {
    authentication?: Array<string | { id?: string }>
    capabilityInvocation?: Array<string | { id?: string }>
  }
}): boolean {
  const invocation = new Set(relationIds(doc.capabilityInvocation))
  return relationIds(doc.authentication).some(id => !invocation.has(id))
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
  const { displayInfoBox } = useInfoBox()
  const [deleteError, setDeleteError] = useState(false)
  const [deleteUnverified, setDeleteUnverified] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deletePassphrase, setDeletePassphrase] = useState('')
  const [deletePassphraseIncorrect, setDeletePassphraseIncorrect] =
    useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deletePhase, setDeletePhase] = useState<string | null>(null)
  const [deleteRefusalKey, setDeleteRefusalKey] = useState<string | null>(null)
  const [deleteResidueCount, setDeleteResidueCount] = useState(0)
  const [deleteActingResidue, setDeleteActingResidue] = useState(false)
  // The Spaces a refused run had already deleted, for the refusal's own copy:
  // "nothing was removed" is false once (b3) or part of (b1) has run.
  const [deleteRefusalDeleted, setDeleteRefusalDeleted] = useState<string[]>([])
  // The post-pivot farewell: the account is gone, so the run MUST log out --
  // but not before the residue copy has been read. The dialog holds this
  // state with an acknowledge button, and that button logs out.
  const [deleteFarewell, setDeleteFarewell] = useState(false)
  const [forgettingBrowser, setForgettingBrowser] = useState(false)
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
        const current = await readLoginHandle({ session })
        if (!cancelled) {
          setHandle(current)
          setSavedHandle(current)
        }
      } catch (err) {
        log.error('Could not load the login handle', { err })
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
      log.error('Could not save the login handle', { err })
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
  // How the old credential's retirement went, for the success copy: the
  // content keys rotated, there was nothing standing to retire, the rotation
  // did not finish (the login-time sweep resumes it), or the old credential
  // is still standing and was not retired at all (the next passphrase login's
  // repair finishes it). A failed standing establishment for the NEW
  // passphrase throws instead (the change never touches the old credential),
  // so it surfaces through `passphraseChangeError`, not here.
  const [passphraseRotation, setPassphraseRotation] = useState<
    'rotated' | 'skipped' | 'failed' | 'unretired'
  >('skipped')
  const [passphraseChangeError, setPassphraseChangeError] = useState<
    'incorrect' | 'same' | 'pending' | 'failed' | null
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
      const { oldPassphraseRetired, rotation, registry } =
        await changeAccountPassphrase({
          session,
          oldPassphrase,
          newPassphrase
        })
      setOldPassphrase('')
      setNewPassphrase('')
      setPassphraseRotation(rotation)
      setPassphraseChangeSuccess(oldPassphraseRetired)
      // The ceremony wrote the registry's passphrase entry itself, after the
      // retirement; show what it wrote.
      if (registry) {
        setUnlockRegistry(registry)
      }
    } catch (err) {
      if (err instanceof WrongPassphraseError) {
        setPassphraseChangeError('incorrect')
      } else if (err instanceof SamePassphraseError) {
        setPassphraseChangeError('same')
      } else if (err instanceof PendingPassphraseRetirementError) {
        setPassphraseChangeError('pending')
      } else {
        log.error('Could not change the passphrase', { err })
        setPassphraseChangeError('failed')
      }
    } finally {
      setChangingPassphrase(false)
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
    'duplicate' | 'unsupported' | 'notEstablished' | 'failed' | null
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
  // The stale-seal state is its own load error: the registry is there and
  // intact, only sealed to a superseded user key, and the next login's
  // re-seal repair mends it -- so it gets copy that says so rather than the
  // generic "could not load".
  const [registryStaleSeal, setRegistryStaleSeal] = useState(false)
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
      log.warn('Could not refresh the unlock methods', { err })
      setRegistryLoadError(true)
    }
  }
  // PRF-retry consent dialog: `registerPasskey` calls `promptForPrfRetry` when
  // a second ceremony is needed.
  const { promptForPrfRetry, dialog: prfRetryDialog } = usePrfRetryPrompt()

  const handleAddPasskey = async () => {
    const profile = session?.profile
    const seed = profile?.clientSeed
    if (!session || !profile || !seed) {
      return
    }
    setAddingPasskey(true)
    setPasskeyError(null)
    try {
      const userName =
        session.user.email ??
        `Freewallet ${new Date().toLocaleDateString(i18n.language, DATE_FMT)}`
      const { record, recorded } = await addAccountPasskey({
        session,
        locale: i18n.language,
        userName,
        promptForPrfRetry
      })
      if (!recorded) {
        // The passkey is standing and will log in; only the registry entry's
        // completion failed to persist (its next login rebuilds it).
        setPasskeyError('failed')
        return
      }
      setUnlockRegistry(record)
      showToast({ message: t('settings.passkeyAdded') })
      await reloadRegistry()
    } catch (err) {
      if (err instanceof PasskeyCancelledError) {
        // The user dismissed the ceremony (or declined the PRF retry): silent.
      } else if (err instanceof PasskeyDuplicateError) {
        setPasskeyError('duplicate')
      } else if (err instanceof PasskeyPrfUnsupportedError) {
        setPasskeyError('unsupported')
      } else if (err instanceof PasskeyNotEstablishedError) {
        // The passkey was created on the authenticator but could not be
        // connected to the account; the copy states the authenticator
        // residue and what a retry does.
        log.error('Could not establish the added passkey', { err })
        setPasskeyError('notEstablished')
        await reloadRegistry()
      } else {
        log.error('Could not add a passkey', { err })
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
      const updated = await renameAccountPasskey({
        session,
        entry,
        label: trimmed
      })
      setUnlockRegistry(updated)
      setEditingCredentialId(null)
      showToast({ message: t('settings.passkeyLabelSaved') })
      await reloadRegistry()
    } catch (err) {
      log.error('Could not rename the passkey', { err })
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
      await removeAccountPasskey({ session, entry })
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
        log.error('Could not remove the passkey', { err })
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
      const updated = await addAccountPassphrase({
        session,
        passphrase: addPassphrase
      })
      setUnlockRegistry(updated)
      setAddPassphrase('')
      setAddPassphraseSuccess(true)
      showToast({ message: t('settings.passphraseAdded') })
      await reloadRegistry()
    } catch (err) {
      log.error('Could not add a passphrase', { err })
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
        // Wait out the login-time registry passes first: reading mid-chain
        // could render a stale-seal error the in-flight re-seal repair is
        // about to mend (and hand ceremonies a registry view the passes are
        // still rewriting).
        await session.registryReady
        if (cancelled) {
          return
        }
        const record = await loadUnlockRegistry({ session })
        if (!cancelled) {
          setUnlockRegistry(record)
          setRegistryLoaded(true)
          setRegistryLoadError(false)
          setRegistryStaleSeal(false)
        }
      } catch (err) {
        log.error('Could not load the unlock methods', { err })
        if (!cancelled) {
          setRegistryLoaded(true)
          setRegistryLoadError(true)
          setRegistryStaleSeal(
            err instanceof UnlockRegistryStaleSealError ||
              (err as { name?: string }).name === 'UnlockRegistryStaleSealError'
          )
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
  // The account's did:web projection id and the world-readable URL its
  // document resolves to. The projection is the did:webvh document under its
  // did:web id, so a promoted pointer is the whole evidence it exists -- the
  // id is derived from the pointer rather than read off a provisioned
  // artifact. Whether the account also records a key-server signing key is a
  // separate fact, shown beside it: it is the one surface distinguishing
  // "keystore present, no KMS binding" from a fully provisioned account.
  const accountPointer = session?.profile?.accountPointer
  const publishedDid = isWebvhDid(accountPointer?.did)
    ? didWebFromSpace({
        wasServerUrl: accountPointer!.host,
        spaceId: accountPointer!.spaceId
      })
    : undefined
  // The evidence the DIDAuth holder dispatch reads, so the chip and the
  // dispatch cannot disagree: a verification method the account's verified
  // document lists under `authentication` and NOT under
  // `capabilityInvocation`. The KMS-held key is the only authentication-only
  // method the document carries -- every enrolled client's key is published
  // under both. `profile.kmsAuthentication` is the fallback for a cold memo,
  // and it is all a transient session (the default) would otherwise have:
  // only the remembered session's own provisioning stamps that member, so
  // reading it alone was a permanent false negative there.
  const verifiedDoc = session?.profile
    ? peekVerifiedAccountLog({ profile: session.profile })?.doc
    : undefined
  const kmsBindingRecorded = verifiedDoc
    ? publishesAuthenticationOnlyKey({ doc: verifiedDoc })
    : !!session?.profile?.kmsAuthentication
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
      log.error('Could not copy the did:webvh id', { err })
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
    if (
      !session ||
      !session.storage.remoteStore ||
      !session.profile.clientWebvhKeys ||
      !session.profile.persistClientKeys
    ) {
      return
    }
    setRotateDialogOpen(false)
    setRotating(true)
    setRotateDone(false)
    setRotateError(false)
    try {
      await rotateAccountUpdateKey({ session })
      setRotateDone(true)
    } catch (err) {
      log.error('Could not rotate the did:webvh update key', { err })
      setRotateError(true)
    } finally {
      setRotating(false)
    }
  }

  const openDeleteDialog = () => {
    setDeleteError(false)
    setDeletePassphrase('')
    setDeletePassphraseIncorrect(false)
    setDeleteRefusalKey(null)
    setDeleteResidueCount(0)
    setDeleteActingResidue(false)
    setDeleteRefusalDeleted([])
    setDeleteFarewell(false)
    setDeletePhase(null)
    setDeleteDialogOpen(true)
  }

  const isPasskeySession = session?.profile.unlockMethod?.type === 'passkey'

  // The unload guard: the deletion walk sends one request per Space, and a
  // tab closed mid-walk leaves whatever it had not reached yet.
  useEffect(() => {
    if (!deleting) {
      return
    }
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [deleting])

  /**
   * The post-pivot exit: clear the session and leave for the landing page.
   * Every outcome past the pivot takes it, the ones carrying residue only
   * after the user has acknowledged the residue copy.
   *
   * @returns {Promise<void>}
   */
  const leaveDeletedAccount = async () => {
    // The button's handler is not awaited, so a rejecting `logout` would
    // surface as an unhandled rejection and strand the user on a dialog for
    // an account that is already gone. Leaving is what matters here.
    try {
      await logout()
    } catch (err) {
      log.warn('Could not clear the session after account deletion', { err })
    }
    window.location.href = '/'
  }

  /**
   * The browser-scoped wipe offered beside a `deleted-unverified` outcome:
   * the login page's no-unlock-material forget grade, run from here because
   * this browser could not confirm its own replica is gone.
   *
   * @returns {Promise<void>}
   */
  const handleForgetBrowserAfterDelete = async () => {
    setForgettingBrowser(true)
    try {
      await forgetBrowserWalletData()
    } catch (err) {
      log.warn('Could not forget this browser after account deletion', { err })
    }
    await leaveDeletedAccount()
  }

  const handleDeleteAccount = async () => {
    if (!session) {
      return
    }
    setDeleteError(false)
    setDeleteUnverified(false)
    setDeletePassphraseIncorrect(false)
    setDeleteRefusalKey(null)
    setDeleting(true)
    try {
      // The ceremony states the order that keeps a failure recoverable: every
      // phase before the account Space refuses with nothing deleted, and
      // everything past it reports rather than failing. The catch below is
      // what keeps a refusal in the dialog instead of escaping as an
      // unhandled rejection.
      const outcome = await deleteAccount({
        session,
        passphrase: deletePassphrase,
        onPhase: phase => setDeletePhase(phase.phase)
      })
      const residue = outcome.spaces.filter(
        space => space.kind === 'unlock' && space.outcome !== 'deleted'
      ).length
      const actingResidue = outcome.spaces.some(
        space => space.kind === 'acting-unlock' && space.outcome !== 'deleted'
      )
      setDeleteResidueCount(residue + outcome.unnamed.length)
      setDeleteActingResidue(actingResidue)
      if (outcome.result === 'wrong-passphrase') {
        setDeletePassphraseIncorrect(true)
        return
      }
      if (outcome.result === 'refused') {
        // A pre-pivot refusal leaves the account alive, but not necessarily
        // untouched: (b3) and part of (b1) may already have run, so the
        // dialog names what the run did delete before it stopped.
        setDeleteRefusalDeleted(
          outcome.spaces
            .filter(space => space.outcome === 'deleted')
            .map(space => space.label ?? space.method ?? space.kind)
        )
        setDeleteRefusalKey(
          accountDeletionRefusalKey(outcome.refusal ?? 'space-delete-failed')
        )
        return
      }
      if (outcome.result === 'failed') {
        setDeleteError(true)
        setDeleteDialogOpen(false)
        return
      }
      // Past the pivot: the account is gone, so every remaining outcome logs
      // out. One with residue -- a standing unlock Space, an unnamed
      // credential, a failed (b6), or a replica this browser could not
      // confirm gone -- shows its copy first and logs out on the
      // acknowledge, since the hard reload would otherwise take the copy
      // with it.
      const unverified = outcome.result === 'deleted-unverified'
      setDeleteUnverified(unverified)
      if (
        unverified ||
        actingResidue ||
        residue > 0 ||
        outcome.unnamed.length > 0
      ) {
        setDeleteFarewell(true)
        return
      }
      await leaveDeletedAccount()
    } catch (err) {
      log.error('The account deletion ceremony failed', { err })
      setDeleteRefusalKey('settings.deleteError')
    } finally {
      setDeletePhase(null)
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
                  {passphraseChangeSuccess !== null &&
                    (passphraseRotation === 'failed' ? (
                      <Alert severity="warning">
                        {t('settings.passphraseChangedRotationPending')}
                      </Alert>
                    ) : passphraseRotation === 'unretired' ? (
                      <Alert severity="warning">
                        {t('settings.passphraseChangedUnretired')}
                      </Alert>
                    ) : (
                      <Typography variant="body2" color="success.main">
                        {!passphraseChangeSuccess
                          ? t('settings.passphraseChangedNotRetired')
                          : passphraseRotation === 'rotated'
                            ? t('settings.passphraseChangedRotated')
                            : t('settings.passphraseChanged')}
                      </Typography>
                    ))}
                  {passphraseChangeError && (
                    <Alert severity="error">
                      {passphraseChangeError === 'incorrect'
                        ? t('settings.passphraseIncorrect')
                        : passphraseChangeError === 'same'
                          ? t('settings.passphraseSame')
                          : passphraseChangeError === 'pending'
                            ? t('settings.passphrasePendingRetirement')
                            : t('settings.passphraseChangeFailed')}
                    </Alert>
                  )}
                  <Typography variant="body2" color="text.secondary">
                    {t('settings.passphraseLeakHint')}
                  </Typography>
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
                      {registryStaleSeal
                        ? t('settings.passkeyRegistryStaleSeal')
                        : t('settings.passkeyLoadError')}
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
                          : passkeyError === 'notEstablished'
                            ? t('settings.passkeyNotEstablished')
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
              <Chip
                size="small"
                color={kmsBindingRecorded ? 'success' : 'default'}
                label={
                  kmsBindingRecorded
                    ? t('settings.publishedDidKeyBinding')
                    : t('settings.publishedDidKeyBindingNone')
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
            if (!deleting && !deleteFarewell) {
              setDeleteDialogOpen(false)
            }
          }}
        >
          <DialogTitle>
            {deleteFarewell
              ? t('settings.deleteFarewellTitle')
              : t('settings.deleteConfirmTitle')}
          </DialogTitle>
          <DialogContent>
            {deleteFarewell ? (
              <Stack sx={{ gap: 2, mt: 1 }}>
                {deleteResidueCount > 0 && (
                  <Alert severity="warning">
                    {t('settings.deleteResidue', {
                      count: deleteResidueCount
                    })}
                  </Alert>
                )}
                {deleteActingResidue && (
                  <Alert severity="warning">
                    {t('settings.deleteActingResidue')}
                  </Alert>
                )}
                {deleteUnverified && (
                  <Alert severity="warning">
                    {t('settings.deleteUnverified')}
                  </Alert>
                )}
              </Stack>
            ) : (
              <>
                <DialogContentText>
                  {t('settings.deleteConfirm')}
                </DialogContentText>
                {!session?.isGuest && isPasskeySession && (
                  <DialogContentText sx={{ mt: 2 }}>
                    {t('settings.deleteConfirmPasskey')}
                  </DialogContentText>
                )}
                {!session?.isGuest && !isPasskeySession && (
                  <TextField
                    fullWidth
                    size="small"
                    type="password"
                    label={t('settings.deletePassphraseLabel')}
                    // Autofill disabled deliberately: the confirm IS the
                    // ceremony's authentication, and a manager that saved the
                    // passphrase at login would otherwise hand it to whoever
                    // holds the tab.
                    autoComplete="off"
                    name="freewallet-delete-confirm"
                    slotProps={{
                      htmlInput: {
                        autoComplete: 'off',
                        'data-1p-ignore': true,
                        'data-lpignore': 'true',
                        'data-form-type': 'other'
                      }
                    }}
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
                {deleteRefusalKey && (
                  <Alert severity="error" sx={{ mt: 2 }}>
                    {t(deleteRefusalKey)}
                    {deleteRefusalDeleted.length > 0 && (
                      <Box component="span" sx={{ display: 'block', mt: 1 }}>
                        {t('settings.deleteRefusalDeleted', {
                          count: deleteRefusalDeleted.length,
                          list: deleteRefusalDeleted.join(', ')
                        })}
                      </Box>
                    )}
                  </Alert>
                )}
                {deleting && deletePhase && (
                  <DialogContentText sx={{ mt: 2 }}>
                    {t(`settings.deletePhase.${deletePhaseKey(deletePhase)}`)}{' '}
                    {t('settings.deleteKeepTabOpen')}
                  </DialogContentText>
                )}
              </>
            )}
          </DialogContent>
          <DialogActions>
            {deleteFarewell ? (
              <>
                {deleteUnverified && (
                  <Button
                    onClick={handleForgetBrowserAfterDelete}
                    loading={forgettingBrowser}
                  >
                    {t('settings.deleteForgetBrowserAction')}
                  </Button>
                )}
                <Button
                  variant="contained"
                  onClick={leaveDeletedAccount}
                  disabled={forgettingBrowser}
                >
                  {t('settings.deleteFarewellAction')}
                </Button>
              </>
            ) : (
              <>
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
                  disabled={
                    !session?.isGuest &&
                    !isPasskeySession &&
                    deletePassphrase.length === 0
                  }
                >
                  {t('settings.deleteConfirmAction')}
                </Button>
              </>
            )}
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
            <DialogContentText sx={{ mt: 2 }}>
              {t('settings.passkeyRemoveRotationNote')}
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

        {prfRetryDialog}

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
