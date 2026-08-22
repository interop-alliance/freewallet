/**
 * Recovery codes on the roster identity model. A code is a minimal always-enrolled wallet client: its unlock
 * record carries the account pointer plus a pre-minted PUT-on-`did.jsonl`
 * delegation (never a seed, never a user key wrap), its `keyAgreement`
 * verification method stands in the did:webvh document (unmarked -- a
 * recovery key is the keyAgreement-only case, so client listings keyed on
 * `capabilityInvocation` never see it), its user key wrap stands in the
 * `key-map/user-key.jsonl`
 * roster (maintained for free by rotation fan-out), and its update-key hash
 * stands committed in `nextKeyHashes` -- decryption standing, authority
 * latent, the key material existing nowhere until the code is typed.
 *
 * This module is Freewallet's glue over `@interop/wallet-core/recovery`:
 *
 * - `issueRecoveryCode` -- the Settings flow, in the recovery-anchor order
 *   (decryption material before authorization): roster wrap first, then the
 *   document entry, then the delegation + unlock record, then the registry
 *   entry. Idempotent stage by stage.
 * - `recoverAccountWithCode` -- the `/recover` flow end to end on a fresh
 *   browser: unlock record decrypted, log verified, the delegation invoked
 *   to write the self-enrolling continuation, the user key unwrapped from
 *   the code's standing wrap, the mandatory user key rotation in the roster
 *   (the spent code presumed compromised), the epoch cascade re-keying every
 *   encrypted collection off the spent code's reach, a replacement code
 *   issued hard, and the fresh passphrase bound. The continuation enrolls
 *   what the browser's posture would enroll at login: a new durable client
 *   with `rememberBrowser`, and otherwise (the default) the fresh
 *   credential's LADDER VM -- the transient variant, which lands the account
 *   client-less and ladder-anchored with zero local residue.
 * - `revokeRecoveryCode` -- the Settings removal: document entry out, user key
 *   rotated off the code's wrap, the same collection cascade, unlock Space
 *   deleted, registry entry dropped, and the live session adopting the
 *   rotated key in place.
 * - `checkRecoveryHealth` -- the login-time delegation staleness check: a
 *   stored delegation chains only while its signing client's verification
 *   method is in the current document (rot), lapses at its one-year expiry,
 *   and either way bricks recovery exactly when it is needed. Client
 *   revocation re-mints stale delegations automatically
 *   (`remintRecoveryDelegations`); the check remains the backstop for
 *   entries that predate the re-mint fields and for expiry between
 *   revocations.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import { WAS_SERVER_URL } from '@/app.config'
import { DID_DOCUMENT_RESOURCE } from '@interop/wallet-core/space'
import {
  establishPassphrasePosture,
  unlockLogStore
} from '@/session/standingUnlock'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import {
  deriveUnlockIdentity,
  deleteUnlockSpace,
  ensureUnlockSpace,
  getUnlockKeyring,
  putUnlockKeyring,
  recordSignerFromAgent,
  verifyRecordProof,
  type AccountPointer
} from '@interop/wallet-core/keyring'
import {
  addUserKeyRosterRecipient,
  replaceUserKeyRosterRecipients,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner,
  userKeyVaultKeys,
  readUserKeyRoster,
  rotateUserKeyRoster,
  type UserKey
} from '@interop/wallet-core/keys'
import { accountRosterStore, sessionRosterStore } from '@/session/rosterStore'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import {
  clientSigningKeyMultibase,
  delegatedWebvhLogStore,
  delegationKeyInDocument,
  didKeyZcapClient,
  documentKeyMultibases,
  isWebvhDid,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  verifyAccountLog,
  webvhZcapClient
} from '@interop/wallet-core/webvh'
import {
  clientAnnexLogStore,
  delegatedClientsDelegationMinter,
  embeddedGenerationDelegation,
  enrollTransientClient,
  ensureGenerationDelegationCurrent,
  generateLadderSeed,
  ladderRung,
  ladderVmAgent,
  ladderVmZcapClient,
  mintCredentialClientAnnexGeneration,
  mintDelegatedClientsDelegation,
  mintGenerationDelegation,
  recoverWebvhLadderAnchored
} from '@interop/wallet-core/clientAnnex'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import { WasClient } from '@interop/was-client'
import {
  currentAccountSigningKeys,
  type VerifiedAccountLog
} from '@interop/wallet-core/clients'
import {
  delegateLogWrite,
  delegationProofKeyId,
  generateRecoveryCode,
  publishRecoveryKey,
  recoverWebvhClient,
  recoveryClientFromCode,
  RECOVERY_KDF,
  remintRecoveryDelegations as remintDelegationsCore,
  removeRecoveryKey,
  unwrapUnlockRecord,
  wrapUnlockRecord,
  zcapExpiring,
  type RecoveryClient,
  type RecoveryLogStore,
  type UnlockRecordProofState
} from '@interop/wallet-core/recovery'
import type { Session } from '@/types/auth'
import {
  bindCredentialAnchoredUnlockSecret,
  bindPassphrase,
  delegateUnlockManagement,
  deriveUnlockCredential,
  unlockManagementGrantee
} from '@/session/keyring'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { transientSessionPersistence } from '@/session/persistence'
import {
  backfillPassphraseUnlockMethod,
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  getUnlockMethodsWithClient,
  managementZcapClient,
  putUnlockMethods,
  putUnlockMethodsWithClient,
  refreshStandingDelegationFields,
  revokeUnlockMethod,
  upsertPassphraseUnlockMethod,
  type PassphraseUnlockMethod,
  type PasskeyUnlockMethod,
  type RecoveryCodeUnlockMethod,
  type UnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import {
  enrolledClientContext,
  requireEnrolledClientContext
} from '@/session/enrolledContext'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import {
  adoptRotatedUserKey,
  rewrapUnlockRegistryToUserKey
} from '@/session/userKeyAdoption'
import {
  deleteUnlockLocalTrio,
  loadUserKeyEpochPin,
  savePinFromDescriptor,
  sessionLogPinStore
} from '@/lib/sessionKey'
import { assertAccountCeremonyAllowed } from '@/session/persistence'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { mintSpaceId, WASRemoteStore } from '@/stores/wasRemoteStore'

// Re-exported for the pages, so the UI layer keeps one recovery import.
export {
  formatRecoveryCode,
  generateRecoveryCode,
  RecoveryCodeInvalidError,
  RecoveryKeyNotCommittedError
} from '@interop/wallet-core/recovery'

/**
 * Thrown when recovery is attempted with no WAS server configured: without a
 * Space there is no unlock record, no roster, and no log -- nothing a code
 * could recover.
 */
export class RecoveryUnavailableError extends Error {
  constructor(message = 'Recovery codes require a configured storage server.') {
    super(message)
    this.name = 'RecoveryUnavailableError'
  }
}

/**
 * Thrown when a well-formed code resolves to no unlock record: never issued,
 * or already spent/revoked (retiring a code deletes its unlock Space).
 * Deliberately distinct from a malformed code and from an unreachable server
 * (a network error rethrows unchanged -- "could not check" must never read
 * as "no account").
 */
export class RecoveryCodeNotFoundError extends Error {
  constructor(
    message = 'No wallet was found for this recovery code. It may never ' +
      'have been issued, or it may have been revoked or already used.'
  ) {
    super(message)
    this.name = 'RecoveryCodeNotFoundError'
  }
}

/**
 * Writes a code's unlock Space and recovery record: ensure the Space, wrap
 * the pointer + delegation to the code's unlock KAK, PUT the record, and
 * delegate the management zcap to the account identity. No local cache and
 * no client-key record: a code is not bound to any browser. An issuance path
 * by definition (the caller holds the code), so the record's account binding
 * is MAC'd fresh under the code-derived key.
 *
 * @param options {object}
 * @param options.client {RecoveryClient}
 * @param options.controller {string}   the account did:key, stamped into the
 *   record (an identity label, deliberately not the management grantee)
 * @param options.pointer {AccountPointer}
 * @param options.delegation {IZcap}
 * @returns {Promise<{ unlockSpaceId: string, manageCapability: IZcap,
 *   unlockKeyAgreementKeyId?: string,
 *   unlockKeyAgreementKeyMultibase?: string }>}
 */
async function bindRecoveryRecord({
  client,
  controller,
  pointer,
  delegation
}: {
  client: RecoveryClient
  controller: string
  pointer: AccountPointer
  delegation: IZcap
}): Promise<{
  unlockSpaceId: string
  manageCapability: IZcap
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}> {
  const unlock = await deriveUnlockIdentity({
    secret: client.codeBytes,
    kdf: RECOVERY_KDF
  })
  await ensureUnlockSpace({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId,
    controller: unlock.agent.id
  })
  const record = await wrapUnlockRecord({
    controller,
    pointer,
    delegation,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    // Issuance signs with the code's own unlock key -- the strong path, where
    // a typed code alone establishes what may have signed the record, so
    // recovery verifies the proof before decrypting anything.
    signer: unlock.recordSigner,
    bindingMacKey: client.bindingMacKey
  })
  await putUnlockKeyring({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId,
    record
  })
  // GET/PUT/DELETE, not the default GET/DELETE: PUT is what lets the
  // revocation cascade re-PUT the code's record with a freshly minted
  // delegation when the original's signing client is revoked -- the record's
  // JWE recipient stays the code's unlock KAK, so the re-wrap needs only the
  // public half the registry records.
  const manageCapability = await delegateUnlockManagement({
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId,
    controller: unlockManagementGrantee({ pointer, controller }),
    allowedActions: ['GET', 'PUT', 'DELETE']
  })
  // The unlock KAK's public identity, recorded so the revocation cascade can
  // later re-wrap the record without the code (encryption needs no secret).
  const unlockKak = unlock.keyAgreementKey as unknown as {
    id?: string
    publicKeyMultibase?: string
  }
  return {
    unlockSpaceId: unlock.spaceId,
    manageCapability,
    unlockKeyAgreementKeyId: unlockKak.id,
    unlockKeyAgreementKeyMultibase: unlockKak.publicKeyMultibase
  }
}

/**
 * Assembles the registry entry for an issued code -- public halves only. The
 * unlock-KAK members (when the bind step surfaced them) are what let the
 * revocation cascade re-mint the code's delegation and re-wrap its record
 * without the code.
 *
 * @param options {object}
 * @param options.client {RecoveryClient}
 * @param options.label {string}
 * @param options.unlockSpaceId {string}
 * @param options.manageCapability {IZcap}
 * @param options.delegation {IZcap}
 * @param [options.unlockKeyAgreementKeyId] {string}
 * @param [options.unlockKeyAgreementKeyMultibase] {string}
 * @returns {RecoveryCodeUnlockMethod}
 */
function recoveryRegistryEntry({
  client,
  label,
  unlockSpaceId,
  manageCapability,
  delegation,
  unlockKeyAgreementKeyId,
  unlockKeyAgreementKeyMultibase
}: {
  client: RecoveryClient
  label: string
  unlockSpaceId: string
  manageCapability: IZcap
  delegation: IZcap
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}): RecoveryCodeUnlockMethod {
  const delegationKeyId = delegationProofKeyId(delegation)
  const delegationExpires = (delegation as { expires?: string }).expires
  return {
    type: 'recovery-code',
    label,
    createdAt: new Date().toISOString(),
    unlockSpaceId,
    manageCapability,
    recoveryKid: client.recipientKid,
    keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
    updateKeyMultibase: client.updateKeyMultibase,
    recoveryClientDid: client.clientDid,
    ...(delegationKeyId ? { delegationKeyId } : {}),
    ...(delegationExpires ? { delegationExpires } : {}),
    ...(unlockKeyAgreementKeyId ? { unlockKeyAgreementKeyId } : {}),
    ...(unlockKeyAgreementKeyMultibase
      ? { unlockKeyAgreementKeyMultibase }
      : {})
  }
}

/**
 * The recovery-code entries of an unlock-methods registry record (an absent
 * registry has none).
 *
 * @param options {object}
 * @param [options.record] {UnlockMethodsRecord | null}
 * @returns {RecoveryCodeUnlockMethod[]}
 */
export function recoveryEntriesOf({
  record
}: {
  record?: UnlockMethodsRecord | null
}): RecoveryCodeUnlockMethod[] {
  return (record?.methods ?? []).filter(
    (method): method is RecoveryCodeUnlockMethod =>
      method.type === 'recovery-code'
  )
}

/**
 * Appends (or replaces, matching on `recoveryKid`) a recovery entry in the
 * unlock-methods registry, minting the registry when absent. `dropKids` drops
 * further recovery entries in the same write -- the post-recovery update,
 * which records the replacement code and retires the spent one together (two
 * writes would race: both are read-modify-writes over one resource with
 * last-write-wins puts).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {RecoveryCodeUnlockMethod}
 * @param [options.dropKids] {string[]}   recovery kids to remove
 * @returns {Promise<void>}
 */
export async function recordRecoveryMethod({
  session,
  entry,
  dropKids = []
}: {
  session: Session
  entry: RecoveryCodeUnlockMethod
  dropKids?: string[]
}): Promise<void> {
  const existing = await getUnlockMethods({ session })
  const record = existing ?? emptyUnlockMethodsRegistry()
  const dropped = new Set([entry.recoveryKid, ...dropKids])
  const methods = [
    ...record.methods.filter(
      method =>
        method.type !== 'recovery-code' || !dropped.has(method.recoveryKid)
    ),
    entry
  ]
  await putUnlockMethods({ session, record: { ...record, methods } })
}

/**
 * Whether this session can issue (and revoke) recovery codes: an enrolled
 * wallet client on a promoted account with a remote store, holding the
 * account's current per-user key -- the issuance gate, "an enrolled wallet
 * client holding its key material" (the roster model's restatement of the
 * retired you-must-hold-the-seed gate). Derived from the shared
 * enrolled-client context, so the gate and the ceremony cannot disagree.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {boolean}
 */
export function canIssueRecoveryCode({
  session
}: {
  session: Session
}): boolean {
  return !!enrolledClientContext({ session }) && !!session.profile.userKey
}

/**
 * Issues a recovery code from a live enrolled session, in the
 * recovery-anchor order (decryption material before authorization): the user key
 * wrap lands in the roster FIRST (escrow: every epoch, so recovery decrypts
 * pre-issuance history), then the document entry (the recovery-marked
 * `keyAgreement` VM and the update-key hash commitment), then the delegation
 * and the unlock record, then the registry entry. Nothing is durable until
 * this is called -- the Settings dialog binds only on confirm.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.code {string}   the code to bind -- generated by the caller
 *   (`generateRecoveryCode`) so the confirm-once dialog can display it before
 *   anything becomes durable
 * @param options.label {string}   the display label for the registry entry
 * @returns {Promise<{ entry: RecoveryCodeUnlockMethod }>}
 */
export async function issueRecoveryCode({
  session,
  code,
  label
}: {
  session: Session
  code: string
  label: string
}): Promise<{ entry: RecoveryCodeUnlockMethod }> {
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Issuing a recovery code'
  })
  const {
    remoteStore,
    pointer,
    clientWebvhKeys,
    clientKeyAgreementKey,
    controller
  } = requireEnrolledClientContext({
    session,
    action: 'Recovery-code issuance'
  })

  const client = await recoveryClientFromCode({ code })

  // 1. Decryption material first: the code's wrap into every roster epoch.
  await addUserKeyRosterRecipient({
    store: sessionRosterStore({ profile: session.profile }),
    recipient: {
      id: client.recipientKid,
      publicKeyMultibase: client.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: clientKeyAgreementKey
  })

  // 2. The document entry: the recovery VM and the update-key commitment.
  await publishRecoveryKey({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    recovery: {
      keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
      updateKeyMultibase: client.updateKeyMultibase
    },
    expectedDid: pointer.did
  })
  invalidateVerifiedLog({ profile: session.profile })

  // 3. The authorization bridge and the record that carries it.
  const delegation = await delegateLogWrite({
    zcapClient: session.profile.zcapClient,
    pointer,
    recoveryClientDid: client.clientDid
  })
  const bound = await bindRecoveryRecord({
    client,
    controller,
    pointer,
    delegation
  })

  // 4. The registry entry (public halves only).
  const entry = recoveryRegistryEntry({
    client,
    label,
    unlockSpaceId: bound.unlockSpaceId,
    manageCapability: bound.manageCapability,
    delegation,
    unlockKeyAgreementKeyId: bound.unlockKeyAgreementKeyId,
    unlockKeyAgreementKeyMultibase: bound.unlockKeyAgreementKeyMultibase
  })
  await recordRecoveryMethod({ session, entry })

  return { entry }
}

/**
 * The narrow store the recovery continuation writes through: public fetches
 * for the world-readable log (carrying the response ETag as the ceremony's
 * compare-and-swap token), and the delegated PUT (the record's zcap, invoked
 * by the code-derived did:key client) for `did.jsonl`, forwarding the
 * ceremony's conditional-write preconditions.
 *
 * @param options {object}
 * @param options.pointer {AccountPointer}
 * @param options.delegation {IZcap}
 * @param options.client {RecoveryClient}
 * @returns {RecoveryLogStore}
 */
function delegatedLogStore({
  pointer,
  delegation,
  client
}: {
  pointer: AccountPointer
  delegation: IZcap
  client: RecoveryClient
}): RecoveryLogStore {
  // The shared delegated store (public log GET + bridge-delegated PUT),
  // invoked with the code-derived did:key client.
  return unlockLogStore({
    pointer,
    delegation,
    zcapClient: client.agents.zcapClient
  })
}

/**
 * Thrown when a recovery record's proof is absent, malformed, or made by a key
 * that is neither the code's own unlock key nor a currently enrolled client of
 * the account the record names -- the storage host forged or tampered with it.
 * Recovery refuses rather than acting on the record's pointer and delegation.
 */
export class RecoveryRecordForgedError extends Error {
  constructor({ cause }: { cause?: unknown } = {}) {
    const detail = cause instanceof Error ? ` ${cause.message}` : ''
    super(`Forged or tampered recovery record.${detail}`)
    this.name = 'RecoveryRecordForgedError'
    this.cause = cause
  }
}

/**
 * Reads and unwraps a code's recovery record: derive the client identity and
 * unlock identity, one remote read, one unwrap. Shared by the `/recover`
 * page's locate step and the full recovery flow. Error discipline as on
 * `recoverAccountWithCode`.
 *
 * The record's signer is mixed (see the module doc): a record signed by the
 * code's own unlock key is verified here, before decryption. Anything else --
 * the revocation cascade's re-mint, signed by an enrolled client's account key
 * -- comes back with a pending `proofState`, which the caller MUST settle with
 * `completeRecoveryRecordProof` once it has verified the account's did:webvh
 * log. Nothing about a pending record is trustworthy until then.
 *
 * @param options {object}
 * @param options.code {string}
 * @returns {Promise<object>}   the client identity, unlock identity, the
 *   stored record, its contents, and its proof state
 */
async function readRecoveryRecord({ code }: { code: string }) {
  if (!WAS_SERVER_URL) {
    throw new RecoveryUnavailableError()
  }
  const client = await recoveryClientFromCode({ code })
  const unlock = await deriveUnlockIdentity({
    secret: client.codeBytes,
    kdf: RECOVERY_KDF
  })
  const record = await getUnlockKeyring({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId
  })
  if (record === null) {
    throw new RecoveryCodeNotFoundError()
  }
  const { contents, proofState } = await unwrapUnlockRecord({
    record,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver,
    expectedKeyMultibase: unlock.recordSigner.keyMultibase,
    // The account binding is verified in the unwrap, under the code-derived
    // MAC key -- so the pointer that comes back is code-authenticated, not
    // merely what the (host-re-encryptable) record claims.
    bindingMacKey: client.bindingMacKey
  })
  return { client, unlock, record, contents, proofState }
}

/**
 * Whether the given error is the account-log chain-head continuity refusal
 * (a rollback, a fork, or an SCID/method switch against the pinned head).
 * Matched on `name`, never `instanceof`: the shared wallet-core package may
 * be linked rather than resolved, so its class identity can be duplicated.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isResourceLogContinuityError(err: unknown): boolean {
  return (err as Error | null)?.name === 'ResourceLogContinuityError'
}

/**
 * Settles a pending recovery-record proof: a record the code's own unlock key
 * did not sign is only acceptable when an enrolled client of the account the
 * code-authenticated pointer names signed it -- the pointer's binding was
 * verified under the code-derived MAC key in the unwrap, so the document
 * fetched here belongs to the account the code was issued for, never to an
 * account a forging host substituted. A `'verified'` state passes through
 * untouched; anything the document's current signing keys cannot account for
 * refuses with `RecoveryRecordForgedError`.
 *
 * A failure is classified before it is wrapped, so "could not check" never
 * reads as "forged": an unreachable storage server (the account-log fetch)
 * rethrows unchanged, and so does a `ResourceLogContinuityError` for every
 * reason -- a `rollback` may be nothing worse than replication lag, and a
 * fork or an SCID/method switch is a continuity refusal with its own
 * surface. Neither is evidence that the RECORD was forged. Everything else
 * refuses with `RecoveryRecordForgedError`.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored recovery record, proof included
 * @param options.proofState {UnlockRecordProofState}   as `readRecoveryRecord`
 *   returned it
 * @param options.pointer {AccountPointer}   the code-authenticated account
 *   pointer (as `unwrapUnlockRecord` returned it, its binding verified)
 * @param [options.verifiedLog] {VerifiedAccountLog}   an already-verified
 *   account log; fetched and verified here when absent
 * @param [options.accountLogPinStore] {object}   the chain-head pin store the
 *   log fetch rides when no `verifiedLog` is supplied -- an in-memory store
 *   for a non-remembered browser (nothing durable may be written there); the
 *   durable session store is the default
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
async function completeRecoveryRecordProof({
  record,
  proofState,
  pointer,
  verifiedLog,
  accountLogPinStore,
  idb
}: {
  record: unknown
  proofState: UnlockRecordProofState
  pointer: AccountPointer
  verifiedLog?: VerifiedAccountLog
  accountLogPinStore?: ReturnType<typeof sessionLogPinStore>
  idb?: IDBFactory
}): Promise<void> {
  if (proofState === 'verified') {
    return
  }
  try {
    if (!isWebvhDid(pointer.did)) {
      throw new Error(
        'The record names no did:webvh account, so no document can account ' +
          'for its signer.'
      )
    }
    const logPointer = {
      did: pointer.did!,
      spaceId: pointer.spaceId,
      host: pointer.host
    }
    const signingKeys = await currentAccountSigningKeys({
      pointer: logPointer,
      ...(verifiedLog
        ? { verifiedLog }
        : {
            accountLogPinStore:
              accountLogPinStore ?? sessionLogPinStore({ idb })
          })
    })
    await verifyRecordProof({
      record,
      allowedKeyMultibases: [...signingKeys],
      label: 'recovery'
    })
  } catch (err) {
    // Could-not-check, not forged: the account-log fetch may simply have
    // failed to reach the storage server.
    if (isStorageUnreachable(err)) {
      throw err
    }
    // The account-log continuity refusal has its own surface (and a
    // `rollback` may be only replication lag), so it is never restated as a
    // forged record. Matched on `name` rather than `instanceof`: wallet-core
    // may be linked rather than resolved, duplicating class identity.
    if (isResourceLogContinuityError(err)) {
      throw err
    }
    throw new RecoveryRecordForgedError({ cause: err })
  }
}

/**
 * The `/recover` page's locate step: whether a typed code resolves to an
 * account, without changing anything. Deliberately returns nothing the
 * record claims: the record no longer carries a display cue (the email it
 * once carried was exactly the deception payload a forged record could show
 * as "this is your wallet"), and the account binding plus the settled proof
 * are what establish the account -- the page confirms only that the code
 * located one.
 *
 * @param options {object}
 * @param options.code {string}
 * @param [options.rememberBrowser] {boolean}   `true` establishes the
 *   account-log chain-head pin durably (the browser is about to be
 *   remembered); the default pins in memory only, so the locate step of a
 *   public-terminal recovery leaves zero local residue
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function locateRecoveryAccount({
  code,
  rememberBrowser = false,
  idb
}: {
  code: string
  rememberBrowser?: boolean
  idb?: IDBFactory
}): Promise<void> {
  const { record, contents, proofState } = await readRecoveryRecord({ code })
  await completeRecoveryRecordProof({
    record,
    proofState,
    pointer: contents.pointer,
    ...(rememberBrowser
      ? {}
      : { accountLogPinStore: transientSessionPersistence().logPins }),
    idb
  })
}

/**
 * What `recoverAccountWithCode` hands back for the page to finish on: the
 * replacement code to push hard (shown exactly once) and the spent code's
 * roster kid so the post-login registry update can drop its entry.
 */
export interface RecoveryOutcome {
  replacementCode: string
  replacementEntry: RecoveryCodeUnlockMethod
  spentRecoveryKid: string
}

/**
 * The whole recovery flow on a fresh browser, from a typed code to a
 * recovered account under a new passphrase (the caller then performs an
 * ordinary passphrase login). The continuation enrolls what this browser's
 * posture would enroll at login: with `rememberBrowser` a new DURABLE client
 * (today's flow -- the client-key record persists and the login is durable),
 * and otherwise -- the default, a public terminal -- the TRANSIENT variant:
 * the fresh credential's ladder VM stands in for a durable client, the
 * account lands client-less and ladder-anchored, and the visit continues as
 * an ordinary transient session with zero local residue. See the module doc
 * for the shared sequence; every stage is idempotent or convergent, so
 * re-running with the same code after a tear makes progress rather than
 * forking anything (past the add-and-retire entry the typed code correctly
 * fails as spent, and the replacement code is the resume path).
 *
 * Error discipline: a malformed code throws `RecoveryCodeInvalidError`; a
 * code with no unlock record throws `RecoveryCodeNotFoundError`; a code
 * whose posture the log no longer commits throws
 * `RecoveryKeyNotCommittedError` (revoked while its record survived); a
 * network failure rethrows unchanged, so "could not check" never reads as
 * "no account"; and an account-log continuity refusal
 * (`ResourceLogContinuityError`, any reason) rethrows unchanged too, so it
 * never reads as a forged record.
 *
 * @param options {object}
 * @param options.code {string}   the typed recovery code
 * @param options.newPassphrase {string}   the passphrase to bind the new
 *   client under
 * @param [options.rememberBrowser] {boolean}   `true` runs the durable
 *   continuation (a new enrolled client, persisted locally); the default is
 *   the transient variant, which writes nothing local
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<RecoveryOutcome>}
 */
export async function recoverAccountWithCode({
  code,
  newPassphrase,
  rememberBrowser = false,
  idb
}: {
  code: string
  newPassphrase: string
  rememberBrowser?: boolean
  idb?: IDBFactory
}): Promise<RecoveryOutcome> {
  // The code's client identity and unlock record. The method is passed
  // explicitly (`RECOVERY_KDF`) -- this page knows it holds a code.
  const recovered = await readRecoveryRecord({ code })
  const { client: spent, unlock, record, contents, proofState } = recovered
  const pointer = contents.pointer
  if (!isWebvhDid(pointer.did)) {
    throw new Error(
      'The recovery record names no did:webvh account; it cannot be ' +
        'recovered on the roster model.'
    )
  }
  if (!rememberBrowser) {
    return recoverAccountTransient({ recovered, newPassphrase })
  }
  // Verify the world-readable log locally before invoking anything. The
  // recovering browser normally holds no account-log chain-head pin yet
  // (this read is its first contact), which is exactly the pin's
  // trust-on-first-use establishment.
  const verifiedLog = await verifyAccountLog({
    did: pointer.did,
    spaceId: pointer.spaceId,
    host: pointer.host,
    pinStore: sessionLogPinStore({ idb })
  })

  // Settle the record's proof before acting on anything it carries. An
  // issuance-signed record verified before it was decrypted; a re-minted one
  // is only acceptable if a client the document still lists signed it, which
  // is knowable only now.
  await completeRecoveryRecordProof({
    record,
    proofState,
    pointer,
    verifiedLog
  })

  // Mint the NEW ordinary client and the replacement code -- in memory only
  // until the continuation lands.
  const newClientSeed = crypto.getRandomValues(new Uint8Array(32))
  const newClientAgents = await agentsFromSeed({ seed: newClientSeed })
  const newClientUpdateSeeds = await mintClientWebvhUpdateKeys()
  const { publicKeyMultibase: newClientKaMultibase } =
    newClientAgents.keyAgreementKey as unknown as {
      publicKeyMultibase?: string
    }
  if (!newClientKaMultibase) {
    throw new Error('The minted key-agreement key has no public multibase.')
  }
  const newClientKeys = {
    signingKeyMultibase: newClientAgents.keyAgent.id.split(':')[2]!,
    keyAgreementKeyMultibase: newClientKaMultibase,
    updateKeyMultibase: await updateKeyMultibase({
      seed: newClientUpdateSeeds.updateSeed
    }),
    stagedUpdateKeyMultibase: await updateKeyMultibase({
      seed: newClientUpdateSeeds.stagedSeed
    })
  }
  const replacementCode = generateRecoveryCode()
  const replacement = await recoveryClientFromCode({ code: replacementCode })

  // The self-enrolling continuation, through the delegated log write: the
  // new client in, the spent code out, the replacement code committed.
  const logStore = delegatedLogStore({
    pointer,
    delegation: contents.delegation,
    client: spent
  })
  const continuation = await recoverWebvhClient({
    store: logStore,
    // The ceremony's own did.jsonl reads must resolve to the account the
    // record's pointer names.
    expectedDid: pointer.did,
    recovery: {
      updateSeed: spent.updateSeed,
      keyAgreementKeyMultibase: spent.keyAgreementKeyMultibase,
      updateKeyMultibase: spent.updateKeyMultibase
    },
    newClientKeys,
    newClientUpdateSeeds,
    replacement: {
      keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
      updateKeyMultibase: replacement.updateKeyMultibase
    }
  })
  const did = continuation.did

  // From here the new client is an enrolled client under the current-key-set
  // rule: its `<did:webvh>#<multibase>` key signs everything.
  const newZcapClient = webvhZcapClient({
    keyAgent: newClientAgents.keyAgent,
    did
  })
  const remoteStore = new WASRemoteStore({
    storageServerUrl: pointer.host,
    zcapClient: newZcapClient,
    spaceId: pointer.spaceId,
    controller: did
  })

  // Republish the did.json projection the delegated continuation could not
  // touch (its delegation covers only the log). Non-fatal: the log is the
  // source of truth, and the next enrolled-client provisioning heals it.
  if (continuation.webDoc) {
    try {
      await remoteStore.webvhIdStore().putIdResource({
        resourceId: DID_DOCUMENT_RESOURCE,
        content: continuation.webDoc,
        contentType: 'application/did+json'
      })
    } catch (err) {
      console.warn('Could not republish did.json after recovery:', err)
    }
  }

  // The roster: escrow the new client and the replacement code into every
  // epoch (owner: the spent code's KAK, whose wraps stand since issuance),
  // read the standing user key, then the mandatory rotation off the spent code --
  // it is presumed compromised the moment it is typed.
  // The log-governed store, signing appends with the NEW client's just-
  // published key; its controller view verifies the log fresh, so it sees the
  // continuation entries that enrolled that key.
  const rosterStore = accountRosterStore({
    zcapClient: newZcapClient,
    keyAgent: newClientAgents.keyAgent,
    pointer: { did: pointer.did, spaceId: pointer.spaceId, host: pointer.host },
    pinStore: sessionLogPinStore({ idb })
  })
  await addUserKeyRosterRecipient({
    store: rosterStore,
    recipient: {
      id: newClientAgents.keyAgreementKey.id,
      publicKeyMultibase: newClientKaMultibase
    },
    ownerKeyAgreementKey: spent.agents.keyAgreementKey
  })
  await addUserKeyRosterRecipient({
    store: rosterStore,
    recipient: {
      id: replacement.recipientKid,
      publicKeyMultibase: replacement.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: spent.agents.keyAgreementKey
  })
  const pinnedEpochId = await loadUserKeyEpochPin({
    accountDid: pointer.did,
    idb
  })
  // The just-updated, locally verified document: the recipient source for
  // the rotation below. (Roster provenance is the store's own: every read
  // resolves from the log's verified head, anchored in this same document.)
  const { doc } = await verifyAccountLog({
    did: pointer.did,
    spaceId: pointer.spaceId,
    host: pointer.host,
    pinStore: sessionLogPinStore({ idb })
  })
  const preRotation = await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: newClientAgents.keyAgreementKey,
    pinnedEpochId
  })
  if (!preRotation) {
    throw new Error(
      'The account has no user key roster; it must finish provisioning before ' +
        'it can be recovered.'
    )
  }
  const oldUserKey = preRotation.userKey

  // The rotation wraps the fresh epoch only to recipients the just-updated
  // document backs -- the spent code's VM is gone, so its entry is dropped
  // even before the recipient filter. The pull axis already ran at the
  // document: the spent code's VM and update-key hash left in the
  // continuation's add-and-retire entry.
  await rotateUserKeyRoster({
    store: rosterStore,
    document: doc,
    retireRecipientId: spent.recipientKid
  })
  const postRotation = await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: newClientAgents.keyAgreementKey,
    pinnedEpochId
  })
  if (!postRotation) {
    throw new Error('The user key roster vanished during recovery.')
  }
  const newUserKey = postRotation.userKey
  await savePinFromDescriptor({
    accountDid: pointer.did,
    epochId: postRotation.latestEpochId,
    descriptor: postRotation.descriptor,
    idb
  })

  // The epoch cascade: every encrypted collection takes a fresh epoch naming
  // the rotated user key, the spent code's generation retired, history escrowed --
  // so new writes are sealed away from the spent code, not just future
  // rotations. Best-effort per collection; the completion sweep backstops a
  // partial run, and a stranded collection stays readable meanwhile (the old
  // epochs remain, escrowed to the fresh user key).
  await cascadeCollectionsToUserKey({
    remoteStore,
    rosterDescriptor: postRotation.descriptor,
    clientKeyAgreementKey: newClientAgents.keyAgreementKey,
    userKey: newUserKey
  })

  // Re-seal the unlock-methods registry to the rotated user key: its record is a
  // single-recipient envelope to the vault KAK, and the post-login registry
  // update (`recordRecoveryOutcome`) runs on the new-user key session. Best-effort:
  // a failure leaves the registry sealed to the old user key, which the post-login
  // update then surfaces as a warning.
  if (oldUserKey.id !== newUserKey.id) {
    await rewrapUnlockRegistryToUserKey({
      storageServerUrl: pointer.host,
      zcapClient: newZcapClient,
      spaceId: pointer.spaceId,
      from: userKeyVaultKeys({ userKey: oldUserKey }),
      to: userKeyVaultKeys({ userKey: newUserKey })
    })
  }

  // Retire the spent code's unlock Space -- a typed code is a spent
  // credential. Best-effort: its posture is already out of the document and
  // roster, so a surviving record can locate but never act.
  try {
    await deleteUnlockSpace({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId
    })
    await deleteUnlockLocalTrio({ spaceId: unlock.spaceId, idb })
  } catch (err) {
    console.warn("Could not delete the spent code's unlock Space:", err)
  }

  // The replacement code's record + delegation, minted by the NEW client
  // (its posture -- VM, commitment, roster wrap -- already landed above).
  const replacementPointer: AccountPointer = { ...pointer, did }
  const replacementDelegation = await delegateLogWrite({
    zcapClient: newZcapClient,
    pointer: replacementPointer,
    recoveryClientDid: replacement.clientDid
  })
  const replacementBind = await bindRecoveryRecord({
    client: replacement,
    controller: contents.controller,
    pointer: replacementPointer,
    delegation: replacementDelegation
  })
  const replacementEntry = recoveryRegistryEntry({
    client: replacement,
    label: `Replacement code (recovery ${new Date().toISOString().slice(0, 10)})`,
    unlockSpaceId: replacementBind.unlockSpaceId,
    manageCapability: replacementBind.manageCapability,
    delegation: replacementDelegation,
    unlockKeyAgreementKeyId: replacementBind.unlockKeyAgreementKeyId,
    unlockKeyAgreementKeyMultibase:
      replacementBind.unlockKeyAgreementKeyMultibase
  })

  // Bind the new client under the new passphrase: the keyring record, the
  // local client-key record (client seed + rotated user key + update-key seeds),
  // the freshness pin, and the management zcap. An ordinary passphrase login
  // now finds an enrolled client.
  // Deliberately no email: the recovery record no longer carries one to
  // inherit (it was the forged-record deception payload), and the recovered
  // keyring record starts without one.
  await bindPassphrase({
    clientSeed: newClientSeed,
    controller: contents.controller,
    passphrase: newPassphrase,
    userKey: newUserKey,
    webvhUpdateKeys: newClientUpdateSeeds,
    pointer: replacementPointer,
    // The account controller stamp above is an identity label; management
    // authority goes to the did:webvh, whose current-key-set the just-written
    // add-and-retire entry now resolves to the NEW client (the original
    // controller's key is lost -- delegating to it would strand the method).
    delegateManagementTo: unlockManagementGrantee({
      pointer: replacementPointer,
      controller: contents.controller
    }),
    idb
  })

  return {
    replacementCode,
    replacementEntry,
    spentRecoveryKid: spent.recipientKid
  }
}

/**
 * The TRANSIENT recovery variant (the default on a non-remembered browser):
 * `recoverWebvhLadderAnchored` publishes the fresh credential's ladder VM in
 * place of a durable client, so the account lands client-less and
 * ladder-anchored, and nothing touches local durable storage -- every log
 * read pins in memory and dies with the tab. The freewallet wiring around the
 * shared continuation:
 *
 * 1. Inside the continuation's `onCommitted` seam (after the reveal entry
 *    validates the code, BEFORE the add entry publishes the ladder VM): a
 *    fresh annex generation is minted under the new ladder's bootstrap
 *    did:key (a recovery record carries no annex sibling, so the old
 *    auxiliary Space is unreachable; the old generation falls to orphan
 *    discovery), its delegation embedded and its Space's controller flipped;
 *    then the new credential's bridge and sibling (ladder-VM-signed), the new
 *    passphrase's unlock record (the ladder seed inside), and the replacement
 *    code's record are durably written -- the pinned ordering: a tab death
 *    must never leave a published anchor nobody can derive. The seam names
 *    the fresh generation back to the continuation, which points the
 *    `#DelegatedClients` service entry at it inside the SAME add-and-retire
 *    entry -- that entry retires the pre-recovery credential's ladder VM, so
 *    a pointer written after it would leave a window where the document
 *    names a generation no surviving record's sibling can reach.
 * 2. A per-visit transient client is enrolled into the fresh generation (the
 *    loud entry), and the mandatory rotation runs as ONE ladder-signed roster
 *    append anchored at the add-and-retire entry (the ceremony-tail license's
 *    one shot): the spent code retired, the fresh credential and the
 *    replacement code escrowed, the fresh epoch minted -- invoked as the
 *    annex VM under the generation delegation, the only authority this
 *    visit holds over the promoted Space.
 * 3. The epoch cascade and the registry update (spent entry out, replacement
 *    and new-passphrase entries in, re-sealed to the rotated user key) ride
 *    the same delegation; the spent code's unlock Space is deleted last.
 *
 * @param options {object}
 * @param options.recovered {object}   the typed code's identities and record,
 *   as `readRecoveryRecord` returned them
 * @param options.newPassphrase {string}
 * @returns {Promise<RecoveryOutcome>}
 */
async function recoverAccountTransient({
  recovered,
  newPassphrase
}: {
  recovered: Awaited<ReturnType<typeof readRecoveryRecord>>
  newPassphrase: string
}): Promise<RecoveryOutcome> {
  const { client: spent, unlock, record, contents, proofState } = recovered
  const pointer = contents.pointer
  if (!isWebvhDid(pointer.did)) {
    throw new Error(
      'The recovery record names no did:webvh account; it cannot be ' +
        'recovered on the roster model.'
    )
  }
  const did = pointer.did
  const spaceId = pointer.spaceId
  const host = pointer.host

  // The visit's in-memory persistence handle: trust-on-first-use chain-head
  // pins for every log read here, gone with the tab.
  const persistence = transientSessionPersistence()
  const logPins = persistence.logPins

  const verifiedLog = await verifyAccountLog({
    did,
    spaceId,
    host,
    pinStore: logPins
  })
  await completeRecoveryRecordProof({
    record,
    proofState,
    pointer,
    verifiedLog
  })

  // The fresh credential (one KDF run), its ladder, and the replacement code
  // -- in memory only until the continuation lands.
  const credential = await deriveUnlockCredential({
    secret: newPassphrase,
    kdf: KEYRING_KDF
  })
  const { standing } = credential
  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const bootstrapAgent = await ladderVmAgent({ ladderSeed })
  const bootstrapWas = new WasClient({
    serverUrl: host,
    zcapClient: didKeyZcapClient({ keyAgent: bootstrapAgent })
  })
  const ladderZcap = await ladderVmZcapClient({ accountDid: did, ladderSeed })
  const replacementCode = generateRecoveryCode()
  const replacement = await recoveryClientFromCode({ code: replacementCode })

  const logStore = delegatedLogStore({
    pointer,
    delegation: contents.delegation,
    client: spent
  })

  // Filled by the `onCommitted` seam, consumed by the tail below.
  let clientAnnexSpaceId: string | undefined
  let clientAnnexDid: string | undefined
  let bridge: IZcap | undefined
  let sibling: IZcap | undefined
  let newRecordBind:
    Awaited<ReturnType<typeof bindCredentialAnchoredUnlockSecret>> | undefined
  let replacementEntry: RecoveryCodeUnlockMethod | undefined

  const continuation = await recoverWebvhLadderAnchored({
    store: logStore,
    expectedDid: did,
    recovery: {
      updateSeed: spent.updateSeed,
      keyAgreementKeyMultibase: spent.keyAgreementKeyMultibase,
      updateKeyMultibase: spent.updateKeyMultibase
    },
    ladderSeed,
    // A passphrase-derived key publishes as a hash commitment, never
    // verbatim (the hash-commitment rule).
    credentialKeyAgreement: {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase
      })
    },
    replacement: {
      keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
      updateKeyMultibase: replacement.updateKeyMultibase
    },
    // The persist-before-publish seam: runs after the reveal entry stands
    // (a revoked code has been refused) and before the add entry publishes
    // the ladder VM the seed backs. Idempotent -- a conflict retry re-invokes
    // it, converging on the same generation and re-writing the records. Its
    // returned annex DID rides INTO the add entry, so the `#DelegatedClients`
    // pointer moves atomically with the retirement of the pre-recovery
    // credential's ladder VM.
    onCommitted: async () => {
      // The fresh annex generation, minted once per run (a retry reuses
      // it): genesis under the bootstrap did:key self-commits the fresh
      // credential's per-generation rung 0, the delegation embeds while the
      // auxiliary Space still answers to the bootstrap key, the controller
      // flips after -- the credential-anchored genesis order.
      if (!clientAnnexDid) {
        clientAnnexSpaceId = mintSpaceId()
        const minted = await mintCredentialClientAnnexGeneration({
          was: bootstrapWas,
          wasServerUrl: host,
          spaceId: clientAnnexSpaceId,
          controller: bootstrapAgent.id,
          ladderSeed
        })
        await ensureGenerationDelegationCurrent({
          store: clientAnnexLogStore({
            was: bootstrapWas,
            spaceId: clientAnnexSpaceId,
            generationId: minted.generationId
          }),
          ladderSeed,
          generationId: minted.generationId,
          mintGenerationDelegation: async ({ clientAnnexDid: generationDid }) =>
            mintGenerationDelegation({
              zcapClient: ladderZcap,
              wasServerUrl: host,
              spaceId,
              clientAnnexDid: generationDid
            }),
          expectedDid: minted.did
        })
        await bootstrapWas
          .space(clientAnnexSpaceId)
          .configure({ controller: did, force: true })
        clientAnnexDid = minted.did
      }
      // The new credential's bridge and sibling, ladder-VM-signed: they
      // verify once the add entry publishes the ladder VM.
      bridge = await delegateLogWrite({
        zcapClient: ladderZcap,
        pointer,
        recoveryClientDid: standing.clientDid
      })
      sibling = await mintDelegatedClientsDelegation({
        zcapClient: ladderZcap,
        wasServerUrl: host,
        clientAnnexSpaceId: clientAnnexSpaceId!,
        controller: standing.clientDid
      })
      // The new passphrase's unlock record, the fresh ladder seed inside --
      // durably written before the VM that seed backs publishes.
      newRecordBind = await bindCredentialAnchoredUnlockSecret({
        controller: bootstrapAgent.id,
        pointer,
        delegation: bridge,
        delegatedClients: sibling,
        ladderSeed,
        delegateManagementTo: did,
        credential
      })
      // The replacement code's record (no sibling -- a code needs no
      // annex authority; its delegation is ladder-VM-signed).
      const replacementDelegation = await delegateLogWrite({
        zcapClient: ladderZcap,
        pointer,
        recoveryClientDid: replacement.clientDid
      })
      const replacementBind = await bindRecoveryRecord({
        client: replacement,
        controller: contents.controller,
        pointer,
        delegation: replacementDelegation
      })
      replacementEntry = recoveryRegistryEntry({
        client: replacement,
        label: `Replacement code (recovery ${new Date()
          .toISOString()
          .slice(0, 10)})`,
        unlockSpaceId: replacementBind.unlockSpaceId,
        manageCapability: replacementBind.manageCapability,
        delegation: replacementDelegation,
        unlockKeyAgreementKeyId: replacementBind.unlockKeyAgreementKeyId,
        unlockKeyAgreementKeyMultibase:
          replacementBind.unlockKeyAgreementKeyMultibase
      })
      return { clientAnnexDid }
    }
  })
  if (
    !clientAnnexSpaceId ||
    !clientAnnexDid ||
    !bridge ||
    !sibling ||
    !newRecordBind ||
    !replacementEntry
  ) {
    throw new Error(
      'The recovery continuation completed without establishing the fresh ' +
        "credential's records."
    )
  }

  // The per-visit transient client, enrolled into the fresh generation
  // through the new record's sibling (the loud entry): the invocation
  // identity the rotation, the cascade, and the registry update ride, since
  // the generation delegation is the only authority this visit holds over
  // the promoted Space.
  const visitSeed = crypto.getRandomValues(new Uint8Array(32))
  const visitAgents = await agentsFromSeed({ seed: visitSeed })
  const { doc: clientAnnexDoc } = await enrollTransientClient({
    readAccountDocument: async () =>
      (
        await verifyAccountLog({
          did,
          spaceId,
          host,
          pinStore: logPins
        })
      ).doc,
    storeForGenerationId: generationId =>
      delegatedWebvhLogStore({
        host,
        spaceId: clientAnnexSpaceId!,
        collectionId: generationId,
        delegation: sibling!,
        zcapClient: standing.agents.zcapClient
      }),
    ladderSeed,
    transientKeyMultibase: clientSigningKeyMultibase({
      keyAgent: visitAgents.keyAgent
    }),
    // The fresh genesis embedded its delegation above; a generation without
    // one here is a torn establishment, not a mintable state.
    mintGenerationDelegation: async () => {
      throw new Error(
        'The fresh annex generation carries no embedded delegation.'
      )
    },
    pinStore: logPins
  })
  const generationDelegation = embeddedGenerationDelegation({
    doc: clientAnnexDoc
  })
  if (!generationDelegation) {
    throw new Error(
      'The fresh annex generation carries no embedded delegation.'
    )
  }
  const transientZcapClient = webvhZcapClient({
    keyAgent: visitAgents.keyAgent,
    did: clientAnnexDid
  })

  // The roster store the mandatory rotation drives: appends signed by the
  // fresh ladder VM, anchored at the continuation's own add-and-retire entry
  // (the posture-changing version the ceremony-tail license admits, and the
  // log head -- the pointer rides inside that entry), HTTP invoked as the
  // annex VM under the generation delegation.
  const rosterStore = userKeyRosterDescriptorStore({
    storageServerUrl: host,
    zcapClient: transientZcapClient,
    spaceId,
    resolveController: async () =>
      webvhResourceLogController({ did, log: continuation.log }),
    pinStore: logPins,
    signer: userKeyRosterLogSigner({ keyAgent: bootstrapAgent }),
    capability: generationDelegation
  })
  const preRotation = await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: spent.agents.keyAgreementKey
  })
  if (!preRotation) {
    throw new Error(
      'The account has no user key roster; it must finish provisioning before ' +
        'it can be recovered.'
    )
  }
  const oldUserKey = preRotation.userKey

  // The mandatory rotation, in the ONE ladder-signed append the license
  // admits: the spent code's wrap retired, the fresh credential's standing
  // key and the replacement code escrowed into every epoch, and the fresh
  // epoch minted -- all in a single descriptor write. Convergent: a re-run
  // writes nothing.
  await replaceUserKeyRosterRecipients({
    store: rosterStore,
    document: continuation.doc as Parameters<
      typeof replaceUserKeyRosterRecipients
    >[0]['document'],
    retireRecipientIds: [spent.recipientKid],
    recipients: [
      {
        id: standing.recipientKid,
        publicKeyMultibase: standing.keyAgreementKeyMultibase
      },
      {
        id: replacement.recipientKid,
        publicKeyMultibase: replacement.keyAgreementKeyMultibase
      }
    ],
    ownerKeyAgreementKey: spent.agents.keyAgreementKey
  })
  const postRotation = await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: standing.agents.keyAgreementKey
  })
  if (!postRotation) {
    throw new Error('The user key roster vanished during recovery.')
  }
  const newUserKey = postRotation.userKey

  // The epoch cascade under the generation delegation: every encrypted
  // collection takes a fresh epoch naming the rotated user key. Best-effort
  // per collection; a stranded collection stays keyed to the spent code
  // until the next durable login or a spend re-run (the documented residue
  // -- the transient completion is its own follow-up).
  const remoteStore = new WASRemoteStore({
    storageServerUrl: host,
    zcapClient: transientZcapClient,
    spaceId,
    controller: did,
    capability: generationDelegation
  })
  await cascadeCollectionsToUserKey({
    remoteStore,
    rosterDescriptor: postRotation.descriptor,
    clientKeyAgreementKey: standing.agents.keyAgreementKey,
    userKey: newUserKey
  })

  // The registry, one read-modify-write (the durable flow's re-seal and
  // post-login updates folded into the ceremony, since a transient session
  // cannot run them later): the spent code's entry out, the replacement's
  // and the new passphrase's in, the record re-sealed to the rotated user
  // key. Best-effort -- the account is recovered without it, and the next
  // durable login surfaces a stale registry as a warning.
  try {
    const existing = await getUnlockMethodsWithClient({
      zcapClient: transientZcapClient,
      spaceId,
      userKey: oldUserKey,
      capability: generationDelegation
    })
    const base = existing ?? emptyUnlockMethodsRegistry()
    const dropped = new Set([replacementEntry.recoveryKid, spent.recipientKid])
    const methods = [
      ...base.methods.filter(
        method =>
          method.type !== 'recovery-code' || !dropped.has(method.recoveryKid)
      ),
      replacementEntry
    ]
    const bridgeKeyId = delegationProofKeyId(bridge)
    const siblingKeyId = delegationProofKeyId(sibling)
    const updated = upsertPassphraseUnlockMethod({
      record: { ...base, methods },
      unlockSpaceId: newRecordBind.unlockSpaceId,
      manageCapability: newRecordBind.manageCapability,
      standing: {
        rosterKid: standing.recipientKid,
        keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
        updateKeyMultibase: rung0.keyMultibase,
        unlockClientDid: standing.clientDid,
        ...(bridgeKeyId ? { delegationKeyId: bridgeKeyId } : {}),
        ...((bridge as { expires?: string }).expires
          ? { delegationExpires: (bridge as { expires?: string }).expires }
          : {}),
        ...(siblingKeyId ? { delegatedClientsKeyId: siblingKeyId } : {}),
        ...((sibling as { expires?: string }).expires
          ? {
              delegatedClientsExpires: (sibling as { expires?: string }).expires
            }
          : {}),
        ...(newRecordBind.unlockKeyAgreementKeyId
          ? { unlockKeyAgreementKeyId: newRecordBind.unlockKeyAgreementKeyId }
          : {}),
        ...(newRecordBind.unlockKeyAgreementKeyMultibase
          ? {
              unlockKeyAgreementKeyMultibase:
                newRecordBind.unlockKeyAgreementKeyMultibase
            }
          : {})
      }
    })
    await putUnlockMethodsWithClient({
      zcapClient: transientZcapClient,
      spaceId,
      userKey: newUserKey,
      record: updated,
      capability: generationDelegation
    })
  } catch (err) {
    console.warn(
      'Could not update the unlock-methods registry during recovery:',
      err
    )
  }

  // Retire the spent code's unlock Space -- a typed code is a spent
  // credential. Remote only: a transient visit touches no local storage.
  try {
    await deleteUnlockSpace({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId
    })
  } catch (err) {
    console.warn("Could not delete the spent code's unlock Space:", err)
  }

  return {
    replacementCode,
    replacementEntry,
    spentRecoveryKid: spent.recipientKid
  }
}

/**
 * The account's issued recovery codes, read off the unlock-methods registry.
 * A read failure is reported as an empty listing (the panel is informational;
 * issuing and revoking each read the registry again).
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<RecoveryCodeUnlockMethod[]>}
 */
export async function listRecoveryCodeEntries({
  session
}: {
  session: Session
}): Promise<RecoveryCodeUnlockMethod[]> {
  try {
    return recoveryEntriesOf({ record: await getUnlockMethods({ session }) })
  } catch (err) {
    console.warn('Could not load the recovery-code entries:', err)
    return []
  }
}

/**
 * The two post-login registry updates a recovery owes, run in sequence.
 *
 * Sequenced, not concurrent: both are read-modify-writes over the same
 * registry resource with last-write-wins puts, so firing them together races
 * -- the loser's read goes stale and its put silently drops the winner's
 * update (losing the replacement code's entry, or repointing the passphrase
 * entry at the deleted pre-recovery unlock Space). Both halves are
 * best-effort: the account is already recovered and logged in.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.outcome {RecoveryOutcome}
 * @param [options.passphrase] {string}   the freshly chosen passphrase, still
 *   in hand on the recovery page: when given, it is promoted to a standing
 *   credential (roster wrap, commitment document entry, bridge delegation,
 *   standing-layout record) after the registry writes
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function updateRegistryAfterRecovery({
  session,
  outcome,
  passphrase,
  idb
}: {
  session: Session
  outcome: RecoveryOutcome
  passphrase?: string
  idb?: IDBFactory
}): Promise<void> {
  try {
    // The replacement recorded and the spent code dropped in one write.
    await recordRecoveryMethod({
      session,
      entry: outcome.replacementEntry,
      dropKids: [outcome.spentRecoveryKid]
    })
  } catch (err) {
    console.warn('Could not update the unlock-methods registry:', err)
  }
  try {
    await backfillPassphraseUnlockMethod({ session })
  } catch (err) {
    console.warn('Could not backfill the unlock-methods registry:', err)
  }
  if (passphrase) {
    // Best-effort inside (a plain-layout record still logs in); runs after
    // the registry writes so its upsert reads their result.
    await establishPassphrasePosture({ session, passphrase, idb })
  }
}

/**
 * Revokes a recovery code from a live enrolled session -- the issuance
 * reversal, in the cascade order: the document entry out first (the pull
 * axis: the code's VM and commitment leave, so the doc-backed resolver drops
 * its roster entry), then the mandatory user key rotation off the code's wrap,
 * then the epoch cascade re-keying every encrypted collection, then the
 * unlock Space (whose deletion is what makes the code resolve to nothing
 * afterwards) and the registry entry. The revocation is REAL -- the secret
 * was only ever a pointer to the record -- which is stronger than what the
 * sharing layer can promise.
 *
 * The rotated user key is persisted into this client's client-key record and
 * epoch pin, and the live session ADOPTS it in place (it drove the rotation,
 * so it holds the fresh key): profile vault keys swapped, storage ciphers
 * rebuilt -- no re-login. Other clients adopt the rotation at their next
 * login via the ordinary roster read.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {RecoveryCodeUnlockMethod}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function revokeRecoveryCode({
  session,
  entry,
  idb
}: {
  session: Session
  entry: RecoveryCodeUnlockMethod
  idb?: IDBFactory
}): Promise<void> {
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Revoking a recovery code'
  })
  const { epochPins } = session.profile.persistence
  const { remoteStore, pointer, clientWebvhKeys, clientKeyAgreementKey } =
    requireEnrolledClientContext({
      session,
      action: 'Recovery-code revocation'
    })

  // 1. The document entry out (idempotent).
  await removeRecoveryKey({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    recovery: {
      keyAgreementKeyMultibase: entry.keyAgreementKeyMultibase,
      updateKeyMultibase: entry.updateKeyMultibase
    },
    expectedDid: pointer.did
  })

  // 2. The user key rotation off the code's wrap, recipients resolved from the
  // just-updated document (the pull axis already ran there) -- so the memo
  // from before the edit is dropped first, and the re-read refills it with
  // the document every later surface should see.
  invalidateVerifiedLog({ profile: session.profile })
  const { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer
  })
  const rosterStore = sessionRosterStore({ profile: session.profile })
  await rotateUserKeyRoster({
    store: rosterStore,
    document: doc,
    retireRecipientId: entry.recoveryKid
  })
  const read = await readUserKeyRoster({
    store: rosterStore,
    userKey: session.profile.userKey,
    clientKeyAgreementKey,
    pinnedEpochId: await epochPins.load({ accountDid: pointer.did })
  })
  let rotatedUserKey: UserKey | undefined
  if (read) {
    await epochPins.saveFromDescriptor({
      accountDid: pointer.did,
      epochId: read.latestEpochId,
      descriptor: read.descriptor
    })
    if (read.rotated) {
      // Persist the rotated user key for the next login, then re-epoch every
      // encrypted collection onto it (best-effort per collection; the
      // completion sweep backstops a partial run).
      rotatedUserKey = read.userKey
      await session.profile.persistClientKeys?.({ userKey: read.userKey })
      await cascadeCollectionsToUserKey({
        remoteStore,
        rosterDescriptor: read.descriptor,
        clientKeyAgreementKey,
        userKey: read.userKey
      })
    }
  }

  // 3. The unlock Space and the registry entry -- the shared tap-free
  // revocation path (the entry's management zcap, invoked with this
  // client's did:key). Still under the OLD vault keys, so the registry
  // reads/writes decrypt the stored record.
  await revokeUnlockMethod({ session, entry, idb })

  // 4. Re-seal the registry to the rotated user key (step 3's write went out
  // under the old vault KAK), then adopt the rotation in the live session:
  // profile vault keys swapped and the storage ciphers rebuilt, so this
  // session keeps reading and writing the re-epoch'd collections without a
  // re-login. Best-effort: a failed re-seal leaves the registry sealed to
  // the old user key, which the next login surfaces as a warning.
  if (rotatedUserKey) {
    await adoptRotatedUserKey({
      session,
      spaceId: pointer.spaceId,
      userKey: rotatedUserKey
    })
  }
}

/**
 * Re-mints the unlock-record bridge delegations the current document no
 * longer backs -- the delta riding the revocation cascade, for the recovery
 * codes AND the standing passphrase/passkey credentials alike (one bridge
 * machinery, per FW-154's one-codepath model). The mechanism, the skip
 * policy, and the binding-carried-forward re-wrap all live in
 * `@interop/wallet-core/recovery`; this binding supplies the app seams: the
 * storage server URL, the session's delegating signer and account record
 * signer, the management-zcap client factory, and the unlock-methods registry
 * read/record halves.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.doc {PublishedKeyDocument}   the locally verified
 *   did:webvh document, AFTER the revocation edit
 * @param [options.registryRecord] {UnlockMethodsRecord | null}   the
 *   unlock-methods registry, when the caller already read it (the revocation
 *   cascade reads it once for its document edit and this stage)
 * @returns {Promise<{ reminted: number; skipped: number }>}
 */
export async function remintRecoveryDelegations({
  session,
  doc,
  registryRecord: prefetched
}: {
  session: Session
  doc: Parameters<typeof remintDelegationsCore>[0]['doc']
  registryRecord?: UnlockMethodsRecord | null
}): Promise<{ reminted: number; skipped: number }> {
  const pointer = session.profile.accountPointer
  const keyAgent = session.profile.keyAgent
  if (!WAS_SERVER_URL || !pointer || !keyAgent) {
    return { reminted: 0, skipped: 0 }
  }
  const record =
    prefetched !== undefined ? prefetched : await getUnlockMethods({ session })
  const entries = recoveryEntriesOf({ record })
  // The standing passphrase/passkey entries ride the same re-mint: their
  // bridge delegations rot on the same document edit and refresh through
  // the same record machinery, with `unlockClientDid` filling the
  // delegation-grantee slot the recovery entries call `recoveryClientDid`.
  const standingSources = (record?.methods ?? []).filter(
    (method): method is PassphraseUnlockMethod | PasskeyUnlockMethod =>
      (method.type === 'passphrase' || method.type === 'passkey') &&
      !!method.unlockClientDid
  )
  // The sibling pair is absent on recovery codes by construction; stating it
  // keeps the entry union uniform for the recordEntry callback below.
  const remintEntries = [
    ...entries.map(entry => ({
      ...entry,
      delegatedClientsKeyId: undefined,
      delegatedClientsExpires: undefined,
      source: entry as UnlockMethod
    })),
    ...standingSources.map(method => ({
      label: method.type,
      unlockSpaceId: method.unlockSpaceId,
      manageCapability: method.manageCapability,
      delegationKeyId: method.delegationKeyId,
      delegationExpires: method.delegationExpires,
      delegatedClientsKeyId: method.delegatedClientsKeyId,
      delegatedClientsExpires: method.delegatedClientsExpires,
      recoveryClientDid: method.unlockClientDid,
      unlockKeyAgreementKeyId: method.unlockKeyAgreementKeyId,
      unlockKeyAgreementKeyMultibase: method.unlockKeyAgreementKeyMultibase,
      source: method as UnlockMethod
    }))
  ]
  if (remintEntries.length === 0) {
    return { reminted: 0, skipped: 0 }
  }
  return remintDelegationsCore({
    doc,
    entries: remintEntries,
    pointer,
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: session.profile.zcapClient,
    mintDelegatedClientsDelegation: delegatedClientsDelegationMinter({
      doc,
      zcapClient: session.profile.zcapClient,
      wasServerUrl: pointer.host
    }),
    // The re-mint holds the credential's KAK public half but not its signing
    // key, so every record it re-PUTs is signed with this client's own
    // account key -- the mixed-signer case a reader settles against the
    // verified document.
    recordSigner: recordSignerFromAgent({ keyAgent }),
    managementZcapClient: ({ capability }) =>
      managementZcapClient({ session, capability }),
    recordEntry: async ({ entry }) => {
      if (entry.source.type === 'recovery-code') {
        await recordRecoveryMethod({
          session,
          entry: {
            ...(entry.source as RecoveryCodeUnlockMethod),
            ...(entry.delegationKeyId
              ? { delegationKeyId: entry.delegationKeyId }
              : {}),
            ...(entry.delegationExpires
              ? { delegationExpires: entry.delegationExpires }
              : {})
          }
        })
        return
      }
      await refreshStandingDelegationFields({
        session,
        unlockSpaceId: entry.unlockSpaceId,
        delegationKeyId: entry.delegationKeyId,
        delegationExpires: entry.delegationExpires,
        delegatedClientsKeyId: entry.delegatedClientsKeyId,
        delegatedClientsExpires: entry.delegatedClientsExpires
      })
    }
  })
}

/**
 * One flagged registry entry from the login-time recovery health check, with
 * the reasons it is flagged.
 */
export interface RecoveryHealthFlag {
  entry: RecoveryCodeUnlockMethod
  delegationRotted: boolean
  delegationExpiring: boolean
  postureMissing: boolean
}

/**
 * The login-time recovery health check: for each recovery-code
 * registry entry, tests that the stored delegation still chains against the
 * current document (its signing client's verification method is still
 * listed -- the current-key-set rule), that it is not expired or inside the
 * renewal window (the one-year TTL lapses within a code's expected
 * lifetime), and that the code's posture (its `keyAgreement` VM and
 * committed update-key hash) still stands. A stale delegation bricks
 * recovery exactly when it is needed. The revocation cascade re-mints stale
 * delegations automatically (`remintRecoveryDelegations`); this check is
 * the backstop for entries that predate the re-mint fields -- whose flag
 * nudges the user to regenerate the code -- and for expiry between
 * revocations. Both stages ask the same shared predicates
 * (`delegationKeyInDocument`, `zcapExpiring`), so an entry
 * recording no delegation key or expiry at all -- uncheckable, and
 * therefore not assumed healthy -- is flagged here
 * rather than being simultaneously "fine" and "needs re-minting".
 * Returns only the flagged entries; resolves `[]` when there is nothing to
 * check or the account has no recovery codes.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.entries] {RecoveryCodeUnlockMethod[]}   the registry's
 *   recovery entries, when the caller already read them (the Settings panel
 *   lists them immediately before checking their health)
 * @returns {Promise<RecoveryHealthFlag[]>}
 */
export async function checkRecoveryHealth({
  session,
  entries: prefetched
}: {
  session: Session
  entries?: RecoveryCodeUnlockMethod[]
}): Promise<RecoveryHealthFlag[]> {
  const remoteStore = session.storage.remoteStore
  const pointer = session.profile.accountPointer
  if (!remoteStore || !pointer || !isWebvhDid(pointer.did)) {
    return []
  }
  const entries =
    prefetched ??
    recoveryEntriesOf({ record: await getUnlockMethods({ session }) })
  if (entries.length === 0) {
    return []
  }
  const { doc, nextKeyHashes } = await verifiedAccountLog({
    profile: session.profile,
    pointer
  })
  const publishedMultibases = documentKeyMultibases({ doc })
  // Each entry's update-key hash is an independent derivation; run them
  // together rather than one per loop turn.
  const updateKeyHashes = await Promise.all(
    entries.map(entry => deriveNextKeyHash(entry.updateKeyMultibase))
  )
  const flags: RecoveryHealthFlag[] = []
  for (const [position, entry] of entries.entries()) {
    // The same predicate the re-mint stage uses, so one registry entry can no
    // longer be "needs re-minting" here and "fine" there: an entry recording
    // no delegation key is uncheckable, so it is flagged (the documented
    // fallback to the regenerate nudge).
    const delegationRotted = !delegationKeyInDocument({
      doc,
      ...(entry.delegationKeyId
        ? { delegationKeyId: entry.delegationKeyId }
        : {})
    })
    // The expiry half of the same shared predicate the re-mint uses: a
    // delegation expired or inside the renewal window (or recording no
    // expiry) is flagged before it lapses.
    const delegationExpiring = zcapExpiring({
      ...(entry.delegationExpires ? { expires: entry.delegationExpires } : {})
    })
    const postureMissing =
      !publishedMultibases.has(entry.keyAgreementKeyMultibase) ||
      !nextKeyHashes.includes(updateKeyHashes[position])
    if (delegationRotted || delegationExpiring || postureMissing) {
      flags.push({
        entry,
        delegationRotted,
        delegationExpiring,
        postureMissing
      })
    }
  }
  return flags
}
