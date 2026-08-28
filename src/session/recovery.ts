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
 *   what the browser's login routing would enroll: a new enrolled client
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
import {
  memoryResourceLogPinStore,
  type ResourceLogPinStore
} from '@interop/vh-resource-log'
import { WAS_SERVER_URL } from '@/app.config'
import { DID_DOCUMENT_RESOURCE } from '@interop/wallet-core/space'
import {
  standingFieldsOfKeyringHit,
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
  accountLogPinId,
  clientSigningKeyMultibase,
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
  clientAnnexDidParts,
  clientAnnexLogPinId,
  delegatedClientsPointer,
  clientAnnexLogStore,
  delegatedClientsDelegationMinter,
  embeddedGenerationDelegation,
  enrollClientAnnexTransientClient,
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
import { WasClient, type CollectionEncryption } from '@interop/was-client'
import { unwrapEpochSecret } from '@interop/was-client/edv'
import {
  currentAccountRecordSigners,
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
  type RecoveryDelegationEntry,
  type RecoveryLogStore,
  type UnlockRecordProofState
} from '@interop/wallet-core/recovery'
import { base58 } from '@scure/base'
import {
  publishUnlockKey,
  unlockClientIdentityFromSeed,
  unlockKeyVmId
} from '@interop/wallet-core/unlock'
import type {
  ClientKeyRecord,
  UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import type { Session } from '@/types/auth'
import {
  bindCredentialAnchoredUnlockSecret,
  bindPassphrase,
  delegateUnlockManagement,
  deriveUnlockCredential,
  probeUnlockSpaceCollision,
  unlockManagementGrantee,
  type KeyringFetchResult,
  type PersistableClientKeys
} from '@/session/keyring'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { transientSessionStores } from '@/session/persistence'
import {
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  getUnlockMethodsWithClient,
  managementZcapClient,
  refreshStandingDelegationFields,
  updateUnlockMethods,
  updateUnlockMethodsWithClient,
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
  adoptRotatedUserKeyInBand,
  rewrapUnlockRegistryToUserKey
} from '@/session/userKeyAdoption'
import { deleteUnlockLocalState } from '@/lib/sessionKey'
import { assertAccountCeremonyAllowed } from '@/session/persistence'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { mintSpaceId, WASRemoteStore } from '@/stores/wasRemoteStore'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:recovery')

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
 * which records the replacement code and retires the spent one together in
 * one atomic write (the write itself is the shared compare-and-swap
 * read-modify-write, so a lost race re-applies both on the fresh record).
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
  const dropped = new Set([entry.recoveryKid, ...dropKids])
  await updateUnlockMethods({
    session,
    mutate: existing => {
      const record = existing ?? emptyUnlockMethodsRegistry()
      const methods = [
        ...record.methods.filter(
          method =>
            method.type !== 'recovery-code' || !dropped.has(method.recoveryKid)
        ),
        entry
      ]
      return { ...record, methods }
    }
  })
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
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes; on a settled session the chain resolved long ago.
  await session.registryReady
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
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   the chain-head
 *   pin store the log fetch rides when no `verifiedLog` is supplied; this
 *   check's own in-memory store is the default
 * @returns {Promise<void>}
 */
async function completeRecoveryRecordProof({
  record,
  proofState,
  pointer,
  verifiedLog,
  accountLogPinStore
}: {
  record: unknown
  proofState: UnlockRecordProofState
  pointer: AccountPointer
  verifiedLog?: VerifiedAccountLog
  accountLogPinStore?: ResourceLogPinStore
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
    // The allowlist is the record-signer set, not the enrolled-client set:
    // a code's record re-minted by the last-client forget is signed by the
    // ladder VM, the one key a client-less account's document still lists.
    const signingKeys = await currentAccountRecordSigners({
      pointer: logPointer,
      ...(verifiedLog
        ? { verifiedLog }
        : {
            accountLogPinStore:
              accountLogPinStore ?? memoryResourceLogPinStore()
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
 * @returns {Promise<void>}
 */
export async function locateRecoveryAccount({
  code
}: {
  code: string
}): Promise<void> {
  const { record, contents, proofState } = await readRecoveryRecord({ code })
  await completeRecoveryRecordProof({
    record,
    proofState,
    pointer: contents.pointer
  })
}

/**
 * What `recoverAccountWithCode` hands back for the page to finish on: the
 * replacement code to push hard (shown exactly once), the spent code's roster
 * kid (the registry backfill drops its entry), and -- on the remembered
 * variant -- the confirm-gated record completion: the page runs it on the
 * "I saved this code" confirm, before the login, so the show-once code stays
 * re-displayable from the pending record's persisted bytes until the user
 * has confirmed saving it.
 *
 * `standing` reports the new passphrase's standing configuration truthfully:
 * `'established'` when the ceremony tail landed both halves (the roster wrap
 * and the document entry), `'pending'` when it did not. Pending means the
 * account IS recovered and the new passphrase IS live; only its setup for
 * logging in from other browsers is outstanding, and it completes at a later
 * resume or remembered-login mend. The continuation never fails for a pending
 * standing.
 */
export interface RecoveryOutcome {
  replacementCode: string
  replacementEntry: RecoveryCodeUnlockMethod
  spentRecoveryKid: string
  standing: 'established' | 'pending'
  completeRecovery?: (options?: { currentUserKey?: UserKey }) => Promise<void>
}

/**
 * The whole recovery flow on a fresh browser, from a typed code to a
 * recovered account under a new passphrase (the caller then performs an
 * ordinary passphrase login). The continuation enrolls what this browser's
 * login routing would enroll: with `rememberBrowser` a new ENROLLED client
 * (today's flow -- the client-key record persists and the browser is
 * remembered), and otherwise -- the default, a public terminal -- the
 * TRANSIENT variant: the fresh credential's ladder VM stands in for an
 * enrolled client, the account lands client-less and ladder-anchored, and
 * the visit continues as an ordinary transient session with zero local
 * residue. See the module doc for the shared sequence; every stage is
 * idempotent or convergent, so re-running with the same code after a tear
 * makes progress rather than forking anything (past the add-and-retire
 * entry the typed code correctly fails as spent, and the pending-record
 * spend resume -- or the replacement code -- finishes the tail).
 *
 * The remembered variant is persist-before-publish end to end. The required
 * `onCommitted` seam fires between the reveal entry (the loud validation of
 * the typed code) and the add-and-retire entry, and persists everything
 * whose only holder would otherwise be tab memory once the pivot lands: the
 * new passphrase's STANDING-layout unlock record (bridge, best-effort annex
 * sibling, fresh ladder seed, management zcap), the local PENDING
 * client-key record (seeds, controller, `pointerDid`, and the pending
 * group -- the ceremony discriminator, the built-on head, the spent
 * code's unwrap key, the replacement code's bytes -- no user key), and
 * the replacement code's record and bridge. The tail (escrows, rotation,
 * registry mutation, cascade, spent-Space delete) stays post-entry --
 * structurally, since every write signs as the just-published client -- and
 * the final record completion is CONFIRM-GATED through the returned
 * `completeRecovery` closure, so the show-once replacement code stays
 * re-displayable from the persisted bytes until the user confirms saving
 * it. A tab death anywhere after the entry leaves a pending record the next
 * login's spend resume (`resumeRecoverySpend`) finishes.
 *
 * Error discipline: a malformed code throws `RecoveryCodeInvalidError`; a
 * code with no unlock record throws `RecoveryCodeNotFoundError`; a code
 * whose inventory the log no longer commits throws
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
 * @param [options.rememberBrowser] {boolean}   `true` runs the remembered
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
  // recovering browser holds no account-log chain-head pin yet (this read
  // is its first contact), which is exactly the pin's trust-on-first-use
  // establishment.
  const verifiedLog = await verifyAccountLog({
    did: pointer.did,
    spaceId: pointer.spaceId,
    host: pointer.host,
    pinStore: memoryResourceLogPinStore()
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

  // The new passphrase's credential (one KDF run, reused by every bind
  // below) and the read-first collision probe: a served record at the new
  // passphrase's unlock Space that names another account, or a standing
  // credential's record this ceremony would clobber, refuses HERE -- before
  // the reveal entry burns anything -- and surfaces at the new-passphrase
  // form. The probe also finds this ceremony's own earlier attempt (a
  // pre-entry tear's pending record), whose persisted replacement-code bytes
  // the re-run reuses so the replacement's unlock Space address stays
  // stable across attempts.
  const newCredential = await deriveUnlockCredential({
    secret: newPassphrase,
    kdf: KEYRING_KDF
  })
  const { ownPending } = await probeUnlockSpaceCollision({
    credential: newCredential,
    controller: contents.controller,
    pointer,
    // The one overwrite license: a tab death in an earlier attempt's bind
    // (remote record PUT landed, local persists did not) leaves a served
    // standing record with no pending record behind it, and only the
    // verified document can prove it this ceremony's own inert residue (an
    // unpublished credential inventory).
    accountDoc: verifiedLog.doc,
    idb
  })

  // Mint the NEW ordinary client and the replacement code -- in memory only
  // until the persist hook below writes them (the unlock records
  // server-side, the pending client-key record browser-local), right before
  // the add-and-retire entry publishes them.
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
  // The replacement code is minted ONCE per ceremony: a re-run after a
  // pre-entry tear re-derives it from the pending record's persisted bytes,
  // so the same unlock Space address is reused and no orphan Space strands.
  const replacementCode = ownPending?.replacementCode
    ? base58.encode(ownPending.replacementCode)
    : generateRecoveryCode()
  if (ownPending?.replacementCode) {
    log.info(
      'Recovery spend re-run: reusing the replacement code persisted by a ' +
        'torn earlier attempt'
    )
  }
  const replacement = await recoveryClientFromCode({ code: replacementCode })

  // The account did and the new client's promoted signer. The bridge and
  // sibling delegations minted inside the hook are signed with this key
  // PRE-entry: they verify at use time, once the add-and-retire entry has
  // published the signer (the current-key-set rule).
  const accountDid = pointer.did!
  const newZcapClient = webvhZcapClient({
    keyAgent: newClientAgents.keyAgent,
    did: accountDid
  })
  const newLadderSeed = generateLadderSeed()
  const newRung0 = await ladderRung({ ladderSeed: newLadderSeed, index: 0 })

  // Filled by the `onCommitted` seam, consumed by the tail below.
  let hookFires = 0
  let newRecordBind: Awaited<ReturnType<typeof bindPassphrase>> | undefined
  let bridge: IZcap | undefined
  let sibling: IZcap | undefined
  let replacementEntry: RecoveryCodeUnlockMethod | undefined

  // The self-enrolling continuation, through the delegated log write: the
  // new client in, the spent code out, the replacement code committed. Both
  // entry builds run over the ceremony's own chain-head pin.
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
    pinStore: memoryResourceLogPinStore(),
    logId: accountLogPinId({ spaceId: pointer.spaceId }),
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
    },
    // The persist-before-publish seam: fires after the reveal entry stands
    // (a revoked or spent code has been refused) and before the
    // add-and-retire entry publishes the successors. Idempotent per attempt
    // -- a conflict retry re-invokes it, overwriting the same records.
    // Everything whose only holder would otherwise be tab memory once the
    // pivot lands is written here.
    onCommitted: async ({ builtOnHead }) => {
      hookFires += 1
      if (hookFires > 1) {
        log.info('Recovery-spend persist hook re-fired on a conflict retry', {
          attempt: hookFires
        })
      }
      // The new passphrase's standing members, signed by the new client's
      // promoted key pre-entry (verifying at use time). The annex-Space
      // sibling is best-effort, exactly as the standing establishment's: an
      // account with no pointed generation binds without one. No annex rung
      // commit runs here -- the spend holds no acting ladder seed to sign
      // one with, so the fresh credential waits for the next generation
      // swap (the documented mid-generation lockout).
      bridge = await delegateLogWrite({
        zcapClient: newZcapClient,
        pointer,
        recoveryClientDid: newCredential.standing.clientDid
      })
      sibling = undefined
      const clientAnnexDid = delegatedClientsPointer({
        doc: verifiedLog.doc as Parameters<
          typeof delegatedClientsPointer
        >[0]['doc']
      })
      if (clientAnnexDid) {
        try {
          sibling = await mintDelegatedClientsDelegation({
            zcapClient: newZcapClient,
            wasServerUrl: pointer.host,
            clientAnnexSpaceId: clientAnnexDidParts({ did: clientAnnexDid })
              .spaceId,
            controller: newCredential.standing.clientDid
          })
        } catch (err) {
          log.warn(
            'Could not mint the annex-Space sibling delegation; the record binds without one',
            { err }
          )
        }
      }
      // The new passphrase's unlock record in the STANDING layout, plus the
      // local PENDING client-key record: seeds, controller, `pointerDid`,
      // and the pending group -- the ceremony discriminator, the built-on
      // head, the spent code's unwrap key (what keeps the first post-pivot
      // roster escrow re-derivable at every kill point), and the
      // replacement code's bytes (the show-once re-display and the stable
      // re-run address) -- and NO user key, so the record classifies
      // pending at login and routes to the resume. The bind re-runs the
      // collision refusal and advances its stamp past the served record.
      newRecordBind = await bindPassphrase({
        clientSeed: newClientSeed,
        controller: contents.controller,
        passphrase: newPassphrase,
        webvhUpdateKeys: newClientUpdateSeeds,
        pointer,
        delegateManagementTo: unlockManagementGrantee({
          pointer,
          controller: contents.controller
        }),
        delegation: bridge,
        ...(sibling ? { delegatedClients: sibling } : {}),
        ladderSeed: newLadderSeed,
        pending: {
          ceremony: 'recovery-spend',
          builtOnHead,
          unwrapKey: spent.clientSeed,
          replacementCode: replacement.codeBytes
        },
        // The guarded bind re-runs the collision refusal with the document
        // license the pre-flight held (the pin license alone cannot account
        // for the bind window's own residue -- see the pre-flight probe).
        refuseCollidingRecord: { accountDoc: verifiedLog.doc },
        credential: newCredential,
        idb
      })
      // The replacement code's record and bridge delegation (the delegation
      // signed by the new client's pre-entry key, verifying once the entry
      // publishes the signer), and the registry entry built from them for
      // the tail's registry mutation.
      const replacementDelegation = await delegateLogWrite({
        zcapClient: newZcapClient,
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
    }
  })
  const did = continuation.did

  // The build-skew guard: a core that cannot say whether the hook fired is a
  // stale hook-less wallet-core build, and proceeding would silently
  // reinstate the publish-then-persist phantom window the seam closes. The
  // hook (when it fired) has already persisted the pending record, so the
  // refusal strands nothing the resume cannot finish.
  if (
    typeof (continuation as { committed?: unknown }).committed !== 'boolean'
  ) {
    log.error(
      'The recovery continuation did not state whether the persist hook fired; refusing a possibly hook-less run'
    )
    throw new RecoverySpendSkewError()
  }
  if ((continuation as { committed?: unknown }).committed === false) {
    // The completed branch, named explicitly: `committed: false` means the
    // continuation found both entries already standing and skipped the hook
    // by design -- a state a remembered spend cannot legitimately produce (a
    // spent code refuses at the reveal attribution long before this point),
    // so nothing was persisted and nothing can be derived. Refused loudly
    // rather than guessed at.
    log.error(
      'The recovery continuation reported already-complete ' +
        '(committed: false); a remembered spend cannot produce that state'
    )
    throw new RecoverySpendSkewError({
      message:
        'The recovery continuation reported the log entries already ' +
        'complete without firing the persist hook; refusing rather than ' +
        'guessing at the successor records.'
    })
  }
  if (!newRecordBind || !bridge || !replacementEntry) {
    throw new Error(
      'The recovery continuation completed without establishing the fresh ' +
        "credential's records."
    )
  }

  // From here the new client is an enrolled client under the current-key-set
  // rule: its `<did:webvh>#<multibase>` key signs everything.
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
      log.warn('Could not republish did.json after recovery', { err })
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
    pinStore: memoryResourceLogPinStore()
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

  // The new passphrase's standing establishment, in the ceremony tail: the
  // hook wrote the standing-LAYOUT record pre-pivot, but the remote halves
  // that make the credential actually standing take the just-published
  // client's authority, so they run here -- the credential's roster wrap
  // first (the recovery-anchor order: decryption material before the
  // document entry), then the document entry (keyAgreement commitment plus
  // the rung-0 hash), signed by the new client's update keys. Placed BEFORE
  // the mandatory rotation, whose recipients resolve from the just-updated
  // document: with the commitment published, the rotation's resolver keeps
  // the wrap; torn before either half, the rotation drops the wrap and the
  // state converges to not-established, which the spend resume's backfill
  // detects from durable state and finishes. No annex rung commit runs (the
  // spend holds no acting ladder seed; the fresh credential waits for the
  // next generation swap -- the documented mid-generation lockout).
  // Best-effort, like the establishment always was: a failure leaves a
  // record that logs in without self-enrolling -- and a BARE registry entry
  // below (the success flag gates the standing block), so nothing downstream
  // claims a standing configuration the account does not back.
  let standingEstablished = false
  try {
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: newCredential.standing.recipientKid,
        publicKeyMultibase: newCredential.standing.keyAgreementKeyMultibase
      },
      // The new client, escrowed into every epoch above, is the owner: it
      // can open every epoch whether or not the spent code's wraps survive.
      ownerKeyAgreementKey: newClientAgents.keyAgreementKey
    })
    await publishUnlockKey({
      idStore: remoteStore.webvhIdStore(),
      updateKeys: newClientUpdateSeeds,
      unlockKeys: {
        keyAgreement: {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase:
              newCredential.standing.keyAgreementKeyMultibase
          })
        },
        updateKeyMultibase: newRung0.keyMultibase
      },
      expectedDid: pointer.did,
      pinStore: memoryResourceLogPinStore(),
      logId: accountLogPinId({ spaceId: pointer.spaceId })
    })
    standingEstablished = true
    log.debug(
      "Recovery-spend tail established the new passphrase's standing configuration"
    )
  } catch (err) {
    log.warn(
      'Could not establish the new passphrase as a standing credential during recovery; the spend resume backfills it on a pending record',
      { err }
    )
  }

  // The just-updated, locally verified document: the recipient source for
  // the rotation below. (Roster provenance is the store's own: every read
  // resolves from the log's verified head, anchored in this same document.)
  const { doc } = await verifyAccountLog({
    did: pointer.did,
    spaceId: pointer.spaceId,
    host: pointer.host,
    pinStore: memoryResourceLogPinStore()
  })
  const preRotation = await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: newClientAgents.keyAgreementKey
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
    clientKeyAgreementKey: newClientAgents.keyAgreementKey
  })
  if (!postRotation) {
    throw new Error('The user key roster vanished during recovery.')
  }
  const newUserKey = postRotation.userKey
  // No roster epoch pin is written here or by the confirm-gated closure
  // below: the epoch pin is in-memory on every session and dies with the
  // tab, so a recovery has nothing to carry into the next visit.

  // Re-seal the unlock-methods registry to the rotated user key: its record is a
  // single-recipient envelope to the vault KAK, and the registry mutation
  // below runs under the rotated key. Ahead
  // of the collection cascade below, which is the long stage a torn visit
  // dies in: the spent code is the only holder of the pre-rotation key left,
  // so a re-seal deferred past it would strand the registry. Best-effort: a
  // failure leaves the registry sealed to the old user key, which the next
  // login's re-seal repair mends from the roster escrow.
  if (oldUserKey.id !== newUserKey.id) {
    await rewrapUnlockRegistryToUserKey({
      storageServerUrl: pointer.host,
      zcapClient: newZcapClient,
      spaceId: pointer.spaceId,
      from: userKeyVaultKeys({ userKey: oldUserKey }),
      to: userKeyVaultKeys({ userKey: newUserKey })
    })
  }

  // The registry mutation, moved into the ceremony tail from the post-login
  // update so a re-run or the spend resume can complete it from durable
  // state: the spent code's entry out, the replacement code's entry in, and
  // the new passphrase's entry recording the standing members the hook
  // minted -- one read-modify-write under the rotated user key the re-seal
  // above just adopted. Best-effort: a torn write here is re-applied by the
  // spend resume's backfill or the post-login recovery-entry backfill.
  const recordBind = newRecordBind
  const replacementMethod = replacementEntry
  const newBridge = bridge
  try {
    const bridgeKeyId = delegationProofKeyId(newBridge)
    const siblingKeyId = sibling ? delegationProofKeyId(sibling) : undefined
    const dropped = new Set([replacementMethod.recoveryKid, spent.recipientKid])
    await updateUnlockMethodsWithClient({
      zcapClient: newZcapClient,
      spaceId: pointer.spaceId,
      userKey: newUserKey,
      mutate: existing => {
        const base = existing ?? emptyUnlockMethodsRegistry()
        const methods = [
          ...base.methods.filter(
            method =>
              method.type !== 'recovery-code' ||
              !dropped.has(method.recoveryKid)
          ),
          replacementMethod
        ]
        // The standing block only when the establishment above landed: a
        // failed establishment writes a BARE entry instead -- the shape the
        // bare-entry repairs treat as mendable (and they rebuild only once
        // the document actually carries the credential's commitment), so
        // the registry never asserts a standing configuration the account
        // does not back.
        return upsertPassphraseUnlockMethod({
          record: { ...base, methods },
          unlockSpaceId: recordBind.unlockSpaceId,
          manageCapability: recordBind.manageCapability,
          ...(standingEstablished
            ? {
                standing: {
                  rosterKid: newCredential.standing.recipientKid,
                  keyAgreementKeyMultibase:
                    newCredential.standing.keyAgreementKeyMultibase,
                  updateKeyMultibase: newRung0.keyMultibase,
                  unlockClientDid: newCredential.standing.clientDid,
                  ...(bridgeKeyId ? { delegationKeyId: bridgeKeyId } : {}),
                  ...((newBridge as { expires?: string }).expires
                    ? {
                        delegationExpires: (newBridge as { expires?: string })
                          .expires
                      }
                    : {}),
                  ...(siblingKeyId
                    ? { delegatedClientsKeyId: siblingKeyId }
                    : {}),
                  ...(sibling && (sibling as { expires?: string }).expires
                    ? {
                        delegatedClientsExpires: (
                          sibling as { expires?: string }
                        ).expires
                      }
                    : {}),
                  ...(recordBind.unlockKeyAgreementKeyId
                    ? {
                        unlockKeyAgreementKeyId:
                          recordBind.unlockKeyAgreementKeyId
                      }
                    : {}),
                  ...(recordBind.unlockKeyAgreementKeyMultibase
                    ? {
                        unlockKeyAgreementKeyMultibase:
                          recordBind.unlockKeyAgreementKeyMultibase
                      }
                    : {})
                }
              }
            : {})
        })
      }
    })
    log.debug('Recovery-spend registry mutation written in the ceremony tail')
  } catch (err) {
    log.warn('Could not update the unlock-methods registry during recovery', {
      err
    })
  }

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

  // Retire the spent code's unlock Space -- a typed code is a spent
  // credential. Best-effort: its inventory is already out of the document and
  // roster, so a surviving record can locate but never act.
  try {
    await deleteUnlockSpace({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId
    })
    await deleteUnlockLocalState({ spaceId: unlock.spaceId, idb })
  } catch (err) {
    log.warn("Could not delete the spent code's unlock Space", { err })
  }

  // The confirm-gated record completion (what replaces the old tail bind):
  // the pending client-key record already holds the key set, so completing
  // it -- the rotated user key in, the pending carrier (the ceremony
  // discriminator, the built-on head, the spent code's unwrap key, and the
  // replacement code's bytes) cleared -- waits for the show-once dialog's
  // "I saved this code" confirm. Until then the replacement code stays
  // re-displayable from the persisted bytes: a tab death leaves the pending
  // record, and the next login's spend resume re-displays the code before
  // completing.
  const persistNewClientKeys = recordBind.persistClientKeys
  const completeRecovery = async (
    options: { currentUserKey?: UserKey } = {}
  ) => {
    // The completion prefers the CURRENT user key over the closure capture:
    // a sweep rotation during the show-once display would otherwise be
    // written back over by a stale key. The caller with a live session
    // passes its vault user key; a caller without one (the /recover page
    // pre-login) has nothing rotating underneath it.
    const userKeyToPersist = options.currentUserKey ?? newUserKey
    await persistNewClientKeys({
      userKey: userKeyToPersist,
      pointerDid: did,
      pending: null
    })
    log.info('Recovery-spend record completed; the pending carrier is cleared')
  }

  return {
    replacementCode,
    replacementEntry: replacementMethod,
    spentRecoveryKid: spent.recipientKid,
    standing: standingEstablished ? 'established' : 'pending',
    completeRecovery
  }
}

/**
 * Thrown when wallet-core's recovery continuation returned without the
 * persist hook having fired: `committed` absent from the return (a build
 * skew -- a stale hook-less wallet-core body running under new app code
 * would silently reinstate the publish-then-persist phantom window), or the
 * explicit completed branch (`committed: false`, which a remembered spend
 * cannot legitimately produce -- distinct copy via `message`). Either way
 * the run is refused instead of trusted; when the hook did fire, the
 * pending record is already written, so the refusal strands nothing the
 * spend resume cannot finish.
 */
export class RecoverySpendSkewError extends Error {
  constructor({ message }: { message?: string } = {}) {
    super(
      message ??
        'The recovery continuation did not state whether the persist hook ' +
          'fired; refusing a possibly hook-less run (stale wallet-core build).'
    )
    this.name = 'RecoverySpendSkewError'
  }
}

/**
 * Whether the account document lists a verification-method id -- the
 * standing backfill's completion test over a credential's published
 * `keyAgreement` entry (commitment or verbatim), checking the
 * `verificationMethod` entries and the `keyAgreement` relation's string
 * references.
 *
 * @param options {object}
 * @param options.doc {unknown}   the locally verified account document
 * @param options.vmId {string}
 * @returns {boolean}
 */
function docListsUnlockVm({
  doc,
  vmId
}: {
  doc: unknown
  vmId: string
}): boolean {
  const shaped = doc as {
    verificationMethod?: unknown
    keyAgreement?: unknown
  } | null
  const methods = Array.isArray(shaped?.verificationMethod)
    ? shaped.verificationMethod
    : []
  if (methods.some(method => (method as { id?: string })?.id === vmId)) {
    return true
  }
  const keyAgreement = Array.isArray(shaped?.keyAgreement)
    ? shaped.keyAgreement
    : []
  return keyAgreement.some(entry =>
    typeof entry === 'string'
      ? entry === vmId
      : (entry as { id?: string })?.id === vmId
  )
}

/**
 * A resumed recovery spend's show-once obligation, handed to the login
 * surface: the replacement code to display (re-derived from the pending
 * record's persisted bytes) and the confirm-gated record completion to run
 * once the user has confirmed saving it.
 */
export interface RecoverySpendPrompt {
  replacementCode: string
  // The credential's standing state, from the resume's own backfill:
  // 'established' when both halves (roster wrap and document entry) are
  // confirmed or completed, 'pending' when the backfill could not finish
  // them. Pending never fails the resume; a later resume or
  // remembered-login mend completes it.
  standing: 'established' | 'pending'
  // The confirm-gated completion. A caller with a live session passes its
  // CURRENT vault user key, so a sweep rotation during the show-once
  // display is not written back over by the closure's captured key.
  complete: (options?: { currentUserKey?: UserKey }) => Promise<void>
}

/**
 * The spend-completion resume: finishes a remembered recovery spend whose
 * add-and-retire entry landed but whose tail was torn, from the pending
 * client-key record alone, at the new passphrase's next login (the
 * pending-enrollment router's VM-listed spend branch). Every stage detects
 * its own completion from durable state:
 *
 * 1. The roster escrows. The read is tried with the new client's own
 *    key-agreement key first; when the current epoch holds no wrap for it
 *    (the pivot-to-escrow band), the spent code's key-agreement identity is
 *    re-derived from the pending record's `unwrapKey` and the new client and
 *    replacement code are escrowed into every epoch, then the read re-runs.
 *    A between-escrows tear (the new client's wrap standing, the
 *    replacement's missing) is backfilled the same way.
 * 2. The standing-establishment backfill (best-effort): the tail publishes
 *    the credential's roster wrap and document commitment post-pivot, so a
 *    tear before them leaves the standing-layout record without the
 *    standing property -- detected here from durable state (wrap in the
 *    roster's current epoch, commitment VM in the verified document) and
 *    finished, exactly like the registry mutation.
 * 3. The registry backfill (best-effort): when the registry does not yet
 *    record the replacement code and the new passphrase's entry, the
 *    replacement's delegation and record are re-minted from the persisted
 *    bytes and the tail's registry mutation re-applies.
 * 4. The completion: the user key (now readable from the roster) fills the
 *    record and the pending carrier clears -- gated on the show-once
 *    confirm when the replacement code's bytes still stand, through the
 *    returned prompt's `complete`.
 *
 * The mandatory rotation and the collection cascade are NOT re-run here: the
 * completing login proceeds enrolled, and its login sweep converges the
 * roster onto the post-entry document (rotating the spent code's wrap away)
 * and finishes the cascade.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   the new passphrase's keyring
 *   hit, holding the spend-written pending record
 * @param [options.verifiedLog] {VerifiedAccountLog}   the caller's verified
 *   account log (the pending router's own read); fetched here when absent
 * @returns {Promise<object>}   the completed key set, its persist closure,
 *   and the show-once prompt while the confirm is still owed
 */
export async function resumeRecoverySpend({
  found,
  verifiedLog
}: {
  found: KeyringFetchResult
  verifiedLog?: VerifiedAccountLog
}): Promise<{
  clientKeys: ClientKeyRecord
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
  recoverySpendPrompt?: RecoverySpendPrompt
}> {
  const clientKeys = found.clientKeys
  const pending = clientKeys?.pending
  const pointer = found.pointer
  const persistClientKeys = found.persistClientKeys
  if (
    !clientKeys ||
    pending?.ceremony !== 'recovery-spend' ||
    !pointer ||
    !isWebvhDid(pointer.did) ||
    !persistClientKeys ||
    !clientKeys.webvhUpdateKeys
  ) {
    throw new Error('This keyring hit cannot resume a recovery spend.')
  }
  const did = pointer.did!
  const logPointer = {
    did,
    spaceId: pointer.spaceId,
    host: pointer.host
  }
  const agents = await agentsFromSeed({ seed: clientKeys.clientSeed })
  const newZcapClient = webvhZcapClient({ keyAgent: agents.keyAgent, did })
  const { publicKeyMultibase: kaMultibase } =
    agents.keyAgreementKey as unknown as { publicKeyMultibase?: string }
  if (!kaMultibase) {
    throw new Error(
      "The pending record's key-agreement key has no public multibase."
    )
  }
  const rosterStore = accountRosterStore({
    zcapClient: newZcapClient,
    keyAgent: agents.keyAgent,
    pointer: logPointer,
    pinStore: memoryResourceLogPinStore()
  })
  const replacement = pending.replacementCode
    ? await recoveryClientFromCode({
        code: base58.encode(pending.replacementCode)
      })
    : undefined

  // 1. The escrow completion. Both `addUserKeyRosterRecipient` calls are the
  // exact writes the torn tail owed, owned by the spent code's re-derived
  // key-agreement identity -- reachable only pre-rotation, which is exactly
  // when they are missing.
  async function escrowFromUnwrapKey({
    includeSelf
  }: {
    includeSelf: boolean
  }): Promise<void> {
    if (!pending?.unwrapKey) {
      throw new Error(
        'The pending record carries no unwrap key to complete the roster ' +
          'escrows with.'
      )
    }
    log.info(
      'Recovery-spend resume: completing the roster escrows from the ' +
        'pending unwrap key',
      { includeSelf }
    )
    const spentIdentity = await unlockClientIdentityFromSeed({
      clientSeed: pending.unwrapKey
    })
    if (includeSelf) {
      await addUserKeyRosterRecipient({
        store: rosterStore,
        recipient: {
          id: agents.keyAgreementKey.id,
          publicKeyMultibase: kaMultibase!
        },
        ownerKeyAgreementKey: spentIdentity.agents.keyAgreementKey
      })
    }
    if (replacement) {
      await addUserKeyRosterRecipient({
        store: rosterStore,
        recipient: {
          id: replacement.recipientKid,
          publicKeyMultibase: replacement.keyAgreementKeyMultibase
        },
        ownerKeyAgreementKey: spentIdentity.agents.keyAgreementKey
      })
    }
  }
  let read: UserKeyRosterReadResult | null
  try {
    read = await readUserKeyRoster({
      store: rosterStore,
      clientKeyAgreementKey: agents.keyAgreementKey
    })
  } catch (err) {
    if ((err as Error | null)?.name !== 'UserKeyRosterUnwrapError') {
      throw err
    }
    // The pivot-to-escrow band: the entry landed, the escrows did not.
    await escrowFromUnwrapKey({ includeSelf: true })
    read = await readUserKeyRoster({
      store: rosterStore,
      clientKeyAgreementKey: agents.keyAgreementKey
    })
  }
  if (!read) {
    throw new Error(
      'The account has no user key roster; the recovery spend cannot resume.'
    )
  }
  const rosterRead = read
  if (replacement) {
    // The between-escrows tear: this client's wrap stands, the replacement
    // code's does not. Best-effort -- a rotation has already re-wrapped the
    // current epoch to the replacement's published VM if one ran.
    const currentEpoch = rosterRead.descriptor.epochs?.find(
      epoch => epoch.id === rosterRead.descriptor.currentEpoch
    )
    const replacementEscrowed = currentEpoch?.recipients.some(
      recipient => recipient.header.kid === replacement.recipientKid
    )
    if (!replacementEscrowed) {
      try {
        await escrowFromUnwrapKey({ includeSelf: false })
      } catch (err) {
        log.warn(
          "Could not backfill the replacement code's roster escrow during the spend resume",
          { err }
        )
      }
    }
  }
  const userKey = rosterRead.userKey

  // 2. The standing-establishment backfill (best-effort): the wrap and the
  // document commitment are each detected from durable state and finished
  // only when missing -- the recovery-anchor order preserved (wrap before
  // the document entry). The wrap's owner is this client's own key, which
  // holds a wrap in every epoch whether or not the rotation has run.
  const standingClient = found.standingClient
  const standingLadderSeed = found.standing?.ladderSeed
  // Whether the credential's standing configuration is real (both halves
  // confirmed or completed) -- the gate on the registry writes below, so a
  // failed backfill leaves a BARE entry rather than asserting standing
  // members the account does not back.
  let standingEstablished = false
  if (standingClient && standingLadderSeed) {
    try {
      const currentEpoch = rosterRead.descriptor.epochs?.find(
        epoch => epoch.id === rosterRead.descriptor.currentEpoch
      )
      const wrapStanding = currentEpoch?.recipients.some(
        recipient => recipient.header.kid === standingClient.recipientKid
      )
      if (!wrapStanding) {
        log.info(
          "Recovery-spend resume: backfilling the credential's standing roster wrap"
        )
        await addUserKeyRosterRecipient({
          store: rosterStore,
          recipient: {
            id: standingClient.recipientKid,
            publicKeyMultibase: standingClient.keyAgreementKeyMultibase
          },
          ownerKeyAgreementKey: agents.keyAgreementKey
        })
      }
      const commitment = await keyAgreementCommitment({
        keyAgreementKeyMultibase: standingClient.keyAgreementKeyMultibase
      })
      const commitmentVmId = unlockKeyVmId({
        did,
        keyAgreement: { commitment }
      })
      const verified =
        verifiedLog ??
        (await verifyAccountLog({
          did,
          spaceId: pointer.spaceId,
          host: pointer.host,
          pinStore: memoryResourceLogPinStore()
        }))
      if (!docListsUnlockVm({ doc: verified.doc, vmId: commitmentVmId })) {
        log.info(
          "Recovery-spend resume: publishing the credential's document entry"
        )
        const remoteStore = new WASRemoteStore({
          storageServerUrl: pointer.host,
          zcapClient: newZcapClient,
          spaceId: pointer.spaceId,
          controller: did
        })
        const rung0 = await ladderRung({
          ladderSeed: standingLadderSeed,
          index: 0
        })
        await publishUnlockKey({
          idStore: remoteStore.webvhIdStore(),
          updateKeys: clientKeys.webvhUpdateKeys,
          unlockKeys: {
            keyAgreement: { commitment },
            updateKeyMultibase: rung0.keyMultibase
          },
          expectedDid: did,
          pinStore: memoryResourceLogPinStore(),
          logId: accountLogPinId({ spaceId: pointer.spaceId })
        })
      }
      standingEstablished = true
    } catch (err) {
      log.warn(
        'Could not backfill the standing establishment during the spend resume',
        { err }
      )
    }
  }

  // 3. The registry backfill (best-effort): re-apply the tail's registry
  // mutation when the registry does not yet record both successors.
  if (replacement) {
    try {
      const existing = await getUnlockMethodsWithClient({
        zcapClient: newZcapClient,
        spaceId: pointer.spaceId,
        userKey
      })
      const hasReplacement = recoveryEntriesOf({ record: existing }).some(
        entry => entry.recoveryKid === replacement.recipientKid
      )
      const passphraseEntry = (existing?.methods ?? []).find(
        method =>
          method.type === 'passphrase' &&
          method.unlockSpaceId === found.unlockSpaceId
      )
      const hasPassphrase = passphraseEntry !== undefined
      // A bare entry (no key-agreement multibase) is the shape a failed
      // establishment leaves; once the backfill above has made the standing
      // configuration real, the entry is upgraded below.
      const hasStandingPassphrase =
        !!passphraseEntry &&
        'keyAgreementKeyMultibase' in passphraseEntry &&
        !!passphraseEntry.keyAgreementKeyMultibase
      if (!hasReplacement || !hasPassphrase) {
        log.info('Recovery-spend resume: backfilling the registry mutation', {
          hasReplacement,
          hasPassphrase
        })
        const replacementDelegation = await delegateLogWrite({
          zcapClient: newZcapClient,
          pointer,
          recoveryClientDid: replacement.clientDid
        })
        const replacementBind = await bindRecoveryRecord({
          client: replacement,
          controller: found.controller,
          pointer,
          delegation: replacementDelegation
        })
        const entry = recoveryRegistryEntry({
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
        const spentKid = pending.unwrapKey
          ? (
              await unlockClientIdentityFromSeed({
                clientSeed: pending.unwrapKey
              })
            ).recipientKid
          : undefined
        // The standing fields only when the establishment above is real: a
        // failed backfill writes the bare entry instead, upgraded on a
        // later resume once the establishment lands.
        const standingFields = standingEstablished
          ? await standingFieldsOfKeyringHit({ found })
          : undefined
        const dropped = new Set([
          entry.recoveryKid,
          ...(spentKid ? [spentKid] : [])
        ])
        await updateUnlockMethodsWithClient({
          zcapClient: newZcapClient,
          spaceId: pointer.spaceId,
          userKey,
          mutate: current => {
            const base = current ?? emptyUnlockMethodsRegistry()
            const methods = [
              ...base.methods.filter(
                method =>
                  method.type !== 'recovery-code' ||
                  !dropped.has(method.recoveryKid)
              ),
              entry
            ]
            return upsertPassphraseUnlockMethod({
              record: { ...base, methods },
              unlockSpaceId: found.unlockSpaceId,
              manageCapability: found.manageCapability,
              ...(standingFields ? { standing: standingFields } : {})
            })
          }
        })
      } else if (standingEstablished && !hasStandingPassphrase) {
        // The upgrade of a bare entry (a tail whose establishment failed
        // wrote it): the backfill above just made the standing
        // configuration real, so the entry now records it.
        log.info(
          'Recovery-spend resume: upgrading the bare passphrase entry with the established standing configuration'
        )
        const standingFields = await standingFieldsOfKeyringHit({ found })
        await updateUnlockMethodsWithClient({
          zcapClient: newZcapClient,
          spaceId: pointer.spaceId,
          userKey,
          mutate: current =>
            upsertPassphraseUnlockMethod({
              record: current ?? emptyUnlockMethodsRegistry(),
              unlockSpaceId: found.unlockSpaceId,
              manageCapability: found.manageCapability,
              standing: standingFields
            })
        })
      }
    } catch (err) {
      log.warn(
        'Could not backfill the unlock-methods registry during the spend resume',
        { err }
      )
    }
  }

  // 4. The completion, confirm-gated while the show-once obligation stands.
  const completedClientKeys: ClientKeyRecord = {
    clientSeed: clientKeys.clientSeed,
    userKey,
    webvhUpdateKeys: clientKeys.webvhUpdateKeys,
    ...(clientKeys.controller ? { controller: clientKeys.controller } : {}),
    pointerDid: did
  }
  const complete = async (options: { currentUserKey?: UserKey } = {}) => {
    // The CURRENT key wins over the closure capture: the confirming session
    // may have adopted a sweep rotation while the code was on display.
    const userKeyToPersist = options.currentUserKey ?? userKey
    await persistClientKeys({
      userKey: userKeyToPersist,
      pointerDid: did,
      pending: null
    })
    log.info(
      'Recovery-spend resume: record completed; the pending carrier is cleared'
    )
  }
  if (pending.replacementCode) {
    return {
      clientKeys: completedClientKeys,
      persistClientKeys,
      recoverySpendPrompt: {
        replacementCode: base58.encode(pending.replacementCode),
        standing: standingEstablished ? 'established' : 'pending',
        complete
      }
    }
  }
  await complete()
  return { clientKeys: completedClientKeys, persistClientKeys }
}

/**
 * The user key of the epoch a rotation just superseded, unwrapped through a
 * recipient escrowed into it. The roster is append-only and its current
 * epoch is always the newest, so the superseded epoch is the one immediately
 * before the current one in the descriptor's list.
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}   the rotated roster
 * @param options.keyAgreementKey {IKeyAgreementKey}   a recipient's
 *   key-agreement key holding a wrap in the prior epoch
 * @returns {Promise<UserKey>}
 */
async function unwrapPriorEpochUserKey({
  descriptor,
  keyAgreementKey
}: {
  descriptor: CollectionEncryption
  keyAgreementKey: IKeyAgreementKey
}): Promise<UserKey> {
  const epochs = descriptor.epochs ?? []
  const currentIndex = epochs.findIndex(
    epoch => epoch.id === descriptor.currentEpoch
  )
  const prior = currentIndex > 0 ? epochs[currentIndex - 1] : undefined
  const entry = prior?.recipients.find(
    recipient => recipient.header.kid === keyAgreementKey.id
  )
  if (!prior || !entry) {
    throw new Error(
      'The rotated user key roster carries no prior epoch escrowed to the ' +
        'fresh credential.'
    )
  }
  const secret = await unwrapEpochSecret({ entry, keyAgreementKey })
  if (!secret) {
    throw new Error(
      "The fresh credential's escrow in the prior user key epoch failed to " +
        'unwrap.'
    )
  }
  return { id: prior.id, secret }
}

/**
 * The TRANSIENT recovery variant (the default on a non-remembered browser):
 * `recoverWebvhLadderAnchored` publishes the fresh credential's ladder VM in
 * place of an enrolled client, so the account lands client-less and
 * ladder-anchored, and nothing touches browser-local storage (the visit's
 * log pins are in memory, as on every session, and die with the tab). The
 * freewallet wiring around the shared continuation:
 *
 * 1. Inside the continuation's `onCommitted` seam (after the reveal entry
 *    validates the code, BEFORE the add entry publishes the ladder VM): a
 *    fresh annex generation is minted under the new ladder's bootstrap
 *    did:key (a recovery record carries no annex sibling, so the old
 *    auxiliary Space is unreachable; the old generation falls to orphan
 *    discovery), its delegation embedded and its Space's controller flipped;
 *    the per-visit transient client is enrolled into it there too (the loud
 *    annex entry, written controller-tier while the auxiliary Space still
 *    answers to the bootstrap key -- it exercises no authority until the
 *    generation delegation's signer publishes); then the new credential's
 *    bridge and sibling (ladder-VM-signed), the new passphrase's unlock
 *    record (the ladder seed inside), and the replacement code's record are
 *    durably written -- the pinned ordering: a tab death must never leave a
 *    published anchor nobody can derive. The seam names the fresh generation
 *    back to the continuation, which points the `#DelegatedClients` service
 *    entry at it inside the SAME add-and-retire entry -- that entry retires
 *    the pre-recovery credential's ladder VM, so a pointer written after it
 *    would leave a window where the document names a generation no surviving
 *    record's sibling can reach.
 * 2. The mandatory rotation runs as ONE ladder-signed roster append anchored
 *    at the add-and-retire entry (the ceremony-tail license's one shot), and
 *    it is the FIRST request after that entry: the spent code retired, the
 *    fresh credential and the replacement code escrowed, the fresh epoch
 *    minted -- invoked as the annex VM under the generation delegation, the
 *    only authority this visit holds over the promoted Space. Everything the
 *    append needs (the enrolled visit key, the embedded delegation) is in
 *    hand before the entry, so the window in which the typed code is dead
 *    and the new credential holds no wrap is the append itself. A tear
 *    inside it is the stated residue: the spent code can no longer re-run
 *    (its key left the document), and no login sweep runs on a client-less
 *    account, so the current epoch stays wrapped to the removed code alone
 *    until a repair that holds both the spent code and the new
 *    passphrase runs the append anchored at the same entry.
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

  // The visit's in-memory store family: trust-on-first-use chain-head
  // pins for every log read here, gone with the tab.
  const persistence = transientSessionStores()
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
  // The read-first collision probe, BEFORE the reveal entry: a served
  // record at the new passphrase's unlock Space that names another account,
  // or a live standing credential's record, refuses here and surfaces at
  // the new-passphrase form. A transient visit must not read browser-local
  // records (even a read creates the session database), so the own-residue
  // license is the verified document: a
  // same-account standing record whose credential inventory the document
  // does not publish is a torn earlier attempt's inert residue, safe to
  // overwrite.
  await probeUnlockSpaceCollision({
    credential,
    controller: contents.controller,
    pointer,
    accountDoc: verifiedLog.doc,
    readLocalRecord: false
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

  // The per-visit transient client: minted here, enrolled inside the seam
  // below, and the invocation identity the rotation, the cascade, and the
  // registry update ride -- the generation delegation is the only authority
  // this visit holds over the promoted Space.
  const visitSeed = crypto.getRandomValues(new Uint8Array(32))
  const visitAgents = await agentsFromSeed({ seed: visitSeed })

  // Filled by the `onCommitted` seam, consumed by the tail below.
  let clientAnnexSpaceId: string | undefined
  let clientAnnexDid: string | undefined
  let clientAnnexDoc:
    Parameters<typeof embeddedGenerationDelegation>[0]['doc'] | undefined
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
        // The visit's key enrolled into the fresh generation BEFORE the
        // add-and-retire entry (the loud annex entry, signed by the
        // credential's static rung 0), written controller-tier while the
        // auxiliary Space still answers to the bootstrap key. Nothing is
        // exercised here: the delegation it will invoke under is signed by a
        // ladder VM the document does not list yet. What the placement buys
        // is the window after the entry -- the roster append is then the
        // first request that follows it.
        const enrolled = await enrollClientAnnexTransientClient({
          store: clientAnnexLogStore({
            was: bootstrapWas,
            spaceId: clientAnnexSpaceId,
            generationId: minted.generationId
          }),
          ladderSeed,
          generationId: minted.generationId,
          transientKeyMultibase: clientSigningKeyMultibase({
            keyAgent: visitAgents.keyAgent
          }),
          expectedDid: minted.did,
          pinStore: logPins,
          logId: clientAnnexLogPinId({
            spaceId: clientAnnexSpaceId,
            generationId: minted.generationId
          })
        })
        clientAnnexDoc = enrolled.doc
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
      // durably written before the VM that seed backs publishes. The bind
      // re-runs the read-first collision refusal (with the served stamp
      // folded into its advance-past set), so a record established between
      // the pre-flight probe and this write still refuses.
      newRecordBind = await bindCredentialAnchoredUnlockSecret({
        controller: bootstrapAgent.id,
        pointer,
        delegation: bridge,
        delegatedClients: sibling,
        ladderSeed,
        delegateManagementTo: did,
        refuseCollidingRecord: { accountDoc: verifiedLog.doc },
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
    !clientAnnexDoc ||
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

  // The fresh genesis embedded its delegation inside the seam; a generation
  // without one here is a torn establishment, not a mintable state.
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
  // (the inventory-changing version the ceremony-tail license admits, and the
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

  // The mandatory rotation, in the ONE ladder-signed append the license
  // admits, and the FIRST request after the add-and-retire entry -- no
  // enrollment, no pre-read stands between the typed code dying in the
  // document and the new credential gaining its wrap: the spent code's wrap
  // retired, the fresh credential's standing key and the replacement code
  // escrowed into every epoch, and the fresh epoch minted -- all in a single
  // descriptor write. Convergent: a re-run writes nothing. An account with
  // no roster yet is refused by the append itself (the owner has nothing
  // to unwrap).
  const rotated = await replaceUserKeyRosterRecipients({
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
    descriptor: rotated,
    clientKeyAgreementKey: standing.agents.keyAgreementKey
  })
  const newUserKey = postRotation.userKey
  // The pre-rotation user key (the registry below is still sealed to it):
  // the epoch the append just superseded, unwrapped through the fresh
  // credential's escrow -- the roster is append-only, so it is the epoch
  // immediately before the current one.
  const oldUserKey = await unwrapPriorEpochUserKey({
    descriptor: rotated,
    keyAgreementKey: standing.agents.keyAgreementKey
  })

  // The epoch cascade under the generation delegation: every encrypted
  // collection takes a fresh epoch naming the rotated user key. Best-effort
  // per collection; a stranded collection stays keyed to the spent code
  // until the next remembered login or a spend re-run (the documented
  // residue -- the transient completion is its own follow-up).
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

  // The registry, one read-modify-write (the remembered flow's re-seal and
  // post-login updates folded into the ceremony, since a transient session
  // cannot run them later): the spent code's entry out, the replacement's
  // and the new passphrase's in, the record re-sealed to the rotated user
  // key. Best-effort -- the account is recovered without it, and the next
  // remembered login surfaces a stale registry as a warning.
  // Captured consts: the guard above already proved these present, and the
  // narrowing of a `let` does not survive into the mutate closure below.
  const recordBind = newRecordBind
  const replacementMethod = replacementEntry
  try {
    const dropped = new Set([replacementMethod.recoveryKid, spent.recipientKid])
    const bridgeKeyId = delegationProofKeyId(bridge)
    const siblingKeyId = delegationProofKeyId(sibling)
    await updateUnlockMethodsWithClient({
      zcapClient: transientZcapClient,
      spaceId,
      userKey: oldUserKey,
      writeUserKey: newUserKey,
      capability: generationDelegation,
      mutate: existing => {
        const base = existing ?? emptyUnlockMethodsRegistry()
        const methods = [
          ...base.methods.filter(
            method =>
              method.type !== 'recovery-code' ||
              !dropped.has(method.recoveryKid)
          ),
          replacementMethod
        ]
        return upsertPassphraseUnlockMethod({
          record: { ...base, methods },
          unlockSpaceId: recordBind.unlockSpaceId,
          manageCapability: recordBind.manageCapability,
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
                  delegatedClientsExpires: (sibling as { expires?: string })
                    .expires
                }
              : {}),
            ...(recordBind.unlockKeyAgreementKeyId
              ? {
                  unlockKeyAgreementKeyId: recordBind.unlockKeyAgreementKeyId
                }
              : {}),
            ...(recordBind.unlockKeyAgreementKeyMultibase
              ? {
                  unlockKeyAgreementKeyMultibase:
                    recordBind.unlockKeyAgreementKeyMultibase
                }
              : {})
          }
        })
      }
    })
  } catch (err) {
    log.warn('Could not update the unlock-methods registry during recovery', {
      err
    })
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
    log.warn("Could not delete the spent code's unlock Space", { err })
  }

  return {
    replacementCode,
    replacementEntry,
    spentRecoveryKid: spent.recipientKid,
    // The transient variant establishes the credential's standing inside
    // the add-and-retire entry and the mandatory rotation, both fatal on
    // failure, so a returned outcome is always established.
    standing: 'established'
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
    log.warn('Could not load the recovery-code entries', { err })
    return []
  }
}

/**
 * The post-login half a remembered recovery still owes, now that the
 * registry mutation AND the new passphrase's standing establishment both
 * run in the ceremony tail (and are backfilled by the spend resume): one
 * best-effort backfill of the recovery entries -- the mender when the
 * tail's registry write was torn AND the pending record was already
 * completed, the one state the resume can no longer reach. It
 * re-establishes nothing: running the full establishment here would mint a
 * second ladder seed and publish a second document entry over a healthy
 * tail's.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.outcome {RecoveryOutcome}
 * @returns {Promise<void>}
 */
export async function updateRegistryAfterRecovery({
  session,
  outcome
}: {
  session: Session
  outcome: RecoveryOutcome
}): Promise<void> {
  try {
    // The backfill of the tail's registry mutation: the replacement recorded
    // and the spent code dropped in one write. A tail that already wrote
    // them converges (the write replaces the same entry by kid).
    await recordRecoveryMethod({
      session,
      entry: outcome.replacementEntry,
      dropKids: [outcome.spentRecoveryKid]
    })
  } catch (err) {
    log.warn('Could not update the unlock-methods registry', { err })
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
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes; on a settled session the chain resolved long ago.
  await session.registryReady
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
  if (read) {
    if (read.rotated) {
      // The in-band adoption: the registry is re-sealed to the rotated key
      // while this browser's browser-local copy of the old one still
      // exists, the key persists into the client-key record, the visit's
      // epoch pin advances, and the live session swaps onto both -- all
      // before the long collection fan-out below, so a tab death in it
      // cannot strand the registry. Then re-epoch every encrypted
      // collection (best-effort per collection; the completion sweep
      // backstops a partial run).
      await adoptRotatedUserKeyInBand({
        session,
        spaceId: pointer.spaceId,
        accountDid: pointer.did,
        userKey: read.userKey,
        latestEpochId: read.latestEpochId,
        descriptor: read.descriptor
      })
      await cascadeCollectionsToUserKey({
        remoteStore,
        rosterDescriptor: read.descriptor,
        clientKeyAgreementKey,
        userKey: read.userKey
      })
    } else {
      await epochPins.saveFromDescriptor({
        accountDid: pointer.did,
        epochId: read.latestEpochId,
        descriptor: read.descriptor
      })
    }
  }

  // 3. The unlock Space and the registry entry -- the shared tap-free
  // revocation path (the entry's management zcap, invoked with this
  // client's did:key). Under the ROTATED vault keys: the adoption above
  // re-sealed the stored record to them and swapped the live session onto
  // them, so these reads and writes decrypt and re-seal under one key.
  await revokeUnlockMethod({ session, entry, idb })
}

/**
 * One registry entry shaped for the shared re-mint pass: wallet-core's
 * `RecoveryDelegationEntry` plus the registry entry it was built from, so
 * the record-back seam can write the refreshed fields to the right place.
 */
export type RemintEntry = RecoveryDelegationEntry & { source: UnlockMethod }

/**
 * The unlock-methods registry entries a re-mint pass walks, in the shape the
 * shared pass takes: the recovery codes AND the standing passphrase/passkey
 * credentials alike (one bridge machinery, per FW-154's one-codepath
 * model), with `unlockClientDid` filling the delegation-grantee slot the
 * recovery entries call `recoveryClientDid`. The sibling pair is absent on
 * recovery codes by construction; stating it keeps the entry union uniform
 * for the record-back seam.
 *
 * @param options {object}
 * @param options.record {UnlockMethodsRecord | null}   the registry
 * @param [options.excludeUnlockSpaceIds] {string[]}   entries to leave out
 *   (the last-client forget re-binds the login credential's own record
 *   through the keyring hit's closure instead)
 * @returns {RemintEntry[]}
 */
export function remintEntriesOf({
  record,
  excludeUnlockSpaceIds = []
}: {
  record: UnlockMethodsRecord | null
  excludeUnlockSpaceIds?: string[]
}): RemintEntry[] {
  const entries = recoveryEntriesOf({ record })
  const standingSources = (record?.methods ?? []).filter(
    (method): method is PassphraseUnlockMethod | PasskeyUnlockMethod =>
      (method.type === 'passphrase' || method.type === 'passkey') &&
      !!method.unlockClientDid
  )
  const mapped: RemintEntry[] = [
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
  return mapped.filter(
    entry => !excludeUnlockSpaceIds.includes(entry.unlockSpaceId)
  )
}

/**
 * The re-mint pass's record-back seam: writes a re-minted entry's refreshed
 * delegation fields to the unlock-methods registry, by the entry's kind.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {RemintEntry}
 * @returns {Promise<void>}
 */
export async function recordRemintedEntry({
  session,
  entry
}: {
  session: Session
  entry: RemintEntry
}): Promise<void> {
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

/**
 * Re-mints the unlock-record bridge delegations the current document no
 * longer backs -- the delta riding the revocation cascade, for the recovery
 * codes AND the standing passphrase/passkey credentials alike. The
 * mechanism, the skip policy, and the binding-carried-forward re-wrap all
 * live in `@interop/wallet-core/recovery`; this binding supplies the app
 * seams: the storage server URL, the session's delegating signer and account
 * record signer, the management-zcap client factory, and the unlock-methods
 * registry read/record halves (`remintEntriesOf` / `recordRemintedEntry`,
 * shared with the last-client forget's ladder-signed pass).
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
  const remintEntries = remintEntriesOf({ record })
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
    recordEntry: async ({ entry }) => recordRemintedEntry({ session, entry })
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
  standingMissing: boolean
}

/**
 * The login-time recovery health check: for each recovery-code
 * registry entry, tests that the stored delegation still chains against the
 * current document (its signing client's verification method is still
 * listed -- the current-key-set rule), that it is not expired or inside the
 * renewal window (the one-year TTL lapses within a code's expected
 * lifetime), and that the code's inventory (its `keyAgreement` VM and
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
  // Read-only, but wait out the login-time registry passes anyway: a read
  // mid-chain would flag entries the refresh passes are about to mend.
  await session.registryReady
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
    const standingMissing =
      !publishedMultibases.has(entry.keyAgreementKeyMultibase) ||
      !nextKeyHashes.includes(updateKeyHashes[position])
    if (delegationRotted || delegationExpiring || standingMissing) {
      flags.push({
        entry,
        delegationRotted,
        delegationExpiring,
        standingMissing
      })
    }
  }
  return flags
}
