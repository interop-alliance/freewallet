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
 *   browser: unlock record decrypted, log verified, a new ordinary client
 *   key set minted, the delegation invoked to write the self-enrolling
 *   continuation, the user key unwrapped from the code's standing wrap, the
 *   mandatory user key rotation in the roster (the spent code presumed
 *   compromised), the epoch cascade re-keying every encrypted collection off
 *   the spent code's reach, a replacement code issued hard, and the new
 *   client bound under a fresh passphrase.
 * - `revokeRecoveryCode` -- the Settings removal: document entry out, user key
 *   rotated off the code's wrap, the same collection cascade, unlock Space
 *   deleted, registry entry dropped, and the live session adopting the
 *   rotated key in place.
 * - `checkRecoveryHealth` -- the login-time delegation-rot check: a stored
 *   delegation chains only while its signing client's verification method is
 *   in the current document, and a rotted delegation bricks recovery exactly
 *   when it is needed. Client revocation re-mints rotted delegations
 *   automatically (`remintRecoveryDelegations`); the check remains the
 *   backstop for entries that predate the re-mint fields.
 */
import { WasClient } from '@interop/was-client'
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { RECOVERY_ZCAP_TTL_MS, WAS_SERVER_URL } from '@/app.config'
import {
  DID_LOG_RESOURCE,
  ID_COLLECTION,
  DID_DOCUMENT_RESOURCE
} from '@interop/wallet-core/space'
import {
  agentsFromSeed,
  singleKeyResolver
} from '@interop/wallet-core/identity'
import {
  deriveUnlockIdentity,
  deleteUnlockSpace,
  ensureUnlockSpace,
  getUnlockKeyring,
  getUnlockKeyringWithCapability,
  putUnlockKeyring,
  putUnlockKeyringWithCapability,
  recordSignerFromAgent,
  verifyRecordProof,
  type AccountPointer
} from '@interop/wallet-core/keyring'
import {
  addUserKeyRosterRecipient,
  userKeyVaultKeys,
  readUserKeyRoster,
  rotateUserKeyRoster,
  type UserKey,
  type RosterRecipientDocument
} from '@interop/wallet-core/keys'
import { accountRosterStore, sessionRosterStore } from '@/session/rosterStore'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import {
  delegationKeyInDocument,
  documentKeyMultibases,
  isWebvhDid,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  verifyAccountLog,
  webvhZcapClient
} from '@interop/wallet-core/webvh'
import {
  currentAccountSigningKeys,
  type VerifiedAccountLog
} from '@interop/wallet-core/clients'
import {
  generateRecoveryCode,
  publishRecoveryKey,
  recoverWebvhClient,
  recoveryClientFromCode,
  RECOVERY_KDF,
  recoveryRecordBinding,
  removeRecoveryKey,
  unwrapRecoveryRecord,
  wrapRecoveryRecord,
  type RecoveryClient,
  type RecoveryLogStore,
  type RecoveryRecordProofState
} from '@interop/wallet-core/recovery'
import type { Session } from '@/types/auth'
import {
  bindPassphrase,
  delegateUnlockManagement,
  unlockManagementGrantee
} from '@/session/keyring'
import {
  backfillPassphraseUnlockMethod,
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  managementZcapClient,
  putUnlockMethods,
  revokeUnlockMethod,
  type RecoveryCodeUnlockMethod,
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
  accountLogPinStore,
  deleteClientKeyRecord,
  deleteKeyringFreshnessPin,
  deleteKeyringCache,
  loadUserKeyEpochPin,
  savePinFromDescriptor
} from '@/lib/sessionKey'
import { WASRemoteStore } from '@/stores/wasRemoteStore'

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
 * The absolute URL of the account's `did.jsonl` log resource -- the
 * invocation target of the pre-minted recovery delegation.
 *
 * @param options {object}
 * @param options.pointer {AccountPointer}
 * @returns {string}
 */
function didLogUrl({ pointer }: { pointer: AccountPointer }): string {
  return new URL(
    `/space/${pointer.spaceId}/${ID_COLLECTION.id}/${DID_LOG_RESOURCE}`,
    pointer.host
  ).toString()
}

/**
 * The verification method that signed a delegation's proof -- recorded in the
 * registry entry so the health check can test it against the current
 * document without holding the code.
 *
 * @param delegation {IZcap}
 * @returns {string | undefined}
 */
function delegationProofKeyId(delegation: IZcap): string | undefined {
  const { proof } = delegation as unknown as {
    proof?:
      | { verificationMethod?: string }
      | Array<{
          verificationMethod?: string
        }>
  }
  const single = Array.isArray(proof) ? proof[0] : proof
  return single?.verificationMethod
}

/**
 * Delegates the narrow log-write bridge to a code-derived client: PUT on the
 * one `did.jsonl` resource, long TTL. The delegation is what lets a
 * latent-authority code write its self-enrolling continuation without any
 * standing invocation presence -- and its narrow scope is what keeps
 * recovery loud (a stolen code must extend the world-readable log before it
 * can read anything).
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating client (an enrolled
 *   client's promoted signer)
 * @param options.pointer {AccountPointer}
 * @param options.recoveryClientDid {string}
 * @returns {Promise<IZcap>}
 */
async function delegateLogWrite({
  zcapClient,
  pointer,
  recoveryClientDid
}: {
  zcapClient: ZcapClient
  pointer: AccountPointer
  recoveryClientDid: string
}): Promise<IZcap> {
  return zcapClient.delegate({
    invocationTarget: didLogUrl({ pointer }),
    controller: recoveryClientDid,
    allowedActions: ['PUT'],
    expires: new Date(Date.now() + RECOVERY_ZCAP_TTL_MS)
  })
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
  const record = await wrapRecoveryRecord({
    controller,
    pointer,
    delegation,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver,
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
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function recordRecoveryMethod({
  session,
  entry,
  dropKids = [],
  idb
}: {
  session: Session
  entry: RecoveryCodeUnlockMethod
  dropKids?: string[]
  idb?: IDBFactory
}): Promise<void> {
  const existing = await getUnlockMethods({ session, idb })
  const record = existing ?? emptyUnlockMethodsRegistry()
  const dropped = new Set([entry.recoveryKid, ...dropKids])
  const methods = [
    ...record.methods.filter(
      method =>
        method.type !== 'recovery-code' || !dropped.has(method.recoveryKid)
    ),
    entry
  ]
  await putUnlockMethods({ session, record: { ...record, methods }, idb })
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
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ entry: RecoveryCodeUnlockMethod }>}
 */
export async function issueRecoveryCode({
  session,
  code,
  label,
  idb
}: {
  session: Session
  code: string
  label: string
  idb?: IDBFactory
}): Promise<{ entry: RecoveryCodeUnlockMethod }> {
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
    store: sessionRosterStore({ profile: session.profile, idb }),
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
  await recordRecoveryMethod({ session, entry, idb })

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
  const was = new WasClient({
    serverUrl: pointer.host,
    zcapClient: client.agents.zcapClient
  })
  return {
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      const response = await fetch(
        new URL(
          `/space/${pointer.spaceId}/${ID_COLLECTION.id}/${resourceId}`,
          pointer.host
        )
      )
      if (response.status === 404) {
        return undefined
      }
      if (!response.ok) {
        throw new Error(
          `Fetching "${resourceId}" failed (HTTP ${response.status}).`
        )
      }
      return {
        text: await response.text(),
        etag: response.headers.get('etag') ?? undefined
      }
    },
    async putIdResource({
      resourceId,
      content,
      contentType,
      ifMatch,
      ifNoneMatch
    }: {
      resourceId: string
      content: object | string
      contentType?: string
      ifMatch?: string
      ifNoneMatch?: boolean
    }) {
      const serialized =
        typeof content === 'string' ? content : JSON.stringify(content)
      const headers: Record<string, string> = {
        'content-type': contentType ?? 'application/json'
      }
      if (ifMatch !== undefined) {
        headers['if-match'] = ifMatch
      }
      if (ifNoneMatch) {
        headers['if-none-match'] = '*'
      }
      // A failed precondition (HTTP 412) surfaces from `was.request` as
      // was-client's `PreconditionFailedError` -- the exact name the
      // `WebvhIdStore` seam contract requires for the ceremony's rebase.
      await was.request({
        path: `/space/${pointer.spaceId}/${ID_COLLECTION.id}/${resourceId}`,
        method: 'PUT',
        headers,
        body: new TextEncoder().encode(serialized),
        capability: delegation
      })
    }
  }
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
  const { contents, proofState } = await unwrapRecoveryRecord({
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
 * Settles a pending recovery-record proof: a record the code's own unlock key
 * did not sign is only acceptable when an enrolled client of the account the
 * code-authenticated pointer names signed it -- the pointer's binding was
 * verified under the code-derived MAC key in the unwrap, so the document
 * fetched here belongs to the account the code was issued for, never to an
 * account a forging host substituted. A `'verified'` state passes through
 * untouched; anything the document's current signing keys cannot account for
 * refuses with `RecoveryRecordForgedError`.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored recovery record, proof included
 * @param options.proofState {RecoveryRecordProofState}   as `readRecoveryRecord`
 *   returned it
 * @param options.pointer {AccountPointer}   the code-authenticated account
 *   pointer (as `unwrapRecoveryRecord` returned it, its binding verified)
 * @param [options.verifiedLog] {VerifiedAccountLog}   an already-verified
 *   account log; fetched and verified here when absent
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
async function completeRecoveryRecordProof({
  record,
  proofState,
  pointer,
  verifiedLog,
  idb
}: {
  record: unknown
  proofState: RecoveryRecordProofState
  pointer: AccountPointer
  verifiedLog?: VerifiedAccountLog
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
            accountLogPinStore: accountLogPinStore({
              accountDid: logPointer.did,
              idb
            })
          })
    })
    await verifyRecordProof({
      record,
      allowedKeyMultibases: [...signingKeys],
      label: 'recovery'
    })
  } catch (err) {
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
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function locateRecoveryAccount({
  code,
  idb
}: {
  code: string
  idb?: IDBFactory
}): Promise<void> {
  const { record, contents, proofState } = await readRecoveryRecord({ code })
  await completeRecoveryRecordProof({
    record,
    proofState,
    pointer: contents.pointer,
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
 * The whole recovery flow on a fresh browser, from a typed code to an
 * enrolled client bound under a new passphrase (the caller then performs an
 * ordinary passphrase login). See the module doc for the sequence; every
 * stage is idempotent or convergent, so re-running with the same code after
 * a tear makes progress rather than forking anything.
 *
 * Error discipline: a malformed code throws `RecoveryCodeInvalidError`; a
 * code with no unlock record throws `RecoveryCodeNotFoundError`; a code
 * whose posture the log no longer commits throws
 * `RecoveryKeyNotCommittedError` (revoked while its record survived); a
 * network failure rethrows unchanged, so "could not check" never reads as
 * "no account".
 *
 * @param options {object}
 * @param options.code {string}   the typed recovery code
 * @param options.newPassphrase {string}   the passphrase to bind the new
 *   client under
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<RecoveryOutcome>}
 */
export async function recoverAccountWithCode({
  code,
  newPassphrase,
  idb
}: {
  code: string
  newPassphrase: string
  idb?: IDBFactory
}): Promise<RecoveryOutcome> {
  // The code's client identity and unlock record. The method is passed
  // explicitly (`RECOVERY_KDF`) -- this page knows it holds a code.
  const {
    client: spent,
    unlock,
    record,
    contents,
    proofState
  } = await readRecoveryRecord({
    code
  })
  const pointer = contents.pointer
  if (!isWebvhDid(pointer.did)) {
    throw new Error(
      'The recovery record names no did:webvh account; it cannot be ' +
        'recovered on the roster model.'
    )
  }
  // Verify the world-readable log locally before invoking anything. The
  // recovering browser normally holds no account-log chain-head pin yet
  // (this read is its first contact), which is exactly the pin's
  // trust-on-first-use establishment.
  const verifiedLog = await verifyAccountLog({
    did: pointer.did,
    spaceId: pointer.spaceId,
    host: pointer.host,
    pinStore: accountLogPinStore({ accountDid: pointer.did, idb })
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
    idb
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
    pinStore: accountLogPinStore({ accountDid: pointer.did, idb })
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
    await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
    await deleteClientKeyRecord({ spaceId: unlock.spaceId, idb })
    await deleteKeyringFreshnessPin({ spaceId: unlock.spaceId, idb })
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
  const rosterStore = sessionRosterStore({ profile: session.profile, idb })
  await rotateUserKeyRoster({
    store: rosterStore,
    document: doc,
    retireRecipientId: entry.recoveryKid
  })
  const read = await readUserKeyRoster({
    store: rosterStore,
    userKey: session.profile.userKey,
    clientKeyAgreementKey,
    pinnedEpochId: await loadUserKeyEpochPin({ accountDid: pointer.did, idb })
  })
  let rotatedUserKey: UserKey | undefined
  if (read) {
    await savePinFromDescriptor({
      accountDid: pointer.did,
      epochId: read.latestEpochId,
      descriptor: read.descriptor,
      idb
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
 * Re-mints the recovery delegations the current document no longer backs --
 * the recovery-code delta riding the revocation cascade: revoking a client
 * kills, by the current-key-set rule, every `did.jsonl` delegation that
 * client signed, which would brick recovery exactly when it is needed. For
 * each registry entry whose recorded delegation no longer chains (its
 * signing verification method left the document), this client signs a fresh
 * delegation to the code's signing DID, re-wraps the record to the code's
 * unlock KAK (the public half the registry records -- the record carries no
 * secrets, so re-encryption needs none), re-PUTs it through the entry's
 * management zcap, and updates the registry's `delegationKeyId`.
 *
 * The record's code-authenticated account binding is preserved verbatim: the
 * re-mint reads the standing record through the same management zcap and
 * carries its `binding` frame member forward (the tag rides in the clear; it
 * cannot be recomputed without the code, and does not need to be). A re-mint
 * therefore can never change the pointer or controller the code was issued
 * against -- and after a host migration the tag no longer matches the moved
 * pointer, so codes must be re-issued when the account moves hosts.
 *
 * Best-effort per entry: an entry that predates the re-mint fields (no
 * `recoveryClientDid` / unlock-KAK members, or a GET/DELETE-only management
 * zcap), or whose standing record cannot be read or carries no binding, is
 * skipped and stays flagged by the login-time health check, whose regenerate
 * nudge remains the backstop.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.doc {RosterRecipientDocument}   the locally verified
 *   did:webvh document, AFTER the revocation edit
 * @param [options.entries] {RecoveryCodeUnlockMethod[]}   the registry's
 *   recovery entries, when the caller already read them (the revocation
 *   cascade reads the registry once for its document edit and this stage)
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ reminted: number; skipped: number }>}
 */
export async function remintRecoveryDelegations({
  session,
  doc,
  entries: prefetched,
  idb
}: {
  session: Session
  doc: RosterRecipientDocument
  entries?: RecoveryCodeUnlockMethod[]
  idb?: IDBFactory
}): Promise<{ reminted: number; skipped: number }> {
  const pointer = session.profile.accountPointer
  const keyAgent = session.profile.keyAgent
  if (!WAS_SERVER_URL || !pointer || !keyAgent) {
    return { reminted: 0, skipped: 0 }
  }
  // The re-mint holds the code's KAK public half but not its signing key, so
  // every record it re-PUTs is signed with this client's own account key --
  // the mixed-signer case a reader settles against the verified document.
  const recordSigner = recordSignerFromAgent({ keyAgent })
  const entries =
    prefetched ??
    recoveryEntriesOf({ record: await getUnlockMethods({ session, idb }) })
  if (entries.length === 0) {
    return { reminted: 0, skipped: 0 }
  }
  let reminted = 0
  let skipped = 0
  for (const entry of entries) {
    // The current-key-set rule, decided once in wallet-core: an entry whose
    // recorded signing key the document no longer publishes -- or that
    // records no signing key at all -- is rotted.
    const stands = delegationKeyInDocument({
      doc,
      ...(entry.delegationKeyId
        ? { delegationKeyId: entry.delegationKeyId }
        : {})
    })
    if (stands) {
      continue
    }
    if (
      !entry.recoveryClientDid ||
      !entry.unlockKeyAgreementKeyId ||
      !entry.unlockKeyAgreementKeyMultibase ||
      !entry.manageCapability
    ) {
      // An entry issued before the re-mint fields existed: the health check
      // keeps flagging it until the code is regenerated.
      skipped += 1
      continue
    }
    try {
      // The standing record's code-authenticated binding, carried forward
      // verbatim (a record with none predates the binding and cannot be
      // re-minted -- `recoveryRecordBinding` refuses, and the entry is
      // skipped into the health check's regenerate nudge).
      const standing = await getUnlockKeyringWithCapability({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: managementZcapClient({
          session,
          capability: entry.manageCapability
        }),
        spaceId: entry.unlockSpaceId,
        capability: entry.manageCapability
      })
      const binding = recoveryRecordBinding({ record: standing })
      const delegation = await delegateLogWrite({
        zcapClient: session.profile.zcapClient,
        pointer,
        recoveryClientDid: entry.recoveryClientDid
      })
      // The code's unlock KAK, public half only -- exactly enough to
      // re-encrypt the record to the same recipient the code derives.
      const unlockKak = (await X25519KeyAgreementKey2020.from({
        id: entry.unlockKeyAgreementKeyId,
        controller: entry.unlockKeyAgreementKeyId.split('#')[0],
        type: 'X25519KeyAgreementKey2020',
        publicKeyMultibase: entry.unlockKeyAgreementKeyMultibase
      })) as IKeyAgreementKey
      const wrapped = await wrapRecoveryRecord({
        controller: session.profile.accountController ?? session.user.id,
        pointer,
        delegation,
        keyAgreementKey: unlockKak,
        keyResolver: singleKeyResolver({ keyAgreementKey: unlockKak }),
        signer: recordSigner,
        binding
      })
      await putUnlockKeyringWithCapability({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: managementZcapClient({
          session,
          capability: entry.manageCapability
        }),
        spaceId: entry.unlockSpaceId,
        record: wrapped,
        capability: entry.manageCapability
      })
      const delegationKeyId = delegationProofKeyId(delegation)
      await recordRecoveryMethod({
        session,
        entry: {
          ...entry,
          ...(delegationKeyId ? { delegationKeyId } : {})
        },
        idb
      })
      reminted += 1
    } catch (err) {
      console.warn(
        `Could not re-mint the recovery delegation for "${entry.label}":`,
        err
      )
      skipped += 1
    }
  }
  return { reminted, skipped }
}

/**
 * One flagged registry entry from the login-time recovery health check, with
 * the reasons it is flagged.
 */
export interface RecoveryHealthFlag {
  entry: RecoveryCodeUnlockMethod
  delegationRotted: boolean
  postureMissing: boolean
}

/**
 * The login-time recovery health check: for each recovery-code
 * registry entry, tests that the stored delegation still chains against the
 * current document (its signing client's verification method is still
 * listed -- the current-key-set rule) and that the code's posture (its
 * `keyAgreement` VM and committed update-key hash) still stands. A rotted
 * delegation bricks recovery exactly when it is needed. The revocation
 * cascade re-mints rotted delegations automatically
 * (`remintRecoveryDelegations`); this check is the backstop for entries that
 * predate the re-mint fields, whose flag nudges the user to regenerate the
 * code. Both stages ask the one shared predicate
 * (`delegationKeyInDocument`), so an entry recording no delegation key at
 * all -- uncheckable, and therefore not assumed healthy -- is flagged here
 * rather than being simultaneously "fine" and "needs re-minting".
 * Returns only the flagged entries; resolves `[]` when there is nothing to
 * check or the account has no recovery codes.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.entries] {RecoveryCodeUnlockMethod[]}   the registry's
 *   recovery entries, when the caller already read them (the Settings panel
 *   lists them immediately before checking their health)
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<RecoveryHealthFlag[]>}
 */
export async function checkRecoveryHealth({
  session,
  entries: prefetched,
  idb
}: {
  session: Session
  entries?: RecoveryCodeUnlockMethod[]
  idb?: IDBFactory
}): Promise<RecoveryHealthFlag[]> {
  const remoteStore = session.storage.remoteStore
  const pointer = session.profile.accountPointer
  if (!remoteStore || !pointer || !isWebvhDid(pointer.did)) {
    return []
  }
  const entries =
    prefetched ??
    recoveryEntriesOf({ record: await getUnlockMethods({ session, idb }) })
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
    const postureMissing =
      !publishedMultibases.has(entry.keyAgreementKeyMultibase) ||
      !nextKeyHashes.includes(updateKeyHashes[position])
    if (delegationRotted || postureMissing) {
      flags.push({ entry, delegationRotted, postureMissing })
    }
  }
  return flags
}
