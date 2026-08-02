/**
 * Recovery codes on the roster identity model. A code is a minimal always-enrolled wallet client: its unlock
 * record carries the account pointer plus a pre-minted PUT-on-`did.jsonl`
 * delegation (never a seed, never a PUK wrap), its `keyAgreement`
 * verification method stands in the did:webvh document (unmarked -- a
 * recovery key is the keyAgreement-only case, so client listings keyed on
 * `capabilityInvocation` never see it), its PUK wrap stands in the
 * `key-map/puk.json`
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
 *   continuation, the PUK unwrapped from the code's standing wrap, the
 *   mandatory PUK rotation in the roster (the spent code presumed
 *   compromised), the epoch cascade re-keying every encrypted collection off
 *   the spent code's reach, a replacement code issued hard, and the new
 *   client bound under a fresh passphrase.
 * - `revokeRecoveryCode` -- the Settings removal: document entry out, PUK
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
import {
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { base64urlnopad } from '@scure/base'
import {
  RECOVERY_ZCAP_TTL_MS,
  UNLOCK_MANAGE_ZCAP_TTL_MS,
  WAS_SERVER_URL
} from '@/app.config'
import {
  DID_LOG_RESOURCE,
  ID_COLLECTION,
  DID_DOCUMENT_RESOURCE
} from '@interop/wallet-core/space'
import { agentsFromSeed, singleKeyResolver } from '@interop/wallet-core/identity'
import {
  deriveUnlockIdentity,
  deleteUnlockSpace,
  ensureUnlockSpace,
  getUnlockKeyring,
  putUnlockKeyring,
  putUnlockKeyringWithCapability,
  type AccountPointer,
  type UnlockIdentity
} from '@interop/wallet-core/keyring'
import {
  addPukRosterRecipient,
  pukRosterDescriptorStore,
  pukVaultKeys,
  readPukRoster,
  rotatePukRoster,
  type Puk,
  type RosterRecipientDocument
} from '@interop/wallet-core/keys'
import { cascadeCollectionsToPuk } from '@/session/pukCascade'
import {
  didKeyZcapClient,
  isWebvhDid,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  webvhZcapClient
} from '@interop/wallet-core/webvh'
import {
  generateRecoveryCode,
  publishRecoveryKey,
  recoverWebvhClient,
  recoveryClientFromCode,
  RECOVERY_KDF,
  removeRecoveryKey,
  unwrapRecoveryRecord,
  wrapRecoveryRecord,
  type RecoveryClient,
  type RecoveryLogStore
} from '@interop/wallet-core/recovery'
import type { Session } from '@/types/auth'
import { bindPassphrase } from '@/session/keyring'
import {
  getUnlockMethods,
  putUnlockMethods,
  revokeUnlockMethod,
  rewrapUnlockMethodsRecord,
  type RecoveryCodeUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import {
  deleteAccountPointerPin,
  deleteClientKeyRecord,
  deleteKeyringCache,
  savePukEpochPin
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
 * Delegates the unlock-Space management zcap (GET/PUT/DELETE) from a code's
 * unlock identity to the account controller, so the code stays revocable
 * from Settings without re-typing it (the same bridge every other unlock
 * method records). PUT is what lets the revocation cascade re-PUT the code's
 * record with a freshly minted delegation when the original's signing client
 * is revoked -- the record's JWE recipient stays the code's unlock KAK, so
 * the re-wrap needs only the public half the registry records.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}
 * @param options.controller {string}   the account did:key
 * @returns {Promise<IZcap>}
 */
async function delegateUnlockManagement({
  unlock,
  controller
}: {
  unlock: UnlockIdentity
  controller: string
}): Promise<IZcap> {
  const invocationTarget = new URL(
    `/space/${unlock.spaceId}`,
    WAS_SERVER_URL
  ).toString()
  return await unlock.zcapClient.delegate({
    invocationTarget,
    controller,
    allowedActions: ['GET', 'PUT', 'DELETE'],
    expires: new Date(Date.now() + UNLOCK_MANAGE_ZCAP_TTL_MS)
  })
}

/**
 * Writes a code's unlock Space and recovery record: ensure the Space, wrap
 * the pointer + delegation to the code's unlock KAK, PUT the record, and
 * delegate the management zcap to the account controller. No local cache and
 * no client-key record: a code is not bound to any browser.
 *
 * @param options {object}
 * @param options.client {RecoveryClient}
 * @param options.controller {string}   the account did:key
 * @param [options.email] {string}
 * @param options.pointer {AccountPointer}
 * @param options.delegation {IZcap}
 * @returns {Promise<{ unlockSpaceId: string, manageCapability: IZcap,
 *   unlockKeyAgreementKeyId?: string,
 *   unlockKeyAgreementKeyMultibase?: string }>}
 */
async function bindRecoveryRecord({
  client,
  controller,
  email,
  pointer,
  delegation
}: {
  client: RecoveryClient
  controller: string
  email?: string
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
    email,
    pointer,
    delegation,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver
  })
  await putUnlockKeyring({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId,
    record
  })
  const manageCapability = await delegateUnlockManagement({
    unlock,
    controller
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
 * Appends (or replaces, matching on `recoveryKid`) a recovery entry in the
 * unlock-methods registry, minting the registry when absent.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {RecoveryCodeUnlockMethod}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function recordRecoveryMethod({
  session,
  entry,
  idb
}: {
  session: Session
  entry: RecoveryCodeUnlockMethod
  idb?: IDBFactory
}): Promise<void> {
  const existing = await getUnlockMethods({ session, idb })
  const record: UnlockMethodsRecord = existing ?? {
    version: 1,
    userHandle: base64urlnopad.encode(
      crypto.getRandomValues(new Uint8Array(16))
    ),
    methods: []
  }
  const methods = [
    ...record.methods.filter(
      method =>
        method.type !== 'recovery-code' ||
        method.recoveryKid !== entry.recoveryKid
    ),
    entry
  ]
  await putUnlockMethods({ session, record: { ...record, methods }, idb })
}

/**
 * The issuance preconditions, resolved from a live session: a configured WAS
 * server and remote store, a promoted did:webvh account pointer, and this
 * client's own key material (update keys + identity KAK). Throws with a
 * specific message on each miss -- the Settings section gates on
 * `canIssueRecoveryCode` first, so these are defensive.
 *
 * @param session {Session}
 * @returns {object}   the resolved pieces
 */
function requireIssuancePreconditions(session: Session) {
  if (!WAS_SERVER_URL) {
    throw new RecoveryUnavailableError()
  }
  const remoteStore = session.storage.remoteStore
  if (!remoteStore) {
    throw new RecoveryUnavailableError()
  }
  const { profile } = session
  const pointer = profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    throw new Error(
      'Recovery codes require a promoted did:webvh account; this account ' +
        'has not finished provisioning.'
    )
  }
  if (!profile.clientWebvhKeys) {
    throw new Error(
      "Recovery-code issuance requires this client's did:webvh update keys."
    )
  }
  if (!profile.clientKeyAgreementKey) {
    throw new Error(
      "Recovery-code issuance requires this client's key-agreement key."
    )
  }
  return {
    remoteStore,
    pointer,
    clientWebvhKeys: profile.clientWebvhKeys,
    clientKeyAgreementKey: profile.clientKeyAgreementKey,
    controller: profile.accountController ?? session.user.id
  }
}

/**
 * Whether this session can issue (and revoke) recovery codes: an enrolled
 * wallet client on a promoted account with a remote store -- the issuance
 * gate, "an enrolled wallet client holding its key material" (the roster
 * model's restatement of the retired you-must-hold-the-seed gate).
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
  const { profile } = session
  return !!(
    WAS_SERVER_URL &&
    !session.isGuest &&
    session.storage.remoteStore &&
    isWebvhDid(profile.accountPointer?.did) &&
    profile.clientWebvhKeys &&
    profile.clientKeyAgreementKey &&
    profile.puk
  )
}

/**
 * Issues a recovery code from a live enrolled session, in the
 * recovery-anchor order (decryption material before authorization): the PUK
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
  } = requireIssuancePreconditions(session)

  const client = await recoveryClientFromCode({ code })

  // 1. Decryption material first: the code's wrap into every roster epoch.
  await addPukRosterRecipient({
    store: remoteStore.pukRosterStore(),
    recipient: {
      id: client.recipientKid,
      publicKeyMultibase: client.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: clientKeyAgreementKey
  })

  // 2. The document entry: the recovery VM and the update-key commitment.
  await publishRecoveryKey({
    idStore: remoteStore,
    updateKeys: clientWebvhKeys,
    recovery: {
      keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
      updateKeyMultibase: client.updateKeyMultibase
    }
  })

  // 3. The authorization bridge and the record that carries it.
  const delegation = await delegateLogWrite({
    zcapClient: session.profile.zcapClient,
    pointer,
    recoveryClientDid: client.clientDid
  })
  const bound = await bindRecoveryRecord({
    client,
    controller,
    email: session.user.email,
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
 * Reads and locally verifies the world-readable DID log named by an account
 * pointer, refusing a log that resolves to a different DID. Shared with the
 * client-revocation cascade (`src/session/revocation.ts`), whose roster
 * rotation resolves recipients from the same verified document.
 *
 * @param options {object}
 * @param options.pointer {AccountPointer}
 * @returns {Promise<{ doc: RosterRecipientDocument, updateKeys: string[],
 *   nextKeyHashes: string[] }>}
 */
export async function verifyAccountLog({
  pointer
}: {
  pointer: AccountPointer
}) {
  const response = await fetch(didLogUrl({ pointer }))
  if (response.status === 404) {
    throw new Error('The account has no published DID log.')
  }
  if (!response.ok) {
    throw new Error(
      `Fetching the account's DID log failed (HTTP ${response.status}).`
    )
  }
  const resolvedLog = await resolveDIDFromLog(
    readLogFromString(await response.text())
  )
  if (resolvedLog.meta.error || !resolvedLog.did || !resolvedLog.doc) {
    throw new Error(
      `The account's DID log failed to resolve (${resolvedLog.meta.error}).`
    )
  }
  if (resolvedLog.did !== pointer.did) {
    throw new Error(
      'The published DID log resolves to a different DID than the account ' +
        'pointer names.'
    )
  }
  return {
    doc: resolvedLog.doc as RosterRecipientDocument,
    updateKeys: resolvedLog.meta.updateKeys ?? [],
    nextKeyHashes: resolvedLog.meta.nextKeyHashes ?? []
  }
}

/**
 * The narrow store the recovery continuation writes through: public fetches
 * for the world-readable log, and the delegated PUT (the record's zcap,
 * invoked by the code-derived did:key client) for `did.jsonl`.
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
      return response.text()
    },
    async putIdResource({
      resourceId,
      content,
      contentType
    }: {
      resourceId: string
      content: object | string
      contentType?: string
    }) {
      const serialized =
        typeof content === 'string' ? content : JSON.stringify(content)
      await was.request({
        path: `/space/${pointer.spaceId}/${ID_COLLECTION.id}/${resourceId}`,
        method: 'PUT',
        headers: { 'content-type': contentType ?? 'application/json' },
        body: new TextEncoder().encode(serialized),
        capability: delegation
      })
    }
  }
}

/**
 * Reads and unwraps a code's recovery record: derive the client identity and
 * unlock identity, one remote read, one unwrap. Shared by the `/recover`
 * page's locate step and the full recovery flow. Error discipline as on
 * `recoverAccountWithCode`.
 *
 * @param options {object}
 * @param options.code {string}
 * @returns {Promise<object>}   the client identity, unlock identity, and
 *   record contents
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
  const contents = await unwrapRecoveryRecord({
    record,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver
  })
  return { client, unlock, contents }
}

/**
 * The `/recover` page's locate step: whether a typed code resolves to an
 * account, without changing anything. Returns the account email the record
 * carries (shown so the person can confirm it is the expected wallet).
 *
 * @param options {object}
 * @param options.code {string}
 * @returns {Promise<{ email?: string }>}
 */
export async function locateRecoveryAccount({
  code
}: {
  code: string
}): Promise<{ email?: string }> {
  const { contents } = await readRecoveryRecord({ code })
  return { email: contents.email }
}

/**
 * What `recoverAccountWithCode` hands back for the page to finish on: the
 * replacement code to push hard (shown exactly once), the account email the
 * record carried (prefilled into the login), and the spent code's roster kid
 * so the post-login registry update can drop its entry.
 */
export interface RecoveryOutcome {
  replacementCode: string
  replacementEntry: RecoveryCodeUnlockMethod
  spentRecoveryKid: string
  email?: string
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
    contents
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
  // Verify the world-readable log locally before invoking anything.
  await verifyAccountLog({ pointer })

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
      await remoteStore.putIdResource({
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
  // read the standing PUK, then the mandatory rotation off the spent code --
  // it is presumed compromised the moment it is typed.
  const rosterStore = pukRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient: newZcapClient,
    spaceId: pointer.spaceId
  })
  await addPukRosterRecipient({
    store: rosterStore,
    recipient: {
      id: newClientAgents.keyAgreementKey.id,
      publicKeyMultibase: newClientKaMultibase
    },
    ownerKeyAgreementKey: spent.agents.keyAgreementKey
  })
  await addPukRosterRecipient({
    store: rosterStore,
    recipient: {
      id: replacement.recipientKid,
      publicKeyMultibase: replacement.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: spent.agents.keyAgreementKey
  })
  const preRotation = await readPukRoster({
    store: rosterStore,
    clientKeyAgreementKey: newClientAgents.keyAgreementKey
  })
  if (!preRotation) {
    throw new Error(
      'The account has no PUK roster; it must finish provisioning before ' +
        'it can be recovered.'
    )
  }
  const oldPuk = preRotation.puk

  // The rotation wraps the fresh epoch only to recipients the just-updated,
  // locally verified document backs -- the spent code's VM is gone, so its
  // entry is dropped even before the recipient filter. The pull axis already
  // ran at the document: the spent code's VM and update-key hash left in the
  // continuation's add-and-retire entry.
  const { doc } = await verifyAccountLog({ pointer })
  await rotatePukRoster({
    store: rosterStore,
    document: doc,
    retireRecipientId: spent.recipientKid
  })
  const postRotation = await readPukRoster({
    store: rosterStore,
    clientKeyAgreementKey: newClientAgents.keyAgreementKey
  })
  if (!postRotation) {
    throw new Error('The PUK roster vanished during recovery.')
  }
  const newPuk = postRotation.puk
  await savePukEpochPin({
    spaceId: pointer.spaceId,
    epochId: postRotation.latestEpochId,
    idb
  })

  // The epoch cascade: every encrypted collection takes a fresh epoch naming
  // the rotated PUK, the spent code's generation retired, history escrowed --
  // so new writes are sealed away from the spent code, not just future
  // rotations. Best-effort per collection; the completion sweep backstops a
  // partial run, and a stranded collection stays readable meanwhile (the old
  // epochs remain, escrowed to the fresh PUK).
  await cascadeCollectionsToPuk({
    remoteStore,
    rosterDescriptor: postRotation.descriptor,
    clientKeyAgreementKey: newClientAgents.keyAgreementKey,
    puk: newPuk
  })

  // Re-seal the unlock-methods registry to the rotated PUK: its record is a
  // single-recipient envelope to the vault KAK, and the post-login registry
  // update (`recordRecoveryOutcome`) runs on the new-PUK session. Best-effort:
  // a failure leaves the registry sealed to the old PUK, which the post-login
  // update then surfaces as a warning.
  if (oldPuk.id !== newPuk.id) {
    try {
      await rewrapUnlockMethodsRecord({
        storageServerUrl: pointer.host,
        zcapClient: newZcapClient,
        spaceId: pointer.spaceId,
        from: pukVaultKeys({ puk: oldPuk }),
        to: pukVaultKeys({ puk: newPuk })
      })
    } catch (err) {
      console.warn(
        'Could not re-wrap the unlock-methods registry to the rotated PUK:',
        err
      )
    }
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
    await deleteAccountPointerPin({ spaceId: unlock.spaceId, idb })
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
    email: contents.email,
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
  // local client-key record (client seed + rotated PUK + update-key seeds),
  // the pointer pin, and the management zcap. An ordinary passphrase login
  // now finds an enrolled client.
  await bindPassphrase({
    clientSeed: newClientSeed,
    controller: contents.controller,
    passphrase: newPassphrase,
    email: contents.email,
    puk: newPuk,
    webvhUpdateKeys: newClientUpdateSeeds,
    pointer: replacementPointer,
    delegateManagementTo: contents.controller,
    idb
  })

  return {
    replacementCode,
    replacementEntry,
    spentRecoveryKid: spent.recipientKid,
    email: contents.email
  }
}

/**
 * The post-login registry update after a recovery: drops the spent code's
 * entry and records the replacement's. Runs on the recovered session (the
 * registry is wrapped to the vault KAK, which only a session holds).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.outcome {RecoveryOutcome}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function recordRecoveryOutcome({
  session,
  outcome,
  idb
}: {
  session: Session
  outcome: RecoveryOutcome
  idb?: IDBFactory
}): Promise<void> {
  const existing = await getUnlockMethods({ session, idb })
  const record: UnlockMethodsRecord = existing ?? {
    version: 1,
    userHandle: base64urlnopad.encode(
      crypto.getRandomValues(new Uint8Array(16))
    ),
    methods: []
  }
  const methods = [
    ...record.methods.filter(
      method =>
        method.type !== 'recovery-code' ||
        (method.recoveryKid !== outcome.spentRecoveryKid &&
          method.recoveryKid !== outcome.replacementEntry.recoveryKid)
    ),
    outcome.replacementEntry
  ]
  await putUnlockMethods({ session, record: { ...record, methods }, idb })
}

/**
 * Revokes a recovery code from a live enrolled session -- the issuance
 * reversal, in the cascade order: the document entry out first (the pull
 * axis: the code's VM and commitment leave, so the doc-backed resolver drops
 * its roster entry), then the mandatory PUK rotation off the code's wrap,
 * then the epoch cascade re-keying every encrypted collection, then the
 * unlock Space (whose deletion is what makes the code resolve to nothing
 * afterwards) and the registry entry. The revocation is REAL -- the secret
 * was only ever a pointer to the record -- which is stronger than what the
 * sharing layer can promise.
 *
 * The rotated PUK is persisted into this client's client-key record and
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
    requireIssuancePreconditions(session)

  // 1. The document entry out (idempotent).
  await removeRecoveryKey({
    idStore: remoteStore,
    updateKeys: clientWebvhKeys,
    recovery: {
      keyAgreementKeyMultibase: entry.keyAgreementKeyMultibase,
      updateKeyMultibase: entry.updateKeyMultibase
    }
  })

  // 2. The PUK rotation off the code's wrap, recipients resolved from the
  // just-updated document (the pull axis already ran there).
  const { doc } = await verifyAccountLog({ pointer })
  const rosterStore = remoteStore.pukRosterStore()
  await rotatePukRoster({
    store: rosterStore,
    document: doc,
    retireRecipientId: entry.recoveryKid
  })
  const read = await readPukRoster({
    store: rosterStore,
    puk: session.profile.puk,
    clientKeyAgreementKey
  })
  let rotatedPuk: Puk | undefined
  if (read) {
    await savePukEpochPin({
      spaceId: pointer.spaceId,
      epochId: read.latestEpochId,
      idb
    })
    if (read.rotated) {
      // Persist the rotated PUK for the next login, then re-epoch every
      // encrypted collection onto it (best-effort per collection; the
      // completion sweep backstops a partial run).
      rotatedPuk = read.puk
      await session.profile.persistClientKeys?.({ puk: read.puk })
      await cascadeCollectionsToPuk({
        remoteStore,
        rosterDescriptor: read.descriptor,
        clientKeyAgreementKey,
        puk: read.puk
      })
    }
  }

  // 3. The unlock Space and the registry entry -- the shared tap-free
  // revocation path (the entry's management zcap, invoked with this
  // client's did:key). Still under the OLD vault keys, so the registry
  // reads/writes decrypt the stored record.
  await revokeUnlockMethod({ session, entry, idb })

  // 4. Re-seal the registry to the rotated PUK (step 3's write went out
  // under the old vault KAK), then adopt the rotation in the live session:
  // profile vault keys swapped and the storage ciphers rebuilt, so this
  // session keeps reading and writing the re-epoch'd collections without a
  // re-login. Best-effort: a failed re-seal leaves the registry sealed to
  // the old PUK, which the next login surfaces as a warning.
  const { keyAgreementKey, keyResolver } = session.profile
  if (rotatedPuk && keyAgreementKey && keyResolver) {
    try {
      await rewrapUnlockMethodsRecord({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: session.profile.zcapClient,
        spaceId: pointer.spaceId,
        from: { keyAgreementKey, keyResolver },
        to: pukVaultKeys({ puk: rotatedPuk })
      })
    } catch (err) {
      console.warn(
        'Could not re-wrap the unlock-methods registry to the rotated PUK:',
        err
      )
    }
    const vaultKeys = pukVaultKeys({ puk: rotatedPuk })
    session.profile.puk = rotatedPuk
    session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
    session.profile.keyResolver = vaultKeys.keyResolver
    try {
      await session.storage.adoptRotatedVaultKeys(vaultKeys)
    } catch (err) {
      console.warn(
        'Could not rebuild the storage ciphers on the rotated PUK; the next ' +
          'login adopts it instead:',
        err
      )
    }
  }
}

/**
 * Re-mints the recovery delegations the current document no longer backs --
 * the FW-56 delta riding the revocation cascade: revoking a client kills, by
 * the current-key-set rule, every `did.jsonl` delegation that client signed,
 * which would brick recovery exactly when it is needed. For each registry
 * entry whose recorded delegation no longer chains (its signing verification
 * method left the document), this client signs a fresh delegation to the
 * code's signing DID, re-wraps the record to the code's unlock KAK (the
 * public half the registry records -- the record carries no secrets, so
 * re-encryption needs none), re-PUTs it through the entry's management zcap,
 * and updates the registry's `delegationKeyId`.
 *
 * Best-effort per entry: an entry that predates the re-mint fields (no
 * `recoveryClientDid` / unlock-KAK members, or a GET/DELETE-only management
 * zcap) is skipped and stays flagged by the login-time health check, whose
 * regenerate nudge remains the backstop.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.doc {RosterRecipientDocument}   the locally verified
 *   did:webvh document, AFTER the revocation edit
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ reminted: number; skipped: number }>}
 */
export async function remintRecoveryDelegations({
  session,
  doc,
  idb
}: {
  session: Session
  doc: RosterRecipientDocument
  idb?: IDBFactory
}): Promise<{ reminted: number; skipped: number }> {
  const pointer = session.profile.accountPointer
  if (!WAS_SERVER_URL || !pointer) {
    return { reminted: 0, skipped: 0 }
  }
  const record = await getUnlockMethods({ session, idb })
  const entries = (record?.methods ?? []).filter(
    (method): method is RecoveryCodeUnlockMethod =>
      method.type === 'recovery-code'
  )
  if (entries.length === 0) {
    return { reminted: 0, skipped: 0 }
  }
  const publishedMultibases = new Set(
    (doc.verificationMethod ?? [])
      .map(method => method.publicKeyMultibase)
      .filter((multibase): multibase is string => !!multibase)
  )
  let reminted = 0
  let skipped = 0
  for (const entry of entries) {
    const delegationMultibase = entry.delegationKeyId?.split('#').pop()
    const rotted =
      !delegationMultibase || !publishedMultibases.has(delegationMultibase)
    if (!rotted) {
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
      const delegation = await delegateLogWrite({
        zcapClient: session.profile.zcapClient,
        pointer,
        recoveryClientDid: entry.recoveryClientDid
      })
      // The code's unlock KAK, public half only -- exactly enough to
      // re-encrypt the record to the same recipient the code derives.
      const unlockKak = X25519KeyAgreementKey2020.from({
        id: entry.unlockKeyAgreementKeyId,
        controller: entry.unlockKeyAgreementKeyId.split('#')[0],
        type: 'X25519KeyAgreementKey2020',
        publicKeyMultibase: entry.unlockKeyAgreementKeyMultibase
      }) as IKeyAgreementKey
      const wrapped = await wrapRecoveryRecord({
        controller: session.profile.accountController ?? session.user.id,
        email: session.user.email,
        pointer,
        delegation,
        keyAgreementKey: unlockKak,
        keyResolver: singleKeyResolver({ keyAgreementKey: unlockKak })
      })
      // The management zcap names the account did:key as its controller (the
      // unlock layer stays did:key end to end), so the PUT signs under the
      // did:key keyId, like every other management-zcap invocation.
      const { keyAgent } = session.profile
      await putUnlockKeyringWithCapability({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: keyAgent
          ? didKeyZcapClient({ keyAgent })
          : session.profile.zcapClient,
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
 * code.
 * Returns only the flagged entries; resolves `[]` when there is nothing to
 * check or the account has no recovery codes.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<RecoveryHealthFlag[]>}
 */
export async function checkRecoveryHealth({
  session,
  idb
}: {
  session: Session
  idb?: IDBFactory
}): Promise<RecoveryHealthFlag[]> {
  const remoteStore = session.storage.remoteStore
  const pointer = session.profile.accountPointer
  if (!remoteStore || !pointer || !isWebvhDid(pointer.did)) {
    return []
  }
  const record = await getUnlockMethods({ session, idb })
  const entries = (record?.methods ?? []).filter(
    (method): method is RecoveryCodeUnlockMethod =>
      method.type === 'recovery-code'
  )
  if (entries.length === 0) {
    return []
  }
  const { doc, nextKeyHashes } = await verifyAccountLog({ pointer })
  const publishedMultibases = new Set(
    (doc.verificationMethod ?? [])
      .map(method => method.publicKeyMultibase)
      .filter((multibase): multibase is string => !!multibase)
  )
  const flags: RecoveryHealthFlag[] = []
  for (const entry of entries) {
    const delegationMultibase = entry.delegationKeyId?.split('#').pop()
    const delegationRotted =
      !!delegationMultibase && !publishedMultibases.has(delegationMultibase)
    const postureMissing =
      !publishedMultibases.has(entry.keyAgreementKeyMultibase) ||
      !nextKeyHashes.includes(await deriveNextKeyHash(entry.updateKeyMultibase))
    if (delegationRotted || postureMissing) {
      flags.push({ entry, delegationRotted, postureMissing })
    }
  }
  return flags
}
