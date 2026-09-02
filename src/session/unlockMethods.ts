/**
 * The unlock-methods registry: the list of how an account can be unlocked
 * (passphrase, one or more passkeys). Unlike the keyring record -- which lives
 * in each unlock method's own unlock Space and holds the encrypted account
 * pointer -- the registry lives once in the user's DATA Space, so a logged-in
 * wallet can enumerate and manage its methods without re-deriving each unlock
 * identity.
 *
 * The record carries a single WebAuthn user id (`webAuthnUserId`, minted at
 * the first passkey registration and reused for every later passkey, so
 * authenticator pickers show one account rather than N) and one entry per
 * method. Its stored
 * body is a JWE wrapped to the session's vault KAK (it names credential ids the
 * server must not read), stored as `{ version, encryption, wrapped }` -- the
 * same self-contained envelope shape the keyring record uses (the record seals
 * under its own one-epoch descriptor; see `recordEnvelope.ts`). The remote
 * copy in the data Space is the
 * source of truth and is consulted first; a local cache in the
 * `freewallet-session` IndexedDB (keyed by the data controller did:key) serves
 * no-WAS deployments and refreshes on every remote hit.
 *
 * Each entry also carries, when one was minted, the management zcap the unlock
 * identity delegated to the data identity at bind time -- the authority that
 * makes tap-free revocation of a lost method possible. It grants GET/DELETE on
 * that one unlock Space only (deletion of the method, never decryption), and
 * sits JWE-wrapped to the vault KAK like the rest of the record, so the server
 * never reads it. `revokeUnlockMethod` invokes it with the session's root key
 * to retire a lost passkey; entries predating the capability fall back to
 * `revokeUnlockMethodByCeremony` (a tap on the passkey being removed).
 */
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IZcap
} from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { PreconditionFailedError } from '@interop/was-client'
import { base64urlnopad } from '@scure/base'
import {
  DATE_FMT,
  PASSKEY_KDF,
  UNLOCK_METHODS_COLLECTION,
  WAS_SERVER_URL
} from '@/app.config'
import type { Session } from '@/types/auth'
import { isBrowserLocalSession } from '@/session/persistence'
import {
  assertPasskeyPrf,
  registerPasskey,
  type PasskeyRegistration
} from '@/lib/passkey'
import {
  bindUnlockSecret,
  deleteUnlockMethod,
  deriveUnlockCredential,
  standingLadderSeed
} from '@/session/keyring'
import { zcapExpiring } from '@interop/wallet-core/recovery'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { PersistableClientKeys } from '@/session/keyring'
import {
  didKeyZcapClient,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import {
  preflightCredentialRetirement,
  rotateOffUnlockCredential,
  type CredentialRotationOutcome
} from '@/session/credentialRotation'
import { userKeyVaultKeys, type UserKey } from '@interop/wallet-core/keys'
import {
  RecordEnvelopeDecryptError,
  unwrapRecordEnvelope,
  wrapRecordEnvelope
} from '@/session/recordEnvelope'
import { spacePath, toUrl } from '@interop/was-client/paths'
import { deleteUnlockLocalState } from '@/lib/sessionKey'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:methods')
import { deleteUnlockSpaceWithCapability } from '@interop/wallet-core/keyring'
import {
  DELETION_ZCAP_TTL_MS,
  mintSpaceVerbCapability
} from '@interop/wallet-core/clientAnnex'
import {
  ensureUnlockMethodsCollection,
  getUnlockMethodsRecord,
  putUnlockMethodsRecord
} from '@/stores/wasRemoteStore'

/**
 * The standing-inventory members a passphrase or passkey entry records once the
 * credential holds standing authority (FW-154's one-codepath model): the
 * credential's user-key roster kid (`rosterKid` -- the neutral twin of the
 * recovery entry's `recoveryKid`), its published or commitment-published
 * `keyAgreement` multibase, the update-key ladder's rung-0 multibase (whose
 * hash stood in `nextKeyHashes` at bind time; the CURRENT rung is always
 * recovered from the log itself, never from here), and the bridge-delegation
 * and unlock-KAK members the revocation cascade's re-mint machinery shares
 * with the recovery entries -- `unlockClientDid` being the neutral twin of
 * `recoveryClientDid` (the credential-derived signing DID a fresh delegation
 * is made to). The annex-Space sibling delegation's staleness rides as a
 * second scalar pair (`delegatedClientsKeyId` / `delegatedClientsExpires`),
 * absent while the record carries no sibling and always absent on recovery
 * codes. Public halves only; the secret is never stored anywhere.
 */
export interface StandingUnlockFields {
  rosterKid?: string
  keyAgreementKeyMultibase?: string
  updateKeyMultibase?: string
  delegationKeyId?: string
  delegationExpires?: string
  delegatedClientsKeyId?: string
  delegatedClientsExpires?: string
  unlockClientDid?: string
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * The passphrase unlock method. `manageCapability` -- the management zcap the
 * unlock identity delegated to the data identity -- is present once a full
 * passphrase login or a passphrase change has backfilled it (see
 * `backfillPassphraseUnlockMethod`). The standing fields are recorded by the
 * bind-time inventory ceremony; a passphrase's `keyAgreement` key is published
 * as a hash commitment (never the key verbatim -- a low-entropy-derived
 * public key in the world-readable document would be an offline grind
 * oracle).
 */
export interface PassphraseUnlockMethod extends StandingUnlockFields {
  type: 'passphrase'
  createdAt: string
  unlockSpaceId: string
  manageCapability?: IZcap
}

/**
 * A passkey unlock method. `credentialId` is base64url-encoded; `unlockSpaceId`
 * locates the unlock Space whose keyring record this passkey's PRF output
 * unwraps. The backup flags are captured at registration so a future UI can
 * warn about device-bound (not synced) passkeys. `manageCapability` -- when
 * present -- is the management zcap that allows tap-free revocation of this
 * passkey (deletion of its unlock Space) with the session's root key; it
 * lives one year, refreshed near expiry by a login with this passkey (the
 * backfill's passkey branch). The standing fields are recorded by the
 * bind-time inventory ceremony; a passkey's PRF-derived `keyAgreement` key is
 * high-entropy, so it publishes verbatim.
 */
export interface PasskeyUnlockMethod extends StandingUnlockFields {
  type: 'passkey'
  label: string
  createdAt: string
  credentialId: string
  transports: string[]
  backupEligibility: boolean
  backupState: boolean
  unlockSpaceId: string
  manageCapability?: IZcap
}

/**
 * A recovery-code unlock method (the code is a minimal
 * always-enrolled client). Beside the shared members, the entry records the
 * code's public inventory so Settings can correlate it with the document and
 * roster without the code: `recoveryKid` (its user-key roster kid),
 * `keyAgreementKeyMultibase` / `updateKeyMultibase` (the published
 * `keyAgreement` VM and the `nextKeyHashes` commitment), and
 * `delegationKeyId` (the verification method that signed the record's
 * `did.jsonl` delegation -- what the login-time health check tests against
 * the current document, since a delegation signed by a since-removed client
 * stops verifying under the current-key-set rule), and `delegationExpires`
 * (the delegation's ISO 8601 expiry -- the health check flags one expired
 * or inside the renewal window, since the one-year TTL now lapses within a
 * code's expected lifetime). Public halves only; the
 * code itself is never stored anywhere.
 *
 * The last three members are what let the revocation cascade RE-MINT a
 * rotted delegation without holding the code: `recoveryClientDid` is the
 * code-derived signing DID a fresh delegation is made to, and the unlock-KAK
 * pair identifies the public key the re-wrapped record is encrypted to (the
 * record carries no secrets, so re-encryption needs none). Entries issued
 * before these fields exist fall back to the health check's regenerate
 * nudge. The entry's `manageCapability` is the one zcap here with no refresh
 * path: only the code's own unlock identity can re-delegate it, so it runs
 * out on the same annual clock as the `did.jsonl` delegation, whose expiry
 * nudge drives regeneration of both.
 */
export interface RecoveryCodeUnlockMethod {
  type: 'recovery-code'
  label: string
  createdAt: string
  unlockSpaceId: string
  manageCapability?: IZcap
  recoveryKid: string
  keyAgreementKeyMultibase: string
  updateKeyMultibase: string
  delegationKeyId?: string
  delegationExpires?: string
  recoveryClientDid?: string
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * A single unlock-method entry -- a discriminated union on `type`, kept
 * additive (the quorum seam: a future method joins the union rather than
 * changing the record shape).
 */
export type UnlockMethod =
  PassphraseUnlockMethod | PasskeyUnlockMethod | RecoveryCodeUnlockMethod

/**
 * The version-1 unlock-methods registry record. `webAuthnUserId` is a
 * base64url (16-byte) WebAuthn user id (the ceremony-level `user.id`), one
 * per wallet.
 */
export interface UnlockMethodsRecord {
  version: 1
  webAuthnUserId: string
  methods: UnlockMethod[]
}

/**
 * The version stamped on the stored `{ version, encryption, wrapped }`
 * envelope -- the outer frame around the JWE, distinct from the registry's own
 * `version`.
 */
const STORED_RECORD_VERSION = 1

/**
 * Resolves the session's vault key material for wrap/unwrap. The vault KAK is
 * present for the life of every session, so these keys are expected to resolve;
 * the guard throws only defensively.
 *
 * @param session {Session}
 * @returns {{ keyAgreementKey: IKeyAgreementKey, keyResolver: IKeyResolver }}
 */
function requireVaultKeys(session: Session): {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
} {
  const { keyAgreementKey, keyResolver } = session.profile
  if (!keyAgreementKey || !keyResolver) {
    throw new Error(
      'The vault must be unlocked to read or write unlock methods.'
    )
  }
  return { keyAgreementKey, keyResolver }
}

/**
 * Wraps an unlock-methods record into its stored envelope: the record encrypted
 * (JWE, sealed under a fresh record-own epoch whose key wraps to the vault
 * KAK) under the `{ version, encryption, wrapped }` shape.
 *
 * @param options {object}
 * @param options.record {UnlockMethodsRecord}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<{ version: number, encryption: unknown, wrapped: unknown }>}
 */
async function wrapRecord({
  record,
  keyAgreementKey,
  keyResolver
}: {
  record: UnlockMethodsRecord
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<{ version: number; encryption: unknown; wrapped: unknown }> {
  return wrapRecordEnvelope({
    data: record as unknown as Parameters<typeof wrapRecordEnvelope>[0]['data'],
    version: STORED_RECORD_VERSION,
    collectionId: UNLOCK_METHODS_COLLECTION.id,
    keyAgreementKey,
    keyResolver
  })
}

/**
 * Unwraps and validates a stored unlock-methods envelope: validates the
 * `{ version, encryption, wrapped }` frame (a record with no `encryption`
 * descriptor -- the retired direct-to-KAK form -- is refused), decrypts the
 * payload, then sanity-checks the registry shape (its own `version`, a string
 * `webAuthnUserId`, an array of methods).
 *
 * @param options {object}
 * @param options.record {unknown}   the stored `{ version, encryption,
 *   wrapped }` envelope
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<UnlockMethodsRecord>}
 */
async function unwrapRecord({
  record,
  keyAgreementKey,
  keyResolver
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<UnlockMethodsRecord> {
  const plaintext = (await unwrapRecordEnvelope({
    record,
    version: STORED_RECORD_VERSION,
    collectionId: UNLOCK_METHODS_COLLECTION.id,
    keyAgreementKey,
    keyResolver,
    label: 'unlock-methods'
  })) as {
    version?: unknown
    webAuthnUserId?: unknown
    methods?: unknown
  }

  if (plaintext.version !== 1) {
    throw new Error(
      `Unsupported unlock-methods registry version "${String(
        plaintext.version
      )}".`
    )
  }
  if (
    typeof plaintext.webAuthnUserId !== 'string' ||
    !plaintext.webAuthnUserId
  ) {
    throw new Error('Unlock-methods record is missing a webAuthnUserId.')
  }
  if (!Array.isArray(plaintext.methods)) {
    throw new Error('Unlock-methods record is missing its methods list.')
  }
  return {
    version: 1,
    webAuthnUserId: plaintext.webAuthnUserId,
    methods: plaintext.methods as UnlockMethod[]
  }
}

/**
 * The stored registry exists but does not decrypt under this session's vault
 * keys -- it is still sealed to a superseded user key generation, the residue
 * of a rotation whose re-seal was lost. Distinct from every other refusal:
 * a frame or version refusal says the record is not one this client reads,
 * while this one says the record is ours and the key is not. The login-time
 * re-seal repair (`src/session/registryReseal.ts`) mends it from the roster
 * escrow; Settings names the state meanwhile.
 */
export class UnlockRegistryStaleSealError extends Error {
  constructor(options?: { cause?: unknown }) {
    super(
      'The unlock-methods registry is sealed to a superseded user key.',
      options
    )
    this.name = 'UnlockRegistryStaleSealError'
  }
}

/**
 * A fresh, empty unlock-methods registry: one wallet-wide WebAuthn user id
 * and no methods yet. The registry's shape is minted here alone, so every
 * path that writes it first (a passkey enrollment, a recovery-code issuance,
 * a Settings backfill) agrees on it.
 *
 * @returns {UnlockMethodsRecord}
 */
export function emptyUnlockMethodsRegistry(): UnlockMethodsRecord {
  return {
    version: 1,
    webAuthnUserId: base64urlnopad.encode(
      crypto.getRandomValues(new Uint8Array(16))
    ),
    methods: []
  }
}

/**
 * Loads the account's unlock-methods registry, or `null` when none has been
 * written yet. When a WAS server is configured the remote copy in the data
 * Space is the source of truth: it is read first, refreshes the local cache on
 * a hit, and drops the cache on a 404-shaped miss. A remote read failure
 * rethrows. With no WAS server the cache is the only copy.
 *
 * A served record that does not decrypt under this session's vault keys is a
 * stale seal, not a missing registry: it throws
 * `UnlockRegistryStaleSealError` rather than resolving `null`, so no caller
 * can mistake it for "no methods registered" and clobber the record. Every
 * other refusal (a frame or version mismatch) rethrows unchanged -- a
 * version bump is not a seal problem.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.capability] {IZcap}   an invocation capability the record
 *   GET rides (a transient session's generation delegation, which is the only
 *   authority that session has); the root capability is invoked otherwise
 * @returns {Promise<UnlockMethodsRecord | null>}
 * @throws {UnlockRegistryStaleSealError}
 */
export async function getUnlockMethods({
  session,
  capability
}: {
  session: Session
  capability?: IZcap
}): Promise<UnlockMethodsRecord | null> {
  const controller = session.user.id
  const { unlockMethodsCache } = session.profile.persistence
  const { keyAgreementKey, keyResolver } = requireVaultKeys(session)

  if (!WAS_SERVER_URL) {
    const cached = await unlockMethodsCache.load({ controller })
    if (!cached) {
      return null
    }
    try {
      return await unwrapRecord({
        record: cached,
        keyAgreementKey,
        keyResolver
      })
    } catch (err) {
      log.warn('Discarding an unusable cached unlock-methods record', { err })
      await unlockMethodsCache.delete({ controller })
      return null
    }
  }

  const stored = await getUnlockMethodsRecord({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: session.profile.zcapClient,
    spaceId: requireSpaceId(session),
    ...(capability ? { capability } : {})
  })
  if (!stored) {
    await unlockMethodsCache.delete({ controller })
    return null
  }
  let parsed: UnlockMethodsRecord
  try {
    parsed = await unwrapRecord({
      record: stored.record,
      keyAgreementKey,
      keyResolver
    })
  } catch (err) {
    if (err instanceof RecordEnvelopeDecryptError) {
      throw new UnlockRegistryStaleSealError({ cause: err })
    }
    throw err
  }
  await unlockMethodsCache.save({ controller, record: stored.record })
  return parsed
}

/**
 * The registry's bounded compare-and-swap attempts, matching the roster's
 * recipient loop and the account-log publish retry.
 */
const MAX_CAS_ATTEMPTS = 3

/**
 * Whether `err` is the compare-and-swap conflict a conditional registry PUT
 * raises (`PreconditionFailedError`, 412). Matched by `name` as well as
 * `instanceof`: in a dependency tree that resolves was-client twice the class
 * object differs, and an `instanceof`-only check would turn every lost race
 * into a hard failure instead of a rebase.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isPreconditionFailed(err: unknown): boolean {
  return (
    err instanceof PreconditionFailedError ||
    (err instanceof Error && err.name === 'PreconditionFailedError')
  )
}

/**
 * The one read-modify-write loop every registry write runs: a fresh read
 * (stored envelope plus ETag), `mutate` over the freshly unwrapped record,
 * and a conditional PUT -- `If-Match` on the read's ETag, or `If-None-Match`
 * when the read found nothing (the create-if-absent first materialization). A
 * lost race (412) re-enters the loop with a fresh read, up to
 * {@link MAX_CAS_ATTEMPTS}; exhaustion rethrows the conflict. A read that
 * served a record with no ETag refuses the unconditional overwrite outright
 * rather than degrading to last-write-wins (defensive only: the WAS server
 * always serves ETags).
 *
 * @param options {object}
 * @param options.read {Function}   fresh read of the stored envelope + ETag
 * @param options.write {Function}   conditional PUT of a wrapped envelope
 * @param options.unwrap {Function}   stored envelope to registry record
 * @param options.wrap {Function}   registry record to stored envelope
 * @param options.mutate {Function}   fresh record (or null) to the next
 *   record, or null for "no write needed"
 * @param [options.onUnchanged] {Function}   called with the stored envelope
 *   (or null) when mutate declined the write
 * @param [options.onWritten] {Function}   called with the wrapped envelope
 *   after a landed write
 * @returns {Promise<UnlockMethodsRecord | null>}   the written record, or the
 *   current one when mutate declined (null when none exists)
 */
async function casUpdateRegistryRecord({
  read,
  write,
  unwrap,
  wrap,
  mutate,
  onUnchanged,
  onWritten
}: {
  read: () => Promise<{ record: unknown; etag?: string } | null>
  write: (
    record: object,
    precondition: { ifMatch?: string; ifNoneMatch?: boolean }
  ) => Promise<void>
  unwrap: (stored: unknown) => Promise<UnlockMethodsRecord>
  wrap: (record: UnlockMethodsRecord) => Promise<object>
  mutate: (
    current: UnlockMethodsRecord | null
  ) => UnlockMethodsRecord | null | Promise<UnlockMethodsRecord | null>
  onUnchanged?: (stored: { record: unknown } | null) => Promise<void>
  onWritten?: (wrapped: object) => Promise<void>
}): Promise<UnlockMethodsRecord | null> {
  let lastError: unknown
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
    const stored = await read()
    const current = stored ? await unwrap(stored.record) : null
    const next = await mutate(current)
    if (next === null) {
      await onUnchanged?.(stored)
      return current
    }
    if (stored && stored.etag === undefined) {
      throw new Error(
        'The unlock-methods registry read carried no ETag; refusing an ' +
          'unconditional overwrite.'
      )
    }
    const wrapped = await wrap(next)
    try {
      await write(
        wrapped,
        stored ? { ifMatch: stored.etag } : { ifNoneMatch: true }
      )
    } catch (err) {
      if (isPreconditionFailed(err)) {
        // Another writer landed first: re-read and re-apply on the fresh
        // base.
        lastError = err
        continue
      }
      throw err
    }
    await onWritten?.(wrapped)
    return next
  }
  throw new PreconditionFailedError(
    'The unlock-methods registry write lost the compare-and-swap race ' +
      `after ${MAX_CAS_ATTEMPTS} attempts (another writer kept updating ` +
      'the record). Retry the operation.',
    { cause: lastError as Error }
  )
}

/**
 * The account registry's one write path: applies `mutate` to a FRESH read of
 * the unlock-methods registry and writes the result back as a compare-and-swap
 * on that read's ETag, retrying on a lost race (`casUpdateRegistryRecord`).
 * `mutate` receives the freshly unwrapped record (or `null` when none exists
 * yet) and returns the record to store, or `null` for "no write needed"; it
 * may run more than once, so a caller expresses an intent computed beforehand
 * (upsert this entry, drop that one) rather than reusing a stale page-held
 * record as the base. Wraps under the vault KAK, ensures the `unlock-methods`
 * collection exists before the first PUT, and refreshes the local cache the
 * way a read does: saved after a landed write (or a declined one over an
 * existing record), dropped on a true absent. With no WAS server the local
 * cache is the only copy and the loop is one read-modify-write over it.
 *
 * A served record that does not decrypt under this session's vault keys
 * throws `UnlockRegistryStaleSealError`, the same stale-seal refusal the read
 * path makes -- no mutate may run over a record this session cannot read.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.mutate {Function}   fresh record (or null) to the next
 *   record, or null for "no write needed"
 * @returns {Promise<UnlockMethodsRecord | null>}   the written record, or the
 *   current one when mutate declined (null when none exists)
 * @throws {UnlockRegistryStaleSealError}
 */
export async function updateUnlockMethods({
  session,
  mutate
}: {
  session: Session
  mutate: (
    current: UnlockMethodsRecord | null
  ) => UnlockMethodsRecord | null | Promise<UnlockMethodsRecord | null>
}): Promise<UnlockMethodsRecord | null> {
  const controller = session.user.id
  const { unlockMethodsCache } = session.profile.persistence
  const { keyAgreementKey, keyResolver } = requireVaultKeys(session)

  if (!WAS_SERVER_URL) {
    const cached = await unlockMethodsCache.load({ controller })
    let current: UnlockMethodsRecord | null = null
    if (cached) {
      try {
        current = await unwrapRecord({
          record: cached,
          keyAgreementKey,
          keyResolver
        })
      } catch (err) {
        log.warn('Discarding an unusable cached unlock-methods record', {
          err
        })
        await unlockMethodsCache.delete({ controller })
      }
    }
    const next = await mutate(current)
    if (next === null) {
      return current
    }
    const wrapped = await wrapRecord({
      record: next,
      keyAgreementKey,
      keyResolver
    })
    await unlockMethodsCache.save({ controller, record: wrapped })
    return next
  }

  const storageServerUrl = WAS_SERVER_URL
  const zcapClient = session.profile.zcapClient
  const spaceId = requireSpaceId(session)
  let ensured = false
  return await casUpdateRegistryRecord({
    read: () =>
      getUnlockMethodsRecord({ storageServerUrl, zcapClient, spaceId }),
    unwrap: async stored => {
      try {
        return await unwrapRecord({
          record: stored,
          keyAgreementKey,
          keyResolver
        })
      } catch (err) {
        if (err instanceof RecordEnvelopeDecryptError) {
          throw new UnlockRegistryStaleSealError({ cause: err })
        }
        throw err
      }
    },
    wrap: record => wrapRecord({ record, keyAgreementKey, keyResolver }),
    write: async (record, precondition) => {
      if (!ensured) {
        await ensureUnlockMethodsCollection({
          storageServerUrl,
          zcapClient,
          spaceId
        })
        ensured = true
      }
      await putUnlockMethodsRecord({
        storageServerUrl,
        zcapClient,
        spaceId,
        record,
        ...precondition
      })
    },
    mutate,
    onUnchanged: async stored => {
      if (stored) {
        await unlockMethodsCache.save({ controller, record: stored.record })
      } else {
        await unlockMethodsCache.delete({ controller })
      }
    },
    onWritten: async wrapped => {
      await unlockMethodsCache.save({ controller, record: wrapped })
    }
  })
}

/**
 * The write wrapper's session-less flavor: the same compare-and-swap
 * read-modify-write loop with a caller-supplied signing client and user key.
 * The credential-anchored signup's registry write and the transient recovery
 * ceremony's registry update both run here, before any session exists. Reads
 * decrypt with `userKey`'s vault keys; when the written record must seal to a
 * rotated key instead (the recovery spend, whose base is still sealed to the
 * pre-rotation key), `writeUserKey` names it. No local cache is touched: the
 * callers are transient visits.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the client the collection ensure,
 *   the record GET, and the record PUT invoke with
 * @param options.spaceId {string}   the data Space id
 * @param options.userKey {UserKey}   the user key whose vault KAK the stored
 *   record is sealed to
 * @param [options.writeUserKey] {UserKey}   the user key the written record
 *   seals to; defaults to `userKey`
 * @param options.mutate {Function}   fresh record (or null) to the next
 *   record, or null for "no write needed"
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides (the transient recovery ceremony's generation delegation); the root
 *   capability is invoked otherwise
 * @returns {Promise<UnlockMethodsRecord | null>}   the written record, or the
 *   current one when mutate declined (null when none exists)
 */
export async function updateUnlockMethodsWithClient({
  zcapClient,
  spaceId,
  userKey,
  writeUserKey,
  mutate,
  capability
}: {
  zcapClient: ZcapClient
  spaceId: string
  userKey: UserKey
  writeUserKey?: UserKey
  mutate: (
    current: UnlockMethodsRecord | null
  ) => UnlockMethodsRecord | null | Promise<UnlockMethodsRecord | null>
  capability?: IZcap
}): Promise<UnlockMethodsRecord | null> {
  if (!WAS_SERVER_URL) {
    throw new TypeError(
      'The direct registry write requires a configured WAS server.'
    )
  }
  const storageServerUrl = WAS_SERVER_URL
  const readKeys = userKeyVaultKeys({ userKey })
  const writeKeys = writeUserKey
    ? userKeyVaultKeys({ userKey: writeUserKey })
    : readKeys
  let ensured = false
  return await casUpdateRegistryRecord({
    read: () =>
      getUnlockMethodsRecord({
        storageServerUrl,
        zcapClient,
        spaceId,
        ...(capability ? { capability } : {})
      }),
    unwrap: stored =>
      unwrapRecord({
        record: stored,
        keyAgreementKey: readKeys.keyAgreementKey,
        keyResolver: readKeys.keyResolver
      }),
    wrap: record =>
      wrapRecord({
        record,
        keyAgreementKey: writeKeys.keyAgreementKey,
        keyResolver: writeKeys.keyResolver
      }),
    write: async (record, precondition) => {
      if (!ensured) {
        await ensureUnlockMethodsCollection({
          storageServerUrl,
          zcapClient,
          spaceId,
          ...(capability ? { capability } : {})
        })
        ensured = true
      }
      await putUnlockMethodsRecord({
        storageServerUrl,
        zcapClient,
        spaceId,
        record,
        ...(capability ? { capability } : {}),
        ...precondition
      })
    },
    mutate
  })
}

/**
 * Reads the registry with a caller-supplied signing client and user key -- no
 * session involved, the read half of `updateUnlockMethodsWithClient`. The
 * transient recovery ceremony's registry update: it runs before any session
 * exists, decrypting the stored record with the PRE-rotation user key still in
 * hand. No local cache is consulted or touched: the caller is a transient
 * visit.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the client the record GET invokes
 *   with
 * @param options.spaceId {string}   the data Space id
 * @param options.userKey {UserKey}   the user key whose vault KAK the stored
 *   record is sealed to
 * @param [options.capability] {IZcap}   an invocation capability the request
 *   rides; the root capability is invoked otherwise
 * @returns {Promise<UnlockMethodsRecord | null>}
 */
export async function getUnlockMethodsWithClient({
  zcapClient,
  spaceId,
  userKey,
  capability
}: {
  zcapClient: ZcapClient
  spaceId: string
  userKey: UserKey
  capability?: IZcap
}): Promise<UnlockMethodsRecord | null> {
  if (!WAS_SERVER_URL) {
    throw new TypeError(
      'The direct registry read requires a configured WAS server.'
    )
  }
  const stored = await getUnlockMethodsRecord({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient,
    spaceId,
    ...(capability ? { capability } : {})
  })
  if (!stored) {
    return null
  }
  const { keyAgreementKey, keyResolver } = userKeyVaultKeys({ userKey })
  return await unwrapRecord({
    record: stored.record,
    keyAgreementKey,
    keyResolver
  })
}

/**
 * Re-seals the remote unlock-methods record from one set of vault keys to
 * another -- the user-key-rotation bridge. The stored record is a single-recipient
 * envelope to the vault KAK, so whichever client rotates the user key must re-wrap
 * the registry to the new one, or every later session (holding only the
 * rotated user key) meets an envelope it cannot decrypt and the registry is lost
 * for good. Reads the remote copy (the source of truth), decrypts with the
 * pre-rotation keys, re-encrypts to the post-rotation keys, and PUTs it back
 * as a compare-and-swap on the read's ETag, re-reading and re-wrapping on a
 * lost race -- so a concurrent registry write is never met with a stale
 * re-seal, and a concurrent re-seal is never downgraded (a fresh base no
 * longer sealed to `from` surfaces as `RecordEnvelopeDecryptError`, which
 * callers already treat as "not sealed to these keys"). A registry that does
 * not exist yet is a no-op. The local cache is left alone: with a WAS server
 * the remote copy is read first and refreshes the cache on the next hit.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   an enrolled client's root client
 * @param options.spaceId {string}   the data Space id
 * @param options.from {object}   the pre-rotation vault keys
 * @param options.from.keyAgreementKey {IKeyAgreementKey}
 * @param options.from.keyResolver {IKeyResolver}
 * @param options.to {object}   the post-rotation vault keys
 * @param options.to.keyAgreementKey {IKeyAgreementKey}
 * @param options.to.keyResolver {IKeyResolver}
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides (a transient session's generation delegation); the root capability
 *   is invoked otherwise
 * @returns {Promise<void>}
 */
export async function rewrapUnlockMethodsRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  from,
  to,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  from: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  to: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  capability?: IZcap
}): Promise<void> {
  let lastError: unknown
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
    const stored = await getUnlockMethodsRecord({
      storageServerUrl,
      zcapClient,
      spaceId,
      ...(capability ? { capability } : {})
    })
    if (!stored) {
      return
    }
    if (stored.etag === undefined) {
      throw new Error(
        'The unlock-methods registry read carried no ETag; refusing an ' +
          'unconditional overwrite.'
      )
    }
    const record = await unwrapRecord({
      record: stored.record,
      keyAgreementKey: from.keyAgreementKey,
      keyResolver: from.keyResolver
    })
    const wrapped = await wrapRecord({
      record,
      keyAgreementKey: to.keyAgreementKey,
      keyResolver: to.keyResolver
    })
    try {
      await putUnlockMethodsRecord({
        storageServerUrl,
        zcapClient,
        spaceId,
        record: wrapped,
        ...(capability ? { capability } : {}),
        ifMatch: stored.etag
      })
      return
    } catch (err) {
      if (isPreconditionFailed(err)) {
        // Another writer landed first: re-read and re-seal the fresh base.
        lastError = err
        continue
      }
      throw err
    }
  }
  throw new PreconditionFailedError(
    'The unlock-methods registry re-seal lost the compare-and-swap race ' +
      `after ${MAX_CAS_ATTEMPTS} attempts (another writer kept updating ` +
      'the record). Retry the operation.',
    { cause: lastError as Error }
  )
}

/**
 * Resolves the data Space id from the session's storage, throwing when absent
 * (a WAS server is configured but the session has no remote store -- e.g. a
 * guest, which never reaches this registry).
 *
 * @param session {Session}
 * @returns {string}
 */
function requireSpaceId(session: Session): string {
  const spaceId = session.storage.spaceId
  if (!spaceId) {
    throw new Error('No remote data Space is available for unlock methods.')
  }
  return spaceId
}

/**
 * Whether a registry entry names a given unlock method: a passkey entry matches
 * on `credentialId`, a recovery-code entry on `recoveryKid`, a passphrase
 * entry on its type (there is only ever one passphrase entry). Used to drop
 * the retired entry from the methods list.
 *
 * @param candidate {UnlockMethod}   an entry in the stored registry
 * @param target {UnlockMethod}   the entry being removed
 * @returns {boolean}
 */
function isSameMethod(candidate: UnlockMethod, target: UnlockMethod): boolean {
  if (target.type === 'passkey') {
    return (
      candidate.type === 'passkey' &&
      candidate.credentialId === target.credentialId
    )
  }
  if (target.type === 'recovery-code') {
    return (
      candidate.type === 'recovery-code' &&
      candidate.recoveryKid === target.recoveryKid
    )
  }
  return candidate.type === target.type
}

/**
 * Reloads the registry, drops the given entry, and writes the result. Shared
 * by both revocation paths -- the Space and keyring cache are already gone by
 * the time this runs, so a missing registry is simply a no-op.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {UnlockMethod}   the entry to remove
 * @returns {Promise<void>}
 */
async function dropRegistryEntry({
  session,
  entry
}: {
  session: Session
  entry: UnlockMethod
}): Promise<void> {
  await updateUnlockMethods({
    session,
    mutate: current => {
      if (!current) {
        return null
      }
      const methods = current.methods.filter(
        method => !isSameMethod(method, entry)
      )
      if (methods.length === current.methods.length) {
        return null
      }
      return { ...current, methods }
    }
  })
}

/**
 * Whether an unlock method can be revoked without a WebAuthn ceremony: always
 * true with no WAS server (there is no Space to delete -- only the keyring cache
 * and the registry entry are cleared), otherwise only when the entry carries a
 * management zcap the session's root key can invoke to delete its unlock Space.
 *
 * @param entry {UnlockMethod}
 * @returns {boolean}
 */
export function canRevokeWithoutCeremony(entry: UnlockMethod): boolean {
  return !WAS_SERVER_URL || !!entry.manageCapability
}

/**
 * Picks the signer for a management-zcap invocation by the capability's own
 * `controller`: a grant delegated to this client's bare did:key (the
 * unpromoted single-client account, and every entry minted before grants
 * moved to the account did:webvh) signs under the did:key keyId; anything
 * else signs with the session's root zcapClient, which on a promoted account
 * signs under this client's `<did:webvh>#<multibase>` verification method --
 * the form the current-key-set rule authorizes for every enrolled client.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.capability {IZcap}   the management zcap being invoked
 * @returns {ZcapClient}
 */
export function managementZcapClient({
  session,
  capability
}: {
  session: Session
  capability: IZcap
}): ZcapClient {
  const { keyAgent } = session.profile
  const controller = (capability as { controller?: string }).controller
  return keyAgent && controller === keyAgent.id
    ? didKeyZcapClient({ keyAgent })
    : session.profile.zcapClient
}

/**
 * What one unlock Space's deletion did, so a best-effort walk can name what it
 * left standing instead of failing or skipping in silence:
 *
 * - `deleted` -- the server accepted the DELETE.
 * - `not-found` -- the server answered 404, which is absent OR unauthorized
 *   (it masks the two), so this is never proof the Space is gone.
 * - `no-server` -- no WAS server is configured, so there is no Space at all.
 * - `no-capability` -- the entry records no management zcap, or one naming no
 *   delegatee. Nothing can be minted from it and the Space stays; that
 *   credential's own next login re-delegates.
 * - `expired-capability` -- the recorded management zcap has already expired,
 *   so a child of it would verify nowhere. Same residue, same mender.
 * - `foreign-controller` -- the recorded management zcap names a delegatee
 *   this session's signer cannot act as (an entry bound before promotion
 *   names the account did:key, and a later enrolled client signs as the
 *   account did:webvh). Same residue, same mender.
 * - `stale-target` -- the recorded management zcap names a Space URL other
 *   than the one this deployment addresses (an entry minted before the target
 *   was built with was-client's path helpers carries a root-anchored URL on a
 *   sub-path deployment). Same residue, same mender.
 * - `unsupported-capability` -- the recorded management zcap's `allowedAction`
 *   does not carry the verb the caller asked for, so a child of it would
 *   verify nowhere. Same residue, same mender.
 *
 * The last five are refused locally, before anything is minted or sent. A
 * child the server would refuse comes back as a 404 like an absent Space,
 * and a walk reading that as `not-found` would drop the entry and its local
 * state around a Space that in fact still stands.
 */
export type UnlockSpaceDeletionOutcome =
  | 'deleted'
  | 'not-found'
  | 'no-server'
  | 'no-capability'
  | 'expired-capability'
  | 'foreign-controller'
  | 'stale-target'
  | 'unsupported-capability'

/**
 * The identities this session's own management-zcap signer can act as: this
 * client's did:key (which `managementZcapClient` signs under directly), and
 * the account's did:webvh when the pointer names one (which the session's
 * root zcapClient signs under as `<did:webvh>#<multibase>`). A stored parent
 * naming anything else cannot be delegated from here.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Set<string>}
 */
function sessionDelegatorIdentities({
  session
}: {
  session: Session
}): Set<string> {
  const { keyAgent, accountPointer } = session.profile
  const identities = new Set<string>()
  if (keyAgent?.id) {
    identities.add(keyAgent.id)
  }
  if (accountPointer?.did?.startsWith('did:webvh:')) {
    identities.add(accountPointer.did)
  }
  return identities
}

/**
 * The read-only pre-flight of an unlock Space deletion: the caller-side
 * preconditions `mintSpaceVerbCapability` leaves to its caller, checked
 * before anything is minted or any credential is retired. Returns the residue
 * outcome that refuses the delete, or `undefined` when the recorded
 * capability is usable.
 *
 * The delegator check is skipped when the caller supplies its own signer: it
 * states the identity it acts as, which this module cannot second-guess.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {UnlockMethod}
 * @param [options.signer] {object}   an explicit delegator, invoker and
 *   delegatee
 * @param options.signer.zcapClient {ZcapClient}
 * @param [options.signer.invoker] {ZcapClient}
 * @param options.signer.controller {string}
 * @param [options.verb] {string}   the verb the child would carry; defaults
 *   to `DELETE`, the deletion walk's own. A discovery probe asks for `GET`,
 *   and a parent that does not allow it is unprobeable rather than
 *   undeletable
 * @returns {UnlockSpaceDeletionOutcome | undefined}
 */
export function unlockSpaceDeletionRefusal({
  session,
  entry,
  signer,
  verb = 'DELETE'
}: {
  session: Session
  entry: UnlockMethod
  signer?: { zcapClient: ZcapClient; invoker?: ZcapClient; controller: string }
  verb?: 'GET' | 'PUT' | 'DELETE'
}): UnlockSpaceDeletionOutcome | undefined {
  const parent = entry.manageCapability as
    | {
        controller?: string
        invocationTarget?: string
        expires?: string
        allowedAction?: string | string[]
      }
    | undefined
  if (!parent?.controller || !parent.invocationTarget) {
    return 'no-capability'
  }
  const expires = Date.parse(parent.expires ?? '')
  if (!Number.isNaN(expires) && expires <= Date.now()) {
    return 'expired-capability'
  }
  if (
    !signer &&
    !sessionDelegatorIdentities({ session }).has(parent.controller)
  ) {
    return 'foreign-controller'
  }
  const target = toUrl({
    serverUrl: WAS_SERVER_URL as string,
    path: spacePath(entry.unlockSpaceId)
  })
  if (parent.invocationTarget !== target) {
    return 'stale-target'
  }
  // The verb check `mintSpaceVerbCapability` makes as a throw, made here as a
  // reported outcome: an absent `allowedAction` delegates every action.
  const allowed = parent.allowedAction
  if (allowed !== undefined) {
    const actions = Array.isArray(allowed) ? allowed : [allowed]
    if (actions.length > 0 && !actions.includes(verb)) {
      return 'unsupported-capability'
    }
  }
  return undefined
}

/**
 * Deletes one unlock Space through a freshly minted DELETE-only child of the
 * entry's management zcap, rather than by invoking that three-verb capability
 * directly. The storage server admits a delegated Space DELETE only when the
 * capability's `invocationTarget` is exactly the Space URL and its
 * `allowedAction` is exactly `['DELETE']`, so the stored GET/PUT/DELETE
 * capability is a parent to delegate from, never a capability to invoke. The
 * child's target is the parent's own bytes, its lifetime the deletion TTL
 * clamped to the parent's `expires`, and nothing stores it: it is minted
 * immediately before its one request and dropped, so a torn run owes no
 * revocation.
 *
 * The delegatee is the delegator itself -- the account DID the parent already
 * names -- unless the caller supplies its own signer, which is how a session
 * with no enrolled-client key (the ladder VM's bare did:key) deletes.
 *
 * Delegating and invoking are two different keys there, and mixing them is a
 * masked 404: the child's parent must be signed by the parent's own
 * controller (the ladder VM under `<accountDid>#<multibase>`), while the
 * child's own DELETE must be sent by the child's controller -- the ladder
 * VM's bare did:key, which carries no `capabilityInvocation` relation in the
 * account document and so can delegate but never invoke under its account
 * form. The caller's `invoker` is that sender; absent, the delegator sends
 * its own child, which is the remembered session's management-zcap path.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {UnlockMethod}   the method whose Space to delete
 * @param [options.signer] {object}   an explicit delegator, invoker and
 *   delegatee, for a caller not signing as an enrolled client
 * @param options.signer.zcapClient {ZcapClient}   the delegating signer
 * @param [options.signer.invoker] {ZcapClient}   the client that sends the
 *   DELETE; defaults to the delegating signer
 * @param options.signer.controller {string}
 * @returns {Promise<UnlockSpaceDeletionOutcome>}
 */
export async function deleteUnlockSpaceForEntry({
  session,
  entry,
  signer
}: {
  session: Session
  entry: UnlockMethod
  signer?: { zcapClient: ZcapClient; invoker?: ZcapClient; controller: string }
}): Promise<UnlockSpaceDeletionOutcome> {
  if (!WAS_SERVER_URL) {
    return 'no-server'
  }
  const refusal = unlockSpaceDeletionRefusal({
    session,
    entry,
    ...(signer ? { signer } : {})
  })
  if (refusal) {
    return refusal
  }
  const parent = entry.manageCapability as IZcap
  const controller =
    signer?.controller ?? (parent as { controller?: string }).controller
  const delegator =
    signer?.zcapClient ?? managementZcapClient({ session, capability: parent })
  // The child's own controller sends it; the delegator only signs it.
  const invoker = signer?.invoker ?? delegator
  let capability
  try {
    capability = await mintSpaceVerbCapability({
      zcapClient: delegator,
      parent,
      verb: 'DELETE',
      controller: controller as string,
      ttlMs: DELETION_ZCAP_TTL_MS
    })
  } catch (err) {
    // Matched by name: the refusal is raised in wallet-core, whose class this
    // module's copy need not be identical to.
    if ((err as Error).name === 'ExpiredParentCapabilityError') {
      return 'expired-capability'
    }
    throw err
  }
  const { outcome } = await deleteUnlockSpaceWithCapability({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: invoker,
    spaceId: entry.unlockSpaceId,
    capability
  })
  return outcome
}

/**
 * Revokes an unlock method tap-free: deletes its unlock Space with the entry's
 * management zcap (invoked by the session's ROOT zcapClient), drops the local
 * keyring cache for that Space, then removes the entry from the registry. This
 * is the path for a LOST passkey -- no ceremony on the authenticator being
 * removed. With a WAS server configured it requires a usable
 * `entry.manageCapability` (callers gate on `canRevokeWithoutCeremony`
 * first), checked read-only BEFORE the retirement below so a refusal leaves
 * the credential standing and the entry removable; a 404 from the Space
 * delete is tolerated (already gone). With no WAS server there is no Space to
 * delete, so only the cache and the registry entry are cleaned up.
 *
 * A standing passphrase or passkey entry is first retired for real by the
 * credential-rotation ceremony, whose outcome is handed back so the caller
 * can adopt the rotated user key in the live session.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {UnlockMethod}   the method to retire
 * @param [options.idb] {IDBFactory}
 * @param [options.verb] {string}   what the caller is doing, for the
 *   rotation's pending-rotation refusal message
 * @returns {Promise<CredentialRotationOutcome | null>}   the rotation
 *   outcome, or null when nothing standing was retired
 * @throws {UnclaimedLadderVmRetirementError}   the credential's ladder VM
 *   cannot be claimed, so the retirement refused before publishing anything.
 *   It propagates: the Space delete, the local state and the registry entry
 *   below all stay, so the entry is still removable once the refusal is
 *   answered
 */
export async function revokeUnlockMethod({
  session,
  entry,
  idb,
  verb = 'removing an unlock method'
}: {
  session: Session
  entry: UnlockMethod
  idb?: IDBFactory
  verb?: string
}): Promise<CredentialRotationOutcome | null> {
  // The read-only pre-flight, BEFORE the rotation below: a capability this
  // session cannot delegate a usable child from refuses the whole revocation
  // with the credential still standing, so the "tap the passkey being
  // removed" fallback the copy names is still available and a retry still
  // finds a removable entry. Refusing after the retirement would leave an
  // entry nothing can remove.
  if (WAS_SERVER_URL) {
    const refusal = unlockSpaceDeletionRefusal({ session, entry })
    if (refusal) {
      throw new Error(
        `This unlock method's management capability is unusable from this ` +
          `session (${refusal}); it can only be revoked by tapping the ` +
          'passkey being removed.'
      )
    }
  }
  // A standing passphrase or passkey is retired for real: its document
  // inventory out, the user key rotated off its roster wrap, every encrypted
  // collection re-epoch'd. Run BEFORE the Space delete and the registry drop
  // below, which then go out under the ROTATED vault keys: the retirement
  // adopts the fresh key in band (re-sealing the stored record to it and
  // swapping the live session onto it), so the drop reads and re-seals under
  // one key. A recovery-code entry has already rotated in its own ceremony.
  const rotation =
    entry.type === 'passphrase' || entry.type === 'passkey'
      ? await rotateOffUnlockCredential({ session, method: entry, verb })
      : null
  if (WAS_SERVER_URL) {
    const outcome = await deleteUnlockSpaceForEntry({ session, entry })
    if (outcome === 'not-found') {
      // Already gone, or this capability no longer authorizes the delete --
      // the server masks the two as one 404. Retiring the method is
      // idempotent either way, and the local state and registry entry below
      // are what the caller is really after.
      log.info('The unlock Space was already gone (or unreachable)', {
        unlockSpaceId: entry.unlockSpaceId
      })
    }
  }
  // Retiring the method also retires this client's local records under it:
  // the keyring cache and the client-key wrap (other methods keep their own
  // wraps of the same key set). Both go straight to the session database:
  // they exist only on a remembered browser, and this path is reached only
  // from remembered-session ceremonies.
  await deleteUnlockLocalState({ spaceId: entry.unlockSpaceId, idb })
  await dropRegistryEntry({ session, entry })
  return rotation
}

/**
 * Deletes one unlock method's unlock SPACE, ceremony-free -- the
 * account-deletion walk's per-entry unit. The Space holds that method's
 * unlock record, and with it the sealed bridge and `delegatedClients`
 * delegations, and it goes through a DELETE-only child of the recorded
 * management zcap; an entry recording none, or one whose recorded capability
 * has expired or does not allow the verb, keeps its Space and says so on the
 * returned outcome -- the account behind the record is dead either way.
 *
 * The REMOTE half only. That method's browser-local state (its keyring cache
 * and client-key record) is left for the caller's own local-wipe stage, which
 * runs past the pivot: these DELETEs run before it, so a run that refuses at
 * the account Space must leave this browser exactly as it found it rather
 * than having quietly un-remembered every other credential on it.
 * Deliberately NO rotation and NO registry rewrite either: the registry and
 * the roster die with the account Space the caller is about to wipe.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {UnlockMethod}
 * @param [options.signer] {object}   an explicit delegator, invoker and
 *   delegatee for the DELETE-only child, for a caller not signing as an
 *   enrolled client
 * @param options.signer.zcapClient {ZcapClient}
 * @param [options.signer.invoker] {ZcapClient}
 * @param options.signer.controller {string}
 * @returns {Promise<{ unlockSpaceId: string, space: UnlockSpaceDeletionOutcome }>}
 *   what became of the entry's unlock Space
 */
export async function deleteUnlockMethodSpace({
  session,
  entry,
  signer
}: {
  session: Session
  entry: UnlockMethod
  signer?: { zcapClient: ZcapClient; invoker?: ZcapClient; controller: string }
}): Promise<{ unlockSpaceId: string; space: UnlockSpaceDeletionOutcome }> {
  const space = await deleteUnlockSpaceForEntry({
    session,
    entry,
    ...(signer ? { signer } : {})
  })
  if (
    space === 'no-capability' ||
    space === 'expired-capability' ||
    space === 'unsupported-capability'
  ) {
    // Not a refusal and not a silent skip: the Space survives the run and is
    // named on the outcome, mended by that credential's own next login (which
    // re-delegates the management zcap) or by its next use once the account
    // behind it is gone.
    log.warn('An unlock method keeps its Space: no usable management zcap', {
      methodType: entry.type,
      unlockSpaceId: entry.unlockSpaceId,
      reason: space
    })
  }
  return { unlockSpaceId: entry.unlockSpaceId, space }
}

/**
 * Revokes a passkey unlock method by ceremony -- the fallback for an entry that
 * carries no management zcap (bound before the capability existed). Asserts the
 * passkey being removed (its PRF output derives the unlock identity), deletes
 * that method's keyring (its unlock Space + cache), then drops the registry
 * entry. Requires the authenticator, so it is unusable for a genuinely lost
 * passkey -- `revokeUnlockMethod` covers that case.
 *
 * The tap comes first: it is the consent and authentication gate for the
 * whole ceremony, including the credential rotation that follows it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {PasskeyUnlockMethod}   the passkey to retire
 * @param [options.idb] {IDBFactory}
 * @param [options.signal] {AbortSignal}   aborts the WebAuthn ceremony
 * @param [options.verb] {string}   what the caller is doing, for the
 *   rotation's pending-rotation refusal message
 * @returns {Promise<CredentialRotationOutcome | null>}   the rotation
 *   outcome, or null when nothing standing was retired
 * @throws {UnclaimedLadderVmRetirementError}   the credential's ladder VM
 *   cannot be claimed; nothing was written
 */
export async function revokeUnlockMethodByCeremony({
  session,
  entry,
  idb,
  signal,
  verb = 'removing a passkey'
}: {
  session: Session
  entry: PasskeyUnlockMethod
  idb?: IDBFactory
  signal?: AbortSignal
  verb?: string
}): Promise<CredentialRotationOutcome | null> {
  const { prfOutput } = await assertPasskeyPrf({
    credentialIds: [base64urlnopad.decode(entry.credentialId)],
    signal
  })
  // The tap put the credential's secret in hand: derive it once (shared with
  // the Space deletion below) and read its record's ladder seed, so the
  // retirement's ladder attribution holds every rung a priori. Best-effort --
  // an unreadable record leaves the log-walk attribution.
  const credential = await deriveUnlockCredential({
    secret: prfOutput,
    kdf: PASSKEY_KDF
  })
  const ladderSeed = await standingLadderSeed({
    credential,
    controller: session.profile.accountController ?? session.user.id,
    idb
  })
  const method = { ...entry, ...(ladderSeed ? { ladderSeed } : {}) }
  // The retirement gate, read-only and before the first write: a credential
  // whose ladder VM the attribution cannot claim refuses here, with the
  // passkey still standing and its entry still removable, rather than after
  // the removal has begun. The tap put the seed in hand, so this pre-flight
  // asks exactly what the retirement below will.
  await preflightCredentialRetirement({ session, method })
  const rotation = await rotateOffUnlockCredential({
    session,
    method,
    verb
  })
  await deleteUnlockMethod({
    secret: prfOutput,
    kdf: PASSKEY_KDF,
    idb,
    credential
  })
  await dropRegistryEntry({ session, entry })
  return rotation
}

/**
 * Upserts the registry's single passphrase entry, preserving the existing
 * entry's creation date and leaving every other method untouched. Pure -- the
 * caller writes the returned record.
 *
 * `keepAbsentManageCapability` is the one behavioural fork between the two
 * callers: the login-time backfill omits the key entirely when no capability
 * is in hand (never storing `manageCapability: undefined`), while the
 * passphrase-change repoint sets it unconditionally, so a change that minted
 * no capability CLEARS the stale one the old unlock Space's entry carried.
 *
 * @param options {object}
 * @param options.record {UnlockMethodsRecord}   the registry to update
 * @param options.unlockSpaceId {string}   the passphrase's unlock Space
 * @param [options.manageCapability] {IZcap}
 * @param [options.keepAbsentManageCapability] {boolean}   write the
 *   `manageCapability` key even when there is none; default false
 * @param [options.standing] {StandingUnlockFields}   the standing-configuration
 *   fields recorded by the establishment ceremony; when absent, an existing
 *   entry's standing fields are carried forward (a backfill must not erase
 *   them)
 * @returns {UnlockMethodsRecord}   the updated registry
 */
export function upsertPassphraseUnlockMethod({
  record,
  unlockSpaceId,
  manageCapability,
  keepAbsentManageCapability = false,
  standing
}: {
  record: UnlockMethodsRecord
  unlockSpaceId: string
  manageCapability?: IZcap
  keepAbsentManageCapability?: boolean
  standing?: StandingUnlockFields
}): UnlockMethodsRecord {
  const existing = record.methods.find(
    (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
  )
  // Carry an existing entry's standing fields forward unless the caller
  // supplies fresh ones -- but only while the entry still names the same
  // unlock Space (a passphrase change retires the old credential's standing configuration
  // wholesale).
  let carried: StandingUnlockFields | undefined = standing
  if (!carried && existing && existing.unlockSpaceId === unlockSpaceId) {
    // Everything the entry holds beside its non-standing members IS its
    // standing configuration, so the rest carries forward without restating the
    // interface here (a field added to `StandingUnlockFields` is carried
    // with no edit at this site).
    const {
      type: _type,
      createdAt: _createdAt,
      unlockSpaceId: _spaceId,
      manageCapability: _manageCapability,
      ...standingMembers
    } = existing
    carried = standingMembers
  }
  const entry: PassphraseUnlockMethod = {
    type: 'passphrase',
    createdAt: existing?.createdAt ?? new Date().toISOString(),
    unlockSpaceId,
    ...(manageCapability || keepAbsentManageCapability
      ? { manageCapability }
      : {}),
    ...(carried ?? {})
  }
  const methods = existing
    ? record.methods.map(method =>
        method.type === 'passphrase' ? entry : method
      )
    : [...record.methods, entry]
  return { ...record, methods }
}

/**
 * Upserts a passkey entry into the registry, matched on its `credentialId`:
 * an entry for the same authenticator credential is replaced in place, and a
 * new one is appended. Everything else in the record -- the user handle and
 * the other entries -- is carried forward untouched, which is what lets a
 * re-run mint (the passkey signup's) land on an existing registry without
 * clobbering it.
 *
 * @param options {object}
 * @param options.record {UnlockMethodsRecord}   the registry to update
 * @param options.entry {PasskeyUnlockMethod}   the passkey entry
 * @returns {UnlockMethodsRecord}   the updated registry
 */
export function upsertPasskeyUnlockMethod({
  record,
  entry
}: {
  record: UnlockMethodsRecord
  entry: PasskeyUnlockMethod
}): UnlockMethodsRecord {
  const exists = record.methods.some(method => isSameMethod(method, entry))
  const methods = exists
    ? record.methods.map(method =>
        isSameMethod(method, entry) ? entry : method
      )
    : [...record.methods, entry]
  return { ...record, methods }
}

/**
 * The zcap's `allowedAction` set as a string array, or `null` for a
 * capability carrying no `allowedAction` at all -- which permits every action
 * and so is wider than any concrete set. A zcap carries the member as a bare
 * string or an array (ezcap accepts both).
 *
 * @param [zcap] {IZcap}
 * @returns {string[] | null}
 */
function zcapActionsOf(zcap?: IZcap): string[] | null {
  const allowedAction = (zcap as { allowedAction?: unknown } | undefined)
    ?.allowedAction
  if (Array.isArray(allowedAction)) {
    return allowedAction.filter(
      (action): action is string => typeof action === 'string'
    )
  }
  return typeof allowedAction === 'string' ? [allowedAction] : null
}

/**
 * Whether a freshly minted management zcap covers a stored one's action set.
 * The refresh exists to push a later expiry, never to narrow authority -- a
 * stored standing capability carries PUT (the record re-mint the revocation
 * cascade runs needs it). An unrestricted capability is covered only by
 * another unrestricted one.
 *
 * @param options {object}
 * @param options.stored {IZcap}   the registry's current capability
 * @param options.fresh {IZcap}   the login-minted replacement
 * @returns {boolean}
 */
function capabilityCoversStored({
  stored,
  fresh
}: {
  stored: IZcap
  fresh: IZcap
}): boolean {
  const storedActions = zcapActionsOf(stored)
  const freshActions = zcapActionsOf(fresh)
  if (freshActions === null) {
    return true
  }
  if (storedActions === null) {
    return false
  }
  return storedActions.every(action => freshActions.includes(action))
}

/**
 * Whether a freshly minted management zcap strictly widens a stored one:
 * it covers the stored action set and adds at least one action. A widening
 * mint is written even when the stored capability is nowhere near expiry,
 * which is what heals an entry a past login narrowed (the login mint once
 * dropped PUT from a standing record's capability) without waiting a year
 * for its renewal window.
 *
 * @param options {object}
 * @param options.stored {IZcap}   the registry's current capability
 * @param options.fresh {IZcap}   the login-minted replacement
 * @returns {boolean}
 */
function capabilityWidensStored({
  stored,
  fresh
}: {
  stored: IZcap
  fresh: IZcap
}): boolean {
  if (!capabilityCoversStored({ stored, fresh })) {
    return false
  }
  const storedActions = zcapActionsOf(stored)
  const freshActions = zcapActionsOf(fresh)
  if (storedActions === null) {
    return false
  }
  return (
    freshActions === null ||
    freshActions.some(action => !storedActions.includes(action))
  )
}

/**
 * Whether the registry may adopt a fresh management zcap over a stored one.
 * A stored capability that is not expiring is replaced only by a mint that
 * covers its actions (a widening one, in practice). An expiring or expired
 * stored capability is replaced regardless -- without the refresh the entry
 * would soon hold a dead capability, which loses DELETE beside PUT -- and a
 * replacement that narrows it is logged as an error, since no login can
 * re-widen what its own mint does not carry.
 *
 * A fresh capability naming a DIFFERENT `invocationTarget` is adopted
 * whatever its actions. The target is the deployment's own Space URL, so a
 * stored one that differs is unusable here (a root-anchored target minted
 * before the mint moved onto was-client's path helpers, on a sub-path
 * deployment); keeping it on an action comparison alone would strand the
 * entry until its year ran out.
 *
 * @param options {object}
 * @param options.stored {IZcap}
 * @param options.fresh {IZcap}
 * @param options.label {string}   the entry, for the log line
 * @returns {boolean}
 */
function shouldAdoptFreshCapability({
  stored,
  fresh,
  label
}: {
  stored: IZcap
  fresh: IZcap
  label: string
}): boolean {
  const expiring = zcapExpiring({
    expires: (stored as { expires?: string }).expires
  })
  const covers = capabilityCoversStored({ stored, fresh })
  const retargeted =
    (stored as { invocationTarget?: string }).invocationTarget !==
    (fresh as { invocationTarget?: string }).invocationTarget
  if (retargeted) {
    log.info(
      "Adopting a fresh management zcap naming this deployment's target",
      {
        label
      }
    )
    return true
  }
  if (expiring) {
    if (!covers) {
      log.error(
        "Refreshing the entry's expiring management zcap with one that does not cover the stored one's actions",
        { label }
      )
    }
    return true
  }
  return covers && capabilityWidensStored({ stored, fresh })
}

/**
 * Backfills the registry's passphrase entry from the current full session,
 * without re-prompting for the passphrase. When this session was produced by a
 * passphrase login (`profile.unlockMethod.type === 'passphrase'`) with the
 * vault unlocked, it records (or corrects) the passphrase entry's unlock Space
 * and management zcap -- created at first passphrase login, updated after a
 * passphrase change made elsewhere, completed once the profile carries a
 * management capability the stored entry lacks, and refreshed when the stored
 * one is expired or inside the renewal window (every login mints a fresh
 * one-year delegation). A passkey session performs the same expiry refresh on
 * its own passkey entry (matched on unlock Space) and otherwise writes
 * nothing. An in-place refresh never narrows a stored capability that is not
 * expiring (the mint is dropped, leaving the entry as it stands), writes one
 * that strictly widens it regardless of expiry, and on expiry writes the
 * fresh one regardless -- logging an error if it narrows -- since a dead
 * capability would lose DELETE beside PUT. But it still returns the
 * existing
 * registry when it can be read, so callers (the Settings passkeys section)
 * can use this as their load-plus-backfill entry point for any session.
 *
 * A transient session makes no call from HERE and returns `null` immediately,
 * before even a read: the registry is remembered-session state, a transient
 * session's annex-signed root invocation could never have authorized it
 * anyway, and threading the generation delegation into these helpers must not
 * turn this into a registry clobber from a public terminal. Its one registry
 * write is `refreshTransientManageCapability`, which creates nothing and
 * touches only the acting credential's own management zcap.
 *
 * The registry is created only when `createIfMissing` is set (a fresh 16-byte
 * webAuthnUserId is minted): the lazy-creation points are first passkey
 * registration and first Settings render, so a plain login never materializes
 * it. Writes only when something changed, and returns the resulting record (or
 * `null` when none exists and none was created). Errors are the caller's to
 * handle (call sites fire-and-forget with a `log.warn`).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.createIfMissing] {boolean}   mint the registry when absent;
 *   default false
 * @returns {Promise<UnlockMethodsRecord | null>}
 */
export async function backfillPassphraseUnlockMethod({
  session,
  createIfMissing = false
}: {
  session: Session
  createIfMissing?: boolean
}): Promise<UnlockMethodsRecord | null> {
  if (!isBrowserLocalSession(session.profile.persistence)) {
    return null
  }
  const { unlockMethod, keyAgreementKey, keyResolver } = session.profile
  // The vault keys are needed to read (let alone write) the registry.
  if (!keyAgreementKey || !keyResolver) {
    return null
  }

  // The whole decision runs inside the shared compare-and-swap wrapper's
  // mutate, over a FRESH read each attempt, so a concurrent registry write
  // is merged on a re-read rather than reverted.
  return await updateUnlockMethods({
    session,
    mutate: record => {
      // A passkey full session refreshes only its own entry's management zcap
      // (matched on unlock Space): the login minted a fresh delegation, and
      // the stored copy goes stale at the one-year TTL. It never creates
      // entries.
      if (unlockMethod?.type === 'passkey') {
        if (!record || !unlockMethod.manageCapability) {
          return null
        }
        const stored = record.methods.find(
          (method): method is PasskeyUnlockMethod =>
            method.type === 'passkey' &&
            method.unlockSpaceId === unlockMethod.unlockSpaceId
        )
        const stale =
          !!stored &&
          (!stored.manageCapability ||
            shouldAdoptFreshCapability({
              stored: stored.manageCapability,
              fresh: unlockMethod.manageCapability,
              label: 'passkey'
            }))
        if (!stale) {
          return null
        }
        return {
          ...record,
          methods: record.methods.map(method =>
            method === stored
              ? { ...stored, manageCapability: unlockMethod.manageCapability }
              : method
          )
        }
      }
      // Only a passphrase full session can backfill; any other session just
      // reports the registry as it stands -- never null when one exists, so a
      // Settings load through this function cannot mistake an account with
      // passkeys for one with no registry.
      if (unlockMethod?.type !== 'passphrase') {
        return null
      }
      let base = record
      if (!base) {
        if (!createIfMissing) {
          return null
        }
        base = emptyUnlockMethodsRegistry()
      }

      const existing = base.methods.find(
        (method): method is PassphraseUnlockMethod =>
          method.type === 'passphrase'
      )
      const { unlockSpaceId, manageCapability } = unlockMethod

      // Write only when the stored entry is missing, points at a stale unlock
      // Space (a passphrase change happened elsewhere), or lacks a management
      // capability the profile now carries -- or holds one that is expired or
      // inside the renewal window (the login minted a fresh one-year
      // delegation to replace it with) -- or one the fresh capability
      // strictly widens (an entry a past login narrowed). An in-place refresh
      // never narrows a capability that is not expiring. An entry naming
      // another unlock Space is a rebind, whose stored capability belongs to
      // the retired Space and is replaced wholesale.
      const changed =
        !existing ||
        existing.unlockSpaceId !== unlockSpaceId ||
        (!!manageCapability &&
          (!existing.manageCapability ||
            shouldAdoptFreshCapability({
              stored: existing.manageCapability,
              fresh: manageCapability,
              label: 'passphrase'
            })))
      if (!changed) {
        return null
      }

      return upsertPassphraseUnlockMethod({
        record: base,
        unlockSpaceId,
        manageCapability
      })
    }
  })
}

/**
 * Refreshes the acting credential's management zcap in the registry from a
 * TRANSIENT visit -- the one registry write an ordinary transient login makes.
 * The remembered login mints a fresh one-year delegation every time and the
 * backfill stores it; without this pass, no credential's management zcap would
 * ever be refreshed on an account that never remembers a browser, and every
 * one of them would lapse a year after its bind -- on the default account
 * shape.
 *
 * Every constraint here narrows it. It refreshes only: no registry is created,
 * no entry is created, and no entry but the acting credential's is touched
 * (matched on unlock Space id, the same match the passkey own-entry refresh
 * makes). The write rides the visit's generation delegation as the annex VM,
 * the only authority a transient visit holds, inside the shared
 * compare-and-swap loop, so a concurrent writer conflicts and re-applies. A
 * pending-shaped entry -- one recording another credential's key-agreement
 * multibase, the residue of a passphrase change torn before its retirement --
 * is skipped, and so is an entry whose stored capability is neither expiring
 * nor narrower than the fresh one. A read that throws (a stale registry seal
 * included) warns and skips: a login must not fail over a capability refresh.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the visit's annex-VM client
 * @param options.spaceId {string}   the data Space id
 * @param options.userKey {UserKey}   the user key the stored record is sealed
 *   to
 * @param options.capability {IZcap}   the generation delegation every request
 *   rides
 * @param options.unlockSpaceId {string}   the acting credential's unlock Space
 * @param options.manageCapability {IZcap}   the freshly minted capability
 * @param [options.keyAgreementKeyMultibase] {string}   the acting
 *   credential's key-agreement multibase; a matched entry recording a
 *   different one is another credential's and is left alone
 * @returns {Promise<void>}
 */
export async function refreshTransientManageCapability({
  zcapClient,
  spaceId,
  userKey,
  capability,
  unlockSpaceId,
  manageCapability,
  keyAgreementKeyMultibase
}: {
  zcapClient: ZcapClient
  spaceId: string
  userKey: UserKey
  capability: IZcap
  unlockSpaceId: string
  manageCapability: IZcap
  keyAgreementKeyMultibase?: string
}): Promise<void> {
  try {
    await updateUnlockMethodsWithClient({
      zcapClient,
      spaceId,
      userKey,
      capability,
      mutate: record => {
        if (!record) {
          return null
        }
        const stored = record.methods.find(
          method =>
            (method.type === 'passphrase' || method.type === 'passkey') &&
            method.unlockSpaceId === unlockSpaceId
        )
        if (!stored) {
          return null
        }
        if (
          keyAgreementKeyMultibase !== undefined &&
          stored.keyAgreementKeyMultibase !== undefined &&
          stored.keyAgreementKeyMultibase !== keyAgreementKeyMultibase
        ) {
          return null
        }
        const stale =
          !stored.manageCapability ||
          shouldAdoptFreshCapability({
            stored: stored.manageCapability,
            fresh: manageCapability,
            label: stored.type
          })
        if (!stale) {
          return null
        }
        return {
          ...record,
          methods: record.methods.map(method =>
            method === stored ? { ...stored, manageCapability } : method
          )
        }
      }
    })
  } catch (err) {
    log.warn('Could not refresh the management zcap from a transient visit', {
      unlockSpaceId,
      err
    })
  }
}

/**
 * Records freshly re-minted delegation members -- the bridge pair, the
 * annex-Space sibling pair where one was resealed -- and, after a
 * self-enrollment climbed the update-key ladder, the current
 * rung's multibase -- on the passphrase or passkey entry matching an unlock
 * Space. The registry half of the login-time bridge-expiry self-refresh and
 * the post-self-enroll rung refresh. Best-effort semantics are the caller's
 * (both refreshes are fire-and-forget behind provisioning); writes only when
 * an entry matches.
 *
 * The unlock Space alone is not always enough to identify the credential: a
 * passphrase change whose retirement failed at its document edit leaves the
 * entry pointing at the NEW unlock Space while recording the OLD credential's
 * standing configuration, so a caller holding the login credential passes its
 * `keyAgreementKeyMultibase` too, and a mismatch writes nothing. Stamping a
 * fresh rung beside another credential's key-agreement multibase would make
 * the next completion run strike the wrong ladder.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.unlockSpaceId {string}   the credential's unlock Space
 * @param [options.keyAgreementKeyMultibase] {string}   the acting
 *   credential's key-agreement multibase; when given and the matched entry
 *   records a different one, nothing is written
 * @param [options.delegationKeyId] {string}
 * @param [options.delegationExpires] {string}
 * @param [options.delegatedClientsKeyId] {string}   the annex-Space
 *   sibling delegation's fresh signer
 * @param [options.delegatedClientsExpires] {string}
 * @param [options.updateKeyMultibase] {string}   the ladder's current
 *   committed rung
 * @returns {Promise<void>}
 */
export async function refreshStandingDelegationFields({
  session,
  unlockSpaceId,
  keyAgreementKeyMultibase,
  delegationKeyId,
  delegationExpires,
  delegatedClientsKeyId,
  delegatedClientsExpires,
  updateKeyMultibase
}: {
  session: Session
  unlockSpaceId: string
  keyAgreementKeyMultibase?: string
  delegationKeyId?: string
  delegationExpires?: string
  delegatedClientsKeyId?: string
  delegatedClientsExpires?: string
  updateKeyMultibase?: string
}): Promise<void> {
  await updateUnlockMethods({
    session,
    mutate: record => {
      if (!record) {
        return null
      }
      const stored = record.methods.find(
        method =>
          (method.type === 'passphrase' || method.type === 'passkey') &&
          method.unlockSpaceId === unlockSpaceId
      )
      if (!stored) {
        return null
      }
      // The entry records another credential's standing configuration (a
      // pending retirement): its members belong to that credential, so
      // nothing here may land on them.
      if (
        keyAgreementKeyMultibase !== undefined &&
        stored.keyAgreementKeyMultibase !== undefined &&
        stored.keyAgreementKeyMultibase !== keyAgreementKeyMultibase
      ) {
        return null
      }
      return {
        ...record,
        methods: record.methods.map(method =>
          method === stored
            ? {
                ...stored,
                ...(delegationKeyId ? { delegationKeyId } : {}),
                ...(delegationExpires ? { delegationExpires } : {}),
                ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
                ...(delegatedClientsExpires ? { delegatedClientsExpires } : {}),
                ...(updateKeyMultibase ? { updateKeyMultibase } : {})
              }
            : method
        )
      }
    }
  })
}

/**
 * Swaps the live session onto the unlock identity a passphrase change just
 * produced. The change deleted the old unlock Space and its client-key
 * record, so the profile's `persistClientKeys` closure would otherwise
 * silently no-op (losing rolled update-key seeds or a rotated user key), and the
 * stale `profile.unlockMethod` would let the registry backfill repoint the
 * passphrase entry at the deleted Space. Mutates `session.profile` in place;
 * the session keeps operating without a re-login.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.unlockSpaceId {string}   the new passphrase's unlock Space
 * @param [options.manageCapability] {IZcap}   the management zcap the new
 *   bind delegated to the account controller
 * @param options.persistClientKeys {Function}   the re-wrap closure over the
 *   new unlock identity (returned by `changePassphrase`)
 * @returns {void}
 */
export function adoptPassphraseRebind({
  session,
  unlockSpaceId,
  manageCapability,
  persistClientKeys
}: {
  session: Session
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}): void {
  session.profile.persistClientKeys = persistClientKeys
  session.profile.unlockMethod = {
    type: 'passphrase',
    unlockSpaceId,
    manageCapability
  }
}

/**
 * Enrolls a new passkey as an unlock method: runs the WebAuthn registration
 * ceremony, binds this client's key set under the passkey's PRF-derived
 * unlock identity, and assembles the registry entry describing the passkey.
 * The caller is responsible for persisting the returned entry in the registry
 * (and, at signup, for provisioning the data Space first). The one caller is
 * the no-WAS passkey signup, where no unlock Space exists and nothing can be
 * standing; every WAS flow runs the standing establishment instead (the
 * credential-anchored signup, and the Settings add-a-passkey ceremony's
 * `registerPasskey` + `establishStandingUnlock` order).
 *
 * `delegateManagementTo` drives the entry's optional `manageCapability`: when
 * an account DID is given (and a WAS server is configured) the bind
 * delegates GET/DELETE on the new unlock Space to it, and the entry carries
 * the resulting capability so the passkey can later be revoked tap-free;
 * otherwise the entry omits it.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   this client's 32-byte seed to bind
 *   under the passkey
 * @param options.controller {string}   the account did:key
 * @param options.userHandle {Uint8Array}   the account's WebAuthn user handle
 * @param options.userName {string}   the WebAuthn user name shown in pickers
 * @param options.locale {string}   active i18n language for the entry's date label
 * @param options.promptForPrfRetry {() => boolean | Promise<boolean>}   PRF-retry
 *   consent callback (see `registerPasskey`)
 * @param [options.email] {string}   account email, carried in the wrapped record
 * @param [options.userKey] {UserKey}   the account's per-user key, cached in the local
 *   client-key record so a passkey login recovers it
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds, cached in the local client-key record so a
 *   passkey login recovers update authority
 * @param [options.pointer] {AccountPointer}   the account pointer the new
 *   keyring record carries
 * @param [options.excludeCredentialIds] {Uint8Array[]}   authenticators already
 *   holding a passkey for this wallet, excluded from the ceremony
 * @param [options.delegateManagementTo] {string}   an account DID to
 *   delegate the unlock Space management zcap to
 * @returns {Promise<{ registration: PasskeyRegistration, entry: PasskeyUnlockMethod }>}
 */
export async function enrollPasskey({
  clientSeed,
  controller,
  userHandle,
  userName,
  locale,
  promptForPrfRetry,
  email,
  userKey,
  webvhUpdateKeys,
  pointer,
  excludeCredentialIds,
  delegateManagementTo
}: {
  clientSeed: Uint8Array
  controller: string
  userHandle: Uint8Array
  userName: string
  locale: string
  promptForPrfRetry: () => boolean | Promise<boolean>
  email?: string
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  pointer?: AccountPointer
  excludeCredentialIds?: Uint8Array[]
  delegateManagementTo?: string
}): Promise<{
  registration: PasskeyRegistration
  entry: PasskeyUnlockMethod
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const registration = await registerPasskey({
    userHandle,
    userName,
    excludeCredentialIds,
    promptForPrfRetry
  })

  // Bind this client's key set under the passkey's PRF-derived unlock
  // identity -- this is what makes the passkey able to log in on this client.
  // Delegating management to the account did:key lets the passkey later be
  // revoked without a tap on the (possibly lost) authenticator.
  const { unlockSpaceId, manageCapability, persistClientKeys } =
    await bindUnlockSecret({
      clientSeed,
      controller,
      secret: registration.prfOutput,
      kdf: PASSKEY_KDF,
      email,
      userKey,
      webvhUpdateKeys,
      pointer,
      delegateManagementTo
    })

  const now = new Date()
  const entry: PasskeyUnlockMethod = {
    type: 'passkey',
    label: `Passkey created ${now.toLocaleDateString(locale, DATE_FMT)}`,
    createdAt: now.toISOString(),
    credentialId: base64urlnopad.encode(registration.credentialId),
    transports: registration.transports,
    backupEligibility: registration.backupEligibility,
    backupState: registration.backupState,
    unlockSpaceId,
    ...(manageCapability ? { manageCapability } : {})
  }
  return { registration, entry, persistClientKeys }
}
