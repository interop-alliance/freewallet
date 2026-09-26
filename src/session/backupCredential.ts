/**
 * The backup credential: the standing unlock credential a backup export
 * establishes from 32 random bytes and packs into the bundle, so the file
 * carries everything a restore login on that credential's record needs,
 * with nothing retired and no key rotated. That login is not built yet, so
 * no login form accepts the credential today and `isLoginEntry` counts none.
 *
 * The establishment (`establishBackupCredential`) is the export ceremony's
 * first stage and its pivot. Its order is entry-first, the passkey's shape
 * with one difference. The passkey writes a bare entry and completes it
 * afterwards, since that passkey's own next login rebuilds a bare row; a
 * backup credential has no next login until a restore runs it, and its
 * secret exists in memory alone until the bundle is written. So the entry
 * written before anything is published carries everything Settings needs to
 * remove it with no secret in hand: the standing fields derivable in memory
 * (the unlock Space id, the roster kid, the key-agreement multibase, rung 0's
 * update key, the client DID) and a pre-minted management zcap. The strike
 * tolerates a verification method the document never listed and the Space
 * delete tolerates a 404, so a row left by a crash at any later stage is
 * removable. The establishment then runs with its annex rung commit
 * required and placed before the document entry, since a restore login on
 * an uncommitted rung mints a fresh generation and loses every restored
 * grant; an in-run failure runs the verify-then-act cleanup the passkey
 * runs; and the entry is completed with the delegation fields.
 *
 * The Settings half is the listing and the removal. The removal is the
 * passkey's minus the authenticator: the entry's management zcap lets the
 * acting session delete the unlock Space, and the ordinary revoke strikes
 * the ladder VM, rotates the user key off the roster wrap, and drops the
 * entry. The bundle that packed the credential then no longer signs in to
 * the live account. It still opens every row it carries offline: removal
 * bounds the live account, not a file already written.
 */
import { BACKUP_CREDENTIAL_KDF } from '@interop/wallet-core/keyring'
import {
  generateLadderSeed,
  ladderRung
} from '@interop/wallet-core/clientAnnex'
import { UNLOCK_MANAGEMENT_ACTIONS } from '@interop/wallet-core/unlock'
import { errorNameOf } from '@interop/wallet-core/menders'
import { createLogger } from '@/lib/log'
import { causeChain } from '@/lib/storageErrors'
import { removeStandingCredential } from '@/session/accountSettings'
import type { AccountCeremonyContext } from '@/session/accountCeremonyContext'
import {
  delegateUnlockManagement,
  deriveUnlockCredential,
  unlockManagementGrantee
} from '@/session/keyring'
import { establishEntryFirstStandingCredential } from '@/session/standingEstablishment'
import {
  canRevokeWithoutCeremony,
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  type BackupCredentialUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import type { Session } from '@/types/auth'

const log = createLogger('fw:session:backup-credential')

/**
 * Thrown when a backup credential's entry records no management zcap, so
 * its unlock Space cannot be deleted from this session. Every entry the
 * export writes carries one from its first write, so this names an entry
 * some other writer produced.
 */
export class BackupCredentialNotRemovableError extends Error {
  constructor() {
    super(
      'This backup credential records no management capability, so it ' +
        'cannot be removed from this session.'
    )
    this.name = 'BackupCredentialNotRemovableError'
  }
}

/**
 * Thrown when the backup credential could not be established, after the
 * verify-then-act cleanup ran. The `cause` is the establishment's own
 * failure. A registry row the cleanup could not clear stays listed under
 * Settings > Backup credentials, removable there.
 */
export class BackupCredentialNotEstablishedError extends Error {
  constructor(options?: { cause?: unknown }) {
    super('The backup credential could not be established.', options)
    this.name = 'BackupCredentialNotEstablishedError'
  }
}

/**
 * Thrown when this session cannot commit the backup credential's rung into
 * the account's client-annex generation: it holds no ladder seed to sign the
 * commit with, or the generation does not commit its own acting rung. A
 * bundle written anyway would restore an account whose first login finds an
 * uncommitted rung, mints a fresh generation, and loses every restored
 * grant, so the export refuses instead. The pre-flight raises it before
 * anything is minted where it can; the establishment raises it after its
 * cleanup where it cannot.
 */
export class BackupAnnexCommitError extends Error {
  /**
   * Why the commit cannot land: `no-ladder-seed`, this session's unlock
   * record sealed no ladder seed to sign it with; `rung-uncommitted`, the
   * pointed generation admits neither this session's rung nor its hash. The
   * remedy differs, so the dialog's copy is keyed on it.
   */
  readonly reason: 'no-ladder-seed' | 'rung-uncommitted'

  constructor({
    reason,
    cause
  }: {
    reason: 'no-ladder-seed' | 'rung-uncommitted'
    cause?: unknown
  }) {
    super(
      reason === 'no-ladder-seed'
        ? 'This session holds no ladder seed to commit the backup credential ' +
            "into the account's client annex with, so a bundle restoring " +
            'through it would lose every connected app.'
        : "The account's client-annex generation does not commit this " +
            "session's own rung, so it cannot commit the backup credential's, " +
            'and a bundle restoring through it would lose every connected app.',
      cause !== undefined ? { cause } : {}
    )
    this.name = 'BackupAnnexCommitError'
    this.reason = reason
  }
}

/**
 * The annex rung commit's failure, where the establishment's failure is one
 * (anywhere in its cause chain), read as the refusal's reason: the honest
 * skip (no acting ladder seed) or the uncommitted acting rung. `undefined`
 * for any other failure.
 *
 * @param err {unknown}
 * @returns {BackupAnnexCommitError['reason'] | undefined}
 */
function annexCommitFailureReason(
  err: unknown
): BackupAnnexCommitError['reason'] | undefined {
  for (const current of causeChain(err)) {
    const name = errorNameOf(current)
    if (name === 'ClientAnnexRungCommitSkipped') {
      return 'no-ladder-seed'
    }
    if (name === 'ClientAnnexRungUncommittedError') {
      return 'rung-uncommitted'
    }
  }
  return undefined
}

/**
 * The export ceremony's first stage: establishes a backup credential from 32
 * fresh random bytes and hands those bytes back for the bundle to pack. The
 * caller holds them for the pack alone; nothing here stores, returns
 * elsewhere, or logs them.
 *
 * The order, and what each tear leaves:
 *
 * 1. Everything derivable in memory: the secret, its unlock credential
 *    (under `BACKUP_CREDENTIAL_KDF`), the ladder seed and rung 0, and the
 *    management zcap the unlock identity delegates to the account. No write.
 * 2. The registry entry, written first and carrying all of that but the
 *    delegation fields. A tear here leaves an entry naming a Space that does
 *    not exist and a key no document lists; its Remove in Settings deletes
 *    nothing and drops the row.
 * 3. The establishment with its annex rung commit required and placed before
 *    the document entry: roster wrap, record, commit, document entry. A tear
 *    inside it, or a failure, runs the verify-then-act cleanup: a standing
 *    record the document lists is a lost-response success and completes the
 *    entry; anything else published is retired; nothing published deletes
 *    the Space and drops the row. A crash the cleanup never runs leaves the
 *    row from step 2, whose Remove converges whatever the establishment
 *    reached.
 * 4. The completion write: the delegation fields, and the establishment's
 *    own management zcap in place of the pre-minted one. A completion that
 *    fails to persist is logged and the row from step 2 stands: the
 *    credential is standing and the bundle restores through it, the entry
 *    just records no delegation expiry until a login with it refreshes one.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}   the ceremony context the
 *   export resolved
 * @param options.label {string}   the label the entry lists under in Settings
 * @param options.clientAnnexDid {string | null}   the client-annex
 *   generation the export's pre-flight resolved from the account document,
 *   or `null` when the document names none. Handed through to the
 *   establishment, so the generation its required rung commit targets is
 *   the one the pre-flight checked this session's rung against, and never a
 *   second resolution the pre-flight's refusal did not cover
 * @param options.registry {UnlockMethodsRecord | null}   the registry as the
 *   pre-flight read it moments ago, the base the entry writes merge onto
 * @returns {Promise<{ secret: Uint8Array, unlockSpaceId: string }>}   the
 *   packed secret and the credential's unlock Space id, which the export's
 *   Space listing checks the registry for
 * @throws {BackupAnnexCommitError}   the annex rung commit could not land
 * @throws {BackupCredentialNotEstablishedError}   any other establishment
 *   failure, after the cleanup
 */
export async function establishBackupCredential({
  session,
  context,
  label,
  clientAnnexDid,
  registry
}: {
  session: Session
  context: AccountCeremonyContext
  label: string
  clientAnnexDid: string | null
  registry: UnlockMethodsRecord | null
}): Promise<{ secret: Uint8Array; unlockSpaceId: string }> {
  const { pointer } = context
  const controller = session.profile.accountController ?? context.controller

  // 1. In memory. The secret is the bundle's whole claim on the account, so
  // it is minted here and travels to exactly two places: the establishment
  // below and the pack.
  const secret = crypto.getRandomValues(new Uint8Array(32))
  const credential = await deriveUnlockCredential({
    secret,
    kdf: BACKUP_CREDENTIAL_KDF
  })
  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  // Pre-minted so the entry below is removable before the record exists;
  // the establishment mints its own, which the completion write adopts.
  const manageCapability = await delegateUnlockManagement({
    zcapClient: credential.unlock.zcapClient,
    spaceId: credential.unlock.spaceId,
    controller: unlockManagementGrantee({ pointer, controller }),
    allowedActions: [...UNLOCK_MANAGEMENT_ACTIONS]
  })
  const { standing } = credential
  const entry: BackupCredentialUnlockMethod = {
    type: 'backup-credential',
    label,
    createdAt: new Date().toISOString(),
    unlockSpaceId: credential.unlock.spaceId,
    manageCapability,
    rosterKid: standing.recipientKid,
    keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
    updateKeyMultibase: rung0.keyMultibase,
    unlockClientDid: standing.clientDid
  }

  // 2-4. The entry-first write, the establishment with its annex rung
  // commit required, and the completion write. A completion that fails to
  // persist is logged there and the entry-first row stands, as described
  // above.
  try {
    await establishEntryFirstStandingCredential({
      session,
      context,
      secret,
      kdf: BACKUP_CREDENTIAL_KDF,
      credential,
      ladderSeed,
      entry,
      base: registry ?? emptyUnlockMethodsRegistry(),
      requiredAnnexCommit: { clientAnnexDid }
    })
  } catch (err) {
    const reason = annexCommitFailureReason(err)
    if (reason) {
      throw new BackupAnnexCommitError({ reason, cause: err })
    }
    throw new BackupCredentialNotEstablishedError({ cause: err })
  }
  return { secret, unlockSpaceId: entry.unlockSpaceId }
}

/**
 * The backup credentials the account lists, in registry order, for the
 * Settings section. A registry that cannot be read lists none, and says so
 * in the log; the section is a listing, not a health check.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<BackupCredentialUnlockMethod[]>}
 */
export async function listBackupCredentialEntries({
  session
}: {
  session: Session
}): Promise<BackupCredentialUnlockMethod[]> {
  try {
    const record = await getUnlockMethods({ session })
    return (record?.methods ?? []).filter(
      (method): method is BackupCredentialUnlockMethod =>
        method.type === 'backup-credential'
    )
  } catch (err) {
    log.warn('Could not load the backup-credential entries', { err })
    return []
  }
}

/**
 * Removes a backup credential: strikes its ladder VM and key agreement from
 * the account document, rotates the user key off its roster wrap, deletes
 * its unlock Space through the entry's management zcap, and drops the entry.
 * The same sequence a passkey removal runs, with no tap: the entry carries
 * its management zcap from the export's first write.
 *
 * The same removal a passkey runs (`removeStandingCredential`): on the
 * ladder branch the generation delegation this visit rides is replaced
 * first, in case the credential being removed is the one whose ladder VM
 * signed it, and the credential this session itself entered on refuses
 * (`ActingCredentialRemovalError`), since every stage would act through the
 * VM being struck.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {BackupCredentialUnlockMethod}
 * @returns {Promise<void>}
 * @throws {ActingCredentialRemovalError}   the credential named is the one
 *   this transient session entered on
 * @throws {BackupCredentialNotRemovableError}   the entry records no
 *   management zcap
 */
export async function removeAccountBackupCredential({
  session,
  entry
}: {
  session: Session
  entry: BackupCredentialUnlockMethod
}): Promise<void> {
  if (!canRevokeWithoutCeremony(entry)) {
    throw new BackupCredentialNotRemovableError()
  }
  await removeStandingCredential({
    session,
    entry,
    verb: 'removing a backup credential'
  })
}
