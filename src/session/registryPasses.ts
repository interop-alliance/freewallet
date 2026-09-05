/**
 * The login-time registry chain: the appender both compositions build their
 * chain with, and the passes they share.
 *
 * Every login-time registry pass rides `session.registryReady`, one ordered
 * promise chain seeded behind storage provisioning and kept off
 * `session.storageReady` so the login pages navigate as soon as the
 * collections are provisioned. The order is the point: several passes
 * compare-and-swap the same registry entry, and two of them racing would
 * spend the retry budget undoing each other. Each pass is best-effort -- a
 * failure is logged and skipped rather than failing the login.
 *
 * Four passes run on both compositions, in this order: the stale-seal
 * repair, the torn-retirement repair, the bare-passkey rebuild, and the
 * registry backfill. The remembered chain adds its own stages around them
 * (the user key sweep ahead, the standing-delegation and ladder-rung
 * refreshes, the pointer heal, the generation-delegation heal and the annex
 * GC behind); the transient chain adds the management-zcap refresh last.
 */
import type { UserKeyRosterReadResult } from '@interop/wallet-core/keys'
import type { Session } from '@/types/auth'
import type { KeyringFetchResult, UnlockCredential } from '@/session/keyring'
import { accountCeremonyContext } from '@/session/accountCeremonyContext'
import { repairStaleUnlockRegistrySeal } from '@/session/registryReseal'
import {
  rebuildBarePasskeyEntry,
  repairTornPassphraseRetirement
} from '@/session/pendingRetirement'
import { backfillPassphraseUnlockMethod } from '@/session/unlockMethods'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:registry')

/**
 * Appends one best-effort stage to `session.registryReady`, reassigning the
 * promise so the chain keeps its single total order. A falsy `when` leaves
 * the chain untouched, and so does an absent `registryReady` (a session whose
 * composition never seeded one). The stage's rejection is caught and logged
 * under `warn`, so a failed pass never breaks the chain for the stages after
 * it or for a ceremony awaiting it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.when] {boolean}   the stage's own guard; default true
 * @param options.warn {string}   the message a failed stage logs
 * @param options.run {Function}   the stage body
 * @returns {void}
 */
export function chainRegistryStage({
  session,
  when = true,
  warn,
  run
}: {
  session: Session
  when?: boolean
  warn: string
  run: () => Promise<void>
}): void {
  if (!session.registryReady || !when) {
    return
  }
  session.registryReady = session.registryReady.then(async () => {
    try {
      await run()
    } catch (err) {
      log.warn(warn, { err })
    }
  })
}

/**
 * The four passes both compositions run, in the order every caller depends
 * on. The stale-seal repair is first because every writer after it reads the
 * record, and a stale seal would make each warn and skip on a registry this
 * same login can mend. The two identity repairs come next: each settles which
 * credential the passphrase or passkey entry names, and the backfill only
 * refreshes fields on whatever they left standing.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.found {KeyringFetchResult}   the login credential's hit
 * @param [options.rosterRead] {UserKeyRosterReadResult}   the login's roster
 *   read, the stale-seal repair's source of escrowed generations; without one
 *   that pass is skipped
 * @param [options.credential] {object}   the login credential, for the
 *   torn-retirement repair's re-derivation
 * @returns {Promise<void>}
 */
export async function runSharedRegistryPasses({
  session,
  found,
  rosterRead,
  credential
}: {
  session: Session
  found: KeyringFetchResult
  rosterRead?: UserKeyRosterReadResult
  credential?: { secret?: string | Uint8Array; derived?: UnlockCredential }
}): Promise<void> {
  const context = await accountCeremonyContext({ session })
  if (rosterRead) {
    try {
      await repairStaleUnlockRegistrySeal({ session, rosterRead, context })
    } catch (err) {
      log.warn(
        'Could not repair the unlock-methods registry seal; the next login retries',
        { err }
      )
    }
  }
  try {
    await repairTornPassphraseRetirement({
      session,
      found,
      ...(credential ? { credential } : {})
    })
  } catch (err) {
    log.warn(
      'Could not finish the pending passphrase retirement; the next login retries',
      { err }
    )
  }
  try {
    await rebuildBarePasskeyEntry({ session, found })
  } catch (err) {
    log.warn(
      'Could not rebuild the bare passkey unlock-method entry; the next login retries',
      { err }
    )
  }
  try {
    await backfillPassphraseUnlockMethod({ session })
  } catch (err) {
    log.warn('Could not backfill the unlock-methods registry', { err })
  }
}
