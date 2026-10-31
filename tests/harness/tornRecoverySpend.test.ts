/**
 * The transient recovery spend torn at its roster append, produced with the
 * server's request fault seam (`harness.faults`) and checked against the
 * store and the server's request record.
 *
 * The spend (`recoverAccountWithCode` with no `rememberBrowser`) promises a
 * write order: every annex write lands before the add-and-retire entry, and
 * the mandatory rotation's roster append is the very next mutating request
 * after it. The window in which the typed code is dead and the new
 * credential holds no wrap is then the append alone.
 *
 * The append is torn two ways. Refused, the server applies nothing: the
 * account is left with the spent code dead and no wrap for the new
 * passphrase, the stated open gap of invariant `recovery-spend-is-completed`.
 * Applied with its response dropped, the write is durable while the client
 * sees a transport failure, and the next login on the new passphrase enters.
 *
 * Run: `pnpm run test:harness`.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { RequestRecord } from 'was-teaching-server/testing'
import { startWalletHarness, type WalletHarness } from './walletHarness'
import { buildRecoveryCodeAccount } from './accountBuilder'
import {
  annexLocationOf,
  ENCRYPTED_STANDARD_COLLECTIONS,
  readCollectionEpoch,
  readPointedAnnexGeneration,
  readStoredLogSize,
  readUserKeyRoster
} from '../shared/storedLogs'

/**
 * The requests that change something, in arrival order: reads and CORS
 * preflights left out. Each keeps its index in the window it was cut from.
 *
 * @param options {object}
 * @param options.requests {RequestRecord[]}
 * @returns {Array<RequestRecord & { index: number }>}
 */
function mutatingRequests({
  requests
}: {
  requests: RequestRecord[]
}): Array<RequestRecord & { index: number }> {
  return requests
    .map((request, index) => ({ ...request, index }))
    .filter(request => !['GET', 'HEAD', 'OPTIONS'].includes(request.method))
}

/**
 * The account log's and the user key roster's paths in the account Space.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @returns {{ accountLog: string, roster: string }}
 */
function accountPaths({ spaceId }: { spaceId: string }): {
  accountLog: string
  roster: string
} {
  return {
    accountLog: `/space/${spaceId}/id/did.jsonl`,
    roster: `/space/${spaceId}/key-map/user-key.jsonl`
  }
}

/**
 * What the store holds that the spend changes: the account log's entry
 * count, the roster's state, and the annex generation the account log's head
 * points at.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.spaceId {string}
 * @returns {Promise<{ accountLogEntries: number, roster: object,
 *   pointed: object | undefined }>}
 */
async function readSpendState({
  dataDir,
  spaceId
}: {
  dataDir: string
  spaceId: string
}) {
  return {
    accountLogEntries: (
      await readStoredLogSize({
        dataDir,
        spaceId,
        collectionId: 'id',
        resourceId: 'did.jsonl'
      })
    ).entries,
    roster: await readUserKeyRoster({ dataDir, spaceId }),
    pointed: await readPointedAnnexGeneration({ dataDir, spaceId })
  }
}

/**
 * Runs the transient spend of a fresh account's recovery code under a fault
 * armed on its roster append, and returns how it ended with the requests the
 * server saw meanwhile. The fault is disarmed before this returns.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param options.tear {'refuse' | 'drop-every-response' | 'drop-one-response'}
 * @returns {Promise<object>}   the account, its paths, the new passphrase,
 *   the spend state before and after, the spend's outcome or error, and the
 *   mutating requests the server saw during the spend
 */
async function spendWithTornAppend({
  harness,
  tear
}: {
  harness: WalletHarness
  tear: 'refuse' | 'drop-every-response' | 'drop-one-response'
}) {
  const account = await buildRecoveryCodeAccount({ harness })
  const { dataDir, faults } = harness
  const paths = accountPaths({ spaceId: account.spaceId })
  const before = await readSpendState({ dataDir, spaceId: account.spaceId })
  const match = { method: 'PUT', path: paths.roster }
  // The spend re-sends a failed append, so a tear the client must not get
  // past covers every attempt.
  if (tear === 'refuse') {
    faults.refuse({ match, times: Infinity })
  } else {
    faults.dropResponse({
      match,
      times: tear === 'drop-every-response' ? Infinity : 1
    })
  }
  const firstRequest = faults.requests.length
  const { recoverAccountWithCode } = await import('@/session/recovery')
  const newPassphrase = `torn-spend-${crypto.randomUUID()}-Zz9!`
  let outcome: Awaited<ReturnType<typeof recoverAccountWithCode>> | undefined
  let error: unknown
  try {
    outcome = await recoverAccountWithCode({
      code: account.recoveryCode,
      newPassphrase
    })
  } catch (err) {
    error = err
  }
  const requests = faults.requests.slice(firstRequest)
  // No actor is live, so emptying the record shifts no visit's window.
  faults.reset()
  return {
    account,
    paths,
    newPassphrase,
    before,
    after: await readSpendState({ dataDir, spaceId: account.spaceId }),
    outcome,
    error,
    writes: mutatingRequests({ requests })
  }
}

describe('the transient recovery spend torn at its roster append', () => {
  let harness: WalletHarness

  beforeAll(async () => {
    harness = await startWalletHarness()
  })

  afterAll(async () => {
    await harness?.close()
  })

  it('refused: the append is the first write after the add-and-retire entry, and nothing follows it', async () => {
    const { errorNameOf } = await import('@interop/wallet-core/menders')
    const { account, paths, newPassphrase, before, after, error, writes } =
      await spendWithTornAppend({ harness, tear: 'refuse' })

    // The spend fails at the append and says so.
    expect(errorNameOf(error)).toBe('PwsServerError')

    // The continuation's two entries: reveal-and-commit, add-and-retire.
    const accountLogWrites = writes.filter(
      write => write.method === 'PUT' && write.path === paths.accountLog
    )
    expect(accountLogWrites).toHaveLength(2)
    const addAndRetire = accountLogWrites[1]!.index
    // Every annex write (the generation genesis, its delegation embed, the
    // visit key's enrollment) precedes the add-and-retire entry.
    const annexLogWrites = writes.filter(
      write =>
        write.path.endsWith('/did.jsonl') && write.path !== paths.accountLog
    )
    expect(annexLogWrites.length).toBeGreaterThan(0)
    for (const write of annexLogWrites) {
      expect(write.index).toBeLessThan(addAndRetire)
    }
    // The roster append is the very next mutating request after the entry,
    // and nothing else is written after it: every later write is a
    // re-attempt of that same append, each one refused.
    const afterEntry = writes.filter(write => write.index > addAndRetire)
    expect(afterEntry.length).toBeGreaterThan(0)
    for (const write of afterEntry) {
      expect(write).toMatchObject({
        method: 'PUT',
        path: paths.roster,
        fault: 'refused'
      })
    }
    // The append invokes as the fresh annex generation the entry points at.
    expect(after.pointed).toBeDefined()
    expect(after.pointed).not.toEqual(before.pointed)
    expect(annexLocationOf({ pointer: afterEntry[0]!.did! })).toEqual(
      after.pointed
    )

    // Durable state: the two entries landed and the roster did not move.
    expect(after.accountLogEntries).toBe(before.accountLogEntries + 2)
    expect(after.roster).toEqual(before.roster)

    // The residue (invariant `recovery-spend-is-completed`, an open gap).
    // The spent code is dead: a re-run refuses it as spent.
    const { recoverAccountWithCode } = await import('@/session/recovery')
    const rerun = await recoverAccountWithCode({
      code: account.recoveryCode,
      newPassphrase: `torn-spend-rerun-${crypto.randomUUID()}-Zz9!`
    }).catch((err: unknown) => err)
    expect(errorNameOf(rerun)).toBe('RecoveryKeyNotCommittedError')
    // The new passphrase holds no wrap of the current user key.
    await expect(
      harness.logIn({ passphrase: newPassphrase, name: 'after refused' })
    ).rejects.toMatchObject({
      name: 'TransientLoginUnavailableError',
      reason: 'no-user-key-wrap'
    })
  })

  it('response dropped on every attempt: the append is durable, and the next login enters', async () => {
    const { errorNameOf } = await import('@interop/wallet-core/menders')
    const { account, paths, newPassphrase, before, after, error, writes } =
      await spendWithTornAppend({ harness, tear: 'drop-every-response' })
    const spaceId = account.spaceId
    const { dataDir } = harness

    // The client saw a transport failure.
    expect(errorNameOf(error)).toBe('PwsError')
    const rosterWrites = writes.filter(write => write.path === paths.roster)
    // The first append was applied; each re-attempt found the head moved.
    expect(rosterWrites.map(write => [write.status, write.fault])).toEqual([
      [200, 'dropped'],
      ...rosterWrites.slice(1).map(() => [412, 'dropped'])
    ])
    // Nothing after the append: the tail stopped there.
    const lastRosterWrite = rosterWrites[rosterWrites.length - 1]!.index
    expect(writes[writes.length - 1]!.index).toBe(lastRosterWrite)

    // Durable state: the rotation landed, one entry with a fresh epoch.
    expect(after.accountLogEntries).toBe(before.accountLogEntries + 2)
    expect(after.roster.entries).toBe(before.roster.entries + 1)
    expect(after.roster.currentEpoch).not.toBe(before.roster.currentEpoch)
    // The epoch cascade did not run: no collection names the new user key.
    for (const collectionId of ENCRYPTED_STANDARD_COLLECTIONS) {
      const { generations } = await readCollectionEpoch({
        dataDir,
        spaceId,
        collectionId
      })
      expect(generations, collectionId).not.toContain(after.roster.currentEpoch)
    }

    // A re-run refuses the spent code.
    const { recoverAccountWithCode, listRecoveryCodeEntries } =
      await import('@/session/recovery')
    const rerun = await recoverAccountWithCode({
      code: account.recoveryCode,
      newPassphrase: `torn-spend-rerun-${crypto.randomUUID()}-Zz9!`
    }).catch((err: unknown) => err)
    expect(errorNameOf(rerun)).toBe('RecoveryKeyNotCommittedError')

    // The next login on the new passphrase enters and reads the account.
    const visit = await harness.logIn({
      passphrase: newPassphrase,
      name: 'after dropped'
    })
    expect(visit.kind).toBe('transient')
    expect(visit.spaceId).toBe(spaceId)
    const { failures } = await visit.settled()
    // The Login activity write races the login's collection fan-out. Written
    // first, it meets `wallet-activity` with no epoch naming the current user
    // key and is refused, so that row is lost. Nothing else fails.
    for (const failure of failures) {
      expect(failure.source).toBe('loginActivity')
      expect(errorNameOf(failure.error)).toBe('KeyUnwrapError')
    }
    // The fan-out re-epoched every collection onto the current user key.
    for (const collectionId of ENCRYPTED_STANDARD_COLLECTIONS) {
      const { generations } = await readCollectionEpoch({
        dataDir,
        spaceId,
        collectionId
      })
      expect(generations, collectionId).toContain(after.roster.currentEpoch)
    }
    const credentials = await visit.run(session =>
      session.storage.listCredentials()
    )
    expect(credentials.length).toBeGreaterThan(0)
    // The tail's registry step never ran: the spent code's entry is still
    // listed, and the replacement code was never recorded (nor shown).
    const recoveryEntries = await visit.run(session =>
      listRecoveryCodeEntries({ session })
    )
    expect(recoveryEntries.map(entry => entry.recoveryKid)).toEqual([
      account.recoveryKid
    ])
    await visit.logout()
  })

  it('response dropped once: the re-attempt converges and the spend completes', async () => {
    const { paths, before, after, outcome, error, writes } =
      await spendWithTornAppend({ harness, tear: 'drop-one-response' })

    expect(error).toBeUndefined()
    expect(outcome).toMatchObject({
      standing: 'established',
      registry: 'written'
    })
    // The applied append, then one re-attempt that found it already there.
    const rosterWrites = writes.filter(write => write.path === paths.roster)
    expect(rosterWrites.map(write => [write.status, write.fault])).toEqual([
      [200, 'dropped'],
      [412, undefined]
    ])
    // The tail carried on past the append.
    expect(writes[writes.length - 1]!.index).toBeGreaterThan(
      rosterWrites[1]!.index
    )
    // One rotation, not two.
    expect(after.roster.entries).toBe(before.roster.entries + 1)
  })
})
