/**
 * The annex GC's repair of an account left pointing at a deleted generation.
 *
 * The account document's `#DelegatedClients` pointer names a generation whose
 * collection is gone: a stale GC pass collected it. No transient visit can
 * enroll until the pointer moves. A remembered login's annex GC reads the
 * pointed generation's log on every pass, finds it absent, and re-points at a
 * fresh generation off the quarterly cadence (swap `repaired`). The next
 * transient visit then finds the generation reachable and mends nothing.
 *
 * Run: `pnpm run test:harness`.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { startWalletHarness, type WalletHarness } from './walletHarness'
import {
  buildEnrolledClientAccount,
  deletePointedGeneration
} from './accountBuilder'
import { readPointedAnnexGeneration } from '../shared/storedLogs'

describe('the annex GC repairs a pointer naming a deleted generation', () => {
  let harness: WalletHarness

  beforeAll(async () => {
    harness = await startWalletHarness()
  })

  afterAll(async () => {
    await harness?.close()
  })

  it('re-points at a fresh generation on the next remembered login', async () => {
    const account = await buildEnrolledClientAccount({ harness })
    const before = await readPointedAnnexGeneration({
      dataDir: harness.dataDir,
      spaceId: account.spaceId
    })
    expect(before, 'the account points at a generation').toBeDefined()

    // The stale pass's delete, run as the enrolled client, which
    // root-invokes the auxiliary Space.
    const breaker = await harness.logIn({
      passphrase: account.passphrase,
      profile: account.enrolledProfile,
      name: 'deletes the pointed generation'
    })
    expect(breaker.kind).toBe('remembered')
    expect((await breaker.settled()).failures).toEqual([])
    await deletePointedGeneration({ actor: breaker })
    await breaker.logout()

    const repairer = await harness.logIn({
      passphrase: account.passphrase,
      profile: account.enrolledProfile,
      name: 'remembered login that repairs'
    })
    expect(repairer.kind).toBe('remembered')
    // The generation-delegation heal runs ahead of the GC and reads the
    // same missing log, so it fails and is skipped (FW-646). Nothing else
    // fails.
    const { failures } = await repairer.settled()
    expect(failures.map(failure => failure.source)).toEqual([
      'mends generation-delegation-is-current'
    ])
    const gc = ((await repairer.session.mends) ?? []).find(
      mend => mend.invariant === 'no-annex-generation-outlives-its-pointer'
    )
    expect(gc?.outcome).toBe('clean')
    expect(gc?.detail).toMatchObject({ swap: 'repaired', failed: 0 })
    await repairer.logout()

    const after = await readPointedAnnexGeneration({
      dataDir: harness.dataDir,
      spaceId: account.spaceId
    })
    expect(after?.annexSpaceId, 'the repair stayed in the same Space').toBe(
      before!.annexSpaceId
    )
    expect(after?.generationId).not.toBe(before!.generationId)

    const visit = await harness.logIn({
      passphrase: account.passphrase,
      name: 'transient visit after the repair'
    })
    expect(visit.kind).toBe('transient')
    expect((await visit.settled()).failures).toEqual([])
    const reachable = ((await visit.session.mends) ?? []).find(
      mend => mend.invariant === 'annex-generation-is-reachable'
    )
    expect(reachable?.outcome, 'the transient visit had nothing to mend').toBe(
      'noop'
    )
    await visit.logout()
  })
})
