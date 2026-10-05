/**
 * The invariant auditor over real accounts: every healthy shape audits
 * clean, and one torn state per gap-allowlist kind audits as exactly its
 * expected violations.
 *
 * - The healthy shapes: a fresh credential-anchored signup, a transient
 *   visit on it, and each account-builder shape (passphrase, passkey,
 *   recovery code, enrolled client), each audited from the stored state
 *   alone and again with a live actor as the key holder. Two shapes are not
 *   clean as built: a passkey add and a recovery-code issuance, run as
 *   ladder-kind ceremonies, leave the did:web projection behind the log
 *   until the next transient visit refreshes it, so their first audit
 *   allows exactly that id and the audit after the visit is clean.
 * - The shared builder's server-state shapes, which have no registry and no
 *   unlock record a login finds, audited from the stored state alone. They
 *   stand violated by construction on what that builder skips (see the
 *   test).
 * - The `unreachable` kind: an account left pointing at a deleted annex
 *   generation (the state `annexGcRepair.test.ts` builds). Three invariants
 *   stand violated, because one deletion breaks three predicates over the
 *   same generation: the generation is unreachable
 *   (`annex-generation-is-reachable`), its embedded delegation is gone with
 *   its log (`generation-delegation-is-current`), and the pointed
 *   generation is not live (`no-annex-generation-outlives-its-pointer`).
 *   The one converger is the remembered login's annex GC, whose `repaired`
 *   swap mints a fresh generation carrying a fresh delegation, so the audit
 *   after that login is clean.
 * - The `none` kind: a signup whose KMS stage failed, the request refused
 *   at the server. The document publishes no `authentication` relation
 *   (`account-document-publishes-an-authentication-key`). A `none` gap has
 *   no mender by declaration, so there is no clean second audit to take.
 *   The second audit, after a transient visit, asserts the gap still stands
 *   with exactly that id.
 *
 * Run: `pnpm run test:harness`.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { InvariantId } from '@interop/wallet-core/menders'
import {
  auditInvariants,
  expectInvariantsHold,
  type InvariantAudit
} from '../shared/invariantAudit'
import { INVARIANT_CENSUS } from '../shared/invariantCensus'
import {
  buildEnrolledClientAccount,
  buildPasskeyAccount,
  buildPassphraseAccount,
  buildRecoveryCodeAccount,
  buildServerStateAccount,
  deletePointedGeneration,
  type EnrolledClientAccount
} from './accountBuilder'
import { auditActor } from './invariantAuditActor'
import {
  startWalletHarness,
  type TestPasskey,
  type WalletHarness
} from './walletHarness'

/**
 * Asserts a key-holder audit checked every `key-holder` row and every
 * key-holder half: what it skipped is only the browser-local and unchecked
 * rows the census says nothing reaches.
 *
 * @param options {object}
 * @param options.audit {InvariantAudit}
 * @returns {void}
 */
function expectKeyHolderRowsChecked({
  audit
}: {
  audit: InvariantAudit
}): void {
  const reachable = audit.skipped.filter(
    ({ id }) =>
      INVARIANT_CENSUS[id].kind !== 'browser-local' &&
      INVARIANT_CENSUS[id].kind !== 'unchecked'
  )
  expect(reachable, 'rows a key holder should have settled').toEqual([])
}

describe('the invariant auditor', () => {
  let harness: WalletHarness

  beforeAll(async () => {
    harness = await startWalletHarness()
  })

  afterAll(async () => {
    await harness?.close()
  })

  it('a fresh credential-anchored signup and a transient visit on it audit clean', async () => {
    const passphrase = `audit-signup-${crypto.randomUUID()}-Zz9!`
    const signup = await harness.signUp({ passphrase })
    expect((await signup.settled()).failures).toEqual([])
    const withHolder = await auditActor({ harness, actor: signup, passphrase })
    expectInvariantsHold({ audit: withHolder })
    expectKeyHolderRowsChecked({ audit: withHolder })
    await signup.logout()
    expectInvariantsHold({
      audit: await auditInvariants({
        dataDir: harness.dataDir,
        spaceId: signup.spaceId
      })
    })

    const visit = await harness.logIn({ passphrase, name: 'transient visit' })
    expect(visit.kind).toBe('transient')
    expect((await visit.settled()).failures).toEqual([])
    const afterVisit = await auditActor({ harness, actor: visit, passphrase })
    expectInvariantsHold({ audit: afterVisit })
    expectKeyHolderRowsChecked({ audit: afterVisit })
    await visit.logout()
    expectInvariantsHold({
      audit: await auditInvariants({
        dataDir: harness.dataDir,
        spaceId: signup.spaceId
      })
    })
  })

  it('each account-builder shape audits clean, with and without a key holder', async () => {
    const passphraseAccount = await buildPassphraseAccount({ harness })
    const passkeyAccount = await buildPasskeyAccount({ harness })
    const recoveryAccount = await buildRecoveryCodeAccount({ harness })
    const enrolledAccount = await buildEnrolledClientAccount({ harness })
    // A passkey add and a recovery-code issuance run from the signup's
    // transient session, as ladder-kind ceremonies. Each appends an
    // inventory-changing entry and leaves the did:web projection behind it;
    // the projection's mender is the next transient visit's refresh, which
    // the audit after that visit sees done.
    const projectionBehind: InvariantId[] = [
      'did-web-projection-matches-the-log'
    ]
    const shapes: Array<{
      shape: string
      spaceId: string
      credential: { passphrase: string } | { passkey: TestPasskey }
      profile?: EnrolledClientAccount['enrolledProfile']
      built: InvariantId[]
    }> = [
      {
        shape: 'passphrase',
        spaceId: passphraseAccount.spaceId,
        credential: { passphrase: passphraseAccount.passphrase },
        built: []
      },
      {
        shape: 'passkey',
        spaceId: passkeyAccount.spaceId,
        credential: { passkey: passkeyAccount.passkey },
        built: projectionBehind
      },
      {
        shape: 'recovery code',
        spaceId: recoveryAccount.spaceId,
        credential: { passphrase: recoveryAccount.passphrase },
        built: projectionBehind
      },
      {
        shape: 'enrolled client',
        spaceId: enrolledAccount.spaceId,
        credential: { passphrase: enrolledAccount.passphrase },
        profile: enrolledAccount.enrolledProfile,
        built: []
      }
    ]
    for (const { shape, spaceId, credential, profile, built } of shapes) {
      expectInvariantsHold({
        audit: await auditInvariants({ dataDir: harness.dataDir, spaceId }),
        allow: built
      })
      const actor = await harness.logIn({ ...credential, profile, name: shape })
      expect((await actor.settled()).failures, shape).toEqual([])
      const audit = await auditActor({ harness, actor, ...credential })
      expectInvariantsHold({ audit })
      expectKeyHolderRowsChecked({ audit })
      await actor.logout()
      expectInvariantsHold({
        audit: await auditInvariants({ dataDir: harness.dataDir, spaceId })
      })
    }
  })

  it('the server-state shapes audit clean from the stored state, but for what the shared builder skips', async () => {
    // The shared builder runs no KMS stage, so a document whose only keys
    // are ladder VMs publishes no `authentication` relation; the enrolled
    // client's entry publishes one. It also writes the did:web projection at
    // genesis alone, so every entry past genesis leaves the projection
    // behind the log. Both are real violations of these shapes, standing by
    // construction, and the allowlist names them shape by shape.
    const noAuthentication: InvariantId =
      'account-document-publishes-an-authentication-key'
    const projectionBehind: InvariantId = 'did-web-projection-matches-the-log'
    const shapes = [
      { shape: 'passphrase', allow: [noAuthentication] },
      {
        shape: 'second-credential',
        allow: [noAuthentication, projectionBehind]
      },
      { shape: 'recovery-code', allow: [noAuthentication, projectionBehind] },
      { shape: 'enrolled-client', allow: [projectionBehind] }
    ] as const
    for (const { shape, allow } of shapes) {
      const account = await buildServerStateAccount({ harness, shape })
      expectInvariantsHold({
        audit: await auditInvariants({
          dataDir: harness.dataDir,
          spaceId: account.spaceId
        }),
        allow: [...allow]
      })
    }
  })

  it('the unreachable kind: a deleted pointed generation stands violated until a remembered login repairs it', async () => {
    const account = await buildEnrolledClientAccount({ harness })
    const breaker = await harness.logIn({
      passphrase: account.passphrase,
      profile: account.enrolledProfile,
      name: 'deletes the pointed generation'
    })
    expect((await breaker.settled()).failures).toEqual([])
    await deletePointedGeneration({ actor: breaker })
    const torn: InvariantId[] = [
      'annex-generation-is-reachable',
      'generation-delegation-is-current',
      'no-annex-generation-outlives-its-pointer'
    ]
    expectInvariantsHold({
      audit: await auditActor({
        harness,
        actor: breaker,
        passphrase: account.passphrase
      }),
      allow: torn
    })
    await breaker.logout()
    expectInvariantsHold({
      audit: await auditInvariants({
        dataDir: harness.dataDir,
        spaceId: account.spaceId
      }),
      allow: torn
    })

    const repairer = await harness.logIn({
      passphrase: account.passphrase,
      profile: account.enrolledProfile,
      name: 'remembered login that repairs'
    })
    expect(repairer.kind).toBe('remembered')
    await repairer.settled()
    const repaired = await auditActor({
      harness,
      actor: repairer,
      passphrase: account.passphrase
    })
    expectInvariantsHold({ audit: repaired })
    expectKeyHolderRowsChecked({ audit: repaired })
    await repairer.logout()
  })

  it('the none kind: a signup whose KMS stage failed stands violated after a transient visit', async () => {
    const passphrase = `audit-no-kms-${crypto.randomUUID()}-Zz9!`
    harness.faults.refuse({ match: { path: /^\/kms(\/|$)/ }, times: Infinity })
    let spaceId: string
    try {
      const signup = await harness.signUp({ passphrase, name: 'no-KMS signup' })
      await signup.settled()
      spaceId = signup.spaceId
      expectInvariantsHold({
        audit: await auditActor({ harness, actor: signup, passphrase }),
        allow: ['account-document-publishes-an-authentication-key']
      })
      await signup.logout()
    } finally {
      // No actor is live, so emptying the request record is safe.
      harness.faults.reset()
    }

    const visit = await harness.logIn({ passphrase, name: 'transient visit' })
    expect(visit.kind).toBe('transient')
    await visit.settled()
    const afterVisit = await auditActor({ harness, actor: visit, passphrase })
    expectInvariantsHold({
      audit: afterVisit,
      allow: ['account-document-publishes-an-authentication-key']
    })
    await visit.logout()
    expectInvariantsHold({
      audit: await auditInvariants({ dataDir: harness.dataDir, spaceId }),
      allow: ['account-document-publishes-an-authentication-key']
    })
  })
})
