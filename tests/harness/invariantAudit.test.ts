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
 * - The shape gate: a ladder-anchored and an enrolled server-state account
 *   each skip exactly the rows whose `standsOn` excludes their shape.
 * - Two key-holder rows over a state a test builds: a passkey removal whose
 *   unlock Space delete the server refused leaves that Space standing
 *   (`no-unlock-space-outlives-its-credential`), and a writer registered
 *   past its inactivity window stands violated until the page's listing
 *   read sweeps it (`no-registered-writer-outlives-its-expiry`).
 *
 * Run: `pnpm run test:harness`.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { InvariantId } from '@interop/wallet-core/menders'
import type { PasskeyUnlockMethod } from '@/session/unlockMethods'
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
 * One day, in milliseconds.
 */
const DAY_MS = 24 * 60 * 60 * 1000

/**
 * Asserts a key-holder audit checked every `key-holder` row and every
 * key-holder half: what it skipped is only the browser-local and unchecked
 * rows the census says nothing reaches, and the rows whose `standsOn`
 * excludes the account's shape.
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
      INVARIANT_CENSUS[id].kind !== 'unchecked' &&
      (audit.shape === undefined ||
        INVARIANT_CENSUS[id].standsOn.includes(audit.shape))
  )
  expect(reachable, 'rows a key holder should have settled').toEqual([])
}

/**
 * The ids an audit skipped on its shape gate, sorted.
 *
 * @param options {object}
 * @param options.audit {InvariantAudit}
 * @returns {InvariantId[]}
 */
function shapeSkippedIds({ audit }: { audit: InvariantAudit }): InvariantId[] {
  return audit.skipped
    .filter(({ reason }) => reason.startsWith('The row stands on '))
    .map(({ id }) => id)
    .sort()
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
    const withHolder = await auditActor({
      harness,
      actor: signup,
      passphrase,
      retiredUnlockSpaceIds: []
    })
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
    const afterVisit = await auditActor({
      harness,
      actor: visit,
      passphrase,
      retiredUnlockSpaceIds: []
    })
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
      // None of the builders retires a credential.
      const audit = await auditActor({
        harness,
        actor,
        ...credential,
        retiredUnlockSpaceIds: []
      })
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
      passphrase: account.passphrase,
      retiredUnlockSpaceIds: []
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

  it('the shape gate skips the rows whose standsOn excludes the account shape', async () => {
    const ladderAnchored = await buildServerStateAccount({
      harness,
      shape: 'passphrase'
    })
    const ladderAudit = await auditInvariants({
      dataDir: harness.dataDir,
      spaceId: ladderAnchored.spaceId
    })
    expect(ladderAudit.shape).toBe('ladder-anchored')
    // The browser-local enrolled-only rows keep their census reason.
    expect(shapeSkippedIds({ audit: ladderAudit })).toEqual([
      'registry-records-the-committed-ladder-rung'
    ])

    const enrolled = await buildServerStateAccount({
      harness,
      shape: 'enrolled-client'
    })
    const enrolledAudit = await auditInvariants({
      dataDir: harness.dataDir,
      spaceId: enrolled.spaceId
    })
    expect(enrolledAudit.shape).toBe('enrolled')
    expect(shapeSkippedIds({ audit: enrolledAudit })).toEqual([
      'acting-credential-manage-zcap-is-current',
      'keystore-controller-is-the-account-did',
      'registry-records-the-establishing-credential',
      'roster-and-collection-epochs-exist'
    ])
  })

  it('an unlock Space whose delete the server refused outlives the removed passkey', async () => {
    const outlives: InvariantId = 'no-unlock-space-outlives-its-credential'
    const account = await buildPasskeyAccount({ harness })
    const actor = await harness.logIn({
      passphrase: account.passphrase,
      name: 'removes the passkey'
    })
    expect((await actor.settled()).failures).toEqual([])
    const { getUnlockMethods } = await import('@/session/unlockMethods')
    const { removeAccountPasskey } = await import('@/session/accountSettings')
    const registry = await actor.run(session => getUnlockMethods({ session }))
    const entry = registry?.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    if (entry === undefined) {
      throw new Error('The passkey account holds no passkey entry.')
    }
    const { unlockSpaceId } = entry

    // Named while the registry still names it, the Space is a live
    // credential's, and the row holds.
    const beforeRemoval = await auditActor({
      harness,
      actor,
      passphrase: account.passphrase,
      retiredUnlockSpaceIds: [unlockSpaceId]
    })
    expect(beforeRemoval.held).toContain(outlives)

    // The server answers the Space delete with the masked 404, so the
    // removal reports the Space as a residue and drops the registry entry.
    const refusal = harness.faults.refuse({
      match: record =>
        record.method === 'DELETE' && record.path.includes(unlockSpaceId),
      status: 404,
      times: Infinity
    })
    await actor.run(session => removeAccountPasskey({ session, entry }))
    await refusal.fired

    const afterRemoval = await auditActor({
      harness,
      actor,
      passphrase: account.passphrase,
      retiredUnlockSpaceIds: [unlockSpaceId]
    })
    expect(
      afterRemoval.violated.find(({ id }) => id === outlives)?.evidence
    ).toEqual({ outlived: [unlockSpaceId] })
    // Without the retired credential's Space named, the row cannot be
    // scoped to this account.
    const unscoped = await auditActor({
      harness,
      actor,
      passphrase: account.passphrase
    })
    expect(unscoped.skipped.map(({ id }) => id)).toContain(outlives)
    await actor.logout()
  })

  it('a writer registered past its inactivity window stands violated until the listing read sweeps it', async () => {
    const outlives: InvariantId = 'no-registered-writer-outlives-its-expiry'
    const account = await buildEnrolledClientAccount({ harness })
    const actor = await harness.logIn({
      passphrase: account.passphrase,
      profile: account.enrolledProfile,
      name: 'registers a stale writer'
    })
    expect(actor.kind).toBe('remembered')
    expect((await actor.settled()).failures).toEqual([])
    const { enrolledCeremonyContext } =
      await import('@/session/accountCeremonyContext')
    const { readDirectoryListing } = await import('@/session/clients')
    const { connectionWritersMend } =
      await import('@/session/menders/encounterSites')
    const { CONNECTION_WRITER_POLICY, registerConnectionWriter } =
      await import('@interop/wallet-core/connections')

    // Registered and last seen a day past the inactivity window, as its
    // second session under the account.
    const lastSeen = new Date(
      Date.now() - CONNECTION_WRITER_POLICY.inactiveAfterMs - DAY_MS
    )
    const writerId = `stale-writer-${crypto.randomUUID()}`
    const outcome = await actor.run(async session => {
      const context = enrolledCeremonyContext({ session })
      if (context === null) {
        throw new Error('The remembered session holds no enrolled context.')
      }
      const accountDid = context.pointer.did
      const { store, hmacKey } = await session.storage.connectionsDirectory()
      return await registerConnectionWriter({
        store,
        hmacKey,
        local: {
          get: async () => ({
            accountDid,
            writerId,
            firstSessionAt: new Date(lastSeen.getTime() - DAY_MS).toISOString()
          }),
          put: async () => {}
        },
        accountDid,
        did: context.keyAgent.id,
        writerId,
        label: 'Harness',
        listedInDocument: true,
        sessionStartedAt: lastSeen,
        now: lastSeen
      })
    })
    expect(outcome).toBe('registered')

    const stale = await auditActor({
      harness,
      actor,
      passphrase: account.passphrase
    })
    const evidence = stale.violated.find(({ id }) => id === outlives)
      ?.evidence as { markedInactive: Array<{ writerId: string }> } | undefined
    expect(evidence?.markedInactive.map(writer => writer.writerId)).toEqual([
      writerId
    ])

    // The page's listing read runs the writer sweep's encounter.
    await actor.run(async session => {
      await readDirectoryListing({ session })
      await connectionWritersMend({ session })
    })
    const swept = await auditActor({
      harness,
      actor,
      passphrase: account.passphrase
    })
    expect(swept.held).toContain(outlives)
    await actor.logout()
  })
})
