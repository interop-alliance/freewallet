// @vitest-environment node
/**
 * Unit tests for the pending-enrollment resume
 * (`src/session/pendingEnrollment.ts`): the routing predicate over a keyring
 * hit, and the four branch outcomes decided from the verified account-log
 * HISTORY -- complete (VM listed now), seeded re-run (never published), wipe
 * (published then removed; a revoked client is never re-published), and
 * discard (a seeded re-run is provably impossible) -- plus the fail-closed
 * bounds: a transport failure or continuity refusal rethrows unchanged and
 * deletes nothing, and an unclassified throw surfaces the typed refusal
 * rather than falling through. The log verification, the ceremony, and the
 * wipe are mocked at their seams; the client-identity derivation
 * (`agentsFromSeed`) runs for real so the VM-id comparison exercises the
 * true did:key multibase.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { WasError } from '@interop/was-client'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import { clientSigningKeyMultibase } from '@interop/wallet-core/webvh'

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn()
}))

vi.mock('@/session/forget', () => ({
  finishForgottenBrowserWipe: vi.fn(async () => {
    const err = new Error('browser forgotten')
    err.name = 'BrowserForgottenError'
    throw err
  })
}))

vi.mock('@/session/standingUnlock', () => ({
  selfEnrollStandingClient: vi.fn()
}))

vi.mock('@/session/recovery', () => ({
  resumeRecoverySpend: vi.fn()
}))

vi.mock('@/lib/sessionKey', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/sessionKey')>()),
  deleteClientKeyRecord: vi.fn(async () => {}),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

import { verifyAccountLog } from '@interop/wallet-core/webvh'
import { unlockClientIdentityFromSeed } from '@interop/wallet-core/unlock'
import { finishForgottenBrowserWipe } from '@/session/forget'
import { selfEnrollStandingClient } from '@/session/standingUnlock'
import { resumeRecoverySpend } from '@/session/recovery'
import { deleteClientKeyRecord } from '@/lib/sessionKey'
import {
  isPendingKeyringHit,
  PendingEnrollmentDiscardedError,
  resumePendingEnrollment
} from '@/session/pendingEnrollment'
import type { KeyringFetchResult } from '@/session/keyring'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const BUILT_ON_HEAD = { scid: 'QmScidForTests', versionId: '2-head' }
const USER_KEY = { id: 'did:key:zUserKey', secret: new Uint8Array(32) }

const CLIENT_SEED = new Uint8Array(32).fill(7)
let VM_ID = ''

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

function makeFound(overrides: Record<string, unknown> = {}) {
  const persistClientKeys = vi.fn(async () => {})
  const found = {
    controller: 'did:key:zAccount',
    pointer: POINTER,
    unlockSpaceId: 'unlock-space-test',
    createdAt: new Date().toISOString(),
    clientKeys: {
      clientSeed: CLIENT_SEED,
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      controller: 'did:key:zAccount',
      pointerDid: POINTER.did,
      pending: {
        ceremony: 'self-enrollment' as const,
        builtOnHead: BUILT_ON_HEAD
      }
    },
    standing: {
      delegation: { id: 'urn:zcap:bridge' },
      ladderSeed: randomSeed()
    },
    standingClient: {
      clientDid: 'did:key:zCredential',
      agents: { keyAgreementKey: {}, zcapClient: {} }
    },
    persistClientKeys,
    ...overrides
  } as unknown as KeyringFetchResult
  return { found, persistClientKeys }
}

/**
 * A verified-log stub: the head document, and one earlier version per entry
 * of `history`.
 */
function serveLog({
  headVmIds = [] as string[],
  historyVmIds = [] as string[][]
} = {}) {
  const entries = [
    ...historyVmIds.map(ids => ({
      state: { verificationMethod: ids.map(id => ({ id })) }
    })),
    { state: { verificationMethod: headVmIds.map(id => ({ id })) } }
  ]
  vi.mocked(verifyAccountLog).mockResolvedValue({
    did: POINTER.did,
    doc: { verificationMethod: headVmIds.map(id => ({ id })) },
    log: entries.map((entry, index) => ({
      ...entry,
      versionId: `${index + 1}-hash`
    }))
  } as never)
}

beforeEach(async () => {
  vi.clearAllMocks()
  if (!VM_ID) {
    const { keyAgent } = await agentsFromSeed({ seed: CLIENT_SEED })
    VM_ID = `${POINTER.did}#${clientSigningKeyMultibase({ keyAgent })}`
  }
})

describe('isPendingKeyringHit', () => {
  it('routes a userKey-less record on a promoted account to the resume', () => {
    const { found } = makeFound()
    expect(isPendingKeyringHit({ found })).toBe(true)
  })

  it('routes an enrolled-shape record to the ordinary login', () => {
    const { found } = makeFound()
    found.clientKeys = { ...found.clientKeys!, userKey: USER_KEY }
    delete found.clientKeys.pending
    expect(isPendingKeyringHit({ found })).toBe(false)
  })

  it('routes a userKey-holding record with no pointerDid enrolled (the amended discriminator)', () => {
    // Every record written before `pointerDid` -- and every pre-promotion
    // bind's -- looks like this. It must never route to the resume: that
    // would cost the offline start and misdescribe an enrolled browser.
    const { found } = makeFound()
    found.clientKeys = {
      clientSeed: CLIENT_SEED,
      webvhUpdateKeys: found.clientKeys!.webvhUpdateKeys,
      controller: 'did:key:zAccount',
      userKey: USER_KEY
    }
    expect(isPendingKeyringHit({ found })).toBe(false)
  })

  it('never fires without a record or without a promoted pointer', () => {
    const { found: recordless } = makeFound({ clientKeys: undefined })
    expect(isPendingKeyringHit({ found: recordless })).toBe(false)
    const { found: unpromoted } = makeFound({
      pointer: { did: 'did:key:zAccount', spaceId: 's', host: 'h' }
    })
    expect(isPendingKeyringHit({ found: unpromoted })).toBe(false)
  })
})

describe('resumePendingEnrollment -- branch decision', () => {
  it('completes through the ceremony resume when the VM is listed now', async () => {
    const { found } = makeFound()
    serveLog({ headVmIds: [VM_ID] })
    const completed = {
      clientKeys: { clientSeed: CLIENT_SEED, userKey: USER_KEY },
      persistClientKeys: vi.fn()
    }
    vi.mocked(selfEnrollStandingClient).mockResolvedValue(completed as never)

    const result = await resumePendingEnrollment({ found })

    expect(result).toBe(completed)
    expect(selfEnrollStandingClient).toHaveBeenCalledWith(
      expect.objectContaining({
        found,
        resume: {
          clientSeed: CLIENT_SEED,
          webvhUpdateKeys: found.clientKeys!.webvhUpdateKeys,
          builtOnHead: BUILT_ON_HEAD
        }
      })
    )
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('re-runs the enrollment seeded with the recorded key set when the VM was never published', async () => {
    const { found } = makeFound()
    serveLog({ headVmIds: ['did:webvh:other#zSomeoneElse'] })
    vi.mocked(selfEnrollStandingClient).mockResolvedValue({
      clientKeys: { clientSeed: CLIENT_SEED, userKey: USER_KEY },
      persistClientKeys: vi.fn()
    } as never)

    await resumePendingEnrollment({ found })

    expect(selfEnrollStandingClient).toHaveBeenCalledWith(
      expect.objectContaining({
        resume: expect.objectContaining({ clientSeed: CLIENT_SEED })
      })
    )
  })

  it('wipes (never re-publishes) a client published at an earlier version and since removed', async () => {
    const { found } = makeFound()
    serveLog({ headVmIds: [], historyVmIds: [[VM_ID]] })

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'BrowserForgottenError'
    })
    expect(finishForgottenBrowserWipe).toHaveBeenCalled()
    // The revoked client is NOT re-published or re-escrowed, and the record
    // is the wipe's to remove, not the discard's.
    expect(selfEnrollStandingClient).not.toHaveBeenCalled()
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('discards the record when the credential carries no standing authority', async () => {
    const { found } = makeFound({ standing: undefined })
    serveLog()

    await expect(resumePendingEnrollment({ found })).rejects.toThrow(
      PendingEnrollmentDiscardedError
    )
    expect(deleteClientKeyRecord).toHaveBeenCalledWith(
      expect.objectContaining({ spaceId: 'unlock-space-test' })
    )
    expect(selfEnrollStandingClient).not.toHaveBeenCalled()
  })

  it('discards the record when its pointerDid no longer matches the credential-authenticated pointer', async () => {
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pointerDid: 'did:webvh:QmOther:was.example.test:space:space-999:id'
    }
    serveLog()

    await expect(resumePendingEnrollment({ found })).rejects.toThrow(
      PendingEnrollmentDiscardedError
    )
    expect(deleteClientKeyRecord).toHaveBeenCalled()
  })

  it('decides the pointerDid-mismatch discard LAST: a listed VM still completes', async () => {
    // decisions/0007's discard-last ordering: the complete and wipe branches
    // are ruled out before any discard signal is consulted.
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pointerDid: 'did:webvh:QmOther:was.example.test:space:space-999:id'
    }
    serveLog({ headVmIds: [VM_ID] })
    vi.mocked(selfEnrollStandingClient).mockResolvedValue({
      clientKeys: { clientSeed: CLIENT_SEED, userKey: USER_KEY },
      persistClientKeys: vi.fn()
    } as never)

    await resumePendingEnrollment({ found })

    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('decides the pointerDid-mismatch discard LAST: a removed VM still wipes', async () => {
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pointerDid: 'did:webvh:QmOther:was.example.test:space:space-999:id'
    }
    serveLog({ headVmIds: [], historyVmIds: [[VM_ID]] })

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'BrowserForgottenError'
    })
    expect(finishForgottenBrowserWipe).toHaveBeenCalled()
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('refuses a spend-written record toward /recover instead of re-running it as an enrollment', async () => {
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pending: {
        ceremony: 'recovery-spend',
        builtOnHead: BUILT_ON_HEAD
      }
    }
    // The served log has reached the recorded built-on head (2 entries).
    serveLog({ historyVmIds: [[]] })

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'PendingEnrollmentError',
      reason: 'recovery-spend'
    })
    // The record is kept: the code is still unspent on this branch, and
    // /recover with the same code is the mender.
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it("surfaces the transport state when the served log has not reached a spend record's built-on head", async () => {
    // A truncated (or lagging) log looks exactly like never-published, so
    // no spend branch is decidable on it: record kept, retry later.
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pending: {
        ceremony: 'recovery-spend',
        builtOnHead: BUILT_ON_HEAD,
        unwrapKey: new Uint8Array(32).fill(3)
      }
    }
    serveLog() // one entry: behind the recorded '2-head'

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'PendingResumeLogUnavailableError'
    })
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
    expect(finishForgottenBrowserWipe).not.toHaveBeenCalled()
  })

  it('discards a spend record whose code was spent elsewhere (inventory retired by another entry)', async () => {
    // The log reached the head, the VM never published, and the spent
    // code's keyAgreement inventory is out of the document: /recover would
    // refuse the code as spent, so keeping the record would wedge the
    // browser -- the pending key set grants nothing and is discarded.
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pending: {
        ceremony: 'recovery-spend',
        builtOnHead: BUILT_ON_HEAD,
        unwrapKey: new Uint8Array(32).fill(3)
      }
    }
    serveLog({ historyVmIds: [[]] })

    await expect(resumePendingEnrollment({ found })).rejects.toThrow(
      PendingEnrollmentDiscardedError
    )
    expect(deleteClientKeyRecord).toHaveBeenCalled()
  })

  it('keeps the /recover refusal when the spent code still stands in the document', async () => {
    const unwrapKey = new Uint8Array(32).fill(3)
    const spentIdentity = await unlockClientIdentityFromSeed({
      clientSeed: unwrapKey
    })
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pending: {
        ceremony: 'recovery-spend',
        builtOnHead: BUILT_ON_HEAD,
        unwrapKey
      }
    }
    // The spent code's keyAgreement VM stands in the current document.
    serveLog({
      headVmIds: [`${POINTER.did}#${spentIdentity.keyAgreementKeyMultibase}`],
      historyVmIds: [[]]
    })

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'PendingEnrollmentError',
      reason: 'recovery-spend'
    })
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('completes a spend-written record through the spend resume when the VM is listed', async () => {
    // The add-and-retire entry landed; the spend resume (not the
    // self-enrollment ceremony) finishes the escrows, the registry
    // backfill, and the confirm-gated completion -- its show-once prompt
    // rides the resume result to the login surface.
    const { found } = makeFound()
    found.clientKeys = {
      ...found.clientKeys!,
      pending: {
        ceremony: 'recovery-spend',
        builtOnHead: BUILT_ON_HEAD,
        unwrapKey: new Uint8Array(32).fill(3),
        replacementCode: new Uint8Array(16).fill(5)
      }
    }
    serveLog({ headVmIds: [VM_ID] })
    const completed = {
      clientKeys: { clientSeed: CLIENT_SEED, userKey: USER_KEY },
      persistClientKeys: vi.fn(),
      recoverySpendPrompt: { replacementCode: 'zCode', complete: vi.fn() }
    }
    vi.mocked(resumeRecoverySpend).mockResolvedValue(completed as never)

    const result = await resumePendingEnrollment({ found })

    expect(result).toBe(completed)
    expect(resumeRecoverySpend).toHaveBeenCalledWith(
      expect.objectContaining({
        found,
        verifiedLog: expect.objectContaining({ did: POINTER.did })
      })
    )
    expect(selfEnrollStandingClient).not.toHaveBeenCalled()
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })
})

describe('resumePendingEnrollment -- fail-closed bounds', () => {
  it('rethrows a transport failure unchanged and deletes nothing', async () => {
    const outage = new WasError('network down')
    vi.mocked(verifyAccountLog).mockRejectedValue(outage)
    const { found } = makeFound()

    await expect(resumePendingEnrollment({ found })).rejects.toBe(outage)
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
    expect(finishForgottenBrowserWipe).not.toHaveBeenCalled()
  })

  it('rethrows a continuity refusal unchanged and deletes nothing', async () => {
    const refusal = new Error('rollback')
    refusal.name = 'ResourceLogContinuityError'
    vi.mocked(verifyAccountLog).mockRejectedValue(refusal)
    const { found } = makeFound()

    await expect(resumePendingEnrollment({ found })).rejects.toBe(refusal)
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('passes BuiltOnHeadNotReachedError through (the record is kept for a later retry)', async () => {
    const { found } = makeFound()
    serveLog()
    const lagging = new Error('log behind the recorded head')
    lagging.name = 'BuiltOnHeadNotReachedError'
    vi.mocked(selfEnrollStandingClient).mockRejectedValue(lagging)

    await expect(resumePendingEnrollment({ found })).rejects.toBe(lagging)
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('classifies a fetch network failure (a plain TypeError) as the transport state', async () => {
    // `verifyAccountLog` uses bare fetch: a network failure surfaces as a
    // plain TypeError, which `isStorageUnreachable` does not recognize. It
    // must still reach the storage-unreachable surface, record kept.
    vi.mocked(verifyAccountLog).mockRejectedValue(
      new TypeError('Failed to fetch')
    )
    const { found } = makeFound()

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'PendingResumeLogUnavailableError'
    })
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
    expect(finishForgottenBrowserWipe).not.toHaveBeenCalled()
  })

  it('classifies a server fault (a plain Error) as the transport state', async () => {
    vi.mocked(verifyAccountLog).mockRejectedValue(
      new Error('Fetching the account log failed: 503')
    )
    const { found } = makeFound()

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'PendingResumeLogUnavailableError'
    })
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('wraps an unclassified throw past the verify as the typed fail-closed refusal', async () => {
    const { found } = makeFound()
    serveLog({ headVmIds: [VM_ID] })
    vi.mocked(selfEnrollStandingClient).mockRejectedValue(new Error('boom'))

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'PendingEnrollmentError',
      reason: 'resume-failed'
    })
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })

  it('refuses (keeps the record) when a listed client cannot be completed', async () => {
    // The VM stands published but the record lost what the completion needs:
    // discarding it would strand a phantom the document lists, so the
    // refusal is fail-closed instead.
    const { found } = makeFound()
    found.clientKeys = {
      clientSeed: CLIENT_SEED,
      webvhUpdateKeys: found.clientKeys!.webvhUpdateKeys,
      controller: 'did:key:zAccount',
      pointerDid: POINTER.did
    }
    serveLog({ headVmIds: [VM_ID] })

    await expect(resumePendingEnrollment({ found })).rejects.toMatchObject({
      name: 'PendingEnrollmentError',
      reason: 'unresumable'
    })
    expect(deleteClientKeyRecord).not.toHaveBeenCalled()
  })
})
