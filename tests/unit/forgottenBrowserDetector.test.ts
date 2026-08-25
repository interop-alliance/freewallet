// @vitest-environment node
/**
 * Unit tests for the forgotten-browser detector's narrowed trigger
 * (`assertClientStillEnrolled` in `src/session/forget.ts`, FW-280): an
 * ENROLLED-shape record whose verification method is gone from the verified
 * document still wipes and throws `BrowserForgottenError` exactly as before,
 * while a PENDING-shape record is spared without even verifying the log --
 * it is the resume's to route, and wiping it would destroy the resume's
 * only key set (freewallet `decisions/0007`). The log verification, the
 * replica store, and the wipe executor are mocked at their seams; the
 * client-identity derivation runs for real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import { clientSigningKeyMultibase } from '@interop/wallet-core/webvh'

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn()
}))

vi.mock('@/stores/browserStore', async importOriginal => ({
  ...(await importOriginal<typeof import('@/stores/browserStore')>()),
  BrowserStore: {
    initClient: vi.fn(async () => ({
      localStore: { wipeStorage: vi.fn(async () => {}) }
    }))
  }
}))

vi.mock('@/session/wipe', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/wipe')>()),
  executeLocalWipe: vi.fn(async () => ({ failed: [], unverified: [] }))
}))

import { verifyAccountLog } from '@interop/wallet-core/webvh'
import { executeLocalWipe } from '@/session/wipe'
import { assertClientStillEnrolled } from '@/session/forget'
import type { KeyringFetchResult } from '@/session/keyring'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const CLIENT_SEED = new Uint8Array(32).fill(9)
const USER_KEY = { id: 'did:key:zUserKey', secret: new Uint8Array(32) }

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

function enrolledRecord() {
  return {
    clientSeed: CLIENT_SEED,
    userKey: USER_KEY,
    webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
    controller: 'did:key:zAccount',
    pointerDid: POINTER.did
  }
}

function makeFound(clientKeys: Record<string, unknown>) {
  return {
    controller: 'did:key:zAccount',
    pointer: POINTER,
    unlockSpaceId: 'unlock-space-test',
    createdAt: new Date().toISOString(),
    clientKeys
  } as unknown as KeyringFetchResult
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('assertClientStillEnrolled -- the narrowed trigger', () => {
  it('wipes and throws for an enrolled-shape record whose VM left the document', async () => {
    vi.mocked(verifyAccountLog).mockResolvedValue({
      did: POINTER.did,
      doc: { verificationMethod: [{ id: `${POINTER.did}#zSomeoneElse` }] },
      log: []
    } as never)

    await expect(
      assertClientStillEnrolled({ found: makeFound(enrolledRecord()) })
    ).rejects.toMatchObject({ name: 'BrowserForgottenError' })
    expect(executeLocalWipe).toHaveBeenCalled()
  })

  it('returns the verification for an enrolled-shape record whose VM still stands', async () => {
    const { keyAgent } = await agentsFromSeed({ seed: CLIENT_SEED })
    const vmId = `${POINTER.did}#${clientSigningKeyMultibase({ keyAgent })}`
    const verified = {
      did: POINTER.did,
      doc: { verificationMethod: [{ id: vmId }] },
      log: []
    }
    vi.mocked(verifyAccountLog).mockResolvedValue(verified as never)

    await expect(
      assertClientStillEnrolled({ found: makeFound(enrolledRecord()) })
    ).resolves.toBe(verified)
    expect(executeLocalWipe).not.toHaveBeenCalled()
  })

  it('spares a pending-shape record without verifying anything (the resume owns it)', async () => {
    const pending = enrolledRecord() as Record<string, unknown>
    delete pending.userKey

    await expect(
      assertClientStillEnrolled({ found: makeFound(pending) })
    ).resolves.toBeUndefined()
    expect(verifyAccountLog).not.toHaveBeenCalled()
    expect(executeLocalWipe).not.toHaveBeenCalled()
  })

  it('treats a record predating pointerDid as enrolled (the userKey-only discriminator)', async () => {
    // Question 2 as amended: a userKey-holding record is enrolled whatever
    // its other members, so a pre-change record keeps today's detector
    // behavior instead of routing to the resume.
    const preChange = enrolledRecord() as Record<string, unknown>
    delete preChange.pointerDid
    vi.mocked(verifyAccountLog).mockResolvedValue({
      did: POINTER.did,
      doc: { verificationMethod: [{ id: `${POINTER.did}#zSomeoneElse` }] },
      log: []
    } as never)

    await expect(
      assertClientStillEnrolled({ found: makeFound(preChange) })
    ).rejects.toMatchObject({ name: 'BrowserForgottenError' })
    expect(executeLocalWipe).toHaveBeenCalled()
  })
})
