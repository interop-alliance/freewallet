// @vitest-environment node
/**
 * Unit tests for the credential-anchored establishment
 * (`src/session/credentialAnchoredGenesis.ts`), focused on the genesis
 * landing check: wallet-core's ceremony COLLECTS its roster and epoch
 * failures instead of throwing, and on a credential-anchored account no
 * login-time sweep ever finishes them -- so the establishment must refuse
 * before the re-bind, leaving the record DID-less and the next login's heal
 * re-run as the completer. The wallet-core boundaries are mocked at the
 * module seam; what runs here is the stage wiring and the refusal.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined
}))

// Hoisted so the module-seam mock factories (which run before the module
// body's initializers) can name them.
const { CANDIDATE_USER_KEY_ID, CLIENT_ANNEX_DID } = vi.hoisted(() => ({
  CANDIDATE_USER_KEY_ID: 'did:key:zCandidate',
  CLIENT_ANNEX_DID:
    'did:webvh:QmClientAnnexScid:was.example.test:space:clientAnnex-space-1:' +
    'gen-Ux3v0kQf9aPmB2hZ'
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@interop/was-client', async importOriginal => {
  const configure = vi.fn(async () => undefined)
  class MockWasClient {
    space() {
      return { configure }
    }
  }
  return {
    ...(await importOriginal<typeof import('@interop/was-client')>()),
    WasClient: MockWasClient
  }
})

vi.mock('@interop/wallet-core/genesis', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/genesis')>()),
  ensurePromotedSpaceController: vi.fn(async () => undefined)
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  didKeyZcapClient: vi.fn(() => ({ isBootstrapZcapClient: true })),
  keyAgreementCommitment: vi.fn(async () => ({ commitment: 'zCommitment' })),
  verifyAccountLog: vi.fn(),
  wasWebvhIdStore: vi.fn(() => ({ isIdStore: true }))
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  clientAnnexDidParts: vi.fn(() => ({
    spaceId: 'clientAnnex-space-1',
    generationId: 'gen-Ux3v0kQf9aPmB2hZ'
  })),
  clientAnnexLogStore: vi.fn(() => ({ isAnnexLogStore: true })),
  delegatedClientsPointer: vi.fn(() => undefined),
  ensureCredentialAnchoredAccountGenesis: vi.fn(),
  ensureGenerationDelegationCurrent: vi.fn(async () => undefined),
  ladderRung: vi.fn(async ({ index }: { index: number }) => ({
    seed: new Uint8Array(32).fill(index),
    keyMultibase: `z6MkRung${index}`
  })),
  ladderVmAgent: vi.fn(async () => ({ id: 'did:key:zLadder' })),
  ladderVmZcapClient: vi.fn(async () => ({ isLadderZcapClient: true })),
  mintCredentialClientAnnexGeneration: vi.fn(async () => ({
    did: CLIENT_ANNEX_DID,
    generationId: 'gen-Ux3v0kQf9aPmB2hZ'
  })),
  mintDelegatedClientsDelegation: vi.fn(async () => ({
    id: 'urn:zcap:sibling'
  })),
  mintGenerationDelegation: vi.fn(async () => ({ id: 'urn:zcap:generation' })),
  setDelegatedClientsPointer: vi.fn(async () => undefined)
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  ensureWalletSpaceEpochs: vi.fn(async () => ({ outcomes: {}, failed: [] })),
  mintUserKey: vi.fn(async () => ({
    id: CANDIDATE_USER_KEY_ID,
    secret: new Uint8Array(32)
  })),
  readUserKeyRoster: vi.fn()
}))

vi.mock('@interop/wallet-core/recovery', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/recovery')>()),
  delegateLogWrite: vi.fn(async () => ({ id: 'urn:zcap:bridge' })),
  delegationProofKeyId: vi.fn(() => 'did:key:zLadder#zLadderVm')
}))

vi.mock('@/session/keyring', () => ({
  bindCredentialAnchoredUnlockSecret: vi.fn(async () => ({
    unlockSpaceId: 'unlock-space-1',
    createdAt: '2026-08-22T00:00:00.000Z'
  }))
}))

vi.mock('@/session/rosterStore', () => ({
  accountRosterStore: vi.fn(() => ({ isRosterStore: true }))
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  mintSpaceId: vi.fn(() => 'clientAnnex-space-1')
}))

import {
  ensureCredentialAnchoredAccountGenesis,
  mintCredentialClientAnnexGeneration,
  setDelegatedClientsPointer
} from '@interop/wallet-core/clientAnnex'
import { ensurePromotedSpaceController } from '@interop/wallet-core/genesis'
import {
  ensureWalletSpaceEpochs,
  readUserKeyRoster
} from '@interop/wallet-core/keys'
import { verifyAccountLog } from '@interop/wallet-core/webvh'
import { bindCredentialAnchoredUnlockSecret } from '@/session/keyring'
import type { UnlockCredential } from '@/session/keyring'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import { transientSessionPersistence } from '@/session/persistence'

const ACCOUNT_DID =
  'did:webvh:QmScidForTests:was.example.test:space:space-123:id'
const POINTER = {
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const CREDENTIAL = {
  standing: {
    recipientKid: 'did:key:z6MkStandingClient#z6LSkak',
    keyAgreementKeyMultibase: 'z6LSkak',
    clientDid: 'did:key:z6MkStandingClient',
    agents: {
      keyAgreementKey: { id: 'did:key:z6MkStandingClient#z6LSkak' }
    }
  }
} as unknown as UnlockCredential

/**
 * A genesis result in the standing shape, overridable per test.
 */
function genesisResult(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    did: ACCOUNT_DID,
    rosterDescriptor: { currentEpoch: CANDIDATE_USER_KEY_ID, epochs: [] },
    epochs: { outcomes: {}, failed: [] },
    failed: [],
    ...overrides
  }
}

/**
 * Runs the establishment against the current mocks, with an optional
 * pre-promotion tail spy.
 */
async function establish(
  beforePromotion?: (context: { userKey: { id: string } }) => Promise<void>
) {
  return establishCredentialAnchoredAccount({
    credential: CREDENTIAL,
    ladderSeed: new Uint8Array(32).fill(7),
    pointer: POINTER,
    lowEntropy: true,
    persistence: transientSessionPersistence(),
    ...(beforePromotion ? { beforePromotion } : {})
  } as never)
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  vi.mocked(verifyAccountLog).mockResolvedValue({
    doc: { id: ACCOUNT_DID },
    log: [{ entry: 1 }]
  } as never)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('establishCredentialAnchoredAccount -- the landed genesis', () => {
  it('completes the establishment and hands the tail the candidate user key', async () => {
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult() as never
    )
    const seen: string[] = []

    const establishment = await establish(async ({ userKey }) => {
      seen.push(userKey.id)
    })

    expect(establishment.did).toBe(ACCOUNT_DID)
    expect(establishment.unlockSpaceId).toBe('unlock-space-1')
    expect(seen).toEqual([CANDIDATE_USER_KEY_ID])
    // No adopted roster, so no read-back and no follow-up epoch fan-out.
    expect(readUserKeyRoster).not.toHaveBeenCalled()
    expect(ensureWalletSpaceEpochs).not.toHaveBeenCalled()
    // The annex generation and both binds ran, and promotion came last.
    expect(mintCredentialClientAnnexGeneration).toHaveBeenCalledTimes(1)
    expect(setDelegatedClientsPointer).toHaveBeenCalledTimes(1)
    expect(bindCredentialAnchoredUnlockSecret).toHaveBeenCalledTimes(2)
    expect(ensurePromotedSpaceController).toHaveBeenCalledTimes(1)
  })

  it('recovers the adopted roster key on a heal and passes THAT key on', async () => {
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult({
        rosterDescriptor: { currentEpoch: 'did:key:zAdopted', epochs: [] },
        // The ceremony skips its own epochs stage on the key mismatch.
        epochs: undefined,
        epochsSkipped: { rosterEpochId: 'did:key:zAdopted' }
      }) as never
    )
    vi.mocked(readUserKeyRoster).mockResolvedValue({
      userKey: { id: 'did:key:zAdopted', secret: new Uint8Array(32) }
    } as never)
    const seen: string[] = []

    await establish(async ({ userKey }) => {
      seen.push(userKey.id)
    })

    expect(readUserKeyRoster).toHaveBeenCalledWith({
      store: expect.objectContaining({ isRosterStore: true }),
      clientKeyAgreementKey: CREDENTIAL.standing.agents.keyAgreementKey
    })
    // The collection epochs complete under the adopted key, not the candidate.
    expect(ensureWalletSpaceEpochs).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        userKey: expect.objectContaining({ id: 'did:key:zAdopted' })
      })
    )
    expect(seen).toEqual(['did:key:zAdopted'])
  })
})

describe('establishCredentialAnchoredAccount -- the genesis landing check', () => {
  /**
   * Runs the establishment against the current mocks and returns the caught
   * refusal.
   */
  async function refusal() {
    try {
      await establish()
    } catch (err) {
      return err
    }
    throw new Error('expected a refusal')
  }

  it('refuses a failed roster stage before anything downstream runs', async () => {
    const cause = new Error('the roster append lost its CAS')
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult({
        rosterDescriptor: undefined,
        failed: [{ stage: 'roster', error: cause }]
      }) as never
    )

    const err = await refusal()

    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toMatch(/roster stage failed/)
    expect((err as Error).cause).toBe(cause)
    // The first (interim) bind legitimately precedes the genesis; the
    // re-bind, the annex generation, the caller's tail, and the promotion
    // must all be unreached, so the record stays DID-less and heal-able.
    expect(bindCredentialAnchoredUnlockSecret).toHaveBeenCalledTimes(1)
    expect(mintCredentialClientAnnexGeneration).not.toHaveBeenCalled()
    expect(setDelegatedClientsPointer).not.toHaveBeenCalled()
    expect(ensurePromotedSpaceController).not.toHaveBeenCalled()
  })

  it('refuses a failed roster stage without invoking the caller tail', async () => {
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult({
        rosterDescriptor: undefined,
        failed: [{ stage: 'roster', error: new Error('nope') }]
      }) as never
    )
    const tail = vi.fn(async () => undefined)

    await expect(establish(tail)).rejects.toThrow(/roster stage failed/)
    expect(tail).not.toHaveBeenCalled()
  })

  it('refuses a failed epochs stage', async () => {
    const cause = new Error('the epoch stage never ran')
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult({ failed: [{ stage: 'epochs', error: cause }] }) as never
    )

    const err = await refusal()

    expect((err as Error).message).toMatch(/epochs stage failed/)
    expect((err as Error).cause).toBe(cause)
    expect(bindCredentialAnchoredUnlockSecret).toHaveBeenCalledTimes(1)
    expect(ensurePromotedSpaceController).not.toHaveBeenCalled()
  })

  it('refuses a per-collection epoch failure', async () => {
    const cause = new Error('the collection would not epoch')
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult({
        epochs: {
          outcomes: {},
          failed: [{ collectionId: 'contacts', error: cause }]
        }
      }) as never
    )

    const err = await refusal()

    expect((err as Error).message).toMatch(/key epoch on collection "contacts"/)
    expect((err as Error).cause).toBe(cause)
    expect(ensurePromotedSpaceController).not.toHaveBeenCalled()
  })

  it('refuses a genesis that reported no roster descriptor', async () => {
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult({ rosterDescriptor: undefined }) as never
    )

    const err = await refusal()

    expect((err as Error).message).toMatch(
      /user-key roster genesis did not land/
    )
    expect(bindCredentialAnchoredUnlockSecret).toHaveBeenCalledTimes(1)
    expect(mintCredentialClientAnnexGeneration).not.toHaveBeenCalled()
    expect(ensurePromotedSpaceController).not.toHaveBeenCalled()
  })

  it("refuses the heal branch's own per-collection epoch failure", async () => {
    const cause = new Error('the heal fan-out stranded a collection')
    vi.mocked(ensureCredentialAnchoredAccountGenesis).mockResolvedValue(
      genesisResult({
        rosterDescriptor: { currentEpoch: 'did:key:zAdopted', epochs: [] },
        // The ceremony skips its own epochs stage on the key mismatch.
        epochs: undefined,
        epochsSkipped: { rosterEpochId: 'did:key:zAdopted' }
      }) as never
    )
    vi.mocked(readUserKeyRoster).mockResolvedValue({
      userKey: { id: 'did:key:zAdopted', secret: new Uint8Array(32) }
    } as never)
    vi.mocked(ensureWalletSpaceEpochs).mockResolvedValue({
      outcomes: {},
      failed: [{ collectionId: 'wallet-activity', error: cause }]
    } as never)

    const err = await refusal()

    expect((err as Error).message).toMatch(
      /key epoch on collection "wallet-activity"/
    )
    expect((err as Error).cause).toBe(cause)
    expect(bindCredentialAnchoredUnlockSecret).toHaveBeenCalledTimes(1)
    expect(mintCredentialClientAnnexGeneration).not.toHaveBeenCalled()
    expect(ensurePromotedSpaceController).not.toHaveBeenCalled()
  })
})
