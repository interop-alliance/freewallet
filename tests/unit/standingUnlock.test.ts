// @vitest-environment node
/**
 * Unit tests for the standing-configuration establishment
 * (`establishStandingUnlock` in `src/session/standingUnlock.ts`): it hands
 * the registry-entry members back to its caller (the Settings ceremonies own
 * the registry write, deciding after their own outcome which credential's
 * standing configuration the entry names), and it honors a caller-minted
 * ladder seed, so a ceremony can clean up a torn establishment by an actual
 * retirement.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { ladderRung } from '@interop/wallet-core/clientAnnex'
import { transientSessionPersistence } from '@/session/persistence'

vi.mock('@/session/enrolledContext', () => ({
  enrolledClientContext: vi.fn(() => ({ pointer: POINTER })),
  requireEnrolledClientContext: vi.fn(() => ({
    remoteStore: { webvhIdStore: vi.fn(() => ({ isWebvhIdStore: true })) },
    pointer: POINTER,
    clientWebvhKeys: { updateSeed: new Uint8Array(32) },
    clientKeyAgreementKey: { id: 'did:key:zClient#zKak' },
    keyAgent: { id: 'did:key:zClient' },
    controller: 'did:key:zAccount'
  }))
}))

vi.mock('@interop/wallet-core/unlock', () => ({
  publishUnlockKey: vi.fn(async () => ({}))
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  addUserKeyRosterRecipient: vi.fn(async () => ({}))
}))

vi.mock('@interop/wallet-core/recovery', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/recovery')>()),
  delegateLogWrite: vi.fn(async () => ({ id: 'urn:zcap:bridge' })),
  delegationProofKeyId: vi.fn(() => 'did:webvh:account#zSigner')
}))

vi.mock('@/session/keyring', () => ({
  bindUnlockSecret: vi.fn(async () => ({
    unlockSpaceId: 'space-new',
    manageCapability: { id: 'urn:zcap:manage' },
    persistClientKeys: vi.fn(async () => {})
  })),
  deriveUnlockCredential: vi.fn(async () => CREDENTIAL),
  fetchKeyring: vi.fn(async () => null),
  unlockManagementGrantee: vi.fn(() => 'did:key:zAccount')
}))

vi.mock('@/session/rosterStore', () => ({
  sessionRosterStore: vi.fn(() => ({ rosterStore: true }))
}))

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(),
  verifiedAccountLog: vi.fn(async () => ({ doc: { id: POINTER.did } }))
}))

vi.mock('@/session/annexReach', () => ({
  clientAnnexReachOf: vi.fn(),
  ensureGenerationDelegation: vi.fn(async () => {})
}))

vi.mock('@/lib/sessionKey', () => ({
  saveUserKeyEpochPin: vi.fn(async () => {}),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  mintSpaceId: vi.fn(() => 'space-annex')
}))

vi.mock('@/session/unlockMethods', () => ({
  emptyUnlockMethodsRegistry: vi.fn(() => ({
    version: 1,
    webAuthnUserId: 'handle',
    methods: []
  })),
  getUnlockMethods: vi.fn(async () => ({
    version: 1,
    webAuthnUserId: 'handle',
    methods: []
  })),
  updateUnlockMethods: vi.fn(
    async ({ mutate }: { mutate: (current: never) => unknown }) =>
      mutate({ version: 1, webAuthnUserId: 'handle', methods: [] } as never)
  ),
  refreshStandingDelegationFields: vi.fn(async () => {}),
  upsertPassphraseUnlockMethod: vi.fn(({ record }) => record)
}))

const POINTER = {
  did: 'did:webvh:QmScid:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const CREDENTIAL = {
  unlock: {},
  standing: {
    recipientKid: 'did:key:zCredential#zCredentialKak',
    keyAgreementKeyMultibase:
      'z6LSgJbFbAEq4zhHZ7FrQKqF6ja8tcjNpVu8ZbhnxmunPkN7',
    clientDid: 'did:key:zCredential'
  }
}

const { establishStandingUnlock } = await import('@/session/standingUnlock')
const { updateUnlockMethods } = await import('@/session/unlockMethods')

function makeSession() {
  return {
    user: { id: 'did:key:zClient', email: 'user@example.test' },
    profile: {
      clientSeed: new Uint8Array(32),
      accountController: 'did:key:zAccount',
      accountPointer: POINTER,
      zcapClient: { isZcapClient: true },
      userKey: { id: 'did:key:zUserKey', secret: new Uint8Array(32) },
      persistence: transientSessionPersistence()
    }
  } as unknown as Parameters<typeof establishStandingUnlock>[0]['session']
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('establishStandingUnlock', () => {
  it('returns the entry members and never writes the registry itself', async () => {
    const outcome = await establishStandingUnlock({
      session: makeSession(),
      secret: 'new',
      kdf: KEYRING_KDF,
      lowEntropy: true
    })
    expect(vi.mocked(updateUnlockMethods)).not.toHaveBeenCalled()
    expect(outcome.unlockSpaceId).toBe('space-new')
    expect(outcome.manageCapability).toEqual({ id: 'urn:zcap:manage' })
    expect(outcome.standingFields).toEqual(
      expect.objectContaining({
        rosterKid: CREDENTIAL.standing.recipientKid,
        keyAgreementKeyMultibase: CREDENTIAL.standing.keyAgreementKeyMultibase,
        unlockClientDid: CREDENTIAL.standing.clientDid
      })
    )
    expect(outcome.ladderSeed).toBeInstanceOf(Uint8Array)
  })

  it('uses a caller-minted ladder seed, so a torn run stays retirable by it', async () => {
    const ladderSeed = new Uint8Array(32).fill(9)
    const outcome = await establishStandingUnlock({
      session: makeSession(),
      secret: 'new',
      kdf: KEYRING_KDF,
      lowEntropy: true,
      ladderSeed
    })
    expect(outcome.ladderSeed).toBe(ladderSeed)
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    expect(outcome.standingFields.updateKeyMultibase).toBe(rung0.keyMultibase)
  })
})
