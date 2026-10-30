// @vitest-environment node
/**
 * Unit tests for the standing-configuration establishment
 * (`establishStandingUnlock` in `src/session/standingUnlock.ts`): it hands
 * the registry-entry members back to its caller (the Settings ceremonies own
 * the registry write, deciding after their own outcome which credential's
 * standing configuration the entry names), and it honors a caller-minted
 * ladder seed, so a ceremony can clean up a torn establishment by an actual
 * retirement. The annex-generation establishment
 * (`establishClientAnnexGeneration`) is covered for its adoption of the
 * shared stage-3 fold: the pointer entry signs with this enrolled client's
 * own update keys, a generation the fold just minted skips the separate
 * delegation renewal, and an already-pointed generation runs it.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { ladderRung } from '@interop/wallet-core/webvh'
import { transientSessionStores } from '@/session/persistence'

vi.mock('@/session/accountCeremonyContext', async importOriginal => ({
  // The real projection-store pick: the enrolled kind hands its own id
  // store, so the stub's is what the publish receives.
  ceremonyProjectionStore: (
    await importOriginal<typeof import('@/session/accountCeremonyContext')>()
  ).ceremonyProjectionStore,
  enrolledCeremonyContext: vi.fn(() => ({ pointer: POINTER })),
  requireEnrolledCeremonyContext: vi.fn(() => enrolledContextStub()),
  // The establishment resolves the ceremony context when the caller supplies
  // none. A remembered session's is the enrolled kind, which root-invokes.
  accountCeremonyContext: vi.fn(async () => enrolledContextStub())
}))

/**
 * The enrolled-kind ceremony context the establishment's enrolled branch
 * reads: this client's own update keys sign the document entry, its
 * key-agreement key opens the roster, and every request root-invokes.
 *
 * @returns {object}
 */
function enrolledContextStub() {
  return {
    kind: 'enrolled',
    remoteStore: { webvhIdStore: vi.fn(() => ({ isWebvhIdStore: true })) },
    pointer: POINTER,
    signer: {
      kind: 'enrolled',
      updateKeys: { updateSeed: new Uint8Array(32) }
    },
    idStore: { isWebvhIdStore: true },
    rosterStore: { rosterStore: true },
    invoker: { zcapClient: { isZcapClient: true } },
    clientWebvhKeys: { updateSeed: new Uint8Array(32) },
    clientKeyAgreementKey: { id: 'did:key:zClient#zKak' },
    keyAgent: { id: 'did:key:zClient' },
    controller: 'did:key:zAccount'
  }
}

vi.mock('@interop/wallet-core/unlock', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/unlock')>()),
  publishUnlockKey: vi.fn(async () => ({}))
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  commitClientAnnexRung: vi.fn(async () => ({})),
  ensurePointedClientAnnexGeneration: vi.fn(async () => ({
    clientAnnexDid: ANNEX_DID,
    generationDelegation: { id: 'urn:zcap:generation' },
    generationMinted: true,
    spaceMinted: true
  })),
  mintDelegatedClientsDelegation: vi.fn(async () => ({
    id: 'urn:zcap:sibling'
  })),
  mintGenerationDelegation: vi.fn(async () => ({ id: 'urn:zcap:generation' }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  didKeyZcapClient: vi.fn(() => ({ isBootstrapZcapClient: true }))
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
  verifiedAccountLog: vi.fn(async () => ({
    doc: { id: POINTER.did },
    log: []
  }))
}))

vi.mock('@/session/annexReach', async importOriginal => ({
  clientAnnexReachOf: vi.fn(),
  ensureGenerationDelegation: vi.fn(async () => {}),
  isClientAnnexRungUncommittedError: (
    await importOriginal<typeof import('@/session/annexReach')>()
  ).isClientAnnexRungUncommittedError
}))

vi.mock('@/lib/sessionKey', () => ({
  saveUserKeyEpochPin: vi.fn(async () => {}),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  standingUnlockFields: (
    await importOriginal<typeof import('@/session/unlockMethods')>()
  ).standingUnlockFields,
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
  did: 'did:webvh:QmScid:localhost:space:space-123:id',
  spaceUrl: 'http://localhost/space/space-123/'
}

const ANNEX_DID = 'did:webvh:QmAnnexScid:localhost:space:space-annex:gen-1'

const CREDENTIAL = {
  unlock: {},
  standing: {
    recipientKid: 'did:key:zCredential#zCredentialKak',
    keyAgreementKeyMultibase:
      'z6LSgJbFbAEq4zhHZ7FrQKqF6ja8tcjNpVu8ZbhnxmunPkN7',
    clientDid: 'did:key:zCredential'
  }
}

const { establishClientAnnexGeneration, establishStandingUnlock } =
  await import('@/session/standingUnlock')
const { updateUnlockMethods } = await import('@/session/unlockMethods')
const { fetchKeyring } = await import('@/session/keyring')
const { clientAnnexReachOf, ensureGenerationDelegation } =
  await import('@/session/annexReach')
const { ensurePointedClientAnnexGeneration, mintDelegatedClientsDelegation } =
  await import('@interop/wallet-core/clientAnnex')

function makeSession() {
  return {
    user: { id: 'did:key:zClient', email: 'user@example.test' },
    profile: {
      clientSeed: new Uint8Array(32),
      accountController: 'did:key:zAccount',
      accountPointer: POINTER,
      zcapClient: { isZcapClient: true },
      userKey: { id: 'did:key:zUserKey', secret: new Uint8Array(32) }
    },
    persistence: transientSessionStores()
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

describe('establishClientAnnexGeneration', () => {
  /**
   * A standing credential's keyring hit and the annex reach the
   * establishment resolves.
   */
  function stubStandingCredential() {
    vi.mocked(fetchKeyring).mockResolvedValue({
      unlockSpaceId: 'space-cred',
      standing: {
        ladderSeed: new Uint8Array(32).fill(3),
        delegation: { id: 'urn:zcap:bridge' }
      },
      standingClient: {
        clientDid: CREDENTIAL.standing.clientDid,
        keyAgreementKeyMultibase: CREDENTIAL.standing.keyAgreementKeyMultibase
      },
      rebindStandingRecord: vi.fn(async () => {})
    } as never)
    vi.mocked(clientAnnexReachOf).mockReturnValue({
      spaceId: 'space-annex'
    } as never)
  }

  it('adopts the shared fold under this client and skips the renewal on a fresh mint', async () => {
    stubStandingCredential()

    await establishClientAnnexGeneration({
      session: makeSession(),
      secret: 'pass',
      kdf: KEYRING_KDF
    })

    // The shared stage-3 fold, driven by this enrolled client: its bare
    // did:key mints, its own document update keys sign the pointer entry.
    expect(ensurePointedClientAnnexGeneration).toHaveBeenCalledWith(
      expect.objectContaining({
        account: expect.objectContaining({ did: POINTER.did }),
        baseServerUrl: 'http://localhost/',
        mintController: 'did:key:zClient',
        signer: {
          kind: 'enrolled',
          updateKeys: expect.objectContaining({
            updateSeed: expect.any(Uint8Array)
          })
        }
      })
    )
    // The fold minted the generation with its delegation embedded, so the
    // separate renewal never runs.
    expect(ensureGenerationDelegation).not.toHaveBeenCalled()
    // The sibling delegation targets the fold's annex Space.
    expect(mintDelegatedClientsDelegation).toHaveBeenCalledWith(
      expect.objectContaining({ clientAnnexSpaceId: 'space-annex' })
    )
    expect(clientAnnexReachOf).toHaveBeenCalledWith(
      expect.objectContaining({ clientAnnexDid: ANNEX_DID })
    )
  })

  it('renews the delegation on an already-pointed generation', async () => {
    stubStandingCredential()
    vi.mocked(ensurePointedClientAnnexGeneration).mockResolvedValueOnce({
      clientAnnexDid: ANNEX_DID,
      generationDelegation: { id: 'urn:zcap:generation' },
      generationMinted: false,
      spaceMinted: false
    } as never)

    await establishClientAnnexGeneration({
      session: makeSession(),
      secret: 'pass',
      kdf: KEYRING_KDF
    })

    // The shared stage reused the pointed generation, so its embedded
    // delegation is installed or renewed on the annex reach, under the
    // credential's ladder.
    expect(ensureGenerationDelegation).toHaveBeenCalledOnce()
    expect(ensureGenerationDelegation).toHaveBeenCalledWith(
      expect.objectContaining({
        pointer: POINTER,
        reach: { spaceId: 'space-annex' },
        ladderSeed: new Uint8Array(32).fill(3)
      })
    )
    // The renewal precedes the sibling delegation's mint.
    expect(
      vi.mocked(ensureGenerationDelegation).mock.invocationCallOrder[0]!
    ).toBeLessThan(
      vi.mocked(mintDelegatedClientsDelegation).mock.invocationCallOrder[0]!
    )
  })
})
