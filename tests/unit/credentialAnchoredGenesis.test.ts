// @vitest-environment node
/**
 * Unit tests for freewallet's binding onto the credential-anchored
 * establishment (`src/session/credentialAnchoredGenesis.ts`). The stage
 * order and the genesis landing checks live in wallet-core's orchestrator
 * (covered by its own suite); what runs here is the binding: the options the
 * app hands the orchestrator, the hooks it closes over (the unlock-record
 * codec with the credential/email/freshness floor, the bootstrap-identity
 * roster store, the keystore promotion), and the warn-only handling of the
 * ceremony's collected best-effort failures.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  kmsUrl: undefined as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  },
  get KMS_SERVER_URL() {
    return state.kmsUrl
  }
}))

vi.mock('@interop/was-client', async importOriginal => {
  class MockWasClient {
    options: unknown
    constructor(options: unknown) {
      this.options = options
    }
  }
  return {
    ...(await importOriginal<typeof import('@interop/was-client')>()),
    WasClient: MockWasClient
  }
})

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  establishCredentialAnchoredAccount: vi.fn(),
  ladderVmAgent: vi.fn(async () => ({ id: 'did:key:zLadder' }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  didKeyZcapClient: vi.fn(() => ({ isBootstrapZcapClient: true })),
  wasWebvhIdStore: vi.fn(() => ({ isIdStore: true }))
}))

vi.mock('@/lib/didWeb', () => ({
  didWebFromSpace: vi.fn(() => 'did:web:was.example.test:space:space-123'),
  ensureDidWeb: vi.fn(async () => ({ isKeyMap: true }))
}))

vi.mock('@/lib/kms', () => ({
  ensureKeystore: vi.fn(async () => ({ isKeystoreAgent: true })),
  promoteKeystoreController: vi.fn(async () => undefined)
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

import {
  establishCredentialAnchoredAccount as coreEstablish,
  ladderVmAgent
} from '@interop/wallet-core/clientAnnex'
import { bindCredentialAnchoredUnlockSecret } from '@/session/keyring'
import type { UnlockCredential } from '@/session/keyring'
import { accountRosterStore } from '@/session/rosterStore'
import { promoteKeystoreController } from '@/lib/kms'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import { transientSessionStores } from '@/session/persistence'

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
 * A completed orchestrator result, overridable per test.
 */
function establishmentResult(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    did: ACCOUNT_DID,
    unlockSpaceId: 'unlock-space-1',
    standingFields: { rosterKid: CREDENTIAL.standing.recipientKid },
    failed: [],
    ...overrides
  }
}

/**
 * Runs the binding against the current mocks and returns the options the
 * mocked wallet-core orchestrator received.
 */
async function establish(
  overrides: Record<string, unknown> = {}
): Promise<{
  establishment: Awaited<
    ReturnType<typeof establishCredentialAnchoredAccount>
  >
  options: Record<string, unknown>
}> {
  const persistence =
    (overrides.persistence as { logPins: unknown } | undefined) ??
    transientSessionStores()
  const establishment = await establishCredentialAnchoredAccount({
    credential: CREDENTIAL,
    ladderSeed: new Uint8Array(32).fill(7),
    pointer: POINTER,
    lowEntropy: true,
    ...overrides,
    persistence
  } as never)
  expect(coreEstablish).toHaveBeenCalledTimes(1)
  const options = vi.mocked(coreEstablish).mock
    .calls[0][0] as unknown as Record<string, unknown>
  return { establishment, options }
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.kmsUrl = undefined
  vi.mocked(coreEstablish).mockResolvedValue(establishmentResult() as never)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('establishCredentialAnchoredAccount -- the orchestrator binding', () => {
  it('hands wallet-core the standing members and the bootstrap wiring', async () => {
    const persistence = transientSessionStores()
    const { establishment, options } = await establish({ persistence })

    expect(establishment.did).toBe(ACCOUNT_DID)
    expect(options.wasServerUrl).toBe(POINTER.host)
    expect(options.spaceId).toBe(POINTER.spaceId)
    expect(options.standing).toEqual({
      clientDid: CREDENTIAL.standing.clientDid,
      keyAgreementKeyMultibase:
        CREDENTIAL.standing.keyAgreementKeyMultibase,
      recipientKid: CREDENTIAL.standing.recipientKid,
      keyAgreementKey: CREDENTIAL.standing.agents.keyAgreementKey
    })
    expect(options.lowEntropy).toBe(true)
    expect(options.pinStore).toBe(persistence.logPins)
    expect(options.idStore).toEqual({ isIdStore: true })
    expect(ladderVmAgent).toHaveBeenCalledTimes(1)
    // The bootstrap storage client the hooks share, signing as the ladder
    // VM's bare did:key.
    const bootstrapWas = (
      options.bootstrapWasFor as (context: object) => {
        options: { serverUrl: string; zcapClient: unknown }
      }
    )({})
    expect(bootstrapWas.options.serverUrl).toBe(POINTER.host)
    expect(bootstrapWas.options.zcapClient).toEqual({
      isBootstrapZcapClient: true
    })
    // A DID-less signup pointer states no expectedDid and no prior stamp.
    expect(options).not.toHaveProperty('expectedDid')
    expect(options).not.toHaveProperty('priorCreatedAt')
  })

  it('threads expectedDid, priorCreatedAt, and the caller tail through', async () => {
    const beforePromotion = vi.fn(async () => undefined)
    const { options } = await establish({
      pointer: { ...POINTER, did: ACCOUNT_DID },
      priorCreatedAt: '2026-08-20T00:00:00.000Z',
      beforePromotion
    })

    expect(options.expectedDid).toBe(ACCOUNT_DID)
    expect(options.priorCreatedAt).toBe('2026-08-20T00:00:00.000Z')
    expect(options.beforePromotion).toBe(beforePromotion)
  })

  it('closes the bindRecord hook over the credential, email, and pin floor', async () => {
    const freshnessPinFloor = { idb: { isIdbFactory: true } as never }
    const { options } = await establish({
      email: 'user@example.test',
      freshnessPinFloor
    })

    const bindRecord = options.bindRecord as (
      bind: Record<string, unknown>
    ) => Promise<unknown>
    const bind = {
      controller: 'did:key:zLadder',
      pointer: { ...POINTER, did: ACCOUNT_DID },
      delegation: { id: 'urn:zcap:bridge' },
      delegatedClients: { id: 'urn:zcap:sibling' },
      delegateManagementTo: ACCOUNT_DID,
      priorCreatedAt: '2026-08-22T00:00:00.000Z'
    }
    await bindRecord(bind)

    expect(bindCredentialAnchoredUnlockSecret).toHaveBeenCalledWith({
      ...bind,
      email: 'user@example.test',
      ladderSeed: new Uint8Array(32).fill(7),
      freshnessPinFloor,
      credential: CREDENTIAL
    })
  })

  it('builds the roster store on the bootstrap identity and the pin store', async () => {
    const persistence = transientSessionStores()
    const { options } = await establish({ persistence })

    const rosterStoreFor = options.rosterStoreFor as (context: {
      did: string
    }) => unknown
    expect(rosterStoreFor({ did: ACCOUNT_DID })).toEqual({
      isRosterStore: true
    })
    expect(accountRosterStore).toHaveBeenCalledWith({
      zcapClient: { isBootstrapZcapClient: true },
      keyAgent: { id: 'did:key:zLadder' },
      pointer: {
        did: ACCOUNT_DID,
        spaceId: POINTER.spaceId,
        host: POINTER.host
      },
      pinStore: persistence.logPins
    })
  })

  it('refuses with no WAS server before wallet-core is ever called', async () => {
    state.wasUrl = undefined

    await expect(
      establishCredentialAnchoredAccount({
        credential: CREDENTIAL,
        ladderSeed: new Uint8Array(32).fill(7),
        pointer: POINTER,
        lowEntropy: true,
        persistence: transientSessionStores()
      } as never)
    ).rejects.toThrow(TypeError)
    expect(coreEstablish).not.toHaveBeenCalled()
  })

  it('arms no KMS thunk without a KMS, and promoteKeystore no-ops', async () => {
    const { options } = await establish()

    expect(options).not.toHaveProperty('provideDidWebKeys')
    const promoteKeystore = options.promoteKeystore as (context: {
      did: string
    }) => Promise<void>
    await promoteKeystore({ did: ACCOUNT_DID })
    expect(promoteKeystoreController).not.toHaveBeenCalled()
  })

  it('arms the KMS thunk when a KMS is configured', async () => {
    state.kmsUrl = 'https://was.example.test/kms'
    const { options } = await establish()

    expect(typeof options.provideDidWebKeys).toBe('function')
  })

  it('warns the collected best-effort failures instead of throwing', async () => {
    const didWebError = new Error('the KMS hung')
    const keystoreError = new Error('the keystore promotion was refused')
    vi.mocked(coreEstablish).mockResolvedValue(
      establishmentResult({
        failed: [
          { stage: 'didWebKeys', error: didWebError },
          { stage: 'keystorePromotion', error: keystoreError }
        ]
      }) as never
    )
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    const { establishment } = await establish()

    expect(establishment.failed).toHaveLength(2)
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:genesis',
        level: 'warn',
        msg: expect.stringContaining('did:web provisioning failed'),
        err: didWebError
      })
    )
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:genesis',
        level: 'warn',
        msg: expect.stringContaining('Keystore controller promotion failed'),
        err: keystoreError
      })
    )
    removeSink()
  })
})
