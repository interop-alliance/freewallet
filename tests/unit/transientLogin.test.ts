// @vitest-environment node
/**
 * Unit tests for the transient login (`src/session/transientLogin.ts`): the
 * post-KDF posture routing (`routeUnlockLogin`) and the public-terminal
 * composition (`transientSessionFromKeyringHit`). The wallet-core companion
 * and roster boundaries are mocked at the module seam so the composition's
 * wiring -- what enrolls with which key, what reads under which capability,
 * what refuses with which typed reason before anything is written -- runs
 * deterministically; the per-visit key mint (`agentsFromSeed`) runs for real.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@/lib/sessionKey', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/sessionKey')>()),
  hasClientKeyRecord: vi.fn()
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn(),
  enrollTransientClient: vi.fn(),
  embeddedGenerationDelegation: vi.fn(),
  delegatedClientsPointer: vi.fn(),
  delegatedClientsDelegationSpaceId: vi.fn(),
  delegatedWebvhLogStore: vi.fn(),
  webvhZcapClient: vi.fn()
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  userKeyRosterDescriptorStore: vi.fn(),
  readUserKeyRoster: vi.fn(),
  userKeyRosterLogSigner: vi.fn(() => ({ isRosterSigner: true })),
  ensureUserKeyRoster: vi.fn(),
  ensureWalletSpaceEpochs: vi.fn(async () => ({ outcomes: {}, failed: [] }))
}))

vi.mock('@/session/initSession', () => ({
  initSessionFromSeed: vi.fn()
}))

vi.mock('@/session/clientlessGenesis', () => ({
  establishClientlessAccount: vi.fn()
}))

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/keyring')>()),
  fetchTransientKeyring: vi.fn()
}))

import {
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  delegatedWebvhLogStore,
  embeddedGenerationDelegation,
  enrollTransientClient,
  verifyAccountLog,
  webvhZcapClient
} from '@interop/wallet-core/webvh'
import {
  ensureUserKeyRoster,
  ensureWalletSpaceEpochs,
  readUserKeyRoster,
  userKeyRosterDescriptorStore
} from '@interop/wallet-core/keys'
import { hasClientKeyRecord } from '@/lib/sessionKey'
import { establishClientlessAccount } from '@/session/clientlessGenesis'
import { fetchTransientKeyring } from '@/session/keyring'
import { initSessionFromSeed } from '@/session/initSession'
import type { TransientKeyringFetchResult } from '@/session/keyring'
import { transientSessionPersistence } from '@/session/persistence'
import {
  AlreadyRememberedError,
  routeUnlockLogin,
  TransientLoginUnavailableError,
  transientSessionFromKeyringHit
} from '@/session/transientLogin'

const KDF = { algorithm: 'PBKDF2', iterations: 1, version: 1 } as never
const CREDENTIAL = {
  unlock: { spaceId: 'unlock-space-1' },
  standing: {}
} as never

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const COMPANION_DID =
  'did:webvh:QmCompanionScid:was.example.test:space:companion-space-1:gen-Ux3v0kQf9aPmB2hZ'
const GENERATION_DELEGATION = { id: 'urn:zcap:generation' }
const SIBLING_DELEGATION = { id: 'urn:zcap:sibling' }

/**
 * A transient keyring hit in the standing layout, overridable per test.
 */
function makeFound(
  overrides: Partial<TransientKeyringFetchResult> = {}
): TransientKeyringFetchResult {
  return {
    controller: 'did:key:z6MkController',
    pointer: POINTER,
    email: 'record@example.test',
    createdAt: new Date().toISOString(),
    unlockSpaceId: 'unlock-space-1',
    standing: {
      delegation: { id: 'urn:zcap:bridge' },
      delegatedClients: SIBLING_DELEGATION,
      ladderSeed: new Uint8Array(32).fill(7)
    },
    standingClient: {
      clientDid: 'did:key:z6MkStandingClient',
      agents: {
        zcapClient: { isCredentialZcapClient: true },
        keyAgreementKey: { id: 'did:key:z6MkStandingClient#z6LSkak' }
      }
    },
    ...overrides
  } as unknown as TransientKeyringFetchResult
}

/**
 * Installs the happy-path mocks: a verified account log whose document
 * points at a companion generation, an enrollment handing back the
 * generation document, an embedded delegation, and a roster read that
 * unwraps the user key.
 */
function primeHappyPath() {
  vi.mocked(verifyAccountLog).mockResolvedValue({
    doc: { id: POINTER.did },
    log: [{ entry: 1 }],
    updateKeys: [],
    nextKeyHashes: []
  } as never)
  vi.mocked(delegatedClientsPointer).mockReturnValue(COMPANION_DID)
  vi.mocked(delegatedClientsDelegationSpaceId).mockReturnValue(
    'companion-space-1'
  )
  vi.mocked(delegatedWebvhLogStore).mockReturnValue({
    getIdResourceRaw: vi.fn(async () => ({ text: 'log', etag: '"1"' })),
    putIdResource: vi.fn(async () => undefined)
  } as never)
  vi.mocked(enrollTransientClient).mockResolvedValue({
    companionDid: COMPANION_DID,
    doc: { id: COMPANION_DID },
    log: [{ entry: 1 }]
  } as never)
  vi.mocked(embeddedGenerationDelegation).mockReturnValue(
    GENERATION_DELEGATION as never
  )
  vi.mocked(webvhZcapClient).mockReturnValue({
    isCompanionZcapClient: true
  } as never)
  vi.mocked(userKeyRosterDescriptorStore).mockReturnValue({
    isRosterStore: true
  } as never)
  vi.mocked(readUserKeyRoster).mockResolvedValue({
    descriptor: { epochs: [{ id: 'did:key:z6LSepoch1' }] },
    userKey: { id: 'did:key:z6LSepoch1', secret: new Uint8Array(32) },
    rotated: true,
    latestEpochId: 'did:key:z6LSepoch1'
  } as never)
  vi.mocked(initSessionFromSeed).mockResolvedValue({
    session: { profile: {} },
    userExists: true
  } as never)
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  vi.mocked(hasClientKeyRecord).mockResolvedValue(false)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('routeUnlockLogin -- the post-KDF posture decision', () => {
  it('defaults to transient on a non-remembered browser', async () => {
    const routed = await routeUnlockLogin({ kdf: KDF, credential: CREDENTIAL })
    expect(routed.posture).toBe('transient')
    if (routed.posture === 'transient') {
      expect(routed.credential).toBe(CREDENTIAL)
      expect(routed.persistence.durability).toBe('in-memory')
    }
    expect(hasClientKeyRecord).toHaveBeenCalledWith({
      spaceId: 'unlock-space-1',
      idb: undefined
    })
  })

  it('routes durable when this credential is remembered here (the ratchet)', async () => {
    vi.mocked(hasClientKeyRecord).mockResolvedValue(true)
    const routed = await routeUnlockLogin({ kdf: KDF, credential: CREDENTIAL })
    expect(routed.posture).toBe('durable')
  })

  it('refuses rememberBrowser: false on a remembered browser', async () => {
    vi.mocked(hasClientKeyRecord).mockResolvedValue(true)
    await expect(
      routeUnlockLogin({
        kdf: KDF,
        credential: CREDENTIAL,
        rememberBrowser: false
      })
    ).rejects.toBeInstanceOf(AlreadyRememberedError)
  })

  it('routes durable on rememberBrowser: true without probing', async () => {
    const routed = await routeUnlockLogin({
      kdf: KDF,
      credential: CREDENTIAL,
      rememberBrowser: true
    })
    expect(routed.posture).toBe('durable')
    expect(hasClientKeyRecord).not.toHaveBeenCalled()
  })

  it('routes durable with no WAS server, refusing an explicit transient ask', async () => {
    state.wasUrl = undefined
    const routed = await routeUnlockLogin({ kdf: KDF, credential: CREDENTIAL })
    expect(routed.posture).toBe('durable')
    expect(hasClientKeyRecord).not.toHaveBeenCalled()
    await expect(
      routeUnlockLogin({
        kdf: KDF,
        credential: CREDENTIAL,
        rememberBrowser: false
      })
    ).rejects.toMatchObject({
      name: 'TransientLoginUnavailableError',
      reason: 'no-was-server'
    })
  })

  it('keeps the remote-direct (popup) session on the durable route', async () => {
    const routed = await routeUnlockLogin({
      kdf: KDF,
      credential: CREDENTIAL,
      remoteDirectStorage: true
    })
    expect(routed.posture).toBe('durable')
    expect(hasClientKeyRecord).not.toHaveBeenCalled()
    await expect(
      routeUnlockLogin({
        kdf: KDF,
        credential: CREDENTIAL,
        remoteDirectStorage: true,
        rememberBrowser: false
      })
    ).rejects.toMatchObject({ reason: 'remote-direct' })
  })
})

describe('transientSessionFromKeyringHit -- typed refusals', () => {
  /**
   * Runs the composition against the current mocks and returns the caught
   * refusal.
   */
  async function refusalFor(found: TransientKeyringFetchResult) {
    try {
      await transientSessionFromKeyringHit({
        found,
        type: 'passphrase',
        persistence: transientSessionPersistence()
      })
    } catch (err) {
      return err
    }
    throw new Error('expected a refusal')
  }

  it('refuses a record without standing authority', async () => {
    const err = await refusalFor(makeFound({ standing: undefined }))
    expect(err).toBeInstanceOf(TransientLoginUnavailableError)
    expect((err as TransientLoginUnavailableError).reason).toBe('no-standing')
  })

  it('refuses a standing record without the delegatedClients sibling', async () => {
    const found = makeFound()
    delete (found.standing as { delegatedClients?: unknown }).delegatedClients
    const err = await refusalFor(found)
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-delegated-clients'
    )
  })

  it('refuses an unpromoted account pointer', async () => {
    const err = await refusalFor(
      makeFound({ pointer: { ...POINTER, did: 'did:key:z6MkNotWebvh' } })
    )
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'unpromoted-account'
    )
  })

  it('refuses when the account document carries no companion pointer', async () => {
    primeHappyPath()
    vi.mocked(delegatedClientsPointer).mockReturnValue(undefined)
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-companion-generation'
    )
    expect(enrollTransientClient).not.toHaveBeenCalled()
  })

  it('refuses a collected generation from the store wrapper, pre-write', async () => {
    primeHappyPath()
    vi.mocked(delegatedWebvhLogStore).mockReturnValue({
      getIdResourceRaw: vi.fn(async () => undefined),
      putIdResource: vi.fn(async () => undefined)
    } as never)
    // Drive the wrapper the way the enrollment's first read would.
    vi.mocked(enrollTransientClient).mockImplementation(
      async ({ storeForGenerationId }) => {
        await storeForGenerationId('gen-Ux3v0kQf9aPmB2hZ').getIdResourceRaw({
          resourceId: 'did.jsonl'
        })
        throw new Error('unreachable')
      }
    )
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-companion-generation'
    )
  })

  it('refuses instead of minting a generation delegation', async () => {
    primeHappyPath()
    vi.mocked(enrollTransientClient).mockImplementation(
      async ({ mintGenerationDelegation }) => {
        await mintGenerationDelegation!({ companionDid: COMPANION_DID })
        throw new Error('unreachable')
      }
    )
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-generation-delegation'
    )
  })

  it('refuses a generation document with no embedded delegation', async () => {
    primeHappyPath()
    vi.mocked(embeddedGenerationDelegation).mockReturnValue(undefined)
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-generation-delegation'
    )
    expect(readUserKeyRoster).not.toHaveBeenCalled()
  })

  it('refuses when even the tear heal leaves no user key roster', async () => {
    primeHappyPath()
    vi.mocked(readUserKeyRoster).mockResolvedValue(null as never)
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-user-key-roster'
    )
    // The heal ran before the refusal: it is the promoted-account-with-no-
    // roster carve-out, and only its own empty re-read refuses.
    expect(ensureUserKeyRoster).toHaveBeenCalled()
    expect(initSessionFromSeed).not.toHaveBeenCalled()
  })

  it('rethrows a network failure unchanged (flap, not lapse)', async () => {
    primeHappyPath()
    const offline = new TypeError('Failed to fetch')
    vi.mocked(verifyAccountLog).mockRejectedValue(offline)
    const err = await refusalFor(makeFound())
    expect(err).toBe(offline)
  })
})

describe('transientSessionFromKeyringHit -- the composition wiring', () => {
  it('enrolls, reads the standing wrap under the delegation, and assembles', async () => {
    primeHappyPath()
    const persistence = transientSessionPersistence()
    const found = makeFound()

    const { session, userExists } = await transientSessionFromKeyringHit({
      found,
      type: 'passphrase',
      email: 'typed@example.test',
      persistence
    })

    // The enrollment: the credential's ladder seed, a real per-visit key
    // multibase, the visit's in-memory pins, and the sibling-delegated store.
    const enrollCall = vi.mocked(enrollTransientClient).mock.calls[0]![0]
    expect(enrollCall.ladderSeed).toBe(found.standing!.ladderSeed)
    expect(enrollCall.transientKeyMultibase).toMatch(/^z6Mk/)
    expect(enrollCall.pinStore).toBe(persistence.logPins)
    enrollCall.storeForGenerationId('gen-Ux3v0kQf9aPmB2hZ')
    expect(delegatedWebvhLogStore).toHaveBeenCalledWith({
      host: POINTER.host,
      spaceId: 'companion-space-1',
      collectionId: 'gen-Ux3v0kQf9aPmB2hZ',
      delegation: SIBLING_DELEGATION,
      zcapClient: found.standingClient.agents.zcapClient
    })

    // The account log was verified under the same in-memory pins.
    expect(verifyAccountLog).toHaveBeenCalledWith({
      did: POINTER.did,
      spaceId: POINTER.spaceId,
      host: POINTER.host,
      pinStore: persistence.logPins
    })

    // The roster read: companion spelling under the generation delegation,
    // unwrapped with the credential's own key-agreement key. No escrow: the
    // roster store is read-only here.
    expect(webvhZcapClient).toHaveBeenCalledWith({
      keyAgent: expect.anything(),
      did: COMPANION_DID
    })
    expect(userKeyRosterDescriptorStore).toHaveBeenCalledWith(
      expect.objectContaining({
        storageServerUrl: POINTER.host,
        spaceId: POINTER.spaceId,
        pinStore: persistence.logPins,
        capability: GENERATION_DELEGATION
      })
    )
    expect(readUserKeyRoster).toHaveBeenCalledWith({
      store: expect.objectContaining({ isRosterStore: true }),
      clientKeyAgreementKey: found.standingClient.agents.keyAgreementKey
    })

    // The session assembly: the transient option, the record's email
    // deferring to the typed one, and the stamps the durable tail applies.
    expect(initSessionFromSeed).toHaveBeenCalledWith(
      expect.objectContaining({
        accountPointer: POINTER,
        email: 'typed@example.test',
        persistence,
        transient: {
          companionDid: COMPANION_DID,
          invocationCapability: GENERATION_DELEGATION
        }
      })
    )
    expect(session.profile.accountController).toBe(found.controller)
    expect(session.profile.unlockMethod).toEqual({
      type: 'passphrase',
      unlockSpaceId: 'unlock-space-1'
    })
    expect(userExists).toBe(true)

    // The visit's epoch pin advanced in memory only.
    await expect(
      persistence.epochPins.load({ accountDid: POINTER.did })
    ).resolves.toBe('did:key:z6LSepoch1')
  })

  it('falls back to the record email when none is typed', async () => {
    primeHappyPath()
    await transientSessionFromKeyringHit({
      found: makeFound(),
      type: 'passkey',
      persistence: transientSessionPersistence()
    })
    expect(initSessionFromSeed).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'record@example.test' })
    )
  })
})

describe('transientSessionFromKeyringHit -- the client-less signup heals', () => {
  it('heals a promoted account with no roster: ladder-signed epoch[0] under the delegation', async () => {
    primeHappyPath()
    const persistence = transientSessionPersistence()
    const found = makeFound()
    // The first read finds nothing (the signup died before epoch[0]); the
    // re-read after the heal delivers the fresh key.
    vi.mocked(readUserKeyRoster)
      .mockResolvedValueOnce(null as never)
      .mockResolvedValue({
        descriptor: { epochs: [{ id: 'did:key:z6LSfresh' }] },
        userKey: { id: 'did:key:z6LSfresh', secret: new Uint8Array(32) },
        rotated: false,
        latestEpochId: 'did:key:z6LSfresh'
      } as never)

    const { session } = await transientSessionFromKeyringHit({
      found,
      type: 'passphrase',
      persistence
    })

    // The heal's roster store: the ladder-signed signer (not the visit
    // key's), still invoked under the generation delegation.
    const healStoreCall = vi
      .mocked(userKeyRosterDescriptorStore)
      .mock.calls.at(-1)![0]
    expect(healStoreCall.capability).toBe(GENERATION_DELEGATION)
    const ensureCall = vi.mocked(ensureUserKeyRoster).mock.calls[0]![0]
    expect(ensureCall.clientKeyAgreementKey).toBe(
      found.standingClient.agents.keyAgreementKey
    )
    expect(ensureCall.userKey.id).toMatch(/^did:key:/)
    // The collection epochs complete under the same delegated authority.
    expect(ensureWalletSpaceEpochs).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        capability: GENERATION_DELEGATION
      })
    )
    expect(session).toBeTruthy()
  })

  it('re-runs the establishment for a ladder-seeded record with no did, then re-enters', async () => {
    primeHappyPath()
    const persistence = transientSessionPersistence()
    const credential = CREDENTIAL
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    const refreshed = makeFound()
    vi.mocked(fetchTransientKeyring).mockResolvedValue(refreshed as never)

    const { session } = await transientSessionFromKeyringHit({
      found: torn,
      type: 'passphrase',
      persistence,
      credential
    })

    expect(establishClientlessAccount).toHaveBeenCalledWith(
      expect.objectContaining({
        credential,
        ladderSeed: torn.standing!.ladderSeed,
        pointer: torn.pointer,
        lowEntropy: true,
        persistence
      })
    )
    // The re-entry rode the refreshed record.
    expect(fetchTransientKeyring).toHaveBeenCalledWith({
      credential,
      accountLogPinStore: persistence.logPins
    })
    expect(session).toBeTruthy()
  })

  it('still refuses an unpromoted account with no credential in hand', async () => {
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    await expect(
      transientSessionFromKeyringHit({
        found: torn,
        type: 'passphrase',
        persistence: transientSessionPersistence()
      })
    ).rejects.toMatchObject({ reason: 'unpromoted-account' })
    expect(establishClientlessAccount).not.toHaveBeenCalled()
  })
})
