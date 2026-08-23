// @vitest-environment node
/**
 * Unit tests for freewallet's half of the client-revocation cascade
 * (`src/session/revocation.ts`). The cascade itself -- stage order,
 * convergence, the roster read -- is `revokeAccountClient` in
 * `@interop/wallet-core/clients` and is covered by that package's own tests;
 * what is exercised here is the glue this wallet supplies: the preconditions
 * gate, the self-revocation refusal, the `knownLatentHashes` hand-off from the
 * recovery registry, the options handed to the shared orchestrator, the
 * adoption side effects its callbacks perform (epoch pin, client-key record,
 * unlock-methods re-wrap, live vault keys and storage ciphers), the audit
 * record, and the no-roster outcome. Every remote/durable seam is mocked; the
 * latent-hash derivation runs for real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  calls: [] as string[],
  // The generation-delegation re-mint stage's seams.
  renewed: true,
  renewError: null as Error | null
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@interop/wallet-core/clients', () => ({
  revokeAccountClient: vi.fn()
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  userKeyVaultKeys: vi.fn(({ userKey }: { userKey: { id: string } }) => ({
    keyAgreementKey: { id: `${userKey.id}#kak` },
    keyResolver: async () => ({})
  }))
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  clientAnnexLogStore: vi.fn(() => ({ isClientAnnexLogStore: true })),
  mintGenerationDelegation: vi.fn(async () => ({ id: 'urn:zcap:fresh' })),
  ensureGenerationDelegationCurrent: vi.fn(async () => {
    state.calls.push('ensureGenerationDelegationCurrent')
    if (state.renewError) {
      throw state.renewError
    }
    return { renewed: state.renewed }
  })
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  WasClient: class {
    isWasClient = true
  }
}))

vi.mock('@/lib/sessionKey', () => ({
  savePinFromDescriptor: vi.fn(async () => {
    state.calls.push('savePinFromDescriptor')
  }),
  loadUserKeyEpochPin: vi.fn(async () => {
    state.calls.push('loadUserKeyEpochPin')
    // OLD_USER_KEY.id, restated: the factory is hoisted above the consts.
    return 'did:key:z6LSOldUserKey'
  }),
  // Built eagerly by the durable persistence handle the fixture carries.
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

vi.mock('@/session/rosterStore', () => ({
  sessionRosterStore: vi.fn(() => ({ rosterStore: true }))
}))

vi.mock('@/session/unlockMethods', () => ({
  getUnlockMethods: vi.fn(async () => null),
  rewrapUnlockMethodsRecord: vi.fn(async () => {
    state.calls.push('rewrapUnlockMethodsRecord')
  })
}))

vi.mock('@/session/recovery', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/recovery')>()),
  remintRecoveryDelegations: vi.fn(async () => {
    state.calls.push('remintRecoveryDelegations')
    return { reminted: 0, skipped: 0 }
  })
}))

vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollections: vi.fn(() => ({
    collectionIds: async () => ['private-credentials'],
    storeFor: () => ({ isDescriptorStore: true }),
    isEncrypted: async () => true
  }))
}))

import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { revokeAccountClient } from '@interop/wallet-core/clients'
import { userKeyVaultKeys } from '@interop/wallet-core/keys'
import {
  clientAnnexLogPinId,
  clientAnnexLogStore,
  ensureGenerationDelegationCurrent
} from '@interop/wallet-core/clientAnnex'
import { loadUserKeyEpochPin, savePinFromDescriptor } from '@/lib/sessionKey'
import { durableSessionPersistence } from '@/session/persistence'
import {
  getUnlockMethods,
  rewrapUnlockMethodsRecord
} from '@/session/unlockMethods'
import { remintRecoveryDelegations } from '@/session/recovery'
import { cascadeCollections } from '@/session/userKeyCascade'
import {
  revokeEnrolledClient,
  type RevokedClientKeys
} from '@/session/revocation'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const REVOKED: RevokedClientKeys = {
  signingKeyMultibase: 'z6MkRevokedClient',
  updateKeyMultibase: 'z6MkRevokedUpdate'
}

const OLD_USER_KEY = {
  id: 'did:key:z6LSOldUserKey',
  secret: new Uint8Array(32).fill(1)
}
const FRESH_USER_KEY = {
  id: 'did:key:z6LSFreshUserKey',
  secret: new Uint8Array(32).fill(2)
}
const ROSTER_DESCRIPTOR = { epochs: [{ id: FRESH_USER_KEY.id }] }
const DOCUMENT = { id: 'did:webvh:doc', verificationMethod: [] }

const CLIENT_ANNEX_SPACE_ID = 'clientAnnex-space-1'
const GENERATION_ID = 'gen-Ux3v0kQf9aPmB2hZ'
const CLIENT_ANNEX_DID =
  'did:webvh:QmClientAnnexScid:was.example.test:space:' +
  `${CLIENT_ANNEX_SPACE_ID}:${GENERATION_ID}`

/**
 * The post-edit account document with a `#DelegatedClients` service entry --
 * what makes the generation-delegation stage reachable.
 */
const POINTED_DOCUMENT = {
  ...DOCUMENT,
  service: [
    {
      id: `${DOCUMENT.id}#delegated-clients`,
      type: 'https://w3id.org/byoe#DelegatedClients',
      serviceEndpoint: CLIENT_ANNEX_DID
    }
  ]
}

/**
 * A stand-in for the shared orchestrator that drives its callbacks in the
 * documented order, so the freewallet-side stages are exercised exactly where
 * the real cascade runs them.
 *
 * @param options {object}
 * @param [options.rotated] {boolean}   whether the roster rotated on this run
 * @param [options.failedCollections] {number}
 * @param [options.document] {object}   the post-edit account document the
 *   re-mint stages are handed
 * @returns {Function}
 */
function orchestratorDriving({
  rotated = true,
  failedCollections = 0,
  document = DOCUMENT
}: {
  rotated?: boolean
  failedCollections?: number
  document?: object
} = {}) {
  return async (options: Parameters<typeof revokeAccountClient>[0]) => {
    state.calls.push('revokeAccountClient')
    const userKey = rotated ? FRESH_USER_KEY : OLD_USER_KEY
    if (rotated) {
      await options.onUserKeyAdopted?.({
        userKey,
        latestEpochId: userKey.id,
        descriptor: ROSTER_DESCRIPTOR as never
      })
    }
    state.calls.push('cascadeCollections')
    const recovery = await options.remintRecoveryDelegations?.({
      document: document as never
    })
    const generation = await options.remintGenerationDelegation?.({
      document: document as never
    })
    if (rotated) {
      await options.onRotationAdopted?.({ userKey })
    }
    return {
      rotated,
      collections: {
        outcomes: {
          'private-credentials': 'rotated',
          'wallet-activity': 'escrowed'
        },
        failed: Array.from({ length: failedCollections }, (_unused, index) => ({
          collectionId: `broken-${index}`,
          error: new Error('down')
        }))
      },
      document,
      userKey,
      ...(recovery ? { recovery } : {}),
      ...(generation ? { generation } : {})
    } as never
  }
}

/**
 * A live-session fixture carrying exactly what the cascade touches: the
 * remote store (with its roster-store handle), the profile key material, and
 * the storage adoption/history seams. Overrides poke holes for the
 * precondition tests.
 */
function sessionWith(
  overrides: Partial<{
    remoteStore: unknown
    pointerDid: string | undefined
    clientWebvhKeys: unknown
    clientKeyAgreementKey: unknown
    keyAgentId: string
    ladderSeed: Uint8Array
  }> = {}
): Session {
  const remoteStore =
    'remoteStore' in overrides
      ? overrides.remoteStore
      : {
          webvhIdStore: vi.fn(() => ({ isWebvhIdStore: true }))
        }
  return {
    user: { id: 'did:key:z6MkRevokingClient' },
    isGuest: false,
    storage: {
      remoteStore,
      adoptRotatedVaultKeys: vi.fn(async () => {
        state.calls.push('adoptRotatedVaultKeys')
      }),
      addHistoryClientRevoked: vi.fn(async () => {
        state.calls.push('addHistoryClientRevoked')
      })
    },
    profile: {
      accountPointer:
        'pointerDid' in overrides && overrides.pointerDid === undefined
          ? undefined
          : { ...POINTER, did: overrides.pointerDid ?? POINTER.did },
      keyAgent: {
        id: overrides.keyAgentId ?? 'did:key:z6MkRevokingClient',
        getSigner: () => ({ sign: async () => new Uint8Array(64) })
      },
      zcapClient: { isZcapClient: true },
      clientWebvhKeys:
        'clientWebvhKeys' in overrides
          ? overrides.clientWebvhKeys
          : { updateSeed: new Uint8Array(32), stagedSeed: new Uint8Array(32) },
      clientKeyAgreementKey:
        'clientKeyAgreementKey' in overrides
          ? overrides.clientKeyAgreementKey
          : { id: 'did:key:z6MkRevokingClient#z6LSRevokingClient' },
      userKey: OLD_USER_KEY,
      ...(overrides.ladderSeed ? { ladderSeed: overrides.ladderSeed } : {}),
      keyAgreementKey: { id: `${OLD_USER_KEY.id}#kak` },
      keyResolver: async () => ({}),
      persistence: durableSessionPersistence(),
      persistClientKeys: vi.fn(async () => {
        state.calls.push('persistClientKeys')
      })
    }
  } as unknown as Session
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.calls = []
  state.renewed = true
  state.renewError = null
  vi.clearAllMocks()
  vi.mocked(revokeAccountClient).mockImplementation(orchestratorDriving())
  vi.mocked(remintRecoveryDelegations).mockImplementation(async () => {
    state.calls.push('remintRecoveryDelegations')
    return { reminted: 2, skipped: 1 }
  })
})

describe('the preconditions gate', () => {
  it('refuses without a configured storage server or remote store', async () => {
    state.wasUrl = undefined
    await expect(
      revokeEnrolledClient({ session: sessionWith(), client: REVOKED })
    ).rejects.toThrow('configured storage server')

    state.wasUrl = 'https://was.example.test'
    await expect(
      revokeEnrolledClient({
        session: sessionWith({ remoteStore: undefined }),
        client: REVOKED
      })
    ).rejects.toThrow('configured storage server')
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
  })

  it('refuses an unpromoted pointer and missing client key material', async () => {
    await expect(
      revokeEnrolledClient({
        session: sessionWith({ pointerDid: 'did:key:z6MkNotPromoted' }),
        client: REVOKED
      })
    ).rejects.toThrow('promoted did:webvh')
    await expect(
      revokeEnrolledClient({
        session: sessionWith({ clientWebvhKeys: undefined }),
        client: REVOKED
      })
    ).rejects.toThrow('update keys')
    await expect(
      revokeEnrolledClient({
        session: sessionWith({ clientKeyAgreementKey: undefined }),
        client: REVOKED
      })
    ).rejects.toThrow('key-agreement key')
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
  })

  it('hands its own signing key over, so self-revocation is refused', async () => {
    await revokeEnrolledClient({ session: sessionWith(), client: REVOKED })
    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledWith(
      expect.objectContaining({
        ownSigningKeyMultibase: 'z6MkRevokingClient'
      })
    )
  })
})

describe('the cascade, torn in the collection fan-out', () => {
  it('has already re-sealed the registry when the fan-out dies', async () => {
    // The tear FW-296 closes: the cascade's roster tail adopted the fresh
    // user key -- which persists it into this browser's client-key record,
    // destroying the durable copy of the old one -- and then the collection
    // fan-out died. The registry must already be sealed to the fresh key by
    // then, or nothing anywhere could ever open it again.
    vi.mocked(revokeAccountClient).mockImplementation(async options => {
      state.calls.push('revokeAccountClient')
      await options.onUserKeyAdopted?.({
        userKey: FRESH_USER_KEY,
        latestEpochId: FRESH_USER_KEY.id,
        descriptor: ROSTER_DESCRIPTOR as never
      })
      throw new Error('the tab closed during the collection fan-out')
    })

    await expect(
      revokeEnrolledClient({ session: sessionWith(), client: REVOKED })
    ).rejects.toThrow('the tab closed')

    expect(state.calls).toEqual([
      'loadUserKeyEpochPin',
      'revokeAccountClient',
      'rewrapUnlockMethodsRecord',
      'savePinFromDescriptor',
      'persistClientKeys',
      'adoptRotatedVaultKeys'
    ])
    expect(state.calls.indexOf('rewrapUnlockMethodsRecord')).toBeLessThan(
      state.calls.indexOf('persistClientKeys')
    )
  })
})

describe('the cascade, rotated path', () => {
  it('runs the wallet-side stages in dependency order and reports the outcome', async () => {
    const session = sessionWith()
    const outcome = await revokeEnrolledClient({
      session,
      client: REVOKED,
      label: 'Old laptop'
    })

    expect(state.calls).toEqual([
      'loadUserKeyEpochPin',
      'revokeAccountClient',
      // The in-band adoption: the registry re-seal runs BEFORE this
      // browser's durable copy of the pre-rotation key dies, so a run torn
      // in the collection fan-out below leaves a registry the next login
      // can still open.
      'rewrapUnlockMethodsRecord',
      'savePinFromDescriptor',
      'persistClientKeys',
      'adoptRotatedVaultKeys',
      'cascadeCollections',
      'remintRecoveryDelegations',
      'addHistoryClientRevoked'
    ])
    expect(outcome).toEqual({
      rotated: true,
      collections: {
        outcomes: {
          'private-credentials': 'rotated',
          'wallet-activity': 'escrowed'
        },
        failed: []
      },
      recovery: { reminted: 2, skipped: 1 },
      generation: { renewed: false, skipped: 'no-pointer' }
    })
  })

  it('supplies the stores, key material, and collections source', async () => {
    const session = sessionWith()
    await revokeEnrolledClient({ session, client: REVOKED })

    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledWith(
      expect.objectContaining({
        idStore: { isWebvhIdStore: true },
        rosterStore: { rosterStore: true },
        updateKeys: session.profile.clientWebvhKeys,
        revokedClient: REVOKED,
        knownLatentHashes: [],
        userKey: OLD_USER_KEY,
        clientKeyAgreementKey: session.profile.clientKeyAgreementKey,
        pinnedEpochId: OLD_USER_KEY.id
      })
    )
    expect(vi.mocked(cascadeCollections)).toHaveBeenCalledWith({
      remoteStore: session.storage.remoteStore
    })
    expect(vi.mocked(loadUserKeyEpochPin)).toHaveBeenCalledWith(
      expect.objectContaining({ accountDid: POINTER.did })
    )
  })

  it('pins the fresh epoch and persists the rotated user key together', async () => {
    const session = sessionWith()
    await revokeEnrolledClient({ session, client: REVOKED })

    expect(vi.mocked(savePinFromDescriptor)).toHaveBeenCalledWith(
      expect.objectContaining({
        accountDid: POINTER.did,
        epochId: FRESH_USER_KEY.id,
        descriptor: ROSTER_DESCRIPTOR
      })
    )
    expect(session.profile.persistClientKeys).toHaveBeenCalledWith({
      userKey: FRESH_USER_KEY
    })
  })

  it('adopts the rotated user key into the live session', async () => {
    const session = sessionWith()
    const previousVaultKeys = {
      keyAgreementKey: session.profile.keyAgreementKey,
      keyResolver: session.profile.keyResolver
    }
    await revokeEnrolledClient({ session, client: REVOKED })

    expect(session.profile.userKey).toBe(FRESH_USER_KEY)
    expect(session.profile.keyAgreementKey?.id).toBe(`${FRESH_USER_KEY.id}#kak`)
    expect(vi.mocked(rewrapUnlockMethodsRecord)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        from: previousVaultKeys,
        to: expect.objectContaining({
          keyAgreementKey: { id: `${FRESH_USER_KEY.id}#kak` }
        })
      })
    )
    expect(session.storage.adoptRotatedVaultKeys).toHaveBeenCalledWith(
      expect.objectContaining({
        keyAgreementKey: { id: `${FRESH_USER_KEY.id}#kak` }
      })
    )
    expect(vi.mocked(userKeyVaultKeys)).toHaveBeenCalledWith({
      userKey: FRESH_USER_KEY
    })
  })

  it('records the audit history with the per-collection tallies', async () => {
    const session = sessionWith()
    await revokeEnrolledClient({
      session,
      client: REVOKED,
      label: 'Old laptop'
    })
    expect(session.storage.addHistoryClientRevoked).toHaveBeenCalledWith({
      user: session.user,
      signingKeyMultibase: REVOKED.signingKeyMultibase,
      label: 'Old laptop',
      rotated: 1,
      failed: 0
    })
  })

  it('reports a completed-but-unrotated cascade when there is no roster', async () => {
    // The shared orchestrator returns rather than throwing: the document edit
    // has landed, so the wallet IS disconnected with nothing to rotate.
    vi.mocked(revokeAccountClient).mockResolvedValue({
      rotated: false,
      collections: { outcomes: {}, failed: [] },
      document: DOCUMENT
    } as never)

    const session = sessionWith()
    const outcome = await revokeEnrolledClient({ session, client: REVOKED })

    expect(outcome).toEqual({
      rotated: false,
      collections: { outcomes: {}, failed: [] },
      recovery: { reminted: 0, skipped: 0 },
      generation: { renewed: false, skipped: 'no-pointer' }
    })
    expect(session.storage.addHistoryClientRevoked).toHaveBeenCalledOnce()
  })
})

describe('the knownLatentHashes hand-off', () => {
  it("passes the recovery registry's update-key hashes to the edit", async () => {
    vi.mocked(getUnlockMethods).mockResolvedValue({
      version: 1,
      userHandle: 'handle',
      methods: [
        { type: 'recovery-code', updateKeyMultibase: 'z6MkCodeUpdate' },
        { type: 'passkey', credentialId: 'ignored' }
      ]
    } as never)
    await revokeEnrolledClient({ session: sessionWith(), client: REVOKED })
    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledWith(
      expect.objectContaining({
        knownLatentHashes: [await deriveNextKeyHash('z6MkCodeUpdate')]
      })
    )
  })

  it('proceeds without them when the registry is unreadable', async () => {
    vi.mocked(getUnlockMethods).mockRejectedValue(new Error('offline'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await revokeEnrolledClient({ session: sessionWith(), client: REVOKED })
    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledWith(
      expect.objectContaining({ knownLatentHashes: [] })
    )
    warn.mockRestore()
  })
})

describe('re-run convergence and best-effort stages', () => {
  it('still re-mints on an already-rotated roster without re-adopting', async () => {
    vi.mocked(revokeAccountClient).mockImplementation(
      orchestratorDriving({ rotated: false })
    )
    const session = sessionWith()
    const outcome = await revokeEnrolledClient({ session, client: REVOKED })

    expect(outcome.rotated).toBe(false)
    expect(vi.mocked(remintRecoveryDelegations)).toHaveBeenCalledOnce()
    expect(session.storage.addHistoryClientRevoked).toHaveBeenCalledOnce()
    // Nothing re-persists or re-adopts: the session already holds this user key.
    expect(session.profile.persistClientKeys).not.toHaveBeenCalled()
    expect(vi.mocked(rewrapUnlockMethodsRecord)).not.toHaveBeenCalled()
    expect(session.storage.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(session.profile.userKey).toBe(OLD_USER_KEY)
  })

  it('tolerates failing adoption, re-wrap, and history stages', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const session = sessionWith()
    vi.mocked(rewrapUnlockMethodsRecord).mockRejectedValue(
      new Error('re-wrap down')
    )
    vi.mocked(session.storage.adoptRotatedVaultKeys).mockRejectedValue(
      new Error('cipher rebuild failed')
    )
    vi.mocked(session.storage.addHistoryClientRevoked).mockRejectedValue(
      new Error('history down')
    )
    const outcome = await revokeEnrolledClient({ session, client: REVOKED })
    expect(outcome.rotated).toBe(true)
    // The live profile still adopted the fresh user key even though the storage
    // cipher rebuild failed (the next login converges).
    expect(session.profile.userKey).toBe(FRESH_USER_KEY)
    warn.mockRestore()
  })

  it('reports a partial collection fan-out as a resumable success', async () => {
    vi.mocked(revokeAccountClient).mockImplementation(
      orchestratorDriving({ failedCollections: 2 })
    )
    const session = sessionWith()
    const outcome = await revokeEnrolledClient({ session, client: REVOKED })

    expect(outcome.rotated).toBe(true)
    expect(outcome.collections.failed).toHaveLength(2)
    expect(session.storage.addHistoryClientRevoked).toHaveBeenCalledWith(
      expect.objectContaining({ rotated: 1, failed: 2 })
    )
  })
})

describe('the generation-delegation re-mint stage', () => {
  const LADDER_SEED = new Uint8Array(32).fill(5)

  /**
   * Runs the cascade with the re-mint stage driven over the given document.
   *
   * @param [options] {object}
   * @param [options.document] {object}
   * @param [options.ladderSeed] {Uint8Array}
   * @returns {Promise<object>}
   */
  async function revokeWith({
    document = POINTED_DOCUMENT,
    ladderSeed
  }: { document?: object; ladderSeed?: Uint8Array } = {}) {
    vi.mocked(revokeAccountClient).mockImplementation(
      orchestratorDriving({ document })
    )
    return await revokeEnrolledClient({
      session: sessionWith(ladderSeed ? { ladderSeed } : {}),
      client: REVOKED
    })
  }

  it('re-mints the delegation against the post-edit document', async () => {
    const outcome = await revokeWith({ ladderSeed: LADDER_SEED })

    expect(outcome.generation).toEqual({ renewed: true })
    expect(vi.mocked(ensureGenerationDelegationCurrent)).toHaveBeenCalledWith(
      expect.objectContaining({
        store: { isClientAnnexLogStore: true },
        ladderSeed: LADDER_SEED,
        generationId: GENERATION_ID,
        expectedDid: CLIENT_ANNEX_DID,
        // The signer-death axis: the document the revocation edit just
        // produced, never a cached view.
        accountDoc: POINTED_DOCUMENT,
        logId: clientAnnexLogPinId({
          spaceId: CLIENT_ANNEX_SPACE_ID,
          generationId: GENERATION_ID
        })
      })
    )
    expect(vi.mocked(clientAnnexLogStore)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: CLIENT_ANNEX_SPACE_ID,
        generationId: GENERATION_ID
      })
    )
  })

  it('reports a healthy delegation as not renewed', async () => {
    state.renewed = false
    const outcome = await revokeWith({ ladderSeed: LADDER_SEED })
    expect(outcome.generation).toEqual({ renewed: false })
  })

  it('skips with no-pointer when the document names no annex', async () => {
    const outcome = await revokeWith({
      document: DOCUMENT,
      ladderSeed: LADDER_SEED
    })
    expect(outcome.generation).toEqual({
      renewed: false,
      skipped: 'no-pointer'
    })
    expect(vi.mocked(ensureGenerationDelegationCurrent)).not.toHaveBeenCalled()
  })

  it('skips with no-ladder-seed when the session carries no seed', async () => {
    const outcome = await revokeWith()
    expect(outcome.generation).toEqual({
      renewed: false,
      skipped: 'no-ladder-seed'
    })
    expect(vi.mocked(ensureGenerationDelegationCurrent)).not.toHaveBeenCalled()
  })

  it('reports a failure as skipped, the rest of the cascade intact', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    state.renewError = new Error('annex log unreachable')

    const outcome = await revokeWith({ ladderSeed: LADDER_SEED })

    // Best-effort by the cascade's contract: the login-time self-heal retries.
    expect(outcome.generation).toEqual({ renewed: false, skipped: 'failed' })
    expect(outcome.rotated).toBe(true)
    warn.mockRestore()
  })
})
