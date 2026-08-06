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
  calls: [] as string[]
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

vi.mock('@/lib/sessionKey', () => ({
  saveUserKeyEpochPin: vi.fn(async () => {
    state.calls.push('saveUserKeyEpochPin')
  }),
  loadUserKeyEpochPin: vi.fn(async () => {
    state.calls.push('loadUserKeyEpochPin')
    // OLD_USER_KEY.id, restated: the factory is hoisted above the consts.
    return 'did:key:z6LSOldUserKey'
  })
}))

vi.mock('@/session/unlockMethods', () => ({
  getUnlockMethods: vi.fn(async () => null),
  rewrapUnlockMethodsRecord: vi.fn(async () => {
    state.calls.push('rewrapUnlockMethodsRecord')
  })
}))

vi.mock('@/session/recovery', () => ({
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
import { loadUserKeyEpochPin, saveUserKeyEpochPin } from '@/lib/sessionKey'
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
  keyAgreementKeyMultibase: 'z6LSRevokedClient',
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
const DOCUMENT = { id: 'did:webvh:doc' }

/**
 * A stand-in for the shared orchestrator that drives its callbacks in the
 * documented order, so the freewallet-side stages are exercised exactly where
 * the real cascade runs them.
 *
 * @param options {object}
 * @param [options.rotated] {boolean}   whether the roster rotated on this run
 * @param [options.failedCollections] {number}
 * @returns {Function}
 */
function orchestratorDriving({ rotated = true, failedCollections = 0 } = {}) {
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
      document: DOCUMENT
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
      document: DOCUMENT,
      userKey,
      ...(recovery ? { recovery } : {})
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
  }> = {}
): Session {
  const remoteStore =
    'remoteStore' in overrides
      ? overrides.remoteStore
      : {
          userKeyRosterStore: vi.fn(() => ({ rosterStore: true })),
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
      keyAgreementKey: { id: `${OLD_USER_KEY.id}#kak` },
      keyResolver: async () => ({}),
      persistClientKeys: vi.fn(async () => {
        state.calls.push('persistClientKeys')
      })
    }
  } as unknown as Session
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.calls = []
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
      'saveUserKeyEpochPin',
      'persistClientKeys',
      'cascadeCollections',
      'remintRecoveryDelegations',
      'rewrapUnlockMethodsRecord',
      'adoptRotatedVaultKeys',
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
      recovery: { reminted: 2, skipped: 1 }
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
      expect.objectContaining({ spaceId: POINTER.spaceId })
    )
  })

  it('pins the fresh epoch and persists the rotated user key together', async () => {
    const session = sessionWith()
    await revokeEnrolledClient({ session, client: REVOKED })

    expect(vi.mocked(saveUserKeyEpochPin)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        epochId: FRESH_USER_KEY.id,
        epochIds: [FRESH_USER_KEY.id]
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
      recovery: { reminted: 0, skipped: 0 }
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
