// @vitest-environment node
/**
 * Unit tests for the client-revocation cascade (`src/session/revocation.ts`):
 * the preconditions gate (a configured storage server, a promoted did:webvh
 * pointer, this client's key material), the self-revocation refusal (thrown
 * before anything durable is touched), the dependency order of the cascade
 * stages (document edit, roster rotation, epoch cascade, recovery re-mints,
 * live adoption, history), the `knownLatentHashes` hand-off from the
 * recovery registry, and re-run convergence (an already-rotated roster still
 * drives the collection cascade and the re-mints, but never re-persists or
 * re-adopts). Every remote/durable seam is mocked; the roster-kid and
 * latent-hash derivations run for real.
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

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  revokeWebvhClient: vi.fn(async () => {
    state.calls.push('revokeWebvhClient')
    return { did: 'did:webvh:unused' }
  })
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  rotatePukRoster: vi.fn(async () => {
    state.calls.push('rotatePukRoster')
    return {}
  }),
  readPukRoster: vi.fn(async () => {
    state.calls.push('readPukRoster')
    return null
  }),
  pukVaultKeys: vi.fn(({ puk }: { puk: { id: string } }) => ({
    keyAgreementKey: { id: `${puk.id}#kak` },
    keyResolver: async () => ({})
  }))
}))

vi.mock('@/lib/sessionKey', () => ({
  savePukEpochPin: vi.fn(async () => {
    state.calls.push('savePukEpochPin')
  })
}))

vi.mock('@/session/unlockMethods', () => ({
  getUnlockMethods: vi.fn(async () => null),
  rewrapUnlockMethodsRecord: vi.fn(async () => {
    state.calls.push('rewrapUnlockMethodsRecord')
  })
}))

vi.mock('@/session/recovery', () => ({
  verifyAccountLog: vi.fn(async () => {
    state.calls.push('verifyAccountLog')
    return { doc: { id: 'did:webvh:doc' } }
  }),
  remintRecoveryDelegations: vi.fn(async () => {
    state.calls.push('remintRecoveryDelegations')
    return { reminted: 0, skipped: 0 }
  })
}))

vi.mock('@/session/pukCascade', () => ({
  cascadeCollectionsToPuk: vi.fn(async () => {
    state.calls.push('cascadeCollectionsToPuk')
    return { outcomes: {}, failed: [] }
  })
}))

import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { revokeWebvhClient } from '@interop/wallet-core/webvh'
import {
  pukVaultKeys,
  readPukRoster,
  rotatePukRoster
} from '@interop/wallet-core/keys'
import { savePukEpochPin } from '@/lib/sessionKey'
import {
  getUnlockMethods,
  rewrapUnlockMethodsRecord
} from '@/session/unlockMethods'
import { remintRecoveryDelegations } from '@/session/recovery'
import { cascadeCollectionsToPuk } from '@/session/pukCascade'
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

const OLD_PUK = { id: 'did:key:z6LSOldPuk', secret: new Uint8Array(32).fill(1) }
const FRESH_PUK = {
  id: 'did:key:z6LSFreshPuk',
  secret: new Uint8Array(32).fill(2)
}
const ROSTER_DESCRIPTOR = { rosterDescriptor: true }

/**
 * A rotated-read roster result: another epoch id, a fresh PUK unwrapped with
 * this client's own key.
 */
function rotatedRead() {
  return {
    descriptor: ROSTER_DESCRIPTOR,
    puk: FRESH_PUK,
    rotated: true,
    latestEpochId: FRESH_PUK.id
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
      : { pukRosterStore: vi.fn(() => ({ rosterStore: true })) }
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
      keyAgent: { id: overrides.keyAgentId ?? 'did:key:z6MkRevokingClient' },
      zcapClient: { isZcapClient: true },
      clientWebvhKeys:
        'clientWebvhKeys' in overrides
          ? overrides.clientWebvhKeys
          : { updateSeed: new Uint8Array(32), stagedSeed: new Uint8Array(32) },
      clientKeyAgreementKey:
        'clientKeyAgreementKey' in overrides
          ? overrides.clientKeyAgreementKey
          : { id: 'did:key:z6MkRevokingClient#z6LSRevokingClient' },
      puk: OLD_PUK,
      keyAgreementKey: { id: `${OLD_PUK.id}#kak` },
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
  vi.mocked(readPukRoster).mockImplementation(async () => {
    state.calls.push('readPukRoster')
    return rotatedRead() as never
  })
  vi.mocked(cascadeCollectionsToPuk).mockImplementation(async () => {
    state.calls.push('cascadeCollectionsToPuk')
    return {
      outcomes: {
        'private-credentials': 'rotated',
        'wallet-activity': 'escrowed'
      },
      failed: []
    } as never
  })
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
  })

  it('refuses self-revocation before touching anything durable', async () => {
    await expect(
      revokeEnrolledClient({
        session: sessionWith(),
        client: { ...REVOKED, signingKeyMultibase: 'z6MkRevokingClient' }
      })
    ).rejects.toThrow('cannot disconnect itself')
    expect(vi.mocked(revokeWebvhClient)).not.toHaveBeenCalled()
    expect(vi.mocked(rotatePukRoster)).not.toHaveBeenCalled()
  })
})

describe('the cascade, rotated path', () => {
  it('runs the stages in dependency order and reports the outcome', async () => {
    const session = sessionWith()
    const outcome = await revokeEnrolledClient({
      session,
      client: REVOKED,
      label: 'Old laptop'
    })

    expect(state.calls).toEqual([
      'revokeWebvhClient',
      'verifyAccountLog',
      'rotatePukRoster',
      'readPukRoster',
      'savePukEpochPin',
      'persistClientKeys',
      'cascadeCollectionsToPuk',
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

  it('retires the revoked roster kid and pins the fresh epoch', async () => {
    const session = sessionWith()
    await revokeEnrolledClient({ session, client: REVOKED })

    expect(vi.mocked(revokeWebvhClient)).toHaveBeenCalledWith({
      idStore: session.storage.remoteStore,
      updateKeys: session.profile.clientWebvhKeys,
      revokedClient: REVOKED,
      knownLatentHashes: []
    })
    // The retired kid is the revoked client's own key-agreement key id, as
    // its agentsFromSeed derives it.
    expect(vi.mocked(rotatePukRoster)).toHaveBeenCalledWith(
      expect.objectContaining({
        document: { id: 'did:webvh:doc' },
        retireRecipientId: 'did:key:z6MkRevokedClient#z6LSRevokedClient'
      })
    )
    expect(vi.mocked(savePukEpochPin)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        epochId: FRESH_PUK.id
      })
    )
    expect(session.profile.persistClientKeys).toHaveBeenCalledWith({
      puk: FRESH_PUK
    })
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledWith({
      remoteStore: session.storage.remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: session.profile.clientKeyAgreementKey,
      puk: FRESH_PUK
    })
  })

  it('adopts the rotated PUK into the live session', async () => {
    const session = sessionWith()
    const previousVaultKeys = {
      keyAgreementKey: session.profile.keyAgreementKey,
      keyResolver: session.profile.keyResolver
    }
    await revokeEnrolledClient({ session, client: REVOKED })

    expect(session.profile.puk).toBe(FRESH_PUK)
    expect(session.profile.keyAgreementKey?.id).toBe(`${FRESH_PUK.id}#kak`)
    expect(vi.mocked(rewrapUnlockMethodsRecord)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        from: previousVaultKeys,
        to: expect.objectContaining({
          keyAgreementKey: { id: `${FRESH_PUK.id}#kak` }
        })
      })
    )
    expect(session.storage.adoptRotatedVaultKeys).toHaveBeenCalledWith(
      expect.objectContaining({
        keyAgreementKey: { id: `${FRESH_PUK.id}#kak` }
      })
    )
    expect(vi.mocked(pukVaultKeys)).toHaveBeenCalledWith({ puk: FRESH_PUK })
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

  it('throws when the account has no roster to rotate', async () => {
    vi.mocked(readPukRoster).mockResolvedValue(null)
    await expect(
      revokeEnrolledClient({ session: sessionWith(), client: REVOKED })
    ).rejects.toThrow('no PUK roster')
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
    expect(vi.mocked(revokeWebvhClient)).toHaveBeenCalledWith(
      expect.objectContaining({
        knownLatentHashes: [await deriveNextKeyHash('z6MkCodeUpdate')]
      })
    )
  })

  it('proceeds without them when the registry is unreadable', async () => {
    vi.mocked(getUnlockMethods).mockRejectedValue(new Error('offline'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await revokeEnrolledClient({ session: sessionWith(), client: REVOKED })
    expect(vi.mocked(revokeWebvhClient)).toHaveBeenCalledWith(
      expect.objectContaining({ knownLatentHashes: [] })
    )
    warn.mockRestore()
  })
})

describe('re-run convergence and best-effort stages', () => {
  it('still cascades and re-mints on an already-rotated roster', async () => {
    vi.mocked(readPukRoster).mockImplementation(async () => {
      state.calls.push('readPukRoster')
      return { ...rotatedRead(), puk: OLD_PUK, rotated: false } as never
    })
    const session = sessionWith()
    const outcome = await revokeEnrolledClient({ session, client: REVOKED })

    expect(outcome.rotated).toBe(false)
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledOnce()
    expect(vi.mocked(remintRecoveryDelegations)).toHaveBeenCalledOnce()
    expect(session.storage.addHistoryClientRevoked).toHaveBeenCalledOnce()
    // Nothing re-persists or re-adopts: the session already holds this PUK.
    expect(session.profile.persistClientKeys).not.toHaveBeenCalled()
    expect(vi.mocked(rewrapUnlockMethodsRecord)).not.toHaveBeenCalled()
    expect(session.storage.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(session.profile.puk).toBe(OLD_PUK)
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
    // The live profile still adopted the fresh PUK even though the storage
    // cipher rebuild failed (the next login converges).
    expect(session.profile.puk).toBe(FRESH_PUK)
    warn.mockRestore()
  })
})
