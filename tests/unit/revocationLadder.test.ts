// @vitest-environment node
/**
 * Unit tests for the LADDER branch of the client-revocation cascade
 * (`revokeEnrolledClient` in `src/session/revocation.ts`): disconnecting a
 * wallet client from a transient session on a standing unlock credential.
 * The enrolled branch has its own suite in `revocation.test.ts`, and the
 * cascade body -- document edit, rotation, fan-out -- is wallet-core's.
 *
 * What is exercised here is what the branch adds and what it withholds. It
 * adds three pre-pivot refusals (a registry this session could not read, a
 * pending-shaped passphrase entry, a standing credential the registry does
 * not name) and a generation-delegation replacement that must land BEFORE
 * the removal entry strikes the key that signed the standing one. It
 * withholds the self-revocation multibase (a ladder rung has no self to
 * refuse) and both re-mint stages (every unlock record's bridge is signed by
 * its OWN credential's ladder VM, which this entry does not strike) -- so no
 * sibling credential's record is read or re-signed at any point.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  calls: [] as string[],
  /** the account's unlock-methods registry, or a read that throws */
  registry: null as unknown,
  registryFails: false,
  /** every capability the registry read rode, in order */
  registryCapabilities: [] as unknown[],
  /** whether each pre-pivot detector refuses */
  pendingEntry: false,
  unrecordedCredentials: 0,
  /** whether the generation-delegation replacement fails */
  renewFails: false,
  /**
   * The capability the visit rides right now. The live session's stamp, which
   * the renewal below replaces exactly as the real adoption does.
   */
  invocationCapability: null as unknown,
  /** whether the renewal swaps that capability, as a real renewal does */
  renewSwaps: false,
  /** every capability the adoption stages rode, in order */
  adoptedCapabilities: [] as unknown[],
  /** the arguments the did:web projection store was built with */
  projectionStoreArgs: null as unknown,
  /** every body PUT through that store, in order */
  projectionPuts: [] as unknown[]
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

vi.mock('@/session/unlockMethods', () => ({
  getUnlockMethods: vi.fn(async ({ capability }: { capability?: unknown }) => {
    state.calls.push('getUnlockMethods')
    state.registryCapabilities.push(capability)
    if (state.registryFails) {
      throw new Error('registry unreadable')
    }
    return state.registry
  }),
  rewrapUnlockMethodsRecord: vi.fn(async () => {
    state.calls.push('rewrapUnlockMethodsRecord')
  })
}))

vi.mock('@/session/forget', async importOriginal => {
  const actual = await importOriginal<typeof import('@/session/forget')>()
  return {
    // The refusal classes are matched by name at the settings surface, so
    // the real ones are thrown here.
    PendingRetirementForgetError: actual.PendingRetirementForgetError,
    UnrecordedCredentialForgetError: actual.UnrecordedCredentialForgetError,
    assertNoPendingPassphraseEntry: vi.fn(async () => {
      state.calls.push('assertNoPendingPassphraseEntry')
      if (state.pendingEntry) {
        throw new actual.PendingRetirementForgetError()
      }
    }),
    assertRegistryCoversStandingCredentials: vi.fn(async () => {
      state.calls.push('assertRegistryCoversStandingCredentials')
      if (state.unrecordedCredentials > 0) {
        throw new actual.UnrecordedCredentialForgetError({
          unrecorded: state.unrecordedCredentials
        })
      }
    })
  }
})

vi.mock('@/session/annexReach', () => ({
  clientAnnexReachFor: vi.fn(() => null),
  ensureGenerationDelegation: vi.fn(async () => ({ renewed: false })),
  renewTransientGenerationDelegation: vi.fn(async () => {
    state.calls.push('renewTransientGenerationDelegation')
    if (state.renewFails) {
      throw new Error('the sibling delegation is unreachable')
    }
    const fresh = { id: 'urn:zcap:generation-fresh' }
    if (state.renewSwaps) {
      // What the real renewal does: the fresh delegation is adopted into the
      // live session, so every later stage must ride it.
      state.invocationCapability = fresh
    }
    return fresh
  }),
  didWebProjectionStore: vi.fn((args: unknown) => {
    state.calls.push('didWebProjectionStore')
    state.projectionStoreArgs = args
    return {
      getIdResourceRaw: vi.fn(async () => undefined),
      putIdResource: vi.fn(async ({ content }: { content: string }) => {
        state.calls.push('putDidWebProjection')
        state.projectionPuts.push(JSON.parse(content))
      })
    }
  })
}))

vi.mock('@/session/userKeyAdoption', () => ({
  adoptRotatedUserKey: vi.fn(
    async ({ capability }: { capability?: unknown }) => {
      state.calls.push('adoptRotatedUserKey')
      state.adoptedCapabilities.push(capability)
    }
  ),
  adoptRotatedUserKeyInBand: vi.fn(
    async ({ capability }: { capability?: unknown }) => {
      state.calls.push('adoptRotatedUserKeyInBand')
      state.adoptedCapabilities.push(capability)
    }
  )
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

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(),
  reprimeVerifiedAccountLog: vi.fn(async () => {
    state.calls.push('reprimeVerifiedAccountLog')
  })
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  // The live-rides thunk: the ceremonies read the invocation capability off
  // the context each time they spread it, so the mock must expose it too.
  ceremonyRides:
    ({ context }: { context: { invoker?: { capability?: unknown } } | null }) =>
    () =>
      context?.invoker?.capability
        ? { capability: context.invoker.capability }
        : {},
  accountCeremonyContext: vi.fn(async () => ladderContext())
}))

import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { revokeAccountClient } from '@interop/wallet-core/clients'
import {
  didWebProjectionStore,
  renewTransientGenerationDelegation
} from '@/session/annexReach'
import {
  assertNoPendingPassphraseEntry,
  assertRegistryCoversStandingCredentials
} from '@/session/forget'
import { remintRecoveryDelegations } from '@/session/recovery'
import { reprimeVerifiedAccountLog } from '@/session/verifiedLog'
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

const LADDER_SEED = new Uint8Array(32).fill(7)
const GENERATION_DELEGATION = { id: 'urn:zcap:generation' }
const STANDING_KAK = { id: 'did:key:z6MkStanding#z6LSStanding' }
const BRIDGE_ID_STORE = { isUnlockLogStore: true }
const LADDER_ROSTER_STORE = { isLadderRosterStore: true }
const LADDER_DELETER = {
  zcapClient: { isLadderVmZcapClient: true },
  invoker: { isDidKeyZcapClient: true },
  controller: 'did:key:z6MkLadderVm'
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

/**
 * The post-removal did:web projection wallet-core derives from the entry it
 * is about to publish: the same document with the revoked client's
 * verification method already gone.
 */
const POST_STRIKE_WEB_DOC = { id: 'did:web:doc', verificationMethod: [] }

/**
 * The ladder-kind ceremony context this session resolves. The real one's
 * lazy store getters are plain members here: the assertions care about which
 * authority reaches the orchestrator, not about when it is built.
 *
 * @returns {object}
 */
function ladderContext(): object {
  return {
    kind: 'ladder',
    remoteStore: { webvhIdStore: vi.fn(() => ({ isWebvhIdStore: true })) },
    pointer: POINTER,
    controller: 'did:key:z6MkAccountController',
    signer: { kind: 'ladder', ladderSeed: LADDER_SEED },
    ladderSeed: LADDER_SEED,
    idStore: BRIDGE_ID_STORE,
    rosterStore: LADDER_ROSTER_STORE,
    // Live, as the real context is: a mid-ceremony renewal replaces the
    // session's stamp, and every stage past it must read the replacement.
    get invoker() {
      return {
        zcapClient: { isAnnexVmZcapClient: true },
        capability: state.invocationCapability
      }
    },
    delegationSigner: LADDER_DELETER.zcapClient,
    ladderDeleter: LADDER_DELETER,
    bindRecord: async () => ({}),
    sibling: { id: 'urn:zcap:delegated-clients' },
    unlockSpaceId: 'unlock-space-old',
    standingKeyAgreementKey: STANDING_KAK,
    renew: async () => GENERATION_DELEGATION
  }
}

/**
 * A stand-in for the shared orchestrator that drives its callbacks in the
 * documented order, so the freewallet-side stages run exactly where the real
 * cascade runs them.
 *
 * @param [options] {object}
 * @param [options.rotated] {boolean}
 * @returns {Function}
 */
function orchestratorDriving({ rotated = true }: { rotated?: boolean } = {}) {
  return async (options: Parameters<typeof revokeAccountClient>[0]) => {
    // wallet-core PUTs the post-strike projection through the supplied store
    // immediately BEFORE the entry publishes; the stand-in reproduces that
    // placement so the app-side wiring is exercised where the real one is.
    await options.projectionStore?.putIdResource({
      resourceId: 'did.json',
      content: JSON.stringify(POST_STRIKE_WEB_DOC),
      contentType: 'application/json'
    })
    state.calls.push('revokeAccountClient')
    const userKey = rotated ? FRESH_USER_KEY : OLD_USER_KEY
    if (rotated) {
      await options.onUserKeyAdopted?.({
        userKey,
        latestEpochId: userKey.id,
        descriptor: ROSTER_DESCRIPTOR as never
      })
    }
    const recovery = await options.remintRecoveryDelegations?.({
      document: DOCUMENT as never
    })
    const generation = await options.remintGenerationDelegation?.({
      document: DOCUMENT as never
    })
    if (rotated) {
      await options.onRotationAdopted?.({ userKey })
    }
    return {
      rotated,
      collections: {
        outcomes: { 'private-credentials': 'rotated' },
        failed: []
      },
      document: DOCUMENT,
      userKey,
      ...(recovery ? { recovery } : {}),
      ...(generation ? { generation } : {})
    } as never
  }
}

const epochPinLoad = vi.fn(async () => {
  state.calls.push('loadUserKeyEpochPin')
  return OLD_USER_KEY.id as string | null
})

/**
 * A transient session on a standing credential: the in-memory pin stores,
 * the generation delegation every request rides, and the storage seams the
 * cascade's adoption and audit stages touch.
 *
 * @returns {Session}
 */
function transientSession(): Session {
  return {
    user: { id: 'did:key:z6MkVisitKey' },
    isGuest: false,
    storage: {
      remoteStore: { webvhIdStore: vi.fn(() => ({ isWebvhIdStore: true })) },
      adoptRotatedVaultKeys: vi.fn(async () => {}),
      addHistoryClientRevoked: vi.fn(async () => {
        state.calls.push('addHistoryClientRevoked')
      })
    },
    profile: {
      accountPointer: POINTER,
      accountController: 'did:key:z6MkAccountController',
      zcapClient: { isAnnexVmZcapClient: true },
      keyAgent: { id: 'did:key:z6MkVisitKey' },
      ladderSeed: LADDER_SEED,
      invocationCapability: GENERATION_DELEGATION,
      userKey: OLD_USER_KEY,
      keyAgreementKey: { id: `${OLD_USER_KEY.id}#kak` },
      keyResolver: async () => ({}),
      persistence: {
        logPins: { read: async () => null, write: async () => undefined },
        epochPins: {
          load: epochPinLoad,
          saveFromDescriptor: async () => undefined
        }
      }
    }
  } as unknown as Session
}

/**
 * A registry naming a sibling passphrase credential and an unspent recovery
 * code beside the acting credential -- the shape whose records the ladder
 * branch must never read or re-sign.
 *
 * @returns {object}
 */
function registryWithSiblings(): object {
  return {
    version: 1,
    webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-sibling',
        keyAgreementKeyMultibase: 'z6LSSiblingPassphraseKak',
        updateKeyMultibase: 'z6MkSiblingPassphraseRung',
        manageCapability: { id: 'urn:zcap:manage-sibling' }
      },
      {
        type: 'recovery-code',
        createdAt: '2026-08-02T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-code',
        updateKeyMultibase: 'z6MkCodeUpdate',
        manageCapability: { id: 'urn:zcap:manage-code' }
      }
    ]
  }
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.calls = []
  state.registry = null
  state.registryFails = false
  state.registryCapabilities = []
  state.pendingEntry = false
  state.unrecordedCredentials = 0
  state.renewFails = false
  state.renewSwaps = false
  state.invocationCapability = GENERATION_DELEGATION
  state.adoptedCapabilities = []
  state.projectionStoreArgs = null
  state.projectionPuts = []
  vi.clearAllMocks()
  vi.mocked(revokeAccountClient).mockImplementation(orchestratorDriving())
})

describe('the pre-pivot stage order', () => {
  it('reads the registry, runs both refusals, then replaces the delegation', async () => {
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })

    expect(state.calls).toEqual([
      'getUnlockMethods',
      'loadUserKeyEpochPin',
      'assertNoPendingPassphraseEntry',
      'assertRegistryCoversStandingCredentials',
      // The rule for a struck signer: the replacement is minted and adopted
      // BEFORE the removal entry takes the revoked client's key out of the
      // document, since that key may be what signed the standing one.
      'renewTransientGenerationDelegation',
      // The post-removal projection is PUT before the entry, not after it: a
      // ladder-signed entry writes `did.jsonl` alone, so `id/did.json` would
      // otherwise keep naming the client the log has struck.
      'didWebProjectionStore',
      'putDidWebProjection',
      'revokeAccountClient',
      'adoptRotatedUserKeyInBand',
      'adoptRotatedUserKey',
      'reprimeVerifiedAccountLog',
      'addHistoryClientRevoked'
    ])
  })

  it('names the retiring key so the policy replaces the right delegation', async () => {
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(vi.mocked(renewTransientGenerationDelegation)).toHaveBeenCalledWith(
      expect.objectContaining({
        retiringKeyMultibases: [REVOKED.signingKeyMultibase]
      })
    )
  })

  it('rides the generation delegation on the registry read', async () => {
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(state.registryCapabilities).toEqual([GENERATION_DELEGATION])
  })

  it('proceeds when the delegation replacement fails', async () => {
    // Best-effort: the visit may lose its authority when the revoked key
    // leaves the document, which a re-run or the next visit's readiness
    // stage mends. The disconnect itself is not held up.
    state.renewFails = true
    const outcome = await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(outcome.rotated).toBe(true)
    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledOnce()
  })
})

describe('the three pre-pivot refusals', () => {
  it('refuses an unreadable registry before anything is written', async () => {
    state.registryFails = true
    await expect(
      revokeEnrolledClient({ session: transientSession(), client: REVOKED })
    ).rejects.toThrow('Could not read the unlock-methods registry')
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
    expect(vi.mocked(assertNoPendingPassphraseEntry)).not.toHaveBeenCalled()
    expect(vi.mocked(renewTransientGenerationDelegation)).not.toHaveBeenCalled()
  })

  it('refuses a pending-shaped passphrase entry', async () => {
    state.pendingEntry = true
    state.registry = registryWithSiblings()
    const thrown = await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    }).catch((err: Error) => err)

    expect((thrown as Error).name).toBe('PendingRetirementForgetError')
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
    expect(vi.mocked(renewTransientGenerationDelegation)).not.toHaveBeenCalled()
  })

  it('refuses a standing credential the registry does not name', async () => {
    state.unrecordedCredentials = 2
    const thrown = await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    }).catch((err: Error) => err)

    expect((thrown as Error).name).toBe('UnrecordedCredentialForgetError')
    expect((thrown as { unrecorded?: number }).unrecorded).toBe(2)
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
  })

  it('hands both detectors the one registry the branch already read', async () => {
    state.registry = registryWithSiblings()
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(vi.mocked(assertNoPendingPassphraseEntry)).toHaveBeenCalledWith(
      expect.objectContaining({
        pointer: POINTER,
        registry: state.registry,
        // The detector's own unlock-record reads are single-verb children
        // the ladder VM mints and invokes as its own bare did:key.
        signer: LADDER_DELETER
      })
    )
    expect(
      vi.mocked(assertRegistryCoversStandingCredentials)
    ).toHaveBeenCalledWith(
      expect.objectContaining({ pointer: POINTER, registry: state.registry })
    )
  })
})

describe('the options the ladder branch hands over, and the ones it withholds', () => {
  it('signs with the ladder and unwraps with the standing key', async () => {
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledWith(
      expect.objectContaining({
        signer: { kind: 'ladder', ladderSeed: LADDER_SEED },
        // The bridge store, not the root-invoking one the session's remote
        // store would build.
        idStore: BRIDGE_ID_STORE,
        rosterStore: LADDER_ROSTER_STORE,
        clientKeyAgreementKey: STANDING_KAK,
        revokedClient: REVOKED,
        expectedDid: POINTER.did,
        pinnedEpochId: OLD_USER_KEY.id
      })
    )
  })

  it('withholds the self refusal and both re-mint stages', async () => {
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    const options = vi.mocked(revokeAccountClient).mock.calls[0]?.[0] ?? {}
    // A ladder rung has no self to refuse, and the last enrolled client is
    // removable here: the account simply lands ladder-anchored.
    expect(options).not.toHaveProperty('ownSigningKeyMultibase')
    // Every unlock record's bridge is signed by its OWN credential's ladder
    // VM, which this entry does not strike, and the generation delegation's
    // replacement already ran before the entry.
    expect(options).not.toHaveProperty('remintRecoveryDelegations')
    expect(options).not.toHaveProperty('remintGenerationDelegation')
    expect(vi.mocked(remintRecoveryDelegations)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('remintRecoveryDelegations')
  })

  it("passes the standing credentials' committed rungs as latent hashes", async () => {
    state.registry = registryWithSiblings()
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledWith(
      expect.objectContaining({
        knownLatentHashes: [
          await deriveNextKeyHash('z6MkCodeUpdate'),
          await deriveNextKeyHash('z6MkSiblingPassphraseRung')
        ]
      })
    )
  })

  it("consults no sibling record's signer on a registry full of them", async () => {
    // The whole point of withholding the re-mint stages: a disconnect from a
    // transient session completes on an account carrying a sibling
    // passphrase and an unspent recovery code without reading, re-sealing,
    // or re-signing either credential's unlock record.
    state.registry = registryWithSiblings()
    const outcome = await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })

    expect(outcome.rotated).toBe(true)
    expect(outcome.recovery).toEqual({ reminted: 0, skipped: 0 })
    expect(outcome.generation).toEqual({
      renewed: false,
      skipped: 'no-pointer'
    })
    expect(vi.mocked(remintRecoveryDelegations)).not.toHaveBeenCalled()
  })
})

describe('the post-entry stages', () => {
  it('publishes the did:web projection before the removal entry', async () => {
    const session = transientSession()
    await revokeEnrolledClient({ session, client: REVOKED })

    // The store: the account Space's `id` collection, reached under whatever
    // capability the visit holds when the PUT runs -- the renewal above may
    // have replaced the one the context resolved on.
    expect(vi.mocked(didWebProjectionStore)).toHaveBeenCalledWith(
      expect.objectContaining({
        host: POINTER.host,
        spaceId: POINTER.spaceId,
        invoker: expect.any(Function)
      })
    )
    const { invoker } = state.projectionStoreArgs as {
      invoker: () => { capability?: unknown }
    }
    expect(invoker().capability).toBe(state.invocationCapability)
    // The body reaches the store before the entry, and no longer names the
    // struck client's verification method.
    expect(state.projectionPuts).toEqual([POST_STRIKE_WEB_DOC])
    expect(state.calls.indexOf('putDidWebProjection')).toBeLessThan(
      state.calls.indexOf('revokeAccountClient')
    )
    expect(vi.mocked(reprimeVerifiedAccountLog)).toHaveBeenCalledWith({
      profile: session.profile,
      pointer: POINTER
    })
  })

  it('records the audit history with the per-collection tallies', async () => {
    const session = transientSession()
    await revokeEnrolledClient({ session, client: REVOKED, label: 'Old phone' })
    expect(session.storage.addHistoryClientRevoked).toHaveBeenCalledWith({
      user: session.user,
      signingKeyMultibase: REVOKED.signingKeyMultibase,
      label: 'Old phone',
      rotated: 1,
      failed: 0
    })
  })
})

describe('the delegation the post-pivot stages ride', () => {
  /**
   * The replacement the pre-pivot renewal installs is what everything after
   * it must invoke. The context resolves once, at the top of the cascade, so
   * a stage holding the capability from that moment would invoke a
   * delegation the removal entry has struck the signer of -- and the
   * convergence append, the fan-out, the in-band re-seal, the projection PUT
   * and the registry write would all be refused.
   */
  it('rides the renewed delegation, not the one the context resolved on', async () => {
    state.renewSwaps = true
    state.registry = registryWithSiblings()

    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })

    const fresh = { id: 'urn:zcap:generation-fresh' }
    // The in-band re-seal and the re-seal retry, both past the pivot.
    expect(state.adoptedCapabilities).toEqual([fresh, fresh])
    // The projection store resolves its capability at each use, so the PUT
    // rides the replacement rather than the one the context resolved on.
    const { invoker } = state.projectionStoreArgs as {
      invoker: () => { capability?: unknown }
    }
    expect(invoker().capability).toEqual(fresh)
    // The pre-pivot registry read still rode the delegation the visit
    // arrived on: the renewal had not run yet.
    expect(state.registryCapabilities).toEqual([GENERATION_DELEGATION])
  })

  it('keeps riding the standing delegation when no renewal was needed', async () => {
    state.registry = registryWithSiblings()

    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })

    expect(state.adoptedCapabilities).toEqual([
      GENERATION_DELEGATION,
      GENERATION_DELEGATION
    ])
    const { invoker } = state.projectionStoreArgs as {
      invoker: () => { capability?: unknown }
    }
    expect(invoker().capability).toBe(GENERATION_DELEGATION)
  })
})
