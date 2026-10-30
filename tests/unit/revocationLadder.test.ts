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
 * pending-shaped passphrase entry, and a generation-delegation replacement
 * that did not install), since that replacement must land BEFORE the
 * removal entry strikes the key that signed the standing one. It
 * withholds the self-revocation multibase (a ladder rung has no self to
 * refuse) and both re-mint stages (every unlock record's bridge is signed by
 * its OWN credential's ladder VM, which this entry does not strike) -- so no
 * sibling credential's record is read or re-signed at any point.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { TEST_SERVICE_DESCRIPTION } from '../shared/wasServiceFixture'

import { memoryResourceLogPinStore } from '@interop/vh-resource-log'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  calls: [] as string[],
  /** the account's unlock-methods registry, or a read that throws */
  registry: null as unknown,
  registryFails: false,
  /** the session each registry read was handed, in order */
  registrySessions: [] as unknown[],
  /** whether the pre-pivot detector refuses */
  pendingEntry: false,
  /**
   * What the replacement installs: a freshly minted delegation, the one the
   * visit already invokes (the policy left it standing), or nothing at all,
   * named by the renewal's skip reason.
   */
  renewInstalls: 'fresh' as
    | 'fresh'
    | 'healthy'
    | 'no-pointer'
    | 'no-ladder-seed'
    | 'no-ladder-vm'
    | 'failed',
  /**
   * The capability the visit rides right now. The live session's stamp, which
   * the renewal below replaces exactly as the real adoption does.
   */
  invocationCapability: null as unknown,
  /** whether the renewal swaps that capability, as a real renewal does */
  renewSwaps: false,
  /**
   * every capability the real adoptions' registry re-seal rode, as it
   * reached the re-wrap seam, in order
   */
  resealCapabilities: [] as unknown[],
  /** the session each adoption stage was handed, in order */
  adoptedSessions: [] as unknown[],
  /** every body PUT through that store, in order */
  projectionPuts: [] as unknown[]
}))

type UnlockMethodsModule = typeof import('@/session/unlockMethods')

/**
 * The real unlock-methods module, loaded after the mocks are in place.
 */
const actualUnlockMethods = vi.hoisted(() => ({
  module: undefined as UnlockMethodsModule | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_BASE_SERVER_URL() {
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
  // The real helper: the latent-hash hand-off reads it. Bound lazily, since
  // loading the real module inside this factory would hand the real
  // adoptions below the real re-wrap rather than this mock's.
  latentUpdateKeyMultibasesOf: (
    options: Parameters<UnlockMethodsModule['latentUpdateKeyMultibasesOf']>[0]
  ) => actualUnlockMethods.module!.latentUpdateKeyMultibasesOf(options),
  // The real read resolves the visit's authority itself, off the session it
  // is handed (`registryRides`, covered in registryDelegation.test.ts), so
  // what is recorded here is the session the branch handed over.
  getUnlockMethods: vi.fn(async ({ session }: { session: unknown }) => {
    state.calls.push('getUnlockMethods')
    state.registrySessions.push(session)
    if (state.registryFails) {
      throw new Error('registry unreadable')
    }
    return state.registry
  }),
  // The seam under the real adoptions' re-seal: it records the capability
  // the adoption resolved off the live session when it ran.
  rewrapUnlockMethodsRecord: vi.fn(
    async (options: { capability?: unknown }) => {
      state.calls.push('rewrapUnlockMethodsRecord')
      state.resealCapabilities.push(options.capability)
    }
  )
}))

vi.mock('@/session/forget', async importOriginal => {
  const actual = await importOriginal<typeof import('@/session/forget')>()
  return {
    // The refusal classes are matched by name at the settings surface, so
    // the real ones are thrown here.
    PendingRetirementForgetError: actual.PendingRetirementForgetError,
    assertNoPendingPassphraseEntry: vi.fn(async () => {
      state.calls.push('assertNoPendingPassphraseEntry')
      if (state.pendingEntry) {
        throw new actual.PendingRetirementForgetError()
      }
    })
  }
})

vi.mock('@/session/annexReach', async importOriginal => ({
  // The refusal class is the real one, so the tests match it the way the
  // Settings surface does.
  GenerationDelegationRenewalError: (
    await importOriginal<typeof import('@/session/annexReach')>()
  ).GenerationDelegationRenewalError,
  // So is the refusal that maps the mocked renewal's result onto it.
  refuseUnrenewedGenerationDelegation: (
    await importOriginal<typeof import('@/session/annexReach')>()
  ).refuseUnrenewedGenerationDelegation,
  clientAnnexReachFor: vi.fn(() => null),
  ensureGenerationDelegation: vi.fn(async () => ({ renewed: false })),
  tryRenewTransientGenerationDelegation: vi.fn(async () => {
    state.calls.push('tryRenewTransientGenerationDelegation')
    if (state.renewInstalls === 'failed') {
      // What the real renewal does on a caught failure: it logs it and
      // resolves with the error rather than throwing.
      return {
        skipped: 'failed',
        err: new Error('the sibling delegation is unreachable')
      }
    }
    if (state.renewInstalls !== 'fresh' && state.renewInstalls !== 'healthy') {
      // Installed nothing, for the named reason.
      return { skipped: state.renewInstalls }
    }
    if (state.renewInstalls === 'healthy') {
      // The policy found the embedded delegation standing, so the same
      // delegation comes back and nothing was renewed.
      return { delegation: state.invocationCapability }
    }
    const fresh = { id: 'urn:zcap:generation-fresh' }
    if (state.renewSwaps) {
      // What the real renewal does: the fresh delegation is adopted into the
      // live session, so every later stage must ride it.
      state.invocationCapability = fresh
    }
    return { delegation: fresh }
  }),
  didWebProjectionStore: vi.fn(() => {
    state.calls.push('didWebProjectionStore')
    return {
      getIdResourceRaw: vi.fn(async () => undefined),
      putIdResource: vi.fn(async ({ content }: { content: string }) => {
        state.calls.push('putDidWebProjection')
        state.projectionPuts.push(JSON.parse(content))
      })
    }
  })
}))

vi.mock('@/session/userKeyAdoption', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@/session/userKeyAdoption')>()
  // The real adoptions, wrapped only to trace when each ran and which session
  // it was handed. Each resolves the visit's authority off that session at
  // its own re-seal, which reaches the re-wrap seam above.
  return {
    ...actual,
    adoptRotatedUserKey: vi.fn(
      async (options: Parameters<typeof actual.adoptRotatedUserKey>[0]) => {
        state.calls.push('adoptRotatedUserKey')
        state.adoptedSessions.push(options.session)
        await actual.adoptRotatedUserKey(options)
      }
    ),
    adoptRotatedUserKeyInBand: vi.fn(
      async (
        options: Parameters<typeof actual.adoptRotatedUserKeyInBand>[0]
      ) => {
        state.calls.push('adoptRotatedUserKeyInBand')
        state.adoptedSessions.push(options.session)
        await actual.adoptRotatedUserKeyInBand(options)
      }
    )
  }
})

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

vi.mock('@/session/accountCeremonyContext', async importOriginal => ({
  // The real projection-store pick, so the ladder kind's generation-delegated
  // store is the one the orchestrator receives.
  ceremonyProjectionStore: (
    await importOriginal<typeof import('@/session/accountCeremonyContext')>()
  ).ceremonyProjectionStore,
  accountCeremonyContext: vi.fn(async () => ladderContext())
}))

import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { revokeAccountClient } from '@interop/wallet-core/clients'
import {
  didWebProjectionStore,
  GenerationDelegationRenewalError,
  tryRenewTransientGenerationDelegation
} from '@/session/annexReach'
import { accountCeremonyContext } from '@/session/accountCeremonyContext'
import { assertNoPendingPassphraseEntry } from '@/session/forget'
import {
  adoptRotatedUserKey,
  adoptRotatedUserKeyInBand
} from '@/session/userKeyAdoption'
import { reprimeVerifiedAccountLog } from '@/session/verifiedLog'
import {
  revokeEnrolledClient,
  type RevokedClientKeys
} from '@/session/revocation'
import type { Session } from '@/types/auth'

actualUnlockMethods.module = await vi.importActual<UnlockMethodsModule>(
  '@/session/unlockMethods'
)

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceUrl: 'https://was.example.test/space/space-123/'
}

/**
 * The sibling passphrase's committed rung and the recovery code's update
 * key, as the registry records them. Real Ed25519 multikeys, since the
 * revocation hashes them with `deriveNextKeyHash`, which refuses anything
 * else.
 */
const SIBLING_PASSPHRASE_RUNG = (await Ed25519VerificationKey.generate())
  .publicKeyMultibase
const CODE_UPDATE_KEY = (await Ed25519VerificationKey.generate())
  .publicKeyMultibase

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
  // Live, as the real context is: a mid-ceremony renewal replaces the
  // session's stamp, and every stage past it must read the replacement.
  const invokerNow = () => ({
    zcapClient: { isAnnexVmZcapClient: true },
    capability: state.invocationCapability
  })
  let projection: unknown
  return {
    kind: 'ladder',
    remoteStore: { webvhIdStore: vi.fn(() => ({ isWebvhIdStore: true })) },
    pointer: POINTER,
    controller: 'did:key:z6MkAccountController',
    signer: { kind: 'ladder', ladderSeed: LADDER_SEED },
    idStore: BRIDGE_ID_STORE,
    rosterStore: LADDER_ROSTER_STORE,
    get invoker() {
      return invokerNow()
    },
    // Built on first read and aimed at the invoker thunk, exactly as the real
    // context builds it.
    get projectionStore() {
      return (projection ??= didWebProjectionStore({
        serviceDescription: TEST_SERVICE_DESCRIPTION,
        pinStore: memoryResourceLogPinStore(),
        spaceUrl: POINTER.spaceUrl,
        invoker: invokerNow as never
      }))
    },
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
      holdRotatedVaultKeys: vi.fn(),
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
      // Live, as the real session's stamp is: the renewal replaces it in
      // place, and every stage past it reads the replacement.
      get invocationCapability() {
        return state.invocationCapability
      },
      userKey: OLD_USER_KEY,
      keyAgreementKey: { id: `${OLD_USER_KEY.id}#kak` },
      keyResolver: async () => ({})
    },
    persistence: {
      logPins: { read: async () => null, write: async () => undefined },
      epochPins: {
        load: epochPinLoad,
        saveFromDescriptor: async () => undefined
      },
      // The visit's annex identity, which is what makes a generation
      // delegation renewable at all.
      clientAnnex: {
        clientAnnexDid: 'did:webvh:annex',
        get invocationCapability() {
          return state.invocationCapability
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
        updateKeyMultibase: SIBLING_PASSPHRASE_RUNG,
        manageCapability: { id: 'urn:zcap:manage-sibling' }
      },
      {
        type: 'recovery-code',
        createdAt: '2026-08-02T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-code',
        updateKeyMultibase: CODE_UPDATE_KEY,
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
  state.registrySessions = []
  state.pendingEntry = false
  state.renewInstalls = 'fresh'
  state.renewSwaps = false
  state.invocationCapability = GENERATION_DELEGATION
  state.resealCapabilities = []
  state.adoptedSessions = []
  state.projectionPuts = []
  vi.clearAllMocks()
  vi.mocked(revokeAccountClient).mockImplementation(orchestratorDriving())
})

describe('the pre-pivot stage order', () => {
  it('reads the registry, runs the refusal, then replaces the delegation', async () => {
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })

    expect(state.calls).toEqual([
      'getUnlockMethods',
      'loadUserKeyEpochPin',
      'assertNoPendingPassphraseEntry',
      // The rule for a struck signer: the replacement is minted and adopted
      // BEFORE the removal entry takes the revoked client's key out of the
      // document, since that key may be what signed the standing one.
      'tryRenewTransientGenerationDelegation',
      // The post-removal projection is PUT before the entry, not after it: a
      // ladder-signed entry writes `did.jsonl` alone, so `id/did.json` would
      // otherwise keep naming the client the log has struck.
      'didWebProjectionStore',
      'putDidWebProjection',
      'revokeAccountClient',
      // The in-band adoption re-seals the registry; the post-ceremony one
      // finds the session already on the rotated key and re-seals nothing.
      'adoptRotatedUserKeyInBand',
      'rewrapUnlockMethodsRecord',
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
    expect(
      vi.mocked(tryRenewTransientGenerationDelegation)
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        retiringKeyMultibases: [REVOKED.signingKeyMultibase]
      })
    )
  })

  it('reads the registry once, under the live session, before the renewal', async () => {
    const session = transientSession()
    await revokeEnrolledClient({ session, client: REVOKED })
    // The read resolves its capability off the session it is handed, so it
    // must be handed the live session itself, and run while the visit still
    // rides the delegation it arrived on.
    expect(state.registrySessions).toHaveLength(1)
    expect(state.registrySessions[0]).toBe(session)
    expect(state.calls.indexOf('getUnlockMethods')).toBeLessThan(
      state.calls.indexOf('tryRenewTransientGenerationDelegation')
    )
  })

  it.each(['no-pointer', 'no-ladder-seed'] as const)(
    'proceeds past a %s skip and reports it by name',
    async reason => {
      // No annex generation or no ladder members: unreachable on a
      // ladder-kind context, so a defensive proceed that names its reason.
      state.renewInstalls = reason
      const outcome = await revokeEnrolledClient({
        session: transientSession(),
        client: REVOKED
      })
      expect(outcome.rotated).toBe(true)
      expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledOnce()
      expect(outcome.mended).toEqual([
        {
          invariant: 'generation-delegation-is-current',
          ceremonies: ['client-revocation'],
          outcome: 'refused',
          detail: { reason }
        }
      ])
    }
  )
})

describe('the pre-pivot refusals', () => {
  it('refuses an unreadable registry before anything is written', async () => {
    state.registryFails = true
    await expect(
      revokeEnrolledClient({ session: transientSession(), client: REVOKED })
    ).rejects.toThrow('Could not read the unlock-methods registry')
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
    expect(vi.mocked(assertNoPendingPassphraseEntry)).not.toHaveBeenCalled()
    expect(
      vi.mocked(tryRenewTransientGenerationDelegation)
    ).not.toHaveBeenCalled()
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
    expect(
      vi.mocked(tryRenewTransientGenerationDelegation)
    ).not.toHaveBeenCalled()
  })

  it('refuses before the removal entry when the delegation replacement fails', async () => {
    // Publishing the entry anyway would strike the key the visit's
    // delegation may chain to, losing its authority for the rest of the
    // cascade. Refused here, before the pivot, the wallet stays connected.
    state.renewInstalls = 'failed'
    const session = transientSession()
    const refusal = revokeEnrolledClient({ session, client: REVOKED })

    await expect(refusal).rejects.toBeInstanceOf(
      GenerationDelegationRenewalError
    )
    await expect(refusal).rejects.toMatchObject({
      reason: 'failed',
      cause: { message: 'the sibling delegation is unreachable' }
    })
    // The account document is unchanged: neither the projection PUT nor the
    // removal entry ran, and nothing past them did.
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
    expect(state.projectionPuts).toEqual([])
    expect(session.storage.addHistoryClientRevoked).not.toHaveBeenCalled()
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'loadUserKeyEpochPin',
      'assertNoPendingPassphraseEntry',
      'tryRenewTransientGenerationDelegation'
    ])
  })

  it('refuses before the removal entry when the document anchors no ladder VM', async () => {
    // The ladder kind's roster and collection stores sign with this
    // credential's ladder VM, so with none in the document every append
    // after the entry would be refused. A last-client transition torn
    // between its strike and its install leaves this shape.
    state.renewInstalls = 'no-ladder-vm'
    const session = transientSession()
    const refusal = revokeEnrolledClient({ session, client: REVOKED })

    await expect(refusal).rejects.toBeInstanceOf(
      GenerationDelegationRenewalError
    )
    await expect(refusal).rejects.toMatchObject({ reason: 'no-ladder-vm' })
    expect(vi.mocked(revokeAccountClient)).not.toHaveBeenCalled()
    expect(state.projectionPuts).toEqual([])
    expect(session.storage.addHistoryClientRevoked).not.toHaveBeenCalled()
  })

  it('hands the detector the one registry the branch already read', async () => {
    state.registry = registryWithSiblings()
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(vi.mocked(assertNoPendingPassphraseEntry)).toHaveBeenCalledWith(
      expect.objectContaining({
        registry: state.registry,
        // The detector's own unlock-record reads are single-verb children
        // the ladder VM mints and invokes as its own bare did:key.
        signer: LADDER_DELETER
      })
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

  it('withholds the self refusal and the re-mint stage', async () => {
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
    expect(options).not.toHaveProperty('remintGenerationDelegation')
  })

  it("passes the standing credentials' committed rungs as latent hashes", async () => {
    state.registry = registryWithSiblings()
    await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    // In registry order: the sibling passphrase's rung, then the code's.
    expect(vi.mocked(revokeAccountClient)).toHaveBeenCalledWith(
      expect.objectContaining({
        knownLatentHashes: [
          await deriveNextKeyHash(SIBLING_PASSPHRASE_RUNG),
          await deriveNextKeyHash(CODE_UPDATE_KEY)
        ]
      })
    )
  })

  it("consults no sibling record's signer on a registry full of them", async () => {
    // The whole point of the rule: a disconnect from a transient session
    // completes on an account carrying a sibling passphrase and an unspent
    // recovery code without reading, re-sealing, or re-signing either
    // credential's unlock record.
    state.registry = registryWithSiblings()
    const outcome = await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })

    expect(outcome.rotated).toBe(true)
    // The ladder branch passes no re-mint closure at all, so its tail entry
    // reports the PRE-entry replacement instead: this run minted one.
    expect(outcome.mended).toEqual([
      {
        invariant: 'generation-delegation-is-current',
        ceremonies: ['client-revocation'],
        outcome: 'clean'
      }
    ])
  })

  it('grades a delegation the policy left standing as a no-op', async () => {
    state.renewInstalls = 'healthy'
    const outcome = await revokeEnrolledClient({
      session: transientSession(),
      client: REVOKED
    })
    expect(outcome.mended).toEqual([
      {
        invariant: 'generation-delegation-is-current',
        ceremonies: ['client-revocation'],
        outcome: 'noop'
      }
    ])
  })
})

describe('the post-entry stages', () => {
  it("hands the context's projection store to the removal entry, then re-primes the log", async () => {
    const session = transientSession()
    await revokeEnrolledClient({ session, client: REVOKED })

    // The store the cascade PUTs the post-removal projection through is the
    // context's own, which resolves the visit's capability at each PUT. When
    // the PUT lands relative to the entry is wallet-core's, reproduced by the
    // stand-in orchestrator.
    const context = (await vi.mocked(accountCeremonyContext).mock.results[0]!
      .value) as { projectionStore: unknown }
    const options = vi.mocked(revokeAccountClient).mock.calls[0]![0]
    expect(options.projectionStore).toBe(context.projectionStore)
    expect(state.projectionPuts).toEqual([POST_STRIKE_WEB_DOC])
    // The memo is re-settled once the cascade has published its entry.
    expect(vi.mocked(reprimeVerifiedAccountLog)).toHaveBeenCalledOnce()
    expect(vi.mocked(reprimeVerifiedAccountLog)).toHaveBeenCalledWith({
      session,
      pointer: POINTER
    })
    expect(state.calls.indexOf('reprimeVerifiedAccountLog')).toBeGreaterThan(
      state.calls.indexOf('revokeAccountClient')
    )
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
  it('re-seals the registry under the renewed delegation, past the renewal', async () => {
    state.renewSwaps = true
    state.registry = registryWithSiblings()
    const session = transientSession()

    await revokeEnrolledClient({ session, client: REVOKED })

    // Both adoptions run after the renewal, on the live session, so the real
    // in-band re-seal reads the replacement off it. The post-ceremony
    // adoption finds the session already on the rotated key.
    const renewedAt = state.calls.indexOf(
      'tryRenewTransientGenerationDelegation'
    )
    expect(state.calls.indexOf('adoptRotatedUserKeyInBand')).toBeGreaterThan(
      renewedAt
    )
    expect(state.calls.indexOf('adoptRotatedUserKey')).toBeGreaterThan(
      renewedAt
    )
    expect(state.adoptedSessions).toHaveLength(2)
    expect(state.adoptedSessions[0]).toBe(session)
    expect(state.adoptedSessions[1]).toBe(session)
    expect(state.resealCapabilities).toEqual([
      { id: 'urn:zcap:generation-fresh' }
    ])
  })

  it('re-seals under the standing delegation when the policy left it standing', async () => {
    state.renewInstalls = 'healthy'
    state.registry = registryWithSiblings()
    const session = transientSession()

    await revokeEnrolledClient({ session, client: REVOKED })

    expect(vi.mocked(adoptRotatedUserKeyInBand)).toHaveBeenCalledOnce()
    expect(vi.mocked(adoptRotatedUserKey)).toHaveBeenCalledOnce()
    expect(state.adoptedSessions[0]).toBe(session)
    expect(state.adoptedSessions[1]).toBe(session)
    expect(state.resealCapabilities).toEqual([GENERATION_DELEGATION])
  })
})
