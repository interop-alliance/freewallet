// @vitest-environment node
/**
 * The two encounter registrations the encounter runner runs, through their
 * session bindings (`src/session/menders/encounterSites.ts`).
 *
 * The stranded-collection site: a collection recorded as stranded mid-visit,
 * after `registryReady`, is mended with no second login. The session renews
 * its generation delegation and refreshes the account log before it reads
 * the roster, follows a rotation it is behind with no registry re-seal,
 * stands down when revoked, and cascades what is still stranded. The binding
 * replays construction-time strands once the gate opens, runs one trailing
 * run for a strand reported mid-run, and lets each collection buy at most
 * one budget-free trailing run.
 *
 * The stale-seal site: Settings re-seals a stale registry from a fresh
 * roster read, and a session behind the roster follows the rotation without
 * sealing the registry backward.
 *
 * The storage manager, the log refresh, the roster read, the collection
 * cascade, and the escrow repair are doubles; the follower adoption and the
 * runner are real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { UserKey } from '@interop/wallet-core/keys'
import type { CollectionEncryption } from '@interop/was-client'
import type { Session } from '@/types/auth'

const state = vi.hoisted(() => ({
  calls: [] as string[],
  // What the roster read resolves to, or the error it throws.
  read: null as unknown,
  readError: null as unknown,
  // The collections still stranded after the storage's next rebuild.
  strandsAfterRefresh: [] as string[],
  repairResult: 'repaired' as string,
  contextKind: 'ladder' as 'ladder' | 'enrolled' | null
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

const STANDING_KAK = { id: 'did:key:z6LSStanding#z6LSStanding' }
const CLIENT_KAK = { id: 'did:key:z6MkClient#z6LSClient' }
const VISIT_KAK = { id: 'did:key:z6MkVisit#z6LSVisit' }

vi.mock('@/session/accountCeremonyContext', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@/session/accountCeremonyContext')
  >()),
  accountCeremonyContext: vi.fn(async () => {
    if (state.contextKind === null) {
      return null
    }
    return {
      kind: state.contextKind,
      pointer: { did: ACCOUNT_DID, spaceId: 's-space', host: 'https://was' },
      rosterStore: { rosterStore: true },
      remoteStore: { remoteStore: true },
      collectionStore: () => ({ collectionStore: true }),
      standingKeyAgreementKey: STANDING_KAK,
      clientKeyAgreementKey: CLIENT_KAK,
      renew: vi.fn(async () => {
        state.calls.push('renew')
        return null
      })
    }
  })
}))

vi.mock('@/session/verifiedLog', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/verifiedLog')>()),
  refreshVerifiedAccountLog: vi.fn(async () => {
    state.calls.push('refresh-log')
    return {}
  })
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  readUserKeyRoster: vi.fn(async () => {
    state.calls.push('read-roster')
    if (state.readError) {
      throw state.readError
    }
    return state.read
  })
}))

vi.mock('@/session/userKeyCascade', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/userKeyCascade')>()),
  cascadeCollectionsToUserKey: vi.fn(
    async ({ collectionIds }: { collectionIds?: string[] }) => {
      state.calls.push(`cascade:${(collectionIds ?? []).join(',')}`)
      return {
        outcomes: Object.fromEntries(
          (collectionIds ?? []).map(id => [id, 'rotated'])
        ),
        failed: []
      }
    }
  )
}))

vi.mock('@/session/registryReseal', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/registryReseal')>()),
  repairStaleUnlockRegistrySeal: vi.fn(async () => {
    state.calls.push('repair')
    return state.repairResult
  })
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  rewrapUnlockMethodsRecord: vi.fn(async () => {
    state.calls.push('rewrap')
  })
}))

const { readUserKeyRoster } = await import('@interop/wallet-core/keys')
const { cascadeCollectionsToUserKey } = await import('@/session/userKeyCascade')
const { repairStaleUnlockRegistrySeal } =
  await import('@/session/registryReseal')
const {
  bindStrandedCollectionEncounter,
  encounterLostRosterWrap,
  mendUnlockRegistrySeal,
  strandedCollectionMend,
  subscribeStrandedCollectionMend
} = await import('@/session/menders/encounterSites')
const { browserLocalSessionPersistence } = await import('@/session/persistence')
const { withOwnUserKeyRotation } = await import('@/session/userKeyAdoption')
const {
  armEncounterGate,
  disposeSession,
  openEncounterGateBehindBlock,
  sessionDisposalSignal
} = await import('@/session/sessionLifecycle')

const ACCOUNT_DID = 'did:webvh:QmScid:was.example:space:s-space'
const K1: UserKey = {
  id: 'did:key:z6LSEncounterK1',
  secret: new Uint8Array(32)
}
const K2: UserKey = {
  id: 'did:key:z6LSEncounterK2',
  secret: new Uint8Array(32).fill(2)
}

/**
 * A roster read whose epochs are the given keys, the last one current.
 *
 * @param keys {UserKey[]}
 * @returns {object}
 */
function readOf(keys: UserKey[]) {
  const current = keys[keys.length - 1]!
  return {
    descriptor: {
      scheme: 'edv',
      currentEpoch: current.id,
      epochs: keys.map(key => ({ id: key.id, recipients: [] }))
    } as unknown as CollectionEncryption,
    userKey: current,
    rotated: false,
    latestEpochId: current.id
  }
}

/**
 * A live session on the given kind, over a storage double whose stranded set
 * the tests drive, bound to the stranded-collection encounter.
 *
 * @param [options] {object}
 * @param [options.kind] {'ladder' | 'enrolled'}
 * @param [options.stranded] {string[]}   the collections stranded at
 *   construction
 * @param [options.blockFollows] {boolean}   arm the gate for a login block
 * @returns {object}
 */
function makeSession({
  kind = 'ladder',
  stranded = [],
  blockFollows = false
}: {
  kind?: 'ladder' | 'enrolled'
  stranded?: string[]
  blockFollows?: boolean
} = {}) {
  let strands = [...stranded]
  let onStranded: (() => unknown) | undefined
  const storage = {
    get strandedCollectionIds() {
      return [...strands]
    },
    setOnStranded: vi.fn((callback: (() => unknown) | undefined) => {
      onStranded = callback
    }),
    holdRotatedVaultKeys: vi.fn(),
    // A rebuild re-records what is still stranded, and tells the binding.
    refreshEncryptedDescriptors: vi.fn(async () => {
      state.calls.push('rebuild')
      strands = [...state.strandsAfterRefresh]
      if (strands.length > 0) {
        void Promise.resolve().then(() => onStranded?.())
      }
    })
  }
  const persistClientKeys = vi.fn(async (_changes: { userKey: UserKey }) => {
    state.calls.push('persist')
  })
  const profile =
    kind === 'ladder'
      ? {
          ladderSeed: new Uint8Array(32),
          standingUnlock: {
            unlockSpaceId: 'unlock-space',
            standingClient: { agents: { keyAgreementKey: STANDING_KAK } }
          },
          // The per-visit key: no roster epoch wraps to it.
          clientKeyAgreementKey: VISIT_KAK
        }
      : {
          clientWebvhKeys: { updateSeed: new Uint8Array(32) },
          clientKeyAgreementKey: CLIENT_KAK,
          keyAgent: { id: 'did:key:z6MkClient' },
          persistClientKeys
        }
  const session = {
    user: { id: 'did:key:z6MkClient' },
    isGuest: false,
    profile: {
      ...profile,
      userKey: K1,
      accountPointer: {
        did: ACCOUNT_DID,
        spaceId: 's-space',
        host: 'https://was.example'
      }
    },
    persistence: browserLocalSessionPersistence(),
    storage,
    disposal: sessionDisposalSignal()
  } as unknown as Session
  armEncounterGate({ session, blockFollows })
  bindStrandedCollectionEncounter({ session })
  return {
    session,
    storage,
    persistClientKeys,
    strand: (ids: string[]) => {
      strands = [...ids]
      void Promise.resolve().then(() => onStranded?.())
    }
  }
}

/**
 * Lets pending callbacks run.
 *
 * @returns {Promise<void>}
 */
async function tick(): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, 0))
}

/**
 * Waits until the binding's current run, and any trailing run it started,
 * has settled.
 *
 * @param session {Session}
 * @returns {Promise<void>}
 */
async function settled(session: Session): Promise<void> {
  for (let round = 0; round < 10; round++) {
    await strandedCollectionMend({ session })
    await tick()
  }
}

beforeEach(() => {
  state.calls = []
  state.read = readOf([K1])
  state.readError = null
  state.strandsAfterRefresh = []
  state.repairResult = 'repaired'
  state.contextKind = 'ladder'
  vi.mocked(readUserKeyRoster).mockClear()
  vi.mocked(cascadeCollectionsToUserKey).mockImplementation(
    async ({ collectionIds }: { collectionIds?: string[] }) => {
      state.calls.push(`cascade:${(collectionIds ?? []).join(',')}`)
      return {
        outcomes: Object.fromEntries(
          (collectionIds ?? []).map(id => [id, 'rotated'])
        ),
        failed: []
      } as never
    }
  )
})

describe('the stranded-collection encounter', () => {
  it('resolves the Dashboard getter to an empty list before any run', async () => {
    const { session } = makeSession()
    expect(await strandedCollectionMend({ session })).toEqual([])
    expect(state.calls).toEqual([])
  })

  it('mends a strand raised after registryReady with no second login', async () => {
    const { session, strand } = makeSession()
    // Past the gate's replay: the visit is under way.
    await tick()
    const started = vi.fn()
    subscribeStrandedCollectionMend({ session, listener: started })
    strand(['private-credentials'])
    await tick()
    expect(started).toHaveBeenCalledTimes(1)
    expect(await strandedCollectionMend({ session })).toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'clean'
      }
    ])
    // The delegation first, then the log, then the roster read.
    expect(state.calls).toEqual([
      'renew',
      'refresh-log',
      'read-roster',
      'cascade:private-credentials',
      'rebuild'
    ])
    // The roster read unwraps with the standing key, not the per-visit key.
    expect(vi.mocked(readUserKeyRoster)).toHaveBeenCalledWith(
      expect.objectContaining({ clientKeyAgreementKey: STANDING_KAK })
    )
  })

  it('returns noop with no network call on an empty candidate set', async () => {
    const { session, strand } = makeSession()
    strand([])
    // A rebuild told the binding, and a replacing rebuild cleared the set
    // before the run read it.
    await tick()
    await settled(session)
    const entries = await strandedCollectionMend({ session })
    expect(entries).toEqual([
      expect.objectContaining({
        outcome: 'noop',
        detail: { reason: 'nothing-stranded' }
      })
    ])
    expect(state.calls).toEqual([])
  })

  it('follows a rotation it is behind, re-seals nothing, and cascades what stays stranded', async () => {
    const { session, strand } = makeSession()
    state.read = readOf([K1, K2])
    // The adoption's rebuild leaves the collection stranded: another
    // client's fan-out tore before reaching it.
    state.strandsAfterRefresh = ['private-credentials']
    strand(['private-credentials'])
    await tick()
    const pending = strandedCollectionMend({ session })
    // Once the cascade lands, the next rebuild clears the strand.
    vi.mocked(session.storage.refreshEncryptedDescriptors).mockImplementation(
      async () => {
        state.calls.push('rebuild')
        state.strandsAfterRefresh = []
      }
    )
    await pending
    await settled(session)
    expect(session.profile.userKey).toBe(K2)
    expect(state.calls).not.toContain('rewrap')
    expect(state.calls).toContain('cascade:private-credentials')
    expect(
      await session.persistence.epochPins.load({ accountDid: ACCOUNT_DID })
    ).toBe(K2.id)
  })

  it('stands a revoked session down', async () => {
    const { session, strand } = makeSession()
    state.readError = Object.assign(new Error('no wrap'), {
      name: 'UserKeyRosterUnwrapError'
    })
    strand(['private-credentials'])
    await tick()
    expect(await strandedCollectionMend({ session })).toEqual([
      expect.objectContaining({
        outcome: 'refused',
        detail: { reason: 'no-roster-wrap' }
      })
    ])
    expect(state.calls.some(call => call.startsWith('cascade'))).toBe(false)
  })

  it('fails on a roster read that answers nothing', async () => {
    const { session, strand } = makeSession()
    state.read = null
    strand(['private-credentials'])
    await tick()
    expect(await strandedCollectionMend({ session })).toEqual([
      expect.objectContaining({
        outcome: 'failed',
        detail: { reason: 'no-roster' }
      })
    ])
  })

  it('returns noop on a remembered session, whose login sweep mends it', async () => {
    state.contextKind = 'enrolled'
    const { session, strand } = makeSession({ kind: 'enrolled' })
    strand(['private-credentials'])
    await tick()
    expect(await strandedCollectionMend({ session })).toEqual([
      expect.objectContaining({
        outcome: 'noop',
        detail: { reason: 'no-ladder-context' }
      })
    ])
    expect(state.calls).toEqual([])
  })

  it('replays a strand raised during construction once, after the block starts', async () => {
    const { session } = makeSession({
      stranded: ['private-credentials'],
      blockFollows: true
    })
    await tick()
    expect(state.calls).toEqual([])
    session.registryReady = Promise.resolve()
    openEncounterGateBehindBlock({ session })
    await settled(session)
    expect(state.calls.filter(call => call === 'read-roster')).toHaveLength(1)
  })

  it('does not re-enter itself on its own rebuild, and stops at the budget', async () => {
    const { session, strand } = makeSession()
    // The cascade rotates nothing that clears the strand: every rebuild
    // re-records it, and tells the binding.
    state.strandsAfterRefresh = ['private-credentials']
    strand(['private-credentials'])
    await settled(session)
    expect(state.calls.filter(call => call === 'read-roster')).toHaveLength(1)
    expect(await strandedCollectionMend({ session })).toEqual([
      expect.objectContaining({
        outcome: 'failed',
        detail: { reason: 'still-stranded', strandedCollections: 1 }
      })
    ])
  })

  it('spends the budget on a partial cascade that leaves the collection stranded', async () => {
    const { session, strand } = makeSession()
    vi.mocked(cascadeCollectionsToUserKey).mockImplementation(async () => {
      state.calls.push('cascade')
      return {
        outcomes: {},
        failed: [{ collectionId: 'private-credentials', err: new Error('409') }]
      } as never
    })
    state.strandsAfterRefresh = ['private-credentials']
    strand(['private-credentials'])
    await settled(session)
    expect(state.calls.filter(call => call === 'read-roster')).toHaveLength(1)
    expect(await strandedCollectionMend({ session })).toEqual([
      expect.objectContaining({
        outcome: 'failed',
        detail: {
          reason: 'still-stranded',
          strandedCollections: 1,
          failedCollections: 1
        }
      })
    ])
  })

  it('does not cascade beside its own rotation that began after its read', async () => {
    const { session, strand } = makeSession()
    await tick()
    let ceremony: Promise<unknown> = Promise.resolve()
    let release: () => void = () => undefined
    const held = new Promise<void>(resolve => {
      release = resolve
    })
    vi.mocked(readUserKeyRoster).mockImplementationOnce(async () => {
      state.calls.push('read-roster')
      // A disconnect starts while the read is in flight.
      ceremony = withOwnUserKeyRotation({ session, run: () => held })
      return state.read as never
    })
    strand(['private-credentials'])
    await tick()
    const entries = await strandedCollectionMend({ session })
    release()
    await ceremony
    expect(entries).toEqual([
      expect.objectContaining({
        outcome: 'noop',
        detail: { reason: 'own-rotation-in-progress' }
      })
    ])
    expect(state.calls.some(call => call.startsWith('cascade'))).toBe(false)
  })

  it('starts one trailing run for a collection stranded while a run was in flight', async () => {
    const { session, strand } = makeSession()
    await tick()
    const started = vi.fn()
    subscribeStrandedCollectionMend({ session, listener: started })
    let release: () => void = () => undefined
    const held = new Promise<void>(resolve => {
      release = resolve
    })
    vi.mocked(readUserKeyRoster).mockImplementationOnce(async () => {
      state.calls.push('read-roster')
      await held
      return state.read as never
    })
    strand(['private-credentials'])
    await tick()
    strand(['private-credentials', 'contacts'])
    strand(['private-credentials', 'contacts'])
    await tick()
    release()
    await settled(session)
    // The run reads its candidates after the roster read, so it takes the
    // late collection too; the one trailing run finds nothing left.
    expect(state.calls).toContain('cascade:private-credentials,contacts')
    expect(started).toHaveBeenCalledTimes(2)
    expect(state.calls.filter(call => call === 'read-roster')).toHaveLength(1)
    expect(await strandedCollectionMend({ session })).toEqual([
      expect.objectContaining({
        outcome: 'noop',
        detail: { reason: 'nothing-stranded' }
      })
    ])
  })

  it('lets a host failing collections in turn buy each at most one trailing run', async () => {
    const { session, strand } = makeSession()
    state.strandsAfterRefresh = ['private-credentials']
    strand(['private-credentials'])
    await settled(session)
    // The next rebuild strands another collection: one more run.
    state.strandsAfterRefresh = ['contacts']
    strand(['contacts'])
    await settled(session)
    // Then the first again, then the second: both already seen.
    state.strandsAfterRefresh = ['private-credentials']
    strand(['private-credentials'])
    await settled(session)
    state.strandsAfterRefresh = ['contacts']
    strand(['contacts'])
    await settled(session)
    expect(state.calls.filter(call => call === 'read-roster')).toHaveLength(2)
  })

  it('writes no client-key record once the session is disposed mid-run', async () => {
    const { session, strand, persistClientKeys } = makeSession({
      kind: 'enrolled'
    })
    // A remembered session's stale-seal site adopts; the forget ceremony
    // aborts the signal during the roster read.
    state.contextKind = 'enrolled'
    state.read = readOf([K1, K2])
    vi.mocked(readUserKeyRoster).mockImplementationOnce(async () => {
      disposeSession({ session })
      return state.read as never
    })
    strand([])
    const entries = await mendUnlockRegistrySeal({ session })
    expect(entries).toEqual([expect.objectContaining({ outcome: 'failed' })])
    expect(persistClientKeys).not.toHaveBeenCalled()
    expect(session.profile.userKey).toBe(K1)
  })
})

describe('the stale-seal encounter', () => {
  it('re-seals from a fresh roster read taken behind a log refresh', async () => {
    state.contextKind = 'enrolled'
    const { session } = makeSession({ kind: 'enrolled' })
    const entries = await mendUnlockRegistrySeal({ session })
    expect(entries).toEqual([
      {
        invariant: 'unlock-registry-opens-under-the-current-user-key',
        outcome: 'clean'
      }
    ])
    expect(state.calls).toEqual(['refresh-log', 'read-roster', 'repair'])
    expect(vi.mocked(repairStaleUnlockRegistrySeal)).toHaveBeenCalledWith(
      expect.objectContaining({ rosterRead: state.read })
    )
    // An enrolled session reads with its own key.
    expect(vi.mocked(readUserKeyRoster)).toHaveBeenCalledWith(
      expect.objectContaining({ clientKeyAgreementKey: CLIENT_KAK })
    )
  })

  it('follows a rotation it is behind before any re-seal, so the re-seal only goes forward', async () => {
    state.contextKind = 'enrolled'
    const { session, persistClientKeys } = makeSession({ kind: 'enrolled' })
    state.read = readOf([K1, K2])
    // The rotator sealed the registry forward: it opens once the session
    // is on K2.
    state.repairResult = 'ok'
    const keysAtRepair: Array<string | undefined> = []
    vi.mocked(repairStaleUnlockRegistrySeal).mockImplementationOnce(
      async ({ session: repaired }) => {
        state.calls.push('repair')
        keysAtRepair.push(repaired.profile.userKey?.id)
        return state.repairResult as never
      }
    )
    const entries = await mendUnlockRegistrySeal({ session })
    expect(entries).toEqual([
      expect.objectContaining({ outcome: 'clean', detail: { adopted: true } })
    ])
    expect(state.calls).not.toContain('rewrap')
    expect(state.calls.indexOf('persist')).toBeLessThan(
      state.calls.indexOf('repair')
    )
    expect(keysAtRepair).toEqual([K2.id])
    expect(persistClientKeys).toHaveBeenCalledWith({ userKey: K2 })
    expect(session.profile.userKey).toBe(K2)
  })

  it('re-seals forward after following a rotation whose own re-seal tore', async () => {
    state.contextKind = 'enrolled'
    const { session } = makeSession({ kind: 'enrolled' })
    state.read = readOf([K1, K2])
    state.repairResult = 'repaired'
    const entries = await mendUnlockRegistrySeal({ session })
    expect(entries).toEqual([
      expect.objectContaining({ outcome: 'clean', detail: { adopted: true } })
    ])
    expect(vi.mocked(repairStaleUnlockRegistrySeal)).toHaveBeenCalledWith(
      expect.objectContaining({ rosterRead: state.read })
    )
    expect(session.profile.userKey).toBe(K2)
  })

  it('stands down without spending the budget beside its own rotation', async () => {
    state.contextKind = 'enrolled'
    const { session } = makeSession({ kind: 'enrolled' })
    state.read = readOf([K1, K2])
    let entries: unknown
    await withOwnUserKeyRotation({
      session,
      run: async () => {
        entries = await mendUnlockRegistrySeal({ session })
      }
    })
    expect(entries).toEqual([
      expect.objectContaining({
        outcome: 'noop',
        detail: { reason: 'own-rotation-in-progress' }
      })
    ])
    // Not budgeted: the next encounter runs again.
    await mendUnlockRegistrySeal({ session })
    expect(session.profile.userKey).toBe(K2)
  })

  it('renews the delegation first and unwraps with the standing key on a transient session', async () => {
    const { session } = makeSession()
    await mendUnlockRegistrySeal({ session })
    expect(state.calls).toEqual([
      'renew',
      'refresh-log',
      'read-roster',
      'repair'
    ])
    expect(vi.mocked(readUserKeyRoster)).toHaveBeenCalledWith(
      expect.objectContaining({ clientKeyAgreementKey: STANDING_KAK })
    )
  })

  it('reports a lost race as failed and does not run it again in the session', async () => {
    state.contextKind = 'enrolled'
    const { session } = makeSession({ kind: 'enrolled' })
    state.repairResult = 'unrepaired'
    const first = await mendUnlockRegistrySeal({ session })
    expect(first).toEqual([
      expect.objectContaining({
        outcome: 'failed',
        detail: { reason: 'unrepaired' }
      })
    ])
    expect(await mendUnlockRegistrySeal({ session })).toEqual(first)
    expect(state.calls.filter(call => call === 'repair')).toHaveLength(1)
  })

  it('opens at construction on a session that starts no block, so Settings leaves repairing', async () => {
    state.contextKind = 'enrolled'
    const { session } = makeSession({ kind: 'enrolled', blockFollows: false })
    // A signup or lobby session: no registryReady at all.
    expect(session.registryReady).toBeUndefined()
    await expect(mendUnlockRegistrySeal({ session })).resolves.toHaveLength(1)
  })
})

describe('encounterLostRosterWrap', () => {
  it('is true only for a refused no-roster-wrap entry', () => {
    const entry = {
      invariant: 'collection-epochs-name-the-current-user-key',
      ceremonies: []
    } as const
    expect(
      encounterLostRosterWrap({
        entries: [
          { ...entry, outcome: 'refused', detail: { reason: 'no-roster-wrap' } }
        ]
      })
    ).toBe(true)
    expect(
      encounterLostRosterWrap({
        entries: [
          { ...entry, outcome: 'failed', detail: { reason: 'no-roster' } }
        ]
      })
    ).toBe(false)
    expect(
      encounterLostRosterWrap({
        entries: [{ ...entry, outcome: 'refused', detail: { reason: 'held' } }]
      })
    ).toBe(false)
  })
})
