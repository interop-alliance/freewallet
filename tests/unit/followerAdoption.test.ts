// @vitest-environment node
/**
 * The follower adoption (`adoptFollowerUserKey` in
 * `src/session/userKeyAdoption.ts`): a session another client's rotation
 * left behind the user key roster catches up to the current key mid-visit.
 * It decides on the key's position in the roster rather than on the epoch
 * pin, makes no registry re-seal, runs once per session and epoch, lets a
 * joiner re-check the position, and writes nothing once the session's
 * disposal signal has aborted.
 */
import { describe, expect, it, vi } from 'vitest'
import type { UserKey } from '@interop/wallet-core/keys'
import type { CollectionEncryption } from '@interop/was-client'
import type { Session } from '@/types/auth'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

vi.mock('@/session/unlockMethods', () => ({
  rewrapUnlockMethodsRecord: vi.fn(async () => {})
}))
const { rewrapUnlockMethodsRecord } = await import('@/session/unlockMethods')

const {
  adoptFollowerUserKey,
  joinFollowerAdoption,
  ownUserKeyRotationInProgress,
  userKeyRosterPosition,
  withOwnUserKeyRotation
} = await import('@/session/userKeyAdoption')
const { browserLocalSessionPersistence } = await import('@/session/persistence')
const { disposeSession, sessionDisposalSignal } =
  await import('@/session/sessionLifecycle')

const ACCOUNT_DID = 'did:webvh:QmScid:was.example:space:s-space'

const K1 = { id: 'did:key:z6LSFollowerK1', secret: new Uint8Array(32) }
const K2 = {
  id: 'did:key:z6LSFollowerK2',
  secret: new Uint8Array(32).fill(2)
}
const K3 = {
  id: 'did:key:z6LSFollowerK3',
  secret: new Uint8Array(32).fill(3)
}

/**
 * A roster descriptor whose epochs are the given keys, oldest first, the last
 * one current.
 *
 * @param keys {UserKey[]}
 * @returns {CollectionEncryption}
 */
function rosterOf(keys: UserKey[]): CollectionEncryption {
  return {
    scheme: 'edv',
    currentEpoch: keys[keys.length - 1]!.id,
    epochs: keys.map(key => ({ id: key.id, recipients: [] }))
  } as unknown as CollectionEncryption
}

/**
 * The fresh roster read a site hands over: the descriptor and its current
 * key, unwrapped.
 *
 * @param keys {UserKey[]}
 * @returns {object}
 */
function readOf(keys: UserKey[]) {
  const current = keys[keys.length - 1]!
  return {
    descriptor: rosterOf(keys),
    userKey: current,
    latestEpochId: current.id
  }
}

/**
 * A session stub carrying what the adoption reads and writes: the profile's
 * key and account pointer, the client-key record hook, the persistence
 * strategy's epoch pins, and a storage double.
 *
 * @param [options] {object}
 * @param [options.userKey] {UserKey}   the key the session is on
 * @returns {object}
 */
function makeSession({ userKey = K1 }: { userKey?: UserKey } = {}) {
  const persistClientKeys = vi.fn(
    async (_changes: { userKey: UserKey }) => undefined
  )
  const storage = {
    holdRotatedVaultKeys: vi.fn(),
    refreshEncryptedDescriptors: vi.fn(async () => undefined),
    adoptRotatedVaultKeys: vi.fn(async () => undefined)
  }
  const session = {
    user: { id: 'did:key:z6MkFollower' },
    isGuest: false,
    profile: {
      userKey,
      accountPointer: {
        did: ACCOUNT_DID,
        spaceId: 's-space',
        host: 'https://was.example'
      },
      persistClientKeys
    },
    persistence: browserLocalSessionPersistence(),
    storage,
    disposal: sessionDisposalSignal(),
    encounterGate: Promise.resolve()
  } as unknown as Session
  return { session, storage, persistClientKeys }
}

describe('userKeyRosterPosition', () => {
  it("places the session's key against the roster's current epoch", () => {
    const roster = rosterOf([K1, K2])
    expect(
      userKeyRosterPosition({
        session: makeSession({ userKey: K1 }).session,
        descriptor: roster
      })
    ).toBe('behind')
    expect(
      userKeyRosterPosition({
        session: makeSession({ userKey: K2 }).session,
        descriptor: roster
      })
    ).toBe('current')
    expect(
      userKeyRosterPosition({
        session: makeSession({ userKey: K2 }).session,
        // A read older than the session's own rotation: its current epoch
        // precedes the session's key in the list.
        descriptor: { ...roster, currentEpoch: K1.id }
      })
    ).toBe('ahead')
    expect(
      userKeyRosterPosition({
        session: makeSession({ userKey: K3 }).session,
        descriptor: roster
      })
    ).toBe('unplaced')
  })
})

describe('adoptFollowerUserKey', () => {
  it('moves a session behind the roster onto the current key, with no registry re-seal', async () => {
    const { session, storage, persistClientKeys } = makeSession()
    vi.mocked(rewrapUnlockMethodsRecord).mockClear()

    const result = await adoptFollowerUserKey({
      session,
      read: readOf([K1, K2])
    })

    expect(result).toEqual({ adopted: true, position: 'current' })
    expect(session.profile.userKey).toBe(K2)
    expect(persistClientKeys).toHaveBeenCalledWith({ userKey: K2 })
    expect(
      await session.persistence.epochPins.load({ accountDid: ACCOUNT_DID })
    ).toBe(K2.id)
    expect(storage.holdRotatedVaultKeys).toHaveBeenCalledTimes(1)
    // The refusing rebuild runs, and the throwing one does not.
    expect(storage.refreshEncryptedDescriptors).toHaveBeenCalledTimes(1)
    expect(storage.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(vi.mocked(rewrapUnlockMethodsRecord)).not.toHaveBeenCalled()
  })

  it('still adopts when the epoch pin is already ahead of the key', async () => {
    const { session } = makeSession()
    // A failed in-band re-seal saved the pin and left the session on K1.
    await session.persistence.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: K2.id,
      descriptor: rosterOf([K1, K2])
    })

    const result = await adoptFollowerUserKey({
      session,
      read: readOf([K1, K2])
    })

    expect(result.adopted).toBe(true)
    expect(session.profile.userKey).toBe(K2)
  })

  it('leaves a current or unplaced session alone', async () => {
    const current = makeSession({ userKey: K2 })
    expect(
      await adoptFollowerUserKey({
        session: current.session,
        read: readOf([K1, K2])
      })
    ).toEqual({ adopted: false, position: 'current' })
    expect(current.persistClientKeys).not.toHaveBeenCalled()

    const unplaced = makeSession({ userKey: K3 })
    expect(
      await adoptFollowerUserKey({
        session: unplaced.session,
        read: readOf([K1, K2])
      })
    ).toEqual({ adopted: false, position: 'unplaced' })
    expect(unplaced.session.profile.userKey).toBe(K3)
    expect(unplaced.storage.holdRotatedVaultKeys).not.toHaveBeenCalled()
  })

  it('runs two concurrent adoptions of the same epoch once', async () => {
    const { session, storage, persistClientKeys } = makeSession()
    const [first, second] = await Promise.all([
      adoptFollowerUserKey({ session, read: readOf([K1, K2]) }),
      adoptFollowerUserKey({ session, read: readOf([K1, K2]) })
    ])

    expect(persistClientKeys).toHaveBeenCalledTimes(1)
    expect(storage.refreshEncryptedDescriptors).toHaveBeenCalledTimes(1)
    expect(first).toEqual({ adopted: true, position: 'current' })
    // The joiner re-checks the position rather than assuming it.
    expect(second).toEqual({ adopted: false, position: 'current' })
  })

  it('lets a joiner see a session the first run could not move', async () => {
    const { session } = makeSession()
    // Fail before the profile moves, so the session stays behind.
    session.persistence.epochPins.saveFromDescriptor = async () => {
      throw new Error('the pin store is gone')
    }
    const [first, second] = await Promise.allSettled([
      adoptFollowerUserKey({ session, read: readOf([K1, K2]) }),
      adoptFollowerUserKey({ session, read: readOf([K1, K2]) })
    ])
    expect(first.status).toBe('rejected')
    expect(second).toEqual({
      status: 'fulfilled',
      value: { adopted: false, position: 'behind' }
    })
  })

  it('writes no client-key record once a forget aborts the signal mid-adoption', async () => {
    const { session, storage, persistClientKeys } = makeSession()
    let release: () => void = () => undefined
    const held = new Promise<void>(resolve => {
      release = resolve
    })
    const saveFromDescriptor = session.persistence.epochPins.saveFromDescriptor
    session.persistence.epochPins.saveFromDescriptor = async options => {
      await held
      await saveFromDescriptor(options)
    }

    const adoption = adoptFollowerUserKey({
      session,
      read: readOf([K1, K2])
    })
    // The forget ceremony aborts the signal before its local wipe; the
    // adoption resumes after the wipe has run.
    disposeSession({ session })
    release()

    expect(await adoption).toEqual({ adopted: false, position: 'behind' })
    expect(persistClientKeys).not.toHaveBeenCalled()
    expect(session.profile.userKey).toBe(K1)
    expect(storage.holdRotatedVaultKeys).not.toHaveBeenCalled()
  })

  it('does not move a session whose key changed while the adoption ran', async () => {
    const { session, storage, persistClientKeys } = makeSession()
    persistClientKeys.mockImplementation(async () => {
      // Another stage of this session moved it on meanwhile.
      session.profile.userKey = K3
    })

    const result = await adoptFollowerUserKey({
      session,
      read: readOf([K1, K2])
    })

    expect(result).toEqual({ adopted: false, position: 'unplaced' })
    expect(session.profile.userKey).toBe(K3)
    expect(storage.holdRotatedVaultKeys).not.toHaveBeenCalled()
  })
})

describe('adoptFollowerUserKey against a pin moved past its read', () => {
  it('stands down when a ceremony persisted a newer key and threw before moving the session', async () => {
    const { session, storage, persistClientKeys } = makeSession()
    // The encounter took its read at K2. A revocation then rotated to K3:
    // its re-seal failed, so the pin and the record went to K3 while the
    // session stayed on K1, and it threw before its swap.
    await session.persistence.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: K3.id,
      descriptor: rosterOf([K1, K2, K3])
    })
    await persistClientKeys({ userKey: K3 })
    persistClientKeys.mockClear()

    const result = await adoptFollowerUserKey({
      session,
      read: readOf([K1, K2])
    })

    expect(result.adopted).toBe(false)
    expect(persistClientKeys).not.toHaveBeenCalled()
    expect(session.profile.userKey).toBe(K1)
    expect(storage.holdRotatedVaultKeys).not.toHaveBeenCalled()
  })

  it('keeps an older adoption from writing its key over a newer one mid-flight', async () => {
    const { session, persistClientKeys } = makeSession()
    const gate = () => {
      let open: () => void = () => undefined
      const shut = new Promise<void>(resolve => {
        open = resolve
      })
      return { shut, open }
    }
    const olderPin = gate()
    const newerRecord = gate()
    const saveFromDescriptor = session.persistence.epochPins.saveFromDescriptor
    let saves = 0
    session.persistence.epochPins.saveFromDescriptor = async options => {
      if (saves++ === 0) {
        await olderPin.shut
      }
      await saveFromDescriptor(options)
    }
    persistClientKeys.mockImplementation(async () => {
      await newerRecord.shut
    })
    // The K2 adoption waits at its pin write while the K3 one saves its pin
    // and starts its record write, with the session still on K1.
    const older = adoptFollowerUserKey({ session, read: readOf([K1, K2]) })
    const newer = adoptFollowerUserKey({
      session,
      read: readOf([K1, K2, K3])
    })
    await new Promise(resolve => setTimeout(resolve, 0))
    olderPin.open()
    expect((await older).adopted).toBe(false)
    newerRecord.open()
    expect(await newer).toEqual({ adopted: true, position: 'current' })

    expect(persistClientKeys.mock.calls.map(([call]) => call.userKey)).toEqual([
      K3
    ])
    expect(session.profile.userKey).toBe(K3)
  })
})

describe('joinFollowerAdoption', () => {
  it('waits for an adoption in flight and never rejects', async () => {
    const { session, storage } = makeSession()
    let release: () => void = () => undefined
    storage.refreshEncryptedDescriptors.mockImplementation(
      () =>
        new Promise<undefined>((_resolve, reject) => {
          release = () => reject(new Error('the host is unreachable'))
        })
    )
    const adoption = adoptFollowerUserKey({
      session,
      read: readOf([K1, K2])
    })
    let joined = false
    const join = joinFollowerAdoption({ session }).then(() => {
      joined = true
    })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(joined).toBe(false)
    release()
    await expect(adoption).rejects.toThrow('unreachable')
    await join
    expect(joined).toBe(true)
  })

  it('returns at once when nothing is in flight', async () => {
    const { session } = makeSession()
    await expect(joinFollowerAdoption({ session })).resolves.toBeUndefined()
  })
})

describe('withOwnUserKeyRotation', () => {
  it('stands down an adoption asked for while a rotating ceremony runs', async () => {
    const { session, storage, persistClientKeys } = makeSession()
    let adoption: Awaited<ReturnType<typeof adoptFollowerUserKey>> | undefined
    await withOwnUserKeyRotation({
      session,
      run: async () => {
        expect(ownUserKeyRotationInProgress({ session })).toBe(true)
        // A read taken before this ceremony rotated: K2 is current there.
        adoption = await adoptFollowerUserKey({
          session,
          read: readOf([K1, K2])
        })
        // The ceremony's own rotation lands on K3.
        await persistClientKeys({ userKey: K3 })
        session.profile.userKey = K3
      }
    })
    expect(adoption).toEqual({ adopted: false, position: 'behind' })
    expect(ownUserKeyRotationInProgress({ session })).toBe(false)
    // The last record write is the ceremony's, and nothing wrote the pin.
    expect(persistClientKeys.mock.calls.map(([call]) => call.userKey)).toEqual([
      K3
    ])
    expect(
      await session.persistence.epochPins.load({ accountDid: ACCOUNT_DID })
    ).toBeNull()
    expect(storage.holdRotatedVaultKeys).not.toHaveBeenCalled()
  })

  it('waits out an adoption already in flight, so the ceremony persists last', async () => {
    const { session, persistClientKeys } = makeSession()
    let release: () => void = () => undefined
    const held = new Promise<void>(resolve => {
      release = resolve
    })
    persistClientKeys.mockImplementationOnce(async () => {
      await held
    })
    const adoption = adoptFollowerUserKey({
      session,
      read: readOf([K1, K2])
    })
    await new Promise(resolve => setTimeout(resolve, 0))
    const order: string[] = []
    const ceremony = withOwnUserKeyRotation({
      session,
      run: async () => {
        order.push(`ceremony from ${session.profile.userKey?.id}`)
        await persistClientKeys({ userKey: K3 })
      }
    })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(order).toEqual([])
    release()
    expect(await adoption).toEqual({ adopted: true, position: 'current' })
    await ceremony
    // The ceremony began from the key the adoption moved the session onto.
    expect(order).toEqual([`ceremony from ${K2.id}`])
    expect(persistClientKeys.mock.calls.map(([call]) => call.userKey)).toEqual([
      K2,
      K3
    ])
  })

  it('clears the mark when the ceremony throws', async () => {
    const { session } = makeSession()
    await expect(
      withOwnUserKeyRotation({
        session,
        run: async () => {
          throw new Error('the rotation refused')
        }
      })
    ).rejects.toThrow('refused')
    expect(ownUserKeyRotationInProgress({ session })).toBe(false)
  })
})
