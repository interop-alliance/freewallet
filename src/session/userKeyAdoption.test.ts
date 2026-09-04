/**
 * Unit tests for the rotation adoption's two halves, which split at the
 * collection fan-out:
 *
 * - the in-band step fires before the fan-out, while every collection still
 *   carries the epoch the rotation is about to retire, so it takes the
 *   rotated key material and leaves the storage ciphers alone;
 * - the post-ceremony step runs past the fan-out and is the one that rebuilds
 *   the ciphers, whether or not the in-band step's registry re-seal landed.
 *
 * @vitest-environment node
 */
import { describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import { mintUserKey, type UserKey } from '@interop/wallet-core/keys'
import type { Session } from '@/types/auth'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

vi.mock('@/session/unlockMethods', () => ({
  rewrapUnlockMethodsRecord: vi.fn(async () => {})
}))
const { rewrapUnlockMethodsRecord } = await import('@/session/unlockMethods')

const { adoptRotatedUserKey, adoptRotatedUserKeyInBand } =
  await import('@/session/userKeyAdoption')

/**
 * A session stub carrying only what the adoption touches: the vault keys it
 * re-seals from, the epoch pin store and client-key persist hook the in-band
 * step drives, and a storage double recording which adoption method ran.
 *
 * @param [options] {object}
 * @param [options.userKey] {UserKey}   the key the session is already on
 * @returns {object}
 */
function makeSession({ userKey }: { userKey?: UserKey } = {}): {
  session: Session
  storage: {
    holdRotatedVaultKeys: ReturnType<typeof vi.fn>
    adoptRotatedVaultKeys: ReturnType<typeof vi.fn>
  }
} {
  const storage = {
    holdRotatedVaultKeys: vi.fn(),
    adoptRotatedVaultKeys: vi.fn(async () => {})
  }
  const session = {
    profile: {
      zcapClient: {},
      keyAgreementKey: { id: 'urn:old-kak' },
      keyResolver: async () => ({}),
      ...(userKey ? { userKey } : {}),
      persistence: {
        epochPins: { saveFromDescriptor: vi.fn(async () => {}) }
      }
    },
    storage
  } as unknown as Session
  return { session, storage }
}

const DESCRIPTOR = { epochs: [{ id: 'epoch-2' }] }

describe('adoptRotatedUserKeyInBand', () => {
  it('holds the rotated key material and leaves the ciphers to the fan-out', async () => {
    const userKey = await mintUserKey()
    const { session, storage } = makeSession()
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    try {
      await adoptRotatedUserKeyInBand({
        session,
        spaceId: 's-space',
        accountDid: 'did:webvh:example:account',
        userKey,
        latestEpochId: 'epoch-2',
        descriptor: DESCRIPTOR
      })
    } finally {
      removeSink()
    }

    // The registry moved to the rotated key, and so did the session's own key
    // material -- but the ciphers did not, since the collections still carry
    // the epoch this rotation is about to retire.
    expect(vi.mocked(rewrapUnlockMethodsRecord)).toHaveBeenCalled()
    expect(session.profile.userKey).toBe(userKey)
    expect(storage.holdRotatedVaultKeys).toHaveBeenCalledTimes(1)
    expect(storage.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(
      capture.events.some(event =>
        event.msg.includes('the next login adopts it instead')
      )
    ).toBe(false)
  })
})

describe('adoptRotatedUserKey', () => {
  it('rebuilds the ciphers on a session the in-band step already moved, making no second registry write', async () => {
    const userKey = await mintUserKey()
    const { session, storage } = makeSession({ userKey })
    vi.mocked(rewrapUnlockMethodsRecord).mockClear()

    await adoptRotatedUserKey({ session, spaceId: 's-space', userKey })

    // The id guard is over the re-seal alone: the swap that rebuilds the
    // ciphers on the rotated descriptors runs either way.
    expect(vi.mocked(rewrapUnlockMethodsRecord)).not.toHaveBeenCalled()
    expect(storage.adoptRotatedVaultKeys).toHaveBeenCalledTimes(1)
  })

  it('retries the re-seal and swaps when the in-band step left the session on the old key', async () => {
    const userKey = await mintUserKey()
    const { session, storage } = makeSession()
    vi.mocked(rewrapUnlockMethodsRecord).mockClear()

    await adoptRotatedUserKey({ session, spaceId: 's-space', userKey })

    expect(vi.mocked(rewrapUnlockMethodsRecord)).toHaveBeenCalledTimes(1)
    expect(session.profile.userKey).toBe(userKey)
    expect(storage.adoptRotatedVaultKeys).toHaveBeenCalledTimes(1)
  })
})
