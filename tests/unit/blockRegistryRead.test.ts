// @vitest-environment node
/**
 * Unit tests for the login block's one unlock-methods registry read
 * (`blockRegistryRead`, `src/session/registryPasses.ts`).
 *
 * Four registrations of a block want the registry as it stands, and each
 * reading it for itself is four fetches of one record. The memo is per block
 * rather than per session, and a pass that WROTE the registry drops it, so
 * the passes behind that one read the record it left rather than the one it
 * replaced.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: undefined as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

import { blockRegistryRead } from '@/session/registryPasses'
import type { Session } from '@/types/auth'

/**
 * A session whose registry read resolves off the browser-local cache alone
 * (no WAS server configured), with the cache load counted.
 */
function fakeSession(): { session: Session; load: ReturnType<typeof vi.fn> } {
  const load = vi.fn(async () => null)
  const session = {
    user: { id: 'did:key:z6MkClient' },
    profile: {
      userKey: { id: 'did:key:z6LSVault', secret: new Uint8Array(32) },
      keyAgreementKey: { id: 'did:key:z6LSVault#kak' },
      keyResolver: async () => ({})
    },
    persistence: {
      unlockMethodsCache: {
        load,
        save: vi.fn(async () => undefined),
        delete: vi.fn(async () => undefined)
      }
    }
  } as unknown as Session
  return { session, load }
}

beforeEach(() => {
  vi.clearAllMocks()
  state.wasUrl = undefined
})

describe("the block's registry read", () => {
  it('reads the registry once however many passes ask for it', async () => {
    const { session, load } = fakeSession()
    const registry = blockRegistryRead({ session })

    expect(await registry.read()).toBeNull()
    expect(await registry.read()).toBeNull()
    expect(await registry.read()).toBeNull()

    expect(load).toHaveBeenCalledOnce()
  })

  it('re-reads once a pass that wrote the registry drops the memo', async () => {
    const { session, load } = fakeSession()
    const registry = blockRegistryRead({ session })

    await registry.read()
    registry.invalidate()
    await registry.read()

    expect(load).toHaveBeenCalledTimes(2)
  })

  it('keeps two blocks apart', async () => {
    const { session, load } = fakeSession()

    await blockRegistryRead({ session }).read()
    await blockRegistryRead({ session }).read()

    expect(load).toHaveBeenCalledTimes(2)
  })

  it('hands every asker the same refusal a single read would raise', async () => {
    const { session } = fakeSession()
    // A session with no user key cannot read the registry at all.
    delete (session.profile as { userKey?: unknown }).userKey
    const registry = blockRegistryRead({ session })

    await expect(registry.read()).rejects.toThrow('The vault must be unlocked')
    await expect(registry.read()).rejects.toThrow('The vault must be unlocked')
  })
})
