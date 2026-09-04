// @vitest-environment node
/**
 * Unit tests for the unlock-methods registry write from a transient session
 * (`updateUnlockMethods`, `src/session/unlockMethods.ts`).
 *
 * A transient session holds no root authority over the data Space, so every
 * registry request must ride the visit's generation delegation. The tier
 * guard that used to refuse these writes outright is gone, and what keeps
 * them honest is the write protocol itself: the delegation travels on the
 * read, on the collection ensure, and on the conditional PUT, and a lost
 * compare-and-swap race re-reads and re-applies under the same delegation
 * rather than reverting the concurrent writer.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IZcap } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'

const wasState = vi.hoisted(() => ({
  url: 'https://was.example.test' as string | undefined,
  records: new Map<string, unknown>(),
  versions: new Map<string, number>(),
  // Every capability each seam was invoked with, in call order.
  capabilities: { read: [], ensure: [], put: [] } as Record<string, unknown[]>,
  // A one-shot hook fired at the START of the next PUT: the seam that lands a
  // concurrent write between a read and its PUT.
  beforePut: undefined as (() => void | Promise<void>) | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return wasState.url
  }
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  ensureUnlockMethodsCollection: vi.fn(
    async ({ capability }: { capability?: IZcap }) => {
      wasState.capabilities.ensure!.push(capability)
    }
  ),
  putUnlockMethodsRecord: vi.fn(
    async ({
      spaceId,
      record,
      ifMatch,
      ifNoneMatch,
      capability
    }: {
      spaceId: string
      record: unknown
      ifMatch?: string
      ifNoneMatch?: boolean
      capability?: IZcap
    }) => {
      wasState.capabilities.put!.push(capability)
      if (wasState.beforePut) {
        const hook = wasState.beforePut
        wasState.beforePut = undefined
        await hook()
      }
      const { PreconditionFailedError } = await import('@interop/was-client')
      const exists = wasState.records.has(spaceId)
      const version = wasState.versions.get(spaceId) ?? 0
      if (ifNoneMatch && exists) {
        throw new PreconditionFailedError('A registry record already exists.')
      }
      if (ifMatch !== undefined && (!exists || ifMatch !== `v${version}`)) {
        throw new PreconditionFailedError('The registry record changed.')
      }
      wasState.records.set(spaceId, record)
      wasState.versions.set(spaceId, version + 1)
      return { etag: `v${version + 1}` }
    }
  ),
  getUnlockMethodsRecord: vi.fn(
    async ({
      spaceId,
      capability
    }: {
      spaceId: string
      capability?: IZcap
    }) => {
      wasState.capabilities.read!.push(capability)
      return wasState.records.has(spaceId)
        ? {
            record: wasState.records.get(spaceId),
            etag: `v${wasState.versions.get(spaceId) ?? 0}`
          }
        : null
    }
  )
}))

import {
  emptyUnlockMethodsRegistry,
  updateUnlockMethods,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'

const GENERATION_DELEGATION = { id: 'urn:zcap:generation' } as unknown as IZcap

/**
 * A transient session with real vault keys, so the registry record is really
 * sealed and really re-opened across the compare-and-swap retry.
 */
async function transientSession(): Promise<Session> {
  const keyAgreementKey = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkVisitKey'
  })
  const keyResolver = async () => keyAgreementKey
  return {
    user: { id: 'did:key:z6MkVisitKey' },
    storage: { spaceId: 'space-123' },
    profile: {
      zcapClient: { isAnnexVmZcapClient: true },
      keyAgreementKey,
      keyResolver,
      persistence: {
        unlockMethodsCache: {
          load: async () => null,
          save: async () => {},
          delete: async () => {}
        }
      }
    }
  } as unknown as Session
}

beforeEach(() => {
  wasState.url = 'https://was.example.test'
  wasState.records = new Map()
  wasState.versions = new Map()
  wasState.capabilities = { read: [], ensure: [], put: [] }
  wasState.beforePut = undefined
  vi.clearAllMocks()
})

describe('the registry write under a generation delegation', () => {
  it('carries the delegation on the read, the ensure, and the PUT', async () => {
    const session = await transientSession()
    await updateUnlockMethods({
      session,
      capability: GENERATION_DELEGATION,
      mutate: current => current ?? emptyUnlockMethodsRegistry()
    })
    expect(wasState.capabilities.read).toEqual([GENERATION_DELEGATION])
    expect(wasState.capabilities.ensure).toEqual([GENERATION_DELEGATION])
    expect(wasState.capabilities.put).toEqual([GENERATION_DELEGATION])
  })

  it('re-applies on a lost race, under the same delegation', async () => {
    const session = await transientSession()
    // Seed a record, then land a concurrent write between this run's read and
    // its PUT so the first attempt loses the compare-and-swap.
    await updateUnlockMethods({
      session,
      capability: GENERATION_DELEGATION,
      mutate: () => emptyUnlockMethodsRegistry()
    })
    wasState.capabilities = { read: [], ensure: [], put: [] }
    wasState.beforePut = () => {
      wasState.versions.set('space-123', 99)
    }
    const seen: Array<UnlockMethodsRecord | null> = []
    await updateUnlockMethods({
      session,
      capability: GENERATION_DELEGATION,
      mutate: current => {
        seen.push(current)
        return { ...(current ?? emptyUnlockMethodsRegistry()), methods: [] }
      }
    })
    // Two attempts: the lost one and the re-read, each carrying the
    // delegation, and the mutate ran again over the fresh base.
    expect(seen).toHaveLength(2)
    expect(wasState.capabilities.read).toEqual([
      GENERATION_DELEGATION,
      GENERATION_DELEGATION
    ])
    expect(wasState.capabilities.put).toEqual([
      GENERATION_DELEGATION,
      GENERATION_DELEGATION
    ])
  })

  it('invokes the root capability when no delegation is supplied', async () => {
    const session = await transientSession()
    await updateUnlockMethods({
      session,
      mutate: () => emptyUnlockMethodsRegistry()
    })
    expect(wasState.capabilities.read).toEqual([undefined])
    expect(wasState.capabilities.put).toEqual([undefined])
  })
})
