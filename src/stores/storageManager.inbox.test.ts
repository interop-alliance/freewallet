// @vitest-environment node
/**
 * The storage manager's `inbox` read (`readInbox`, the per-message reads,
 * `deleteInboxMessage`) over a fake remote store's collection handle: the
 * three trust tests that make an `inbox` read as untrusted, the lazy page
 * walk, the metadata and body reads, and the delete that counts a message
 * already gone as done.
 */
import { describe, expect, it, vi } from 'vitest'
import { browserLocalSessionPersistence } from '@/session/persistence'
import { StorageManager } from './storageManager'
import type { WASRemoteStore } from './wasRemoteStore'

/**
 * A named error, the shape the storage manager matches on.
 *
 * @param name {string}
 * @returns {Error}
 */
function namedError(name: string): Error {
  return Object.assign(new Error(name), { name })
}

/**
 * A storage manager over a fake remote whose `inbox` handle answers as
 * given.
 *
 * @param [options] {object}
 * @param [options.metadata] {object | null}   what `describe()` serves
 * @param [options.isPublic] {boolean}
 * @param [options.pages] {string[][]}   the listing's pages of ids
 * @param [options.deleteError] {Error}
 * @returns {object}   the storage manager and the handle's spies
 */
function inboxStorage({
  metadata = { id: 'inbox', type: ['Collection'] },
  isPublic = false,
  pages = [],
  deleteError
}: {
  metadata?: Record<string, unknown> | null
  isPublic?: boolean
  pages?: string[][]
  deleteError?: Error
} = {}) {
  const resources = {
    meta: vi.fn(async () => ({
      contentType: 'application/json',
      size: 120,
      createdBy: 'did:key:z6MkAgent'
    })),
    get: vi.fn(async () => ({ type: 'Grant' })),
    delete: vi.fn(async () => {
      if (deleteError) {
        throw deleteError
      }
    })
  }
  const pageReads = vi.fn()
  const handle = {
    describe: vi.fn(async () => metadata),
    isPublic: vi.fn(async () => isPublic),
    async *listPages() {
      for (const page of pages) {
        pageReads()
        yield { items: page.map(id => ({ id, url: id, contentType: 'x' })) }
      }
    },
    resource: vi.fn(() => resources)
  }
  const remoteStore = {
    spaceId: 's',
    spaceUrl: 'https://was.example/space/s/',
    baseServerUrl: 'https://was.example',
    collectionHandle: vi.fn(() => handle)
  } as unknown as WASRemoteStore
  const storage = new StorageManager({
    persistence: browserLocalSessionPersistence(),
    remoteStore,
    vaultKeys: {} as never
  })
  return { storage, handle, resources, pageReads, remoteStore }
}

describe('StorageManager.readInbox', () => {
  it('reads a trusted inbox page by page, lazily', async () => {
    const { storage, pageReads, remoteStore } = inboxStorage({
      pages: [['m1', 'm2'], ['m3']]
    })

    const read = await storage.readInbox()

    expect(remoteStore.collectionHandle).toHaveBeenCalledWith({
      collectionId: 'inbox'
    })
    expect(read.trust).toBe('trusted')
    expect(pageReads).not.toHaveBeenCalled()
    const seen: string[][] = []
    for await (const page of (read as { pages: AsyncIterable<string[]> })
      .pages) {
      seen.push(page)
      break
    }
    expect(seen).toEqual([['m1', 'm2']])
    expect(pageReads).toHaveBeenCalledTimes(1)
  })

  it('reads an absent inbox as absent', async () => {
    const { storage } = inboxStorage({ metadata: null })
    expect(await storage.readInbox()).toEqual({ trust: 'absent' })
  })

  it.each([
    {
      reason: 'encrypted',
      options: {
        metadata: { id: 'inbox', encryption: { scheme: 'edv' } }
      }
    },
    {
      reason: 'attributed',
      options: {
        metadata: { id: 'inbox', generator: { id: 'did:key:z6MkApp' } }
      }
    },
    { reason: 'public', options: { isPublic: true } }
  ])('refuses an inbox that is $reason', async ({ reason, options }) => {
    const { storage } = inboxStorage(options)
    expect(await storage.readInbox()).toEqual({ trust: 'untrusted', reason })
  })
})

describe('the inbox message reads', () => {
  it('reads the metadata before the body, as stored, with no codec', async () => {
    const { storage, handle } = inboxStorage()

    expect(await storage.readInboxMessageMeta({ resourceId: 'm1' })).toEqual({
      resourceId: 'm1',
      contentType: 'application/json',
      size: 120,
      createdBy: 'did:key:z6MkAgent'
    })
    expect(await storage.readInboxMessageBody({ resourceId: 'm1' })).toEqual({
      type: 'Grant'
    })
    expect(handle.resource).toHaveBeenCalledWith('m1', {
      encryption: 'plaintext'
    })
  })

  it('counts a delete of a message already gone as done', async () => {
    const { storage } = inboxStorage({
      deleteError: namedError('NotFoundError')
    })
    await expect(
      storage.deleteInboxMessage({ resourceId: 'm1' })
    ).resolves.toBeUndefined()
  })

  it('throws any other delete failure', async () => {
    const { storage } = inboxStorage({
      deleteError: namedError('NetworkError')
    })
    await expect(
      storage.deleteInboxMessage({ resourceId: 'm1' })
    ).rejects.toThrow('NetworkError')
  })
})
