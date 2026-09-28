/**
 * Unit tests for the replica-less backend's halves of the content-migration
 * import methods: the verbatim contact-head write and its head listing, the
 * whole-collection revision read the held-content snapshot takes, the
 * by-inner-id activity lookup the import activity's replace needs, and the
 * row-id delete its put-then-delete-others write ends with.
 *
 * @vitest-environment node
 */
import { describe, expect, it } from 'vitest'
import type {
  ContactData,
  ContactHeadPayload,
  ContactRevisionPayload
} from '@interop/social-core'
import type { DocCipher } from '@interop/was-client/edv'
import type { Json } from '@interop/was-sync'
import { RemoteDirectStore } from './remoteDirectStore'
import type { WalletActivity } from './storageManager'
import type { WASRemoteStore } from './wasRemoteStore'

/**
 * A cipher that seals plaintext into a well-formed envelope under a fresh id
 * each time -- the nondeterminism a real JWE has, which is what makes a
 * write-side dedupe necessary in the first place.
 *
 * @returns {DocCipher}
 */
function fakeCipher(): DocCipher {
  let counter = 0
  return {
    async encrypt({ data }: { data: Json }) {
      counter += 1
      const id = `row-${counter}`
      return {
        id,
        envelope: {
          id,
          sequence: 0,
          jwe: { ciphertext: JSON.stringify(data) }
        } as Json,
        epoch: 'epoch-1'
      }
    },
    async decrypt({ envelope }: { envelope: Json }) {
      const { jwe } = envelope as { jwe: { ciphertext: string } }
      return JSON.parse(jwe.ciphertext) as Json
    }
  } as unknown as DocCipher
}

/**
 * An in-memory WAS remote: one resource map per logical collection.
 *
 * @returns {{ remote: WASRemoteStore; rows: Map<string, Map<string, Json>> }}
 */
function fakeRemote(): {
  remote: WASRemoteStore
  rows: Map<string, Map<string, Json>>
} {
  const rows = new Map<string, Map<string, Json>>()
  /**
   * @param logicalKey {string}
   * @returns {Map<string, Json>}
   */
  function collection(logicalKey: string): Map<string, Json> {
    let held = rows.get(logicalKey)
    if (!held) {
      held = new Map<string, Json>()
      rows.set(logicalKey, held)
    }
    return held
  }
  const remote = {
    async listSyncedDocuments({ logicalKey }: { logicalKey: string }) {
      return [...collection(logicalKey)].map(([id, data]) => ({ id, data }))
    },
    async putSyncedResource({
      logicalKey,
      resourceId,
      body
    }: {
      logicalKey: string
      resourceId: string
      body: Json
    }) {
      const held = collection(logicalKey)
      const created = !held.has(resourceId)
      held.set(resourceId, body)
      return { created }
    },
    async deleteSyncedResource({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      collection(logicalKey).delete(resourceId)
    }
  } as unknown as WASRemoteStore
  return { remote, rows }
}

/**
 * A backend over the in-memory remote, with a cipher for each collection the
 * migration writes.
 *
 * @returns {{ store: RemoteDirectStore; rows: Map<string, Map<string, Json>> }}
 */
function makeStore(): {
  store: RemoteDirectStore
  rows: Map<string, Map<string, Json>>
} {
  const { remote, rows } = fakeRemote()
  const store = new RemoteDirectStore({
    remoteStore: remote,
    ciphers: {
      contacts: fakeCipher(),
      contactsHistory: fakeCipher(),
      walletActivity: fakeCipher()
    }
  })
  return { store, rows }
}

const HEAD: ContactHeadPayload = {
  contactId: 'contact-1',
  updatedAt: '2024-03-04T05:06:07.000Z',
  writerId: 'old-writer',
  contact: { displayName: 'Ada' } as ContactData
}

/**
 * @param summary {string}
 * @returns {WalletActivity}
 */
function makeActivity(summary: string): WalletActivity {
  return {
    id: 'activity-1',
    type: ['Create'],
    summary,
    published: '2024-03-04T05:06:07.000Z'
  } as unknown as WalletActivity
}

describe('RemoteDirectStore contact-head import', () => {
  it('writes the archived head verbatim and lists it back', async () => {
    const { store } = makeStore()

    await store.putContactHead({ head: HEAD })

    const heads = await store.listContactHeads()
    expect(heads).toHaveLength(1)
    expect(heads[0].head.contactId).toBe('contact-1')
    expect(heads[0].head.updatedAt).toBe('2024-03-04T05:06:07.000Z')
    expect(heads[0].head.writerId).toBe('old-writer')
    expect(heads[0].head.contact.displayName).toBe('Ada')
    // The listing's projection keeps addressing the row by its row id.
    const contacts = await store.listContacts()
    expect(contacts[0].id).toBe(heads[0].rowId)
    expect(contacts[0].contactId).toBe('contact-1')
  })
})

describe('RemoteDirectStore.listAllContactRevisions', () => {
  it("reads every contact's revisions in one pass", async () => {
    const { store } = makeStore()
    /**
     * @param contactId {string}
     * @param displayName {string}
     * @returns {ContactRevisionPayload}
     */
    function revision(
      contactId: string,
      displayName: string
    ): ContactRevisionPayload {
      return {
        contactId,
        action: 'update',
        timestamp: '2024-03-04T05:06:07.000Z',
        writerId: 'old-writer',
        snapshot: { displayName } as ContactData
      }
    }
    await store.addContactRevision({ revision: revision('contact-1', 'Ada') })
    await store.addContactRevision({ revision: revision('contact-2', 'Grace') })
    await store.addContactRevision({ revision: revision('contact-1', 'Ada L') })

    const all = await store.listAllContactRevisions()
    expect(all.map(entry => entry.contactId).sort()).toEqual([
      'contact-1',
      'contact-1',
      'contact-2'
    ])
    expect(
      await store.listContactRevisions({ contactId: 'contact-1' })
    ).toHaveLength(2)
  })
})

describe('RemoteDirectStore activity row lookups', () => {
  it('finds every row carrying one activity id, where the listing collapses them', async () => {
    const { store } = makeStore()
    const firstRow = await store.addHistoryItem({
      resourceId: 'activity-1',
      activity: makeActivity('first')
    })
    await store.addHistoryItem({
      resourceId: 'activity-1',
      activity: makeActivity('second')
    })

    expect((await store.listHistoryItems()).entries).toHaveLength(1)
    const held = await store.findHistoryItemsByInnerId({ id: 'activity-1' })
    expect(held).toHaveLength(2)
    expect(held.map(({ rowId }) => rowId)).toContain(firstRow)
    expect(held.map(({ doc }) => doc.summary).sort()).toEqual([
      'first',
      'second'
    ])
  })

  it('deletes one row by its row id and leaves the rest', async () => {
    const { store } = makeStore()
    const firstRow = await store.addHistoryItem({
      resourceId: 'activity-1',
      activity: makeActivity('first')
    })
    await store.addHistoryItem({
      resourceId: 'activity-1',
      activity: makeActivity('second')
    })

    await store.deleteHistoryItemByRowId({ rowId: firstRow })

    const held = await store.findHistoryItemsByInnerId({ id: 'activity-1' })
    expect(held).toHaveLength(1)
    expect(held[0].doc.summary).toBe('second')
  })
})
