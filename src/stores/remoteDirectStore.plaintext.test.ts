/**
 * Unit tests for how the replica-less backend treats a body that is not an
 * envelope at all, in a collection it holds a cipher for. Such a body is
 * refused rather than read as the record: it never surfaces as a credential,
 * an app key, an activity, a contact, or a revision. It is also kept out of
 * the purgeable bucket, since the purge on this backend DELETEs the remote
 * resource outright.
 *
 * @vitest-environment node
 */
import { describe, expect, it } from 'vitest'
import type { DocCipher } from '@interop/pws-client/edv'
import { cidFrom } from '@interop/pws-client/sync'
import type { Json } from '@interop/pws-sync'
import { RemoteDirectStore } from './remoteDirectStore'
import type { WASRemoteStore } from './wasRemoteStore'

const CREDENTIAL = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:z6MkIssuer',
  credentialSubject: { name: 'Alice' }
} as Json

const APP_KEY = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'AppKeyCredential'],
  issuer: 'did:key:z6MkApp',
  credentialSubject: {
    id: 'did:key:z6MkApp',
    origin: 'https://app.example',
    appUrl: 'https://app.example/editor',
    seed: 'c2VlZA'
  }
} as Json

const ACTIVITY = {
  id: 'plaintext-activity',
  summary: 'plaintext',
  created: '2026-01-01T00:00:00.000Z'
} as Json

const CONTACT_HEAD = {
  contactId: 'c-plaintext',
  updatedAt: '2026-01-01T00:00:00.000Z',
  writerId: 'writer-0',
  contact: { displayName: 'Plaintext' }
} as Json

const REVISION = {
  contactId: 'c-plaintext',
  action: 'update',
  timestamp: '2026-01-01T00:00:00.000Z',
  writerId: 'writer-0',
  snapshot: { displayName: 'Plaintext' }
} as Json

/**
 * A reversible fake cipher that records every decrypt, so a test can tell a
 * refused body from one that was decrypted or passed through.
 *
 * @returns {{ cipher: DocCipher; decrypted: string[] }}
 */
function recordingCipher(): { cipher: DocCipher; decrypted: string[] } {
  const decrypted: string[] = []
  const cipher: DocCipher = {
    async encrypt({ data }: { data: Json }) {
      return {
        id: 'z6Minted',
        envelope: {
          id: 'z6Minted',
          sequence: 0,
          jwe: { ciphertext: JSON.stringify(data) }
        } as Json
      }
    },
    async encryptUpdate({ id, data }: { id: string; data: Json }) {
      return {
        id,
        envelope: {
          id,
          sequence: 1,
          jwe: { ciphertext: JSON.stringify(data) }
        } as Json
      }
    },
    async decrypt({ id, envelope }: { id?: string; envelope: Json }) {
      decrypted.push(id ?? '')
      const { ciphertext } = (envelope as { jwe: { ciphertext: string } }).jwe
      return JSON.parse(ciphertext) as Json
    }
  }
  return { cipher, decrypted }
}

/**
 * The envelope the recording cipher would have produced for `data` under
 * `id`, so a test can seed an envelope Resource beside a plaintext one.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.data {Json}
 * @returns {Json}
 */
function fakeEnvelope({ id, data }: { id: string; data: Json }): Json {
  return {
    id,
    sequence: 0,
    jwe: { ciphertext: JSON.stringify(data) }
  } as Json
}

/**
 * A remote store whose one collection holds a single plaintext Resource,
 * recording every delete and every write. Further Resources (an envelope
 * beside the plaintext one) go in `extra`. A delete removes the Resource, so
 * a later list no longer sees it.
 *
 * @param options {object}
 * @param options.resourceId {string}
 * @param options.body {Json}
 * @param [options.extra] {Record<string, Json>}
 * @returns {{ remote: WASRemoteStore; deleted: string[]; written: string[] }}
 */
function fakeRemote({
  resourceId,
  body,
  extra = {}
}: {
  resourceId: string
  body: Json
  extra?: Record<string, Json>
}): {
  remote: WASRemoteStore
  deleted: string[]
  written: string[]
} {
  const deleted: string[] = []
  const written: string[] = []
  const resources = new Map<string, Json>([
    ...Object.entries(extra),
    [resourceId, body]
  ])
  const remote = {
    async listSyncedDocuments() {
      return [...resources].map(([id, data]) => ({ id, data }))
    },
    async getSyncedResource({ resourceId: id }: { resourceId: string }) {
      return resources.get(id)
    },
    async getSyncedResourceWithEtag({
      resourceId: id
    }: {
      resourceId: string
    }) {
      const data = resources.get(id)
      return data === undefined ? undefined : { data, etag: '"1"' }
    },
    async putSyncedResource({ resourceId: id }: { resourceId: string }) {
      written.push(id)
      return { created: true }
    },
    async deleteSyncedResource({ resourceId: id }: { resourceId: string }) {
      deleted.push(id)
      resources.delete(id)
    }
  } as unknown as WASRemoteStore
  return { remote, deleted, written }
}

describe('RemoteDirectStore (a plaintext body in an encrypted collection)', () => {
  it('lists no credential, counts it as plaintext, and deletes nothing', async () => {
    const { remote, deleted } = fakeRemote({
      resourceId: 'z6Credential',
      body: CREDENTIAL
    })
    const { cipher, decrypted } = recordingCipher()
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { privateCredentials: cipher }
    })

    expect(await store.listCredentials()).toEqual([])
    expect(store.plaintextCredentials).toBe(1)
    expect(store.undecryptableCredentials).toBe(0)
    expect(store.integrityCredentials).toBe(0)
    expect(store.unknownEpochCredentials).toBe(0)
    expect(store.noEpochKeyCredentials).toBe(0)
    expect(decrypted).toEqual([])

    expect(await store.purgeUndecryptableCredentials()).toBe(0)
    expect(deleted).toEqual([])
  })

  it('deletes only the envelope when a plaintext Resource shares its cid', async () => {
    const cid = await cidFrom({ doc: CREDENTIAL as object })
    // The plaintext Resource is keyed by the credential's cid and carries the
    // same VC as the envelope beside it.
    const { remote, deleted } = fakeRemote({
      resourceId: cid,
      body: CREDENTIAL,
      extra: {
        z6Envelope: fakeEnvelope({ id: 'z6Envelope', data: CREDENTIAL })
      }
    })
    const { cipher, decrypted } = recordingCipher()
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { privateCredentials: cipher }
    })

    const listed = await store.listCredentials()
    expect(listed.map(credential => credential.cid)).toEqual([cid])
    expect(store.plaintextCredentials).toBe(1)
    expect(decrypted).toEqual(['z6Envelope'])

    await store.deleteCredential({ cid })
    expect(deleted).toEqual(['z6Envelope'])

    expect(await store.listCredentials()).toEqual([])
    expect(store.plaintextCredentials).toBe(1)
  })

  it('lists no app key, counts it as plaintext, and deletes nothing', async () => {
    const { remote, deleted } = fakeRemote({
      resourceId: 'z6AppKey',
      body: APP_KEY
    })
    const { cipher, decrypted } = recordingCipher()
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { appKeys: cipher }
    })

    expect(await store.listAppKeys()).toEqual([])
    expect(store.plaintextAppKeys).toBe(1)
    expect(store.undecryptableAppKeys).toBe(0)
    expect(store.integrityAppKeys).toBe(0)
    expect(store.unknownEpochAppKeys).toBe(0)
    expect(store.noEpochKeyAppKeys).toBe(0)
    expect(decrypted).toEqual([])

    expect(await store.purgeUndecryptableAppKeys()).toBe(0)
    expect(deleted).toEqual([])
  })

  it('lists no activity and counts it as unreadable', async () => {
    const { remote, deleted } = fakeRemote({
      resourceId: 'z6Activity',
      body: ACTIVITY
    })
    const { cipher, decrypted } = recordingCipher()
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { walletActivity: cipher }
    })

    const { entries, unknownEpoch, unreadable } = await store.listHistoryItems()
    expect(entries).toEqual([])
    expect(unknownEpoch).toBe(0)
    expect(unreadable).toBe(1)
    expect(
      await store.findHistoryItemsByInnerId({ id: 'plaintext-activity' })
    ).toEqual([])
    expect(decrypted).toEqual([])
    expect(deleted).toEqual([])
  })

  it('reads no contact head, and refuses to update it', async () => {
    const { remote, deleted, written } = fakeRemote({
      resourceId: 'z6Contact',
      body: CONTACT_HEAD
    })
    const { cipher, decrypted } = recordingCipher()
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { contacts: cipher }
    })

    expect(await store.listContacts()).toEqual([])
    expect(await store.listContactHeads()).toEqual([])
    expect(store.unknownEpochContacts).toBe(0)
    expect(await store.loadContact({ id: 'z6Contact' })).toBeUndefined()
    await expect(
      store.updateContact({
        id: 'z6Contact',
        contact: { displayName: 'Renamed' },
        writerId: 'writer-1'
      })
    ).rejects.toThrow(/not an encrypted envelope/)
    expect(decrypted).toEqual([])
    expect(written).toEqual([])
    expect(deleted).toEqual([])
  })

  it('refuses an add whose collision re-read meets a plaintext body', async () => {
    // The create reports not-created, and the re-read serves this call's own
    // head as plaintext at the minted resource id. A body that is not an
    // envelope is refused, so the add is a collision rather than a success.
    const written: Json[] = []
    const reads: string[] = []
    const deleted: string[] = []
    const remote = {
      async putSyncedResource({
        resourceId,
        body
      }: {
        resourceId: string
        body: Json
      }) {
        expect(resourceId).toBe('z6Minted')
        written.push(body)
        return { created: false }
      },
      async getSyncedResourceWithEtag({ resourceId }: { resourceId: string }) {
        reads.push(resourceId)
        const { ciphertext } = (written[0] as { jwe: { ciphertext: string } })
          .jwe
        return { data: JSON.parse(ciphertext) as Json, etag: '"1"' }
      },
      async deleteSyncedResource({ resourceId }: { resourceId: string }) {
        deleted.push(resourceId)
      }
    } as unknown as WASRemoteStore
    const { cipher, decrypted } = recordingCipher()
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { contacts: cipher }
    })

    await expect(
      store.addContact({
        contact: { displayName: 'Added' },
        writerId: 'writer-1'
      })
    ).rejects.toThrow(/"z6Minted" already exists/)
    // The one create attempt, one re-read of the minted id, no decrypt, no
    // further write, and no delete.
    expect(written).toHaveLength(1)
    expect(reads).toEqual(['z6Minted'])
    expect(decrypted).toEqual([])
    expect(deleted).toEqual([])
  })

  it('surfaces no contact revision', async () => {
    const { remote, deleted } = fakeRemote({
      resourceId: 'z6Revision',
      body: REVISION
    })
    const { cipher, decrypted } = recordingCipher()
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { contactsHistory: cipher }
    })

    expect(
      await store.listContactRevisions({ contactId: 'c-plaintext' })
    ).toEqual([])
    expect(await store.listAllContactRevisions()).toEqual([])
    expect(store.unknownEpochContactsHistory).toBe(0)
    expect(decrypted).toEqual([])
    expect(deleted).toEqual([])
  })
})
