/**
 * Unit tests for the store-time app-key refusal: `StorageManager.addCredential`
 * is the single entry point every credential coming from outside the wallet
 * goes through (the CHAPI store popup, the URL / QR / manual-paste import, the
 * credentials half of a space import), and it refuses every credential
 * presenting as an app key -- whether or not it binds to its own seed, since a
 * fully attacker-generated credential binds perfectly. Only the wallet's own
 * mint path stores one, through its own store method (`addMintedAppKey`), which in
 * turn refuses anything that does not carry the mint invariants and writes to
 * the dedicated `app-keys` collection.
 *
 * The second half covers that collection's surface: `addMintedAppKey` /
 * `listAppKeys` / `deleteAppKeyResource`, their idempotence on the
 * credential's content cid, the delete's binding check against the
 * connection's DID, and the two separations that keep an app's seed out of
 * the credential-wide surfaces (no Resource among the credentials, no
 * credential-created activity). A key the connection names that the local
 * replica holds but cannot open refuses the delete. The delete against a remote Space is covered
 * in `storageManager.sharing.test.ts`.
 *
 * The manager runs over a real BrowserStore on memory RxDB with real EDV
 * ciphers and no remote store, so a stored credential really round-trips
 * through encrypt/decrypt and a refused one really leaves the collection empty.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { Json } from '@interop/was-sync'
import { CapabilityAgent } from '@interop/capability-agent'
import {
  AppKeyMintInvariantError,
  AppKeyRefusedError,
  mintAppKeyCredential
} from '@interop/wallet-request'
import {
  closeMemoryStores,
  memoryStorageManager,
  type CollectionPair,
  type MemoryStorageHarness
} from '@/stores/testing/memoryStorageManager'

const app = {
  name: 'Text Editor',
  appUrl: 'https://app.example/editor'
}
const origin = 'https://app.example'

/**
 * The collections an app key's store path touches.
 */
const APP_KEY_COLLECTIONS: CollectionPair[] = [
  ['privateCredentials', 'private-credentials'],
  ['appKeys', 'app-keys'],
  ['walletActivity', 'wallet-activity']
]

afterEach(closeMemoryStores)

/**
 * A StorageManager over a fresh memory-RxDB BrowserStore with real ciphers and
 * no remote store, plus the user its history entries are attributed to.
 *
 * @returns {Promise<MemoryStorageHarness>}
 */
async function makeStorage(): Promise<MemoryStorageHarness> {
  return await memoryStorageManager({
    collections: APP_KEY_COLLECTIONS,
    controller: 'did:key:z6MkTestController',
    userIdPrefix: 'did:key:z6MkAppKeyUser'
  })
}

/**
 * An app-key credential whose subject/issuer DID is an attacker's rather than
 * the one its own seed derives -- the credential a hostile site would hand the
 * wallet through the CHAPI store popup or a crafted import URL.
 */
async function plantedAppKey(): Promise<IVerifiableCredential> {
  const attacker = await CapabilityAgent.fromSecret({
    secret: 'attacker-secret',
    handle: 'attacker'
  })
  const { credential } = await mintAppKeyCredential({ app, origin })
  ;(credential as { issuer: string }).issuer = attacker.id
  ;(credential.credentialSubject as { id: string }).id = attacker.id
  return credential
}

/**
 * The subject DID of an app-key credential: the DID its own seed derives, and
 * the `id` of the app's connections entry.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string}
 */
function subjectOf(credential: IVerifiableCredential): string {
  return (credential.credentialSubject as { id: string }).id
}

describe('StorageManager.addCredential app-key screening', () => {
  it('refuses a planted app key and stores nothing', async () => {
    const { storage, user } = await makeStorage()
    await expect(
      storage.addCredential({ credential: await plantedAppKey(), user })
    ).rejects.toThrow(AppKeyRefusedError)
    expect(await storage.listCredentials()).toEqual([])
  })

  it('refuses an externally arriving app key even when it binds', async () => {
    // The core attack shape: an attacker-generated credential with its OWN
    // fresh seed binds perfectly, so binding cannot admit it -- the marker
    // alone refuses, and only the mint path's store method stores one.
    const { storage, user } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })
    await expect(storage.addCredential({ credential, user })).rejects.toThrow(
      AppKeyRefusedError
    )
    expect(await storage.listCredentials()).toEqual([])
  })

  it('addMintedAppKey refuses a credential that does not bind', async () => {
    const { storage } = await makeStorage()
    await expect(
      storage.addMintedAppKey({ credential: await plantedAppKey() })
    ).rejects.toThrow(AppKeyMintInvariantError)
    expect(await storage.listCredentials()).toEqual([])
    expect((await storage.listAppKeys()).appKeys).toEqual([])
  })

  it('stores an ordinary credential that merely carries seed / origin claims', async () => {
    const { storage, user } = await makeStorage()
    const ordinary = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'SomeOtherCredential'],
      issuer: 'did:key:z6MkTestIssuer',
      credentialSubject: {
        id: 'did:key:z6MkTestSubject',
        seed: 'not-an-app-key-seed',
        origin
      }
    } as unknown as IVerifiableCredential
    await storage.addCredential({ credential: ordinary, user })
    expect(await storage.listCredentials()).toHaveLength(1)
  })
})

describe('StorageManager app-key collection surface', () => {
  it('stores a wallet-minted app key in app-keys, apart from the credentials', async () => {
    const { storage } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })

    await storage.addMintedAppKey({ credential })

    const { appKeys, skipped } = await storage.listAppKeys()
    expect(appKeys).toHaveLength(1)
    expect(appKeys[0].vc).toEqual(credential)
    // Nothing was skipped, so the match path is free to mint on a miss.
    expect(skipped).toEqual({
      unknownEpoch: 0,
      noEpochKey: 0,
      integrity: 0,
      plaintext: 0,
      undecryptable: 0
    })
    // The credential-wide surfaces (the dashboard, public links, shares) must
    // not be able to reach the app's seed, so the key is nowhere among them.
    expect(await storage.listCredentials()).toEqual([])
  })

  it('writes no credential-created activity for a minted app key', async () => {
    // The App Connect Grant activity is the record of the connection; an app
    // key is not a credential the user acquired, so History gets no row.
    const { storage } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })

    await storage.addMintedAppKey({ credential })

    expect((await storage.listHistoryItems()).entries).toEqual([])
  })

  it('is idempotent on a re-store of the same app key (content cid)', async () => {
    // JWE encryption is nondeterministic, so the resource id cannot carry
    // idempotence -- the credential's content cid does.
    const { storage } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })

    await storage.addMintedAppKey({ credential })
    await storage.addMintedAppKey({ credential })

    expect((await storage.listAppKeys()).appKeys).toHaveLength(1)
  })

  it('names the Resource holding the key on a store and on its re-store', async () => {
    const { storage } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })

    const stored = await storage.addMintedAppKey({ credential })
    // A skipped duplicate names the Resource already holding the key, which
    // the app's connections entry records as `appKey`.
    expect(await storage.addMintedAppKey({ credential })).toEqual(stored)

    const { appKeys } = await storage.listAppKeys()
    expect(appKeys.map(({ resourceId }) => resourceId)).toEqual([
      stored.resourceId
    ])
  })

  it('lists two apps apart and deletes the one its connection names', async () => {
    const { storage } = await makeStorage()
    const editor = await mintAppKeyCredential({ app, origin })
    const reader = await mintAppKeyCredential({
      app: { name: 'Reader', appUrl: 'https://app.example/reader' },
      origin
    })
    const { resourceId: editorKey } = await storage.addMintedAppKey({
      credential: editor.credential
    })
    const { resourceId: readerKey } = await storage.addMintedAppKey({
      credential: reader.credential
    })

    // Two inserts can land in the same millisecond, so the listing's
    // `updatedAt` order is not decidable here: assert membership.
    const { appKeys: listed } = await storage.listAppKeys()
    expect(listed.map(({ resourceId }) => resourceId).sort()).toEqual(
      [editorKey, readerKey].sort()
    )

    expect(
      await storage.deleteAppKeyResource({
        appKey: editorKey,
        did: subjectOf(editor.credential)
      })
    ).toBe('deleted')

    expect((await storage.listAppKeys()).appKeys.map(({ vc }) => vc)).toEqual([
      reader.credential
    ])
    // A key already deleted reads as absent, which is not an error.
    expect(
      await storage.deleteAppKeyResource({
        appKey: editorKey,
        did: subjectOf(editor.credential)
      })
    ).toBe('absent')
    expect((await storage.listAppKeys()).appKeys).toHaveLength(1)
  })

  it("leaves a key that does not bind the connection's DID", async () => {
    // A connection entry naming another app's key: its seed is that app's,
    // so the delete refuses it and leaves it stored.
    const { storage } = await makeStorage()
    const editor = await mintAppKeyCredential({ app, origin })
    const reader = await mintAppKeyCredential({
      app: { name: 'Reader', appUrl: 'https://app.example/reader' },
      origin
    })
    const { resourceId: editorKey } = await storage.addMintedAppKey({
      credential: editor.credential
    })

    expect(
      await storage.deleteAppKeyResource({
        appKey: editorKey,
        did: subjectOf(reader.credential)
      })
    ).toBe('foreign')
    expect((await storage.listAppKeys()).appKeys.map(({ vc }) => vc)).toEqual([
      editor.credential
    ])
  })

  it('reads a key reference no Resource answers as absent', async () => {
    const { storage } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })
    await storage.addMintedAppKey({ credential })
    const { credential: other } = await mintAppKeyCredential({ app, origin })

    expect(
      await storage.deleteAppKeyResource({
        appKey: 'z6DanglingAppKeyResource',
        did: subjectOf(other)
      })
    ).toBe('absent')
    expect((await storage.listAppKeys()).appKeys).toHaveLength(1)
  })

  it('refuses when the local replica of the key it names will not open', async () => {
    // A guest or no-WAS session: the Resource `appKey` names is held locally
    // but will not open, and nothing else binds the DID. Reading it as absent
    // would retire the entry and strand the key.
    const { storage, localStore } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })
    const appKey = 'z6UndecryptableAppKey'
    await localStore.rxCollection('appKeys').insert({
      id: appKey,
      updatedAt: new Date().toISOString(),
      data: {
        id: appKey,
        sequence: 0,
        jwe: { ciphertext: 'not-json{' }
      } as Json
    })
    // The listing reports the skipped replica by count alone. A body that
    // will not parse as a JWE is structural garbage (`undecryptable`), not an
    // integrity failure: was-client relabels nothing but an AEAD miss.
    const { appKeys, skipped } = await storage.listAppKeys()
    expect(appKeys).toEqual([])
    expect(skipped.undecryptable).toBe(1)
    expect(skipped.integrity).toBe(0)

    await expect(
      storage.deleteAppKeyResource({ appKey, did: subjectOf(credential) })
    ).rejects.toThrow('could not be read')
    const held = await localStore.rxCollection('appKeys').findOne(appKey).exec()
    expect(held).not.toBeNull()
  })

  it('deletes a key binding the DID when the reference it names is gone', async () => {
    const { storage } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })
    await storage.addMintedAppKey({ credential })

    expect(
      await storage.deleteAppKeyResource({
        appKey: 'z6DanglingAppKeyResource',
        did: subjectOf(credential)
      })
    ).toBe('deleted')
    expect((await storage.listAppKeys()).appKeys).toEqual([])
  })
})
