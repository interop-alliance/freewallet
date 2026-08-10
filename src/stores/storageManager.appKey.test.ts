/**
 * Unit tests for the store-time app-key refusal: `StorageManager.addCredential`
 * is the single door every credential coming from outside the wallet goes
 * through (the CHAPI store popup, the URL / QR / manual-paste import, the
 * credentials half of a space import), and it refuses every credential
 * presenting as an app key -- whether or not it binds to its own seed, since a
 * fully attacker-generated credential binds perfectly. Only the wallet's own
 * mint path stores one, through its own door (`addMintedAppKey`), which in
 * turn refuses anything that does not carry the mint invariants.
 *
 * The manager runs over a real BrowserStore on memory RxDB with real EDV
 * ciphers and no remote store, so a stored credential really round-trips
 * through encrypt/decrypt and a refused one really leaves the collection empty.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { CapabilityAgent } from '@interop/webkms-client'
import { createEdvDocCipher, type DocCipher } from '@interop/was-client/edv'
import { mintRecordEncryption } from '@/session/recordEnvelope'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { User } from '@/types/auth'
import {
  AppKeyMintInvariantError,
  AppKeyRefusedError,
  mintAppKeyCredential
} from '@/lib/appKey'
import { BrowserStore } from './browserStore'
import { StorageManager } from './storageManager'

const app = {
  name: 'Text Editor',
  credentialType: 'TextEditorAppKey',
  vocabBase: 'urn:text-editor:vocab#'
}
const origin = 'https://app.example'

const openStores: BrowserStore[] = []
let userCounter = 0

afterEach(async () => {
  while (openStores.length > 0) {
    await openStores.pop()?.close()
  }
})

/**
 * A StorageManager over a fresh memory-RxDB BrowserStore with real ciphers and
 * no remote store, plus the user its history entries are attributed to.
 */
async function makeStorage(): Promise<{ storage: StorageManager; user: User }> {
  const generated = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkTestController'
  })
  const key = generated as IKeyAgreementKey
  const keyResolver: IKeyResolver = async () => ({
    id: generated.id!,
    type: generated.type,
    publicKeyMultibase: generated.publicKeyMultibase
  })
  const ciphers: Record<string, DocCipher> = {}
  for (const [logicalKey, collectionId] of [
    ['privateCredentials', 'private-credentials'],
    ['walletActivity', 'wallet-activity']
  ]) {
    // Every encrypted collection carries a key-epoch roster from birth, so
    // each cipher gets a local one-epoch descriptor wrapped to the test KAK.
    ciphers[logicalKey] = await createEdvDocCipher({
      keyAgreementKey: key,
      keyResolver,
      collectionId,
      encryption: await mintRecordEncryption({ keyAgreementKey: key })
    })
  }
  userCounter += 1
  const user: User = {
    id: `did:key:z6MkAppKeyUser${userCounter}`,
    email: 'test@example.com'
  }
  const { localStore } = await BrowserStore.initClient({
    user,
    storage: getRxStorageMemory(),
    ciphers
  })
  await localStore.ensureUserCollections({ user })
  openStores.push(localStore)
  const storage = new StorageManager({
    localStore,
    ciphers,
    vaultKeys: { keyAgreementKey: key, keyResolver },
    descriptors: {}
  })
  return { storage, user }
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
    // alone refuses, and only the mint path's door stores one.
    const { storage, user } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })
    await expect(storage.addCredential({ credential, user })).rejects.toThrow(
      AppKeyRefusedError
    )
    expect(await storage.listCredentials()).toEqual([])
  })

  it('stores a wallet-minted app key through addMintedAppKey', async () => {
    const { storage, user } = await makeStorage()
    const { credential } = await mintAppKeyCredential({ app, origin })
    await storage.addMintedAppKey({ credential, user })
    const listed = await storage.listCredentials()
    expect(listed).toHaveLength(1)
    expect(listed[0].vc).toEqual(credential)
  })

  it('addMintedAppKey refuses a credential that does not bind', async () => {
    const { storage, user } = await makeStorage()
    await expect(
      storage.addMintedAppKey({ credential: await plantedAppKey(), user })
    ).rejects.toThrow(AppKeyMintInvariantError)
    expect(await storage.listCredentials()).toEqual([])
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
