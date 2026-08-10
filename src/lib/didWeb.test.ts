/**
 * Unit tests for did:web hosting: DID derivation, DID-document assembly, and
 * the idempotent provisioning flow (driven by fakes -- no KMS, no WAS server).
 */
import { describe, it, expect } from 'vitest'
import type { KeystoreAgent } from '@interop/webkms-client'
import { assembleDidDocument, didWebFromSpace, ensureDidWeb } from './didWeb'
import type { DidWebKeyMap } from '@interop/wallet-core/webvh'
import { DID_DOCUMENT_RESOURCE, DID_KEYS_RESOURCE } from '@/app.config'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

const SPACE_ID = 'space-abc'

describe('didWebFromSpace', () => {
  it('builds a did:web from a plain host', () => {
    expect(
      didWebFromSpace({
        wasServerUrl: 'https://example.com',
        spaceId: SPACE_ID
      })
    ).toBe('did:web:example.com:space:space-abc:id')
  })

  it('percent-encodes a host with a port (dev)', () => {
    expect(
      didWebFromSpace({
        wasServerUrl: 'http://localhost:8080',
        spaceId: SPACE_ID
      })
    ).toBe('did:web:localhost%3A8080:space:space-abc:id')
  })

  it('drops a default port', () => {
    expect(
      didWebFromSpace({
        wasServerUrl: 'https://example.com:443/kms',
        spaceId: SPACE_ID
      })
    ).toBe('did:web:example.com:space:space-abc:id')
  })
})

const DID = 'did:web:localhost%3A8080:space:space-abc:id'

function keyMap(): DidWebKeyMap {
  return {
    authentication: { vmId: `${DID}#z6MkAuth`, kmsKeyId: 'kms/keys/auth' },
    keyAgreement: { vmId: `${DID}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
  }
}

describe('assembleDidDocument', () => {
  const doc = assembleDidDocument({ did: DID, keys: keyMap() }) as {
    '@context': string[]
    id: string
    verificationMethod: Array<{
      id: string
      type: string
      controller: string
      publicKeyMultibase: string
    }>
    authentication: string[]
    keyAgreement: string[]
  }

  it('carries the DID and the three suite contexts', () => {
    expect(doc.id).toBe(DID)
    expect(doc['@context']).toEqual([
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
      'https://w3id.org/security/suites/x25519-2020/v1'
    ])
  })

  it('recovers publicKeyMultibase from each vm id fragment', () => {
    const [auth, agree] = doc.verificationMethod
    expect(auth).toEqual({
      id: `${DID}#z6MkAuth`,
      type: 'Ed25519VerificationKey2020',
      controller: DID,
      publicKeyMultibase: 'z6MkAuth'
    })
    expect(agree).toEqual({
      id: `${DID}#z6LSAgree`,
      type: 'X25519KeyAgreementKey2020',
      controller: DID,
      publicKeyMultibase: 'z6LSAgree'
    })
  })

  it('wires each relationship to its verification-method id', () => {
    expect(doc.authentication).toEqual([`${DID}#z6MkAuth`])
    expect(doc.keyAgreement).toEqual([`${DID}#z6LSAgree`])
    // No assertionMethod relation at all: the relation lists client keys
    // only, and no KMS-held assertion key exists.
    expect('assertionMethod' in doc).toBe(false)
  })
})

/**
 * A fake WASRemoteStore recording writes and serving scripted reads: the key
 * map from a separate `key-map` slot (`getKeyMap` / `putKeyMap`) and `did.json`
 * from the `id` collection. Plus a fake KeystoreAgent whose `generateKey` mints
 * deterministic per-category aliases (as the server's publicAliasTemplate
 * expansion would).
 */
function fakes({
  keys,
  didDoc
}: {
  keys?: DidWebKeyMap
  didDoc?: object
} = {}) {
  const puts: Array<{ resourceId: string; contentType?: string }> = []
  let generated = 0
  const counters: Record<string, number> = {
    asymmetric: 0,
    keyAgreement: 0
  }

  const webvhIdStore = {
    async putKeyMap() {
      // The key map is the `key-map` collection's single `keys.json` resource;
      // record it under DID_KEYS_RESOURCE so write-ordering assertions read
      // naturally (the recovery anchor written before did.json).
      puts.push({ resourceId: DID_KEYS_RESOURCE, contentType: undefined })
    },
    async getIdResource({ resourceId }: { resourceId: string }) {
      if (resourceId === DID_DOCUMENT_RESOURCE) {
        return didDoc
      }
      return undefined
    },
    async putIdResource({
      resourceId,
      contentType
    }: {
      resourceId: string
      content: object
      contentType?: string
    }) {
      puts.push({ resourceId, contentType })
    }
  }

  const remoteStore = {
    async getKeyMap() {
      return keys
    },
    webvhIdStore() {
      return webvhIdStore
    }
  } as unknown as WASRemoteStore

  const keystoreAgent = {
    async generateKey({
      category
    }: {
      category: 'asymmetric' | 'keyAgreement'
    }) {
      generated += 1
      const n = (counters[category] += 1)
      const prefix = category === 'asymmetric' ? 'z6Mk' : 'z6LS'
      return {
        id: `${DID}#${prefix}Gen${n}`,
        kmsId: `kms/keys/gen-${generated}`
      }
    }
  } as unknown as KeystoreAgent

  return {
    remoteStore,
    keystoreAgent,
    puts,
    generatedCount: () => generated
  }
}

describe('ensureDidWeb', () => {
  it('steady state: one read, no regeneration or writes', async () => {
    const { remoteStore, keystoreAgent, puts, generatedCount } = fakes({
      keys: keyMap(),
      didDoc: { id: DID }
    })
    const result = await ensureDidWeb({ keystoreAgent, remoteStore, did: DID })
    expect(result).toEqual(keyMap())
    expect(generatedCount()).toBe(0)
    expect(puts).toEqual([])
  })

  it('torn state (keys.json present, did.json missing): republishes without regenerating', async () => {
    const { remoteStore, keystoreAgent, puts, generatedCount } = fakes({
      keys: keyMap(),
      didDoc: undefined
    })
    const result = await ensureDidWeb({ keystoreAgent, remoteStore, did: DID })
    expect(result).toEqual(keyMap())
    expect(generatedCount()).toBe(0)
    expect(puts).toEqual([
      { resourceId: DID_DOCUMENT_RESOURCE, contentType: 'application/did+json' }
    ])
  })

  it('fresh: generates two keys (no assertion key) and writes keys.json before did.json', async () => {
    const { remoteStore, keystoreAgent, puts, generatedCount } = fakes()
    const result = await ensureDidWeb({ keystoreAgent, remoteStore, did: DID })
    expect(generatedCount()).toBe(2)
    expect(result.authentication.vmId).toBe(`${DID}#z6MkGen1`)
    expect('assertionMethod' in result).toBe(false)
    expect(result.keyAgreement.vmId).toBe(`${DID}#z6LSGen1`)
    // keys.json (the recovery anchor, in the key-map collection) is written
    // first, then did.json.
    expect(puts.map(put => put.resourceId)).toEqual([
      DID_KEYS_RESOURCE,
      DID_DOCUMENT_RESOURCE
    ])
  })
})
