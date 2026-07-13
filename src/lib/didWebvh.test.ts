/**
 * Unit tests for did:webvh hosting: the KMS-signer bridge, log-URL / DID
 * mapping, JSONL serialization, the idempotent provisioning flow and its
 * torn-state matrix, plus two library-behavior pins -- the Multikey `webDoc`
 * shape (decision 5) and the sparse-`updateDID` document preservation the F2.d
 * rotation ceremony depends on. Driven by an in-memory Ed25519 keystore fake
 * (no KMS, no WAS server).
 */
import { describe, it, expect, vi } from 'vitest'
import type { KeystoreAgent } from '@interop/webkms-client'
import {
  createDID,
  deriveNextKeyHash,
  getFileUrl,
  readLogFromString,
  resolveDIDFromLog,
  updateDID
} from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import { verifyPresentation } from '@interop/verifier-core'
import {
  didWebvhControllerTemplate,
  ensureDidWebvh,
  kmsUpdateKeySigner,
  repairKeyBindings,
  rotateWebvhUpdateKey,
  type DidWebKeyMapV2,
  type DidWebvhBlock
} from './didWebvh'
import { assembleDidDocument, type DidWebKeyMap } from './didWeb'
import {
  presentationSuiteFor,
  EDDSA_RDFC_2022
} from '@/lib/walletRequest/presentationSuite'
import { loadSessionRecord, saveSessionRecord } from '@/lib/sessionKey'
import {
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  DID_LOG_RESOURCE
} from '@/app.config'
import type { Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

// jsdom provides no IndexedDB, and the persisted-session cache refresh
// (`refreshPersistedDidWebvh`) reads/writes it. Stub the record helpers: the
// default no-record case is a no-op refresh, and individual tests override
// `loadSessionRecord` to assert the didWebvh cache patch.
vi.mock('@/lib/sessionKey', async importOriginal => {
  const actual = await importOriginal<typeof import('@/lib/sessionKey')>()
  return {
    ...actual,
    loadSessionRecord: vi.fn(async () => null),
    saveSessionRecord: vi.fn(async () => {})
  }
})

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-abc'
const DID_WEB = 'did:web:localhost%3A8080:space:space-abc:id'

/**
 * An in-memory Ed25519 key with the shape `kmsUpdateKeySigner` consumes,
 * standing in for a WebKMS update key.
 */
async function inMemoryKey(): Promise<{
  publicKeyMultibase: string
  nextKeyHash: string
  keyPair: Ed25519VerificationKey
}> {
  const keyPair = await Ed25519VerificationKey.generate()
  const { publicKeyMultibase } = keyPair
  keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`
  const nextKeyHash = await deriveNextKeyHash(publicKeyMultibase)
  return { publicKeyMultibase, nextKeyHash, keyPair }
}

function keyMap(): DidWebKeyMap {
  return {
    authentication: { vmId: `${DID_WEB}#z6MkAuth`, kmsKeyId: 'kms/keys/auth' },
    assertionMethod: {
      vmId: `${DID_WEB}#z6MkAssert`,
      kmsKeyId: 'kms/keys/assert'
    },
    keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
  }
}

describe('getFileUrl (library-owned did -> did.jsonl mapping)', () => {
  it('maps a freewallet-shaped did:webvh id to its world-readable log URL', () => {
    // The library now owns the DID-to-URL mapping (the local `didWebvhLogUrl`
    // helper was deleted); this thin sanity pins the shape freewallet relies on
    // in Settings. localhost keeps http; the port rides the host segment.
    expect(
      getFileUrl(
        `did:webvh:z6MkScidExample:localhost%3A8080:space:${SPACE_ID}:id`
      )
    ).toBe('http://localhost:8080/space/space-abc/id/did.jsonl')
  })

  it('uses https for a non-local host', () => {
    expect(
      getFileUrl(`did:webvh:z6MkScidExample:example.com:space:${SPACE_ID}:id`)
    ).toBe('https://example.com/space/space-abc/id/did.jsonl')
  })
})

describe('didWebvhControllerTemplate', () => {
  it('percent-encodes a host with a port and keeps the {SCID} placeholder', () => {
    expect(
      didWebvhControllerTemplate({ wasServerUrl: WAS_URL, spaceId: SPACE_ID })
    ).toBe('did:webvh:{SCID}:localhost%3A8080:space:space-abc:id')
  })

  it('leaves a plain host unencoded', () => {
    expect(
      didWebvhControllerTemplate({
        wasServerUrl: 'https://example.com',
        spaceId: SPACE_ID
      })
    ).toBe('did:webvh:{SCID}:example.com:space:space-abc:id')
  })
})

describe('kmsUpdateKeySigner', () => {
  it('round-trips: createDID then resolveDIDFromLog verifies the proof', async () => {
    const active = await inMemoryKey()
    const staged = await inMemoryKey()
    const signer = kmsUpdateKeySigner({
      key: active.keyPair.signer(),
      publicKeyMultibase: active.publicKeyMultibase
    })

    const result = await createDID({
      address: 'localhost:8080',
      paths: ['space', SPACE_ID, 'id'],
      signer,
      updateKeys: [active.publicKeyMultibase],
      nextKeyHashes: [staged.nextKeyHash],
      verificationMethods: [
        {
          id: `did:webvh:{SCID}:localhost%3A8080:space:${SPACE_ID}:id#z6MkAuth`,
          type: 'Multikey',
          controller: `did:webvh:{SCID}:localhost%3A8080:space:${SPACE_ID}:id`,
          publicKeyMultibase: 'z6MkAuth'
        }
      ],
      portable: true,
      alsoKnownAsWeb: true
    })

    expect(result.did.startsWith('did:webvh:')).toBe(true)
    expect(signer.getVerificationMethodId()).toBe(
      `did:key:${active.publicKeyMultibase}#${active.publicKeyMultibase}`
    )

    const resolved = await resolveDIDFromLog(result.log)
    expect(resolved.meta.error).toBeUndefined()
    expect(resolved.did).toBe(result.did)
    expect(resolved.meta.scid).toBeTruthy()
  })
})

/**
 * An in-memory keystore fake that mints real Ed25519 keys (so the update-key
 * signer produces verifiable proofs) and hands them back by kmsId, emulating
 * the server's `{publicKeyMultibase}` alias expansion.
 */
class KmsFake {
  keys = new Map<string, Ed25519VerificationKey>()
  generated = 0
  // Extra List Keys entries (e.g. the Phase 1 did:web keys, which this fake
  // does not mint), returned ahead of the generated update keys.
  listed: Array<{
    id: string
    keyUrl: string
    publicKeyMultibase?: string
    type: string
  }> = []

  async generateKey({
    publicAliasTemplate
  }: {
    category: string
    publicAliasTemplate: string
  }) {
    this.generated += 1
    const keyPair = await Ed25519VerificationKey.generate()
    const { publicKeyMultibase } = keyPair
    keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`
    const kmsId = `kms/keys/webvh-${this.generated}`
    this.keys.set(kmsId, keyPair)
    return {
      id: publicAliasTemplate.replaceAll(
        '{publicKeyMultibase}',
        publicKeyMultibase
      ),
      kmsId
    }
  }

  async getAsymmetricKey({ kmsId }: { kmsId: string }) {
    const keyPair = this.keys.get(kmsId)
    if (!keyPair) {
      throw new Error(`KmsFake has no key ${kmsId}`)
    }
    return keyPair.signer()
  }

  /**
   * The List Keys projection: every key's public description plus `keyUrl`,
   * the canonical invocation URL (here the fake's kmsId) -- the K5 list-only
   * field the repair path matches bindings through.
   */
  async listKeys() {
    const generated = [...this.keys.entries()].map(([kmsId, keyPair]) => ({
      id: `did:key:${keyPair.publicKeyMultibase}#${keyPair.publicKeyMultibase}`,
      keyUrl: kmsId,
      publicKeyMultibase: keyPair.publicKeyMultibase,
      type: 'Ed25519VerificationKey2020'
    }))
    return [...this.listed, ...generated]
  }
}

/**
 * A WASRemoteStore fake over the `id` collection: records writes, serves the
 * in-memory `did.jsonl` back (as a real published log would), and reports
 * missing resources as `undefined`.
 */
function webvhFakes({
  webvh,
  logText,
  didDoc,
  kms = new KmsFake()
}: {
  webvh?: DidWebKeyMapV2['webvh']
  logText?: string
  didDoc?: object
  kms?: KmsFake
} = {}) {
  const puts: Array<{
    resourceId: string
    contentType?: string
    content: unknown
  }> = []
  const publicized: string[] = []
  let currentLog = logText
  let currentDidDoc = didDoc

  const didWebKeys: DidWebKeyMapV2 = {
    ...keyMap(),
    ...(webvh ? { webvh } : {})
  }
  // The mutable keys.json the store serves back through getIdResource -- the
  // rotation ceremony reads the authoritative keys.json rather than a cache.
  let currentKeys: DidWebKeyMapV2 = didWebKeys

  const remoteStore = {
    async getIdResource({ resourceId }: { resourceId: string }) {
      if (resourceId === DID_KEYS_RESOURCE) {
        return currentKeys
      }
      return resourceId === DID_DOCUMENT_RESOURCE ? currentDidDoc : undefined
    },
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      return resourceId === DID_LOG_RESOURCE ? currentLog : undefined
    },
    async putIdResource({
      resourceId,
      content,
      contentType
    }: {
      resourceId: string
      content: object | string
      contentType?: string
    }) {
      puts.push({ resourceId, contentType, content })
      if (resourceId === DID_LOG_RESOURCE && typeof content === 'string') {
        currentLog = content
      }
      if (resourceId === DID_KEYS_RESOURCE && typeof content === 'object') {
        currentKeys = content as DidWebKeyMapV2
      }
      if (resourceId === DID_DOCUMENT_RESOURCE && typeof content === 'object') {
        currentDidDoc = content
      }
    },
    async setIdResourcePublic({ resourceId }: { resourceId: string }) {
      publicized.push(resourceId)
    },
    storageServerUrl: WAS_URL,
    spaceId: SPACE_ID
  } as unknown as WASRemoteStore

  return {
    remoteStore,
    keystoreAgent: kms as unknown as KeystoreAgent,
    kms,
    didWebKeys,
    puts,
    publicized,
    log: () => currentLog,
    keys: () => currentKeys,
    didDoc: () => currentDidDoc
  }
}

/**
 * Seeds a KmsFake's List Keys projection with the three Phase 1 did:web keys
 * from {@link keyMap} (which the fake does not mint), so the repair path can
 * match `did.json`'s verification methods back to their kmsKeyIds.
 */
function listPhase1Keys(kms: KmsFake): void {
  for (const key of Object.values(keyMap())) {
    kms.listed.push({
      id: key.vmId,
      keyUrl: key.kmsKeyId,
      publicKeyMultibase: key.vmId.slice(key.vmId.lastIndexOf('#') + 1),
      type: 'Ed25519VerificationKey2020'
    })
  }
}

describe('ensureDidWebvh torn-state matrix', () => {
  it('fresh (no webvh, no log): generates keys, anchors, publishes, finalizes', async () => {
    const fakes = webvhFakes()
    const block = await ensureDidWebvh({
      keystoreAgent: fakes.keystoreAgent,
      remoteStore: fakes.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: fakes.didWebKeys
    })

    // Two update keys (active + staged) minted.
    expect(fakes.kms.generated).toBe(2)
    expect(block.did?.startsWith('did:webvh:')).toBe(true)
    expect(block.updateKey.publicKeyMultibase).toBeTruthy()
    expect(block.stagedKey.nextKeyHash).toBeTruthy()

    // Write ordering: anchor keys.json (no did) -> did.jsonl -> did.json ->
    // finalize keys.json (with did).
    expect(fakes.puts.map(put => put.resourceId)).toEqual([
      DID_KEYS_RESOURCE,
      DID_LOG_RESOURCE,
      DID_DOCUMENT_RESOURCE,
      DID_KEYS_RESOURCE
    ])
    const anchor = fakes.puts[0].content as DidWebKeyMapV2
    expect(anchor.webvh?.did).toBeUndefined()
    const final = fakes.puts[3].content as DidWebKeyMapV2
    expect(final.webvh?.did).toBe(block.did)

    // did.jsonl (text/jsonl) then did.json made public.
    expect(fakes.puts[1].contentType).toBe('text/jsonl')
    expect(fakes.publicized).toEqual([DID_LOG_RESOURCE, DID_DOCUMENT_RESOURCE])

    // The published log resolves and self-verifies.
    const resolved = await resolveDIDFromLog(readLogFromString(fakes.log()!))
    expect(resolved.meta.error).toBeUndefined()
    expect(resolved.did).toBe(block.did)
  })

  it('resume (webvh keys, no did, no log): reuses keys, publishes, finalizes', async () => {
    const active = await inMemoryKey()
    const staged = await inMemoryKey()
    const kms = new KmsFake()
    // Seed the keystore with the already-anchored keys so the signer resolves.
    kms.keys.set('kms/active', active.keyPair)
    kms.keys.set('kms/staged', staged.keyPair)
    const webvh = {
      updateKey: {
        kmsKeyId: 'kms/active',
        publicKeyMultibase: active.publicKeyMultibase
      },
      stagedKey: {
        kmsKeyId: 'kms/staged',
        publicKeyMultibase: staged.publicKeyMultibase,
        nextKeyHash: staged.nextKeyHash
      }
    }
    const fakes = webvhFakes({ webvh, kms })

    const block = await ensureDidWebvh({
      keystoreAgent: fakes.keystoreAgent,
      remoteStore: fakes.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: fakes.didWebKeys
    })

    // No new keys generated (the anchored pair is reused); no anchor re-write.
    expect(fakes.kms.generated).toBe(0)
    expect(fakes.puts.map(put => put.resourceId)).toEqual([
      DID_LOG_RESOURCE,
      DID_DOCUMENT_RESOURCE,
      DID_KEYS_RESOURCE
    ])
    expect(block.did?.startsWith('did:webvh:')).toBe(true)
    expect(block.updateKey.publicKeyMultibase).toBe(active.publicKeyMultibase)
  })

  it('crashed finalize (webvh keys, no did, log present): reconciles did without re-creating', async () => {
    // First, produce a real published log via a fresh run.
    const seed = webvhFakes()
    const published = await ensureDidWebvh({
      keystoreAgent: seed.keystoreAgent,
      remoteStore: seed.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: seed.didWebKeys
    })

    // Now simulate the crash: same keys anchored but no did, and the log is
    // already public. Reuse the seed keystore so the (unused) signer resolves.
    const webvh = {
      updateKey: published.updateKey,
      stagedKey: published.stagedKey
    }
    const fakes = webvhFakes({ webvh, logText: seed.log(), kms: seed.kms })
    const generatedBefore = fakes.kms.generated

    const block = await ensureDidWebvh({
      keystoreAgent: fakes.keystoreAgent,
      remoteStore: fakes.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: fakes.didWebKeys
    })

    // The did is reconciled from the existing log; no NEW keys, no new log,
    // only keys.json is finalized.
    expect(fakes.kms.generated).toBe(generatedBefore)
    expect(fakes.puts.map(put => put.resourceId)).toEqual([DID_KEYS_RESOURCE])
    expect(block.did).toBe(published.did)
  })

  it('steady state (webvh did present, log present): no writes', async () => {
    const seed = webvhFakes()
    const published = await ensureDidWebvh({
      keystoreAgent: seed.keystoreAgent,
      remoteStore: seed.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: seed.didWebKeys
    })

    const webvh = {
      did: published.did,
      updateKey: published.updateKey,
      stagedKey: published.stagedKey
    }
    const fakes = webvhFakes({ webvh, logText: seed.log(), kms: seed.kms })
    const block = await ensureDidWebvh({
      keystoreAgent: fakes.keystoreAgent,
      remoteStore: fakes.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: fakes.didWebKeys
    })

    expect(block.did).toBe(published.did)
    expect(fakes.puts).toEqual([])
    expect(fakes.publicized).toEqual([])
  })

  it('frozen log (no webvh, log present): repairs the bindings via List Keys', async () => {
    // Publish a real Space first, then simulate the disaster: keys.json rolled
    // back to a pre-Phase-2 copy (the Phase 1 map survives, the webvh block --
    // and with it every update-key kmsKeyId -- is lost) while the log and
    // did.json stay public and the keys still live in the keystore.
    const seed = webvhFakes()
    listPhase1Keys(seed.kms)
    const published = await ensureDidWebvh({
      keystoreAgent: seed.keystoreAgent,
      remoteStore: seed.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: seed.didWebKeys
    })

    const fakes = webvhFakes({
      logText: seed.log(),
      didDoc: seed.didDoc(),
      kms: seed.kms
    })
    const warnings: unknown[] = []
    const original = console.warn
    console.warn = (...args: unknown[]) => {
      warnings.push(args)
    }
    let block: DidWebvhBlock
    try {
      block = await ensureDidWebvh({
        keystoreAgent: fakes.keystoreAgent,
        remoteStore: fakes.remoteStore,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        didWebKeys: fakes.didWebKeys
      })
    } finally {
      console.warn = original
    }

    // The signable bindings are rediscovered, not regenerated: same did, same
    // update/staged kmsKeyIds, no new keys minted, and keys.json is rewritten.
    expect(warnings).toHaveLength(1)
    expect(fakes.kms.generated).toBe(2)
    expect(block.did).toBe(published.did)
    expect(block.updateKey).toEqual(published.updateKey)
    expect(block.stagedKey).toEqual(published.stagedKey)
    expect(fakes.keys().webvh?.did).toBe(published.did)
    expect(fakes.keys().authentication).toEqual(keyMap().authentication)
  })

  it('frozen log with no published did.json still throws (nothing to repair from)', async () => {
    const fakes = webvhFakes({ logText: '{"versionId":"1-abc"}' })
    await expect(
      ensureDidWebvh({
        keystoreAgent: fakes.keystoreAgent,
        remoteStore: fakes.remoteStore,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        didWebKeys: fakes.didWebKeys
      })
    ).rejects.toThrow(/did\.json is not published/)
    expect(fakes.kms.generated).toBe(0)
  })
})

describe('repairKeyBindings', () => {
  /** Publishes a full Space (Phase 1 keys listed, log + did.json public). */
  async function publishedSpace() {
    const seed = webvhFakes()
    listPhase1Keys(seed.kms)
    const published = await ensureDidWebvh({
      keystoreAgent: seed.keystoreAgent,
      remoteStore: seed.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: seed.didWebKeys
    })
    return { seed, published }
  }

  it('rebuilds the full keys.json from published artifacts alone', async () => {
    const { seed, published } = await publishedSpace()
    // A completely fresh store holding only the published artifacts -- the
    // total-loss case (keys.json gone entirely).
    const fakes = webvhFakes({
      logText: seed.log(),
      didDoc: seed.didDoc(),
      kms: seed.kms
    })

    const repaired = await repairKeyBindings({
      keystoreAgent: fakes.keystoreAgent,
      remoteStore: fakes.remoteStore
    })

    // Phase 1 map matched from did.json by publicKeyMultibase.
    expect(repaired.authentication).toEqual(keyMap().authentication)
    expect(repaired.assertionMethod).toEqual(keyMap().assertionMethod)
    expect(repaired.keyAgreement).toEqual(keyMap().keyAgreement)
    // The webvh block matched from the log: the active update key by
    // updateKeys membership, the staged key by its nextKeyHashes hash -- the
    // only public trace a staged key has.
    expect(repaired.webvh?.did).toBe(published.did)
    expect(repaired.webvh?.updateKey).toEqual(published.updateKey)
    expect(repaired.webvh?.stagedKey).toEqual(published.stagedKey)
    // The rebuilt anchor is persisted in one write.
    expect(fakes.puts.map(put => put.resourceId)).toEqual([DID_KEYS_RESOURCE])
  })

  it('rebuilds a Phase-1-only Space (no log): key map without a webvh block', async () => {
    const kms = new KmsFake()
    listPhase1Keys(kms)
    const fakes = webvhFakes({
      didDoc: assembleDidDocument({ did: DID_WEB, keys: keyMap() }),
      kms
    })
    const repaired = await repairKeyBindings({
      keystoreAgent: fakes.keystoreAgent,
      remoteStore: fakes.remoteStore
    })
    expect(repaired.authentication).toEqual(keyMap().authentication)
    expect(repaired.webvh).toBeUndefined()
  })

  it('throws when no keystore key matches the log updateKeys (truly frozen)', async () => {
    const { seed } = await publishedSpace()
    // Wipe the generated update keys from the keystore: the listing still
    // carries the Phase 1 keys, but nothing matches the log's authority.
    seed.kms.keys.clear()
    const fakes = webvhFakes({
      logText: seed.log(),
      didDoc: seed.didDoc(),
      kms: seed.kms
    })
    await expect(
      repairKeyBindings({
        keystoreAgent: fakes.keystoreAgent,
        remoteStore: fakes.remoteStore
      })
    ).rejects.toThrow(/cannot be updated/)
  })

  it('throws when the staged prerotation key is lost (next rotation impossible)', async () => {
    const { seed, published } = await publishedSpace()
    // Drop only the staged key: the active update key still matches, but no
    // listed key hashes into the committed nextKeyHashes.
    seed.kms.keys.delete(published.stagedKey.kmsKeyId)
    const fakes = webvhFakes({
      logText: seed.log(),
      didDoc: seed.didDoc(),
      kms: seed.kms
    })
    await expect(
      repairKeyBindings({
        keystoreAgent: fakes.keystoreAgent,
        remoteStore: fakes.remoteStore
      })
    ).rejects.toThrow(/staged prerotation key is lost/)
  })

  it('throws when a did.json verification method matches no keystore key', async () => {
    const { seed } = await publishedSpace()
    // The did:web keys vanish from the keystore listing.
    seed.kms.listed = []
    const fakes = webvhFakes({
      logText: seed.log(),
      didDoc: seed.didDoc(),
      kms: seed.kms
    })
    await expect(
      repairKeyBindings({
        keystoreAgent: fakes.keystoreAgent,
        remoteStore: fakes.remoteStore
      })
    ).rejects.toThrow(/no keystore key matches the authentication/)
  })
})

describe('decision 5: Multikey webDoc shape', () => {
  it('createDID(alsoKnownAsWeb) emits Multikey VMs and cross-links did:web/did:webvh', async () => {
    const active = await inMemoryKey()
    const staged = await inMemoryKey()
    const signer = kmsUpdateKeySigner({
      key: active.keyPair.signer(),
      publicKeyMultibase: active.publicKeyMultibase
    })
    const controllerTemplate = `did:webvh:{SCID}:localhost%3A8080:space:${SPACE_ID}:id`

    const result = await createDID({
      address: 'localhost:8080',
      paths: ['space', SPACE_ID, 'id'],
      signer,
      updateKeys: [active.publicKeyMultibase],
      nextKeyHashes: [staged.nextKeyHash],
      verificationMethods: [
        {
          id: `${controllerTemplate}#z6MkAuth`,
          type: 'Multikey',
          controller: controllerTemplate,
          publicKeyMultibase: 'z6MkAuth'
        }
      ],
      authentication: [`${controllerTemplate}#z6MkAuth`],
      assertionMethod: [`${controllerTemplate}#z6MkAuth`],
      portable: true,
      alsoKnownAsWeb: true
    })

    const webDoc = result.webDoc as {
      id: string
      alsoKnownAs?: string[]
      verificationMethod?: Array<{ type: string; publicKeyMultibase?: string }>
    }
    expect(webDoc.id.startsWith('did:web:')).toBe(true)
    // The webDoc VMs keep the Multikey type (not the 2020 suites).
    expect(webDoc.verificationMethod?.[0].type).toBe('Multikey')
    expect(webDoc.verificationMethod?.[0].publicKeyMultibase).toBe('z6MkAuth')
    // alsoKnownAs cross-links the did:webvh id both ways.
    expect(webDoc.alsoKnownAs).toContain(result.did)
    // The webvh doc carries the did:web alias.
    const webvhDoc = result.doc as { alsoKnownAs?: string[] }
    expect(webvhDoc.alsoKnownAs?.some(id => id.startsWith('did:web:'))).toBe(
      true
    )
  })
})

/**
 * Decision 5 compatibility pin, the runtime half: verifier-core must actually
 * verify a DIDAuth VP whose holder resolves to the Multikey `webDoc` that Phase
 * 2 adopts as `did.json`. The shape test above only asserts the document's VM
 * `type` flipped from the 2020 suites to `Multikey`; this one proves the flip is
 * safe for verifiers -- the holder path decision 8 deliberately keeps on
 * did:web. Both the wallet's default `Ed25519Signature2020` (VC 1.0) and the
 * negotiated `eddsa-rdfc-2022` (VC 2.0) presentation proofs are exercised
 * against the same Multikey verification method, using the wallet's own
 * `presentationSuiteFor`. Fully offline: a custom `httpGetService` serves the
 * webDoc for the did:web resolution, so no network and no WAS server are
 * touched.
 */
describe('decision 5: verifier-core verifies proofs against the Multikey webDoc', () => {
  /**
   * A real Ed25519 key published as a `Multikey` verification method in an
   * offline-served did:web document -- the fixture both suites verify against.
   */
  async function multikeyDidWebFixture() {
    const keyPair = await Ed25519VerificationKey.generate()
    const did = 'did:web:example.com:space:space-abc:id'
    const vmId = `${did}#${keyPair.publicKeyMultibase}`
    keyPair.id = vmId
    keyPair.controller = did

    const webDoc = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: vmId,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: keyPair.publicKeyMultibase
        }
      ],
      authentication: [vmId],
      assertionMethod: [vmId]
    }

    // Serve only the did:web document. Bundled JSON-LD contexts resolve inside
    // the security loader without ever reaching here, so any other fetch is an
    // unexpected network reach the test should fail loudly on.
    const httpGetService = {
      async get(url: string) {
        if (String(url).endsWith('/did.json')) {
          return {
            body: webDoc,
            headers: new Headers({ 'content-type': 'application/json' }),
            status: 200
          }
        }
        throw new Error(`unexpected network fetch in test: ${url}`)
      }
    }

    // Under jsdom the node build of ed25519-verification-key signs via
    // node:crypto, which returns a `Buffer`; `@scure/base` v2 (the suite's
    // multibase encoder) rejects it because it checks `constructor.name ===
    // 'Uint8Array'`, which `Buffer` fails. Real browsers use noble and return a
    // plain Uint8Array, so this normalization is a test-environment shim only.
    const rawSigner = keyPair.signer()
    const signer = {
      algorithm: rawSigner.algorithm,
      id: rawSigner.id,
      async sign(args: { data: Uint8Array }) {
        return Uint8Array.from(await rawSigner.sign(args))
      }
    }

    return { did, vmId, signer, httpGetService }
  }

  // fetchRemoteContexts: false pins issuance/signing to bundled contexts, so a
  // missing context surfaces as a loud failure rather than a silent fetch.
  const signingLoader = securityLoader({ fetchRemoteContexts: false }).build()

  const cases = [
    {
      label: 'Ed25519Signature2020 (VC 1.0 default)',
      cryptosuite: undefined,
      version: 1.0
    },
    {
      label: 'eddsa-rdfc-2022 (VC 2.0 DataIntegrityProof)',
      cryptosuite: EDDSA_RDFC_2022,
      version: 2.0
    }
  ]

  it.each(cases)(
    'a $label DIDAuth VP verifies against the Multikey VM',
    async ({ cryptosuite, version }) => {
      const { did, vmId, signer, httpGetService } =
        await multikeyDidWebFixture()
      const { suite } = presentationSuiteFor({ signer, cryptosuite })
      const challenge = 'decision5-challenge'

      const unsigned = vc.createPresentation({ holder: did, version })
      const signedVP = await vc.signPresentation({
        presentation: unsigned,
        suite,
        challenge,
        documentLoader: signingLoader
      })

      // The DIDAuth proof is anchored on the Multikey VM (not a 2020-suite VM).
      const proof = signedVP.proof as { verificationMethod: string }
      expect(proof.verificationMethod).toBe(vmId)

      const result = await verifyPresentation({
        presentation: signedVP,
        challenge,
        registries: [],
        httpGetService,
        verbose: true
      })

      expect(result.verified).toBe(true)
    }
  )
})

/**
 * The rotation-ceremony (F2.d) correctness pin: `updateDID` clones the prior
 * entry's document and overlays only supplied directives, so a key-only update
 * (updateKeys + nextKeyHashes, no verificationMethods) must leave the document's
 * verification methods intact -- the caller need NOT re-supply the VMs. Verified
 * against `method.v1.0.js` (~lines 528-560): `doc = structuredClone(lastEntry.state)`
 * and the VM arrays are only overwritten `if (safeVerificationMethods !== undefined)`.
 */
describe('updateDID sparse semantics (rotation pin)', () => {
  it('key-only update preserves the document verification methods', async () => {
    const active = await inMemoryKey()
    const staged = await inMemoryKey()
    const controllerTemplate = `did:webvh:{SCID}:localhost%3A8080:space:${SPACE_ID}:id`
    const created = await createDID({
      address: 'localhost:8080',
      paths: ['space', SPACE_ID, 'id'],
      signer: kmsUpdateKeySigner({
        key: active.keyPair.signer(),
        publicKeyMultibase: active.publicKeyMultibase
      }),
      updateKeys: [active.publicKeyMultibase],
      nextKeyHashes: [staged.nextKeyHash],
      verificationMethods: [
        {
          id: `${controllerTemplate}#z6MkAuth`,
          type: 'Multikey',
          controller: controllerTemplate,
          publicKeyMultibase: 'z6MkAuth'
        },
        {
          id: `${controllerTemplate}#z6MkAssert`,
          type: 'Multikey',
          controller: controllerTemplate,
          publicKeyMultibase: 'z6MkAssert'
        }
      ],
      authentication: [`${controllerTemplate}#z6MkAuth`],
      assertionMethod: [`${controllerTemplate}#z6MkAssert`],
      portable: true
    })
    const vmsBefore = created.doc.verificationMethod

    // Key-only rotation: reveal the staged key (it signs its own activation)
    // and commit a fresh next key. No document directives supplied.
    const newStaged = await inMemoryKey()
    const updated = await updateDID({
      log: created.log,
      signer: kmsUpdateKeySigner({
        key: staged.keyPair.signer(),
        publicKeyMultibase: staged.publicKeyMultibase
      }),
      updateKeys: [staged.publicKeyMultibase],
      nextKeyHashes: [newStaged.nextKeyHash]
    })

    expect(updated.doc.verificationMethod).toEqual(vmsBefore)
    expect(updated.doc.verificationMethod).toHaveLength(2)
    // The log still verifies after the sparse update.
    const resolved = await resolveDIDFromLog(updated.log)
    expect(resolved.meta.error).toBeUndefined()
  })
})

/**
 * F2.d rotation ceremony. Reuses the `webvhFakes` fake keystore + WAS store and
 * seeds a real published log via `ensureDidWebvh`, so the reveal dance runs
 * against real library crypto (in-memory Ed25519 keys standing in for the KMS).
 */
describe('rotateWebvhUpdateKey', () => {
  /**
   * Wraps a `webvhFakes` bundle as the minimal Session the ceremony reads: a
   * full-tier profile (root keystore agent) and a storage facade exposing the
   * remote store.
   */
  function rotationSession(fakes: ReturnType<typeof webvhFakes>): Session {
    return {
      profile: { keystoreAgent: fakes.keystoreAgent },
      storage: { remoteStore: fakes.remoteStore }
    } as unknown as Session
  }

  /**
   * Provisions a real published log (fresh ensureDidWebvh run) and returns the
   * seed fakes plus the published block, so rotation tests start from a
   * verifiable steady state sharing the seed keystore.
   */
  async function seedPublishedLog() {
    const seed = webvhFakes()
    const published = await ensureDidWebvh({
      keystoreAgent: seed.keystoreAgent,
      remoteStore: seed.remoteStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: seed.didWebKeys
    })
    return { seed, published }
  }

  it('reveal dance: extends the log with the staged key, commits a fresh next key, preserves the document', async () => {
    const { seed, published } = await seedPublishedLog()
    const before = await resolveDIDFromLog(readLogFromString(seed.log()!))

    const fakes = webvhFakes({
      webvh: published,
      logText: seed.log(),
      kms: seed.kms
    })
    // A stored record so the ceremony patches (not re-mints) the didWebvh cache.
    vi.mocked(loadSessionRecord).mockResolvedValueOnce({
      didWebvh: undefined
    } as never)
    vi.mocked(saveSessionRecord).mockClear()

    const session = rotationSession(fakes)
    const rotated = await rotateWebvhUpdateKey({ session })

    const after = await resolveDIDFromLog(readLogFromString(fakes.log()!))
    // The new entry verifies, the revealed key is now the sole active update
    // key, and the new staged hash is committed.
    expect(after.meta.error).toBeUndefined()
    expect(after.did).toBe(published.did)
    expect(after.meta.updateKeys).toEqual([
      published.stagedKey.publicKeyMultibase
    ])
    expect(after.meta.nextKeyHashes).toEqual([rotated.stagedKey.nextKeyHash])
    // A key-only rotation leaves the document's verification methods intact.
    expect(after.doc?.verificationMethod).toEqual(
      before.doc?.verificationMethod
    )
    expect(after.doc?.verificationMethod).toBeTruthy()

    // keys.json roles rolled forward: updateKey <- old staged, staged <- new,
    // old updateKey retired.
    expect(rotated.updateKey).toEqual({
      kmsKeyId: published.stagedKey.kmsKeyId,
      publicKeyMultibase: published.stagedKey.publicKeyMultibase
    })
    expect(rotated.stagedKey.publicKeyMultibase).not.toBe(
      published.stagedKey.publicKeyMultibase
    )
    expect(rotated.retiredKeys).toContainEqual(published.updateKey)
    expect(rotated.pendingStagedKey).toBeUndefined()

    // Caches refreshed: the in-memory profile and the persisted record.
    expect(session.profile.didWebvh?.did).toBe(published.did)
    expect(session.profile.didWebvh?.updateKey).toEqual(rotated.updateKey)
    expect(vi.mocked(saveSessionRecord)).toHaveBeenCalledWith({
      record: { didWebvh: session.profile.didWebvh }
    })
  })

  it('diverged-state guard: stagedKey.nextKeyHash not committed in the log throws before any write', async () => {
    const { seed, published } = await seedPublishedLog()
    const tampered: DidWebvhBlock = {
      ...published,
      stagedKey: { ...published.stagedKey, nextKeyHash: 'QmBogusNotCommitted' }
    }
    const fakes = webvhFakes({
      webvh: tampered,
      logText: seed.log(),
      kms: seed.kms
    })
    const generatedBefore = fakes.kms.generated

    await expect(
      rotateWebvhUpdateKey({ session: rotationSession(fakes) })
    ).rejects.toThrow(/diverged/)
    // No key minted, no resource written.
    expect(fakes.kms.generated).toBe(generatedBefore)
    expect(fakes.puts).toEqual([])
  })

  it('full-tier backstop: a delegated session (no keystore agent) throws', async () => {
    const { seed, published } = await seedPublishedLog()
    const fakes = webvhFakes({
      webvh: published,
      logText: seed.log(),
      kms: seed.kms
    })
    const delegated = {
      profile: {},
      storage: { remoteStore: fakes.remoteStore }
    } as unknown as Session

    await expect(rotateWebvhUpdateKey({ session: delegated })).rejects.toThrow(
      /full session/
    )
    expect(fakes.puts).toEqual([])
  })

  it('write ordering: the new staged kmsKeyId is anchored in keys.json before did.jsonl is rewritten', async () => {
    const { seed, published } = await seedPublishedLog()
    const fakes = webvhFakes({
      webvh: published,
      logText: seed.log(),
      kms: seed.kms
    })

    await rotateWebvhUpdateKey({ session: rotationSession(fakes) })

    const order = fakes.puts.map(put => put.resourceId)
    // Anchor keys.json -> did.jsonl -> did.json -> finalize keys.json.
    expect(order).toEqual([
      DID_KEYS_RESOURCE,
      DID_LOG_RESOURCE,
      DID_DOCUMENT_RESOURCE,
      DID_KEYS_RESOURCE
    ])
    const anchorIndex = order.indexOf(DID_KEYS_RESOURCE)
    const logIndex = order.indexOf(DID_LOG_RESOURCE)
    expect(anchorIndex).toBeLessThan(logIndex)

    // The anchor records ALL relevant kmsKeyIds -- current active, current
    // staged, and the pending (new) staged -- so no intermediate state can
    // freeze the log (decision 4 invariant).
    const anchor = fakes.puts[anchorIndex].content as DidWebKeyMapV2
    expect(anchor.webvh?.updateKey.kmsKeyId).toBe(published.updateKey.kmsKeyId)
    expect(anchor.webvh?.stagedKey.kmsKeyId).toBe(published.stagedKey.kmsKeyId)
    expect(anchor.webvh?.pendingStagedKey?.kmsKeyId).toBeTruthy()
  })

  it('recovery -- crashed before publish (pending anchored, log NOT advanced): reuses the pending key, no new key minted', async () => {
    const { seed, published } = await seedPublishedLog()
    // Pre-generate a pending staged key (as a prior anchor would have) and
    // simulate the torn state: keys.json carries it, the log is unchanged.
    const pending = await inMemoryKey()
    seed.kms.keys.set('kms/pending', pending.keyPair)
    const tornBlock: DidWebvhBlock = {
      ...published,
      pendingStagedKey: {
        kmsKeyId: 'kms/pending',
        publicKeyMultibase: pending.publicKeyMultibase,
        nextKeyHash: pending.nextKeyHash
      }
    }
    const fakes = webvhFakes({
      webvh: tornBlock,
      logText: seed.log(),
      kms: seed.kms
    })
    const generatedBefore = fakes.kms.generated

    const rotated = await rotateWebvhUpdateKey({
      session: rotationSession(fakes)
    })

    // No new key generated (the pending one is reused), and the anchor write is
    // skipped since keys.json already records it.
    expect(fakes.kms.generated).toBe(generatedBefore)
    expect(fakes.puts.map(put => put.resourceId)).toEqual([
      DID_LOG_RESOURCE,
      DID_DOCUMENT_RESOURCE,
      DID_KEYS_RESOURCE
    ])
    expect(rotated.stagedKey.publicKeyMultibase).toBe(
      pending.publicKeyMultibase
    )
    const after = await resolveDIDFromLog(readLogFromString(fakes.log()!))
    expect(after.meta.updateKeys).toEqual([
      published.stagedKey.publicKeyMultibase
    ])
    expect(after.meta.nextKeyHashes).toEqual([pending.nextKeyHash])
  })

  it('recovery -- crashed before finalize (log advanced, roles not rewritten): finalizes roles only, no new log', async () => {
    const { seed, published } = await seedPublishedLog()
    // Run a full rotation to obtain the advanced log and its new staged key.
    const first = webvhFakes({
      webvh: published,
      logText: seed.log(),
      kms: seed.kms
    })
    const rotatedFirst = await rotateWebvhUpdateKey({
      session: rotationSession(first)
    })
    const advancedLog = first.log()

    // Simulate the crash: the log advanced, but keys.json still holds the OLD
    // roles plus the pending (now log-committed) staged key.
    const tornBlock: DidWebvhBlock = {
      did: published.did,
      updateKey: published.updateKey,
      stagedKey: published.stagedKey,
      pendingStagedKey: rotatedFirst.stagedKey
    }
    const fakes = webvhFakes({
      webvh: tornBlock,
      logText: advancedLog,
      kms: seed.kms
    })
    const generatedBefore = fakes.kms.generated

    const finalized = await rotateWebvhUpdateKey({
      session: rotationSession(fakes)
    })

    // Torn finalize: roles rewritten only, no new key, no new log entry.
    expect(fakes.kms.generated).toBe(generatedBefore)
    expect(fakes.puts.map(put => put.resourceId)).toEqual([DID_KEYS_RESOURCE])
    expect(finalized.updateKey.publicKeyMultibase).toBe(
      published.stagedKey.publicKeyMultibase
    )
    expect(finalized.stagedKey.publicKeyMultibase).toBe(
      rotatedFirst.stagedKey.publicKeyMultibase
    )
    expect(finalized.retiredKeys).toContainEqual(published.updateKey)
    expect(finalized.pendingStagedKey).toBeUndefined()
  })
})
