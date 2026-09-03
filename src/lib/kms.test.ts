/**
 * Unit tests for the KMS-authentication stage: the idempotent provisioning of
 * the account's one KMS-held `authentication` key and the `keys.json` binding
 * that records it (driven by fakes -- no KMS, no WAS server).
 */
import { describe, it, expect, vi } from 'vitest'
import type { KeystoreAgent } from '@interop/webkms-client'
import type { DidWebKeyMapV2 } from '@interop/wallet-core/webvh'
import { DID_DOCUMENT_RESOURCE, DID_KEYS_RESOURCE } from '@/app.config'
import { ensureKmsAuthentication } from './kms'

const DID = 'did:web:localhost%3A8080:space:space-abc:id'
const LISTED_MULTIBASE = 'z6MkAuth'

/**
 * A served `keys.json` naming the key the fake keystore lists.
 *
 * @returns {DidWebKeyMapV2}
 */
function servedMap(): DidWebKeyMapV2 {
  return {
    authentication: {
      vmId: `${DID}#${LISTED_MULTIBASE}`,
      kmsKeyId: 'kms/keys/auth'
    }
  }
}

/**
 * A `keys.json` written before the `keyAgreement` binding was retired: read
 * for its `authentication` member and rewritten without the legacy one.
 *
 * @returns {object}
 */
function legacyMap(): object {
  return {
    ...servedMap(),
    keyAgreement: { vmId: `${DID}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
  }
}

/**
 * A fake key-map store and keystore agent. The store records every write with
 * the precondition it carried; the agent lists one key (the served map's) and
 * mints deterministic aliases, as the server's publicAliasTemplate expansion
 * would.
 *
 * @param options {object}
 * @param [options.keys] {unknown}   the served `keys.json`, if any
 * @param [options.lists] {string[]}   the multibases the keystore lists
 * @param [options.listThrows] {number}   how many leading listing attempts
 *   are refused (`Infinity` for a keystore that never answers)
 * @returns {object}
 */
function fakes({
  keys,
  lists = [LISTED_MULTIBASE],
  listThrows = 0
}: {
  keys?: unknown
  lists?: string[]
  listThrows?: number
} = {}) {
  const puts: Array<{
    resourceId: string
    ifNoneMatch?: boolean
    content?: object
  }> = []
  let generated = 0
  let listed = 0
  let served = keys

  const webvhIdStore = {
    async putKeyMap({
      content,
      ifNoneMatch
    }: {
      content: object
      ifNoneMatch?: boolean
    }) {
      // The key map is the `key-map` collection's single `keys.json`
      // resource; recorded under its resource id so the write assertions
      // read naturally beside the `did.json` one that must never happen.
      puts.push({ resourceId: DID_KEYS_RESOURCE, ifNoneMatch, content })
      return { etag: 'etag-1' }
    },
    async getIdResource() {
      return undefined
    },
    async putIdResource({ resourceId }: { resourceId: string }) {
      puts.push({ resourceId })
    }
  }

  const remoteStore = {
    async getKeyMap() {
      return served
    },
    webvhIdStore() {
      return webvhIdStore
    }
  } as unknown as Parameters<typeof ensureKmsAuthentication>[0]['remoteStore']

  const keystoreAgent = {
    async generateKey() {
      generated += 1
      return {
        id: `${DID}#z6MkGen${generated}`,
        kmsId: `kms/keys/gen-${generated}`
      }
    },
    async listKeys() {
      listed += 1
      if (listed <= listThrows) {
        throw new Error('the keystore listing was refused')
      }
      return lists.map(publicKeyMultibase => ({
        id: `${DID}#${publicKeyMultibase}`,
        publicKeyMultibase
      }))
    }
  } as unknown as KeystoreAgent

  return {
    remoteStore,
    keystoreAgent,
    puts,
    generatedCount: () => generated,
    listedCount: () => listed,
    serve: (map: unknown) => {
      served = map
    }
  }
}

describe('ensureKmsAuthentication', () => {
  it('adopts a served map the keystore lists, minting and writing nothing', async () => {
    const { remoteStore, keystoreAgent, puts, generatedCount } = fakes({
      keys: servedMap()
    })

    const binding = await ensureKmsAuthentication({
      lookupKeystoreAgent: async () => keystoreAgent,
      provideKeystoreAgent: async () => keystoreAgent,
      remoteStore,
      did: DID,
      spaceReady: Promise.resolve()
    })

    expect(binding.keys).toEqual(servedMap())
    expect(binding.etag).toBeUndefined()
    expect(generatedCount()).toBe(0)
    expect(puts).toEqual([])
  })

  it('reads a legacy map for its authentication binding alone', async () => {
    const { remoteStore, keystoreAgent } = fakes({ keys: legacyMap() })

    const binding = await ensureKmsAuthentication({
      lookupKeystoreAgent: async () => keystoreAgent,
      provideKeystoreAgent: async () => keystoreAgent,
      remoteStore,
      did: DID,
      spaceReady: Promise.resolve()
    })

    // The adopted map is handed to the genesis, whose rewrite builds the
    // stored body from the `authentication` member alone, so the legacy
    // member is never republished.
    expect(binding.keys.authentication).toEqual(servedMap().authentication)
  })

  it('refuses a served map naming a key the keystore does not list', async () => {
    const { remoteStore, keystoreAgent, generatedCount, listedCount, puts } =
      fakes({
        keys: servedMap(),
        lists: ['z6MkSomethingElse']
      })
    const sleep = vi.fn(async () => {})

    await expect(
      ensureKmsAuthentication({
        lookupKeystoreAgent: async () => keystoreAgent,
        provideKeystoreAgent: async () => keystoreAgent,
        remoteStore,
        did: DID,
        spaceReady: Promise.resolve(),
        sleep
      })
    ).rejects.toThrow(/does not list/)
    // The integrity verdict: the listing ANSWERED, so a retry answers the
    // same and none is made.
    expect(listedCount()).toBe(1)
    expect(sleep).not.toHaveBeenCalled()
    // Fail-closed and residue-free: nothing is published, and no key is
    // minted against a create-if-absent write that could never land.
    expect(generatedCount()).toBe(0)
    expect(puts).toEqual([])
  })

  it('adopts a served map once a flapping keystore listing answers', async () => {
    const { remoteStore, keystoreAgent, listedCount, puts } = fakes({
      keys: servedMap(),
      listThrows: 2
    })
    const sleep = vi.fn(async () => {})

    const binding = await ensureKmsAuthentication({
      lookupKeystoreAgent: async () => keystoreAgent,
      provideKeystoreAgent: async () => keystoreAgent,
      remoteStore,
      did: DID,
      spaceReady: Promise.resolve(),
      sleep
    })

    expect(binding.keys).toEqual(servedMap())
    expect(listedCount()).toBe(3)
    expect(sleep.mock.calls).toEqual([[250], [500]])
    expect(puts).toEqual([])
  })

  it('refuses a served map when the keystore cannot be listed at all', async () => {
    const { remoteStore, keystoreAgent, listedCount, puts } = fakes({
      keys: servedMap(),
      listThrows: Number.POSITIVE_INFINITY
    })
    const sleep = vi.fn(async () => {})

    let refusal: Error | undefined
    try {
      await ensureKmsAuthentication({
        lookupKeystoreAgent: async () => keystoreAgent,
        provideKeystoreAgent: async () => keystoreAgent,
        remoteStore,
        did: DID,
        spaceReady: Promise.resolve(),
        sleep
      })
    } catch (err) {
      refusal = err as Error
    }

    // The transport verdict: the served map is unverified rather than bad,
    // and the listing's own error rides along.
    expect(refusal?.message).toMatch(/could not be listed/)
    expect((refusal?.cause as Error).message).toMatch(/refused/)
    expect(listedCount()).toBe(3)
    expect(sleep.mock.calls).toEqual([[250], [500]])
    expect(puts).toEqual([])
  })

  it('retries a keystore lookup that throws the same way', async () => {
    const { remoteStore, keystoreAgent, puts } = fakes({ keys: servedMap() })
    const sleep = vi.fn(async () => {})
    const lookupKeystoreAgent = vi.fn(
      async (): Promise<KeystoreAgent | undefined> => {
        throw new Error('the keystore lookup was refused')
      }
    )

    let refusal: Error | undefined
    try {
      await ensureKmsAuthentication({
        lookupKeystoreAgent,
        provideKeystoreAgent: async () => keystoreAgent,
        remoteStore,
        did: DID,
        spaceReady: Promise.resolve(),
        sleep
      })
    } catch (err) {
      refusal = err as Error
    }

    expect(refusal?.message).toMatch(/could not be listed/)
    expect((refusal?.cause as Error).message).toMatch(/lookup was refused/)
    expect(lookupKeystoreAgent).toHaveBeenCalledTimes(3)
    expect(sleep.mock.calls).toEqual([[250], [500]])
    expect(puts).toEqual([])
  })

  it('mints one key and writes keys.json create-if-absent, never did.json', async () => {
    const { remoteStore, keystoreAgent, puts, generatedCount } = fakes()

    const binding = await ensureKmsAuthentication({
      lookupKeystoreAgent: async () => keystoreAgent,
      provideKeystoreAgent: async () => keystoreAgent,
      remoteStore,
      did: DID,
      spaceReady: Promise.resolve()
    })

    expect(generatedCount()).toBe(1)
    expect(binding.keys.authentication.vmId).toBe(`${DID}#z6MkGen1`)
    expect('keyAgreement' in binding.keys).toBe(false)
    expect(binding.etag).toBe('etag-1')
    expect(puts).toEqual([
      {
        resourceId: DID_KEYS_RESOURCE,
        ifNoneMatch: true,
        content: binding.keys
      }
    ])
    // The projection is the only producer of `did.json`; this stage writes it
    // never, which is the regression the retired standalone mint left behind.
    expect(puts.some(put => put.resourceId === DID_DOCUMENT_RESOURCE)).toBe(
      false
    )
  })

  it('waits for the Space before writing', async () => {
    const { remoteStore, keystoreAgent, puts } = fakes()
    let releaseSpace: () => void = () => {}
    const spaceReady = new Promise<void>(resolve => {
      releaseSpace = resolve
    })

    const run = ensureKmsAuthentication({
      lookupKeystoreAgent: async () => keystoreAgent,
      provideKeystoreAgent: async () => keystoreAgent,
      remoteStore,
      did: DID,
      spaceReady
    })
    await Promise.resolve()
    expect(puts).toEqual([])

    releaseSpace()
    await run
    expect(puts).toHaveLength(1)
  })

  it('adopts the winner of a lost create race', async () => {
    const { remoteStore, keystoreAgent, serve } = fakes()
    const store = remoteStore.webvhIdStore()
    store.putKeyMap = async () => {
      // The served map is what the winning establishment wrote.
      serve(servedMap())
      throw Object.assign(new Error('precondition failed'), {
        name: 'PreconditionFailedError'
      })
    }

    const binding = await ensureKmsAuthentication({
      lookupKeystoreAgent: async () => keystoreAgent,
      provideKeystoreAgent: async () => keystoreAgent,
      remoteStore,
      did: DID,
      spaceReady: Promise.resolve()
    })

    expect(binding.keys).toEqual(servedMap())
    expect(binding.etag).toBeUndefined()
  })
  it('verifies a served map through the non-creating lookup alone', async () => {
    const { remoteStore, keystoreAgent, puts, generatedCount } = fakes({
      keys: servedMap()
    })
    const lookupKeystoreAgent = vi.fn(async () => keystoreAgent)
    // The creating ensure: reaching it to VERIFY a served map would mint a
    // keystore to answer a verification question, and on a promoted account
    // an orphan one at that.
    const provideKeystoreAgent = vi.fn(async () => keystoreAgent)

    const binding = await ensureKmsAuthentication({
      lookupKeystoreAgent,
      provideKeystoreAgent,
      remoteStore,
      did: DID,
      spaceReady: Promise.resolve()
    })

    expect(binding.keys).toEqual(servedMap())
    expect(lookupKeystoreAgent).toHaveBeenCalledTimes(1)
    expect(provideKeystoreAgent).not.toHaveBeenCalled()
    expect(generatedCount()).toBe(0)
    expect(puts).toEqual([])
  })

  it('refuses a served map when no keystore is listed at all', async () => {
    const { remoteStore, keystoreAgent, puts } = fakes({ keys: servedMap() })
    const provideKeystoreAgent = vi.fn(async () => keystoreAgent)

    await expect(
      ensureKmsAuthentication({
        // What the lookup answers on a promoted account whose keystore this
        // identity no longer controls: the same refusal an unlisted key gets.
        lookupKeystoreAgent: async () => undefined,
        provideKeystoreAgent,
        remoteStore,
        did: DID,
        spaceReady: Promise.resolve()
      })
    ).rejects.toThrow(/does not list/)
    expect(provideKeystoreAgent).not.toHaveBeenCalled()
    expect(puts).toEqual([])
  })

  it('reaches the creating ensure only on the mint path', async () => {
    const { remoteStore, keystoreAgent, puts } = fakes()
    const lookupKeystoreAgent = vi.fn(async () => keystoreAgent)
    const provideKeystoreAgent = vi.fn(async () => keystoreAgent)

    await ensureKmsAuthentication({
      lookupKeystoreAgent,
      provideKeystoreAgent,
      remoteStore,
      did: DID,
      spaceReady: Promise.resolve()
    })

    expect(provideKeystoreAgent).toHaveBeenCalledTimes(1)
    expect(lookupKeystoreAgent).not.toHaveBeenCalled()
    expect(puts).toHaveLength(1)
  })
})
