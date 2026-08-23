/**
 * @vitest-environment node
 *
 * The forget module: the no-unlock-material grade's whole-database wipe
 * (`forgetBrowserWalletData`), its nothing-to-delete probe, and the
 * login-time forgotten-browser detector (`assertClientStillEnrolled`) --
 * wipe-on-VM-gone, no-op on a listed VM, and skip-on-unverifiable -- plus
 * the two ceremony grades of `forgetThisBrowser`: the ordinary forget, the
 * last-client transition and its record re-bind seam, and the wipe-last
 * ordering both share.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import {
  assertClientStillEnrolled,
  BrowserForgottenError,
  forgetBrowserWalletData,
  forgetThisBrowser,
  hasForgettableBrowserData
} from '@/session/forget'
import type { KeyringFetchResult } from '@/session/keyring'
import { BrowserStore } from '@/stores/browserStore'
import type { Session } from '@/types/auth'

vi.mock('@interop/wallet-core/webvh', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    verifyAccountLog: vi.fn(),
    clientSigningKeyMultibase: vi.fn(
      ({ keyAgent }: { keyAgent: { id: string } }) => keyAgent.id.split(':')[2]
    ),
    updateKeyMultibase: vi.fn(async () => 'zForgottenUpdate')
  }
})
const { accountLogPinId, verifyAccountLog } =
  await import('@interop/wallet-core/webvh')

vi.mock('@interop/did-method-webvh', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    deriveNextKeyHash: vi.fn(async (multibase: string) => `hash:${multibase}`)
  }
})

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    forgetDurableClient: vi.fn(),
    forgetLastDurableClient: vi.fn(),
    ladderVmAgent: vi.fn(async () => ({ id: 'did:key:zLadderVm' })),
    ladderVmZcapClient: vi.fn(async () => LADDER_ZCAP_CLIENT),
    clientAnnexLogStore: vi.fn(() => ({ annexLogStore: true })),
    mintDelegatedClientsDelegation: vi.fn(),
    delegatedClientsDelegationSpaceId: vi.fn(),
    delegatedClientsPointer: vi.fn(),
    clientAnnexDidParts: vi.fn()
  }
})
const {
  clientAnnexDidParts,
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  forgetDurableClient,
  forgetLastDurableClient,
  ladderVmZcapClient,
  mintDelegatedClientsDelegation
} = await import('@interop/wallet-core/clientAnnex')

vi.mock('@interop/wallet-core/keyring', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    getUnlockKeyringWithCapability: vi.fn()
  }
})
const { getUnlockKeyringWithCapability } =
  await import('@interop/wallet-core/keyring')

vi.mock('@interop/wallet-core/keys', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    userKeyRosterDescriptorStore: vi.fn(() => ({ rosterStore: true })),
    userKeyRosterLogSigner: vi.fn(() => ({ signer: true }))
  }
})

vi.mock('@interop/wallet-core/recovery', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    delegateLogWrite: vi.fn(),
    delegationProofKeyId: vi.fn(
      (delegation: { id?: string }) => `${delegation.id}#key`
    )
  }
})
const { delegateLogWrite, delegationProofKeyId } =
  await import('@interop/wallet-core/recovery')

vi.mock('@/session/persistence', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    assertAccountCeremonyAllowed: vi.fn()
  }
})
const { assertAccountCeremonyAllowed } = await import('@/session/persistence')

vi.mock('@/session/enrolledContext', () => ({
  requireEnrolledClientContext: vi.fn()
}))
const { requireEnrolledClientContext } =
  await import('@/session/enrolledContext')

vi.mock('@/session/unlockMethods', () => ({
  getUnlockMethods: vi.fn(),
  managementZcapClient: vi.fn(() => ({ managementZcapClient: true })),
  refreshStandingDelegationFields: vi.fn()
}))
const {
  getUnlockMethods,
  managementZcapClient,
  refreshStandingDelegationFields
} = await import('@/session/unlockMethods')

vi.mock('@/session/recovery', () => ({
  recoveryEntriesOf: vi.fn(() => []),
  remintEntriesOf: vi.fn(() => []),
  recordRemintedEntry: vi.fn()
}))
const { remintEntriesOf, recordRemintedEntry } =
  await import('@/session/recovery')

vi.mock('@/session/rosterStore', () => ({
  sessionRosterStore: vi.fn(() => ({ sessionRosterStore: true }))
}))

vi.mock('@/session/standingUnlock', () => ({
  unlockLogStore: vi.fn(() => ({ unlockLogStore: true }))
}))

vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollections: vi.fn(() => ({ collections: true }))
}))

vi.mock('@/session/userKeyAdoption', () => ({
  adoptRotatedUserKeyInBand: vi.fn()
}))
const { adoptRotatedUserKeyInBand } = await import('@/session/userKeyAdoption')

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(),
  verifiedAccountLog: vi.fn()
}))
const { invalidateVerifiedLog, verifiedAccountLog } =
  await import('@/session/verifiedLog')

vi.mock('@/session/wipe', async importOriginal => {
  const actual = await importOriginal<typeof import('@/session/wipe')>()
  return {
    ...actual,
    snapshotWipeTargets: vi.fn(() => WIPE_TARGETS),
    executeLocalWipe: vi.fn(actual.executeLocalWipe)
  }
})
const { executeLocalWipe, snapshotWipeTargets } = await import('@/session/wipe')

/**
 * The sentinel the ladder-VM zcap client mock hands back, so the re-bind's
 * delegation mints can be asserted to sign with it.
 */
const LADDER_ZCAP_CLIENT = { ladderZcapClient: true }

/**
 * The sentinel wipe-target snapshot, threaded from `snapshotWipeTargets`
 * into `executeLocalWipe` unchanged.
 */
const WIPE_TARGETS = { clientDid: 'did:key:zClientA' }

/**
 * A fake IDBFactory-shaped global: `databases()` serves the live name list
 * and `deleteDatabase` removes the name and fires `onsuccess` (the
 * browserStore test suite's stub, deletion-success arm only). With
 * `enumerable: false` the factory carries no `databases` member at all --
 * the engine the whole no-enumeration path exists for.
 *
 * @param options {object}
 * @param options.names {string[]}
 * @param [options.enumerable] {boolean}   whether the factory exposes
 *   `databases()` (default true)
 * @returns {{ deleted: string[] }}
 */
function stubIndexedDb({
  names,
  enumerable = true
}: {
  names: string[]
  enumerable?: boolean
}): {
  deleted: string[]
} {
  const current = new Set(names)
  const deleted: string[] = []
  vi.stubGlobal('indexedDB', {
    ...(enumerable
      ? {
          databases: async () =>
            [...current].map(name => ({ name, version: 1 }))
        }
      : {}),
    deleteDatabase(name: string) {
      const request: { onsuccess?: () => void; onerror?: () => void } = {}
      queueMicrotask(() => {
        current.delete(name)
        deleted.push(name)
        request.onsuccess?.()
      })
      return request
    },
    open() {
      throw new Error('The wipe must not open databases.')
    }
  })
  return { deleted }
}

/**
 * A minimal in-memory `localStorage` stub carrying the supplied entries.
 *
 * @param options {object}
 * @param options.entries {Record<string, string>}
 * @returns {{ keys: () => string[] }}
 */
function stubLocalStorage({ entries }: { entries: Record<string, string> }): {
  keys: () => string[]
} {
  const map = new Map(Object.entries(entries))
  vi.stubGlobal('localStorage', {
    get length() {
      return map.size
    },
    key: (index: number) => [...map.keys()][index] ?? null,
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => void map.set(key, value),
    removeItem: (key: string) => void map.delete(key)
  })
  return { keys: () => [...map.keys()] }
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.mocked(verifyAccountLog).mockReset()
})

describe('forgetBrowserWalletData (the no-unlock-material grade)', () => {
  it('deletes every replica database, the session database, and the account localStorage families, keeping prefs', async () => {
    vi.stubGlobal(
      'BroadcastChannel',
      class {
        postMessage() {}
        close() {}
      }
    )
    const { deleted } = stubIndexedDb({
      names: [
        'rxdb-dexie-abc-123-wallet-db--0--internal',
        'abc-123-sync-db',
        'freewallet-session',
        'unrelated-app-db'
      ]
    })
    const { keys } = stubLocalStorage({
      entries: {
        'freewallet:collection-encryption:scope-a:col': 'x',
        'freewallet:collection-meta:scope-b:col': 'x',
        'freewallet:plaintext-migrated:abc-123': 'x',
        'freewallet:public-cids-migrated:abc-123': 'x',
        'freewallet:writerId': 'w1',
        'fw-theme': 'dark'
      }
    })
    const { failed } = await forgetBrowserWalletData()
    expect(failed).toEqual([])
    expect(deleted).toContain('rxdb-dexie-abc-123-wallet-db--0--internal')
    expect(deleted).toContain('abc-123-sync-db')
    expect(deleted).toContain('freewallet-session')
    expect(deleted).not.toContain('unrelated-app-db')
    expect(keys()).toEqual(['fw-theme'])
  })

  it('reports nothing to forget on a never-remembered browser', async () => {
    stubIndexedDb({ names: ['unrelated-app-db'] })
    stubLocalStorage({ entries: { 'fw-theme': 'dark' } })
    expect(await hasForgettableBrowserData()).toBe(false)
  })

  it('reports forgettable data when the session database exists', async () => {
    stubIndexedDb({ names: ['freewallet-session'] })
    stubLocalStorage({ entries: {} })
    expect(await hasForgettableBrowserData()).toBe(true)
  })

  it('deletes the session database and the derivable replicas without an enumeration API, reporting them unverified', async () => {
    vi.stubGlobal(
      'BroadcastChannel',
      class {
        postMessage() {}
        close() {}
      }
    )
    const { deleted } = stubIndexedDb({ names: [], enumerable: false })
    // The replica wipe itself is the store's own contract (covered in the
    // browserStore suite); here it stands in for the engine, reporting the
    // delete it could not verify.
    const wiped: string[] = []
    const wipeStorage = vi
      .spyOn(BrowserStore.prototype, 'wipeStorage')
      .mockImplementation(async function (this: BrowserStore) {
        wiped.push(this.dbPrefix)
        return { verified: false }
      })
    const { keys } = stubLocalStorage({
      entries: {
        'freewallet:plaintext-migrated:abc-123': 'x',
        'freewallet:collection-encryption:scope-a:col': 'x',
        'fw-theme': 'dark'
      }
    })
    const { failed, unverified } = await forgetBrowserWalletData()
    wipeStorage.mockRestore()
    // The replica prefix came from the migration marker, the one
    // localStorage trace that names a replica without any enumeration.
    expect(wiped).toEqual(['abc-123'])
    // The known-name delete runs whatever the engine reports.
    expect(deleted).toContain('freewallet-session')
    expect(failed).toEqual([])
    // The session database's delete could not be re-probed, the replica
    // whose prefix the migration marker named could not be either, and no
    // enumeration means other replicas may not have been discovered at all.
    expect(unverified).toContain('session-db')
    expect(unverified).toContain('replica-discovery')
    expect(unverified).toContain('replica:abc-123')
    expect(keys()).toEqual(['fw-theme'])
  })

  it('does not answer "nothing to delete" merely because the enumeration API is missing', async () => {
    stubIndexedDb({ names: [], enumerable: false })
    stubLocalStorage({ entries: { 'fw-theme': 'dark' } })
    expect(await hasForgettableBrowserData()).toBe(true)
  })
})

describe('assertClientStillEnrolled (the forgotten-browser detector)', () => {
  const clientSeed = new Uint8Array(32).fill(7)
  const pointer = {
    did: 'did:webvh:scid-x:example.com:space-1',
    spaceId: 'space-1',
    host: 'https://storage.example'
  }

  /**
   * A keyring hit carrying this browser's client keys, shaped as the
   * detector consumes it.
   *
   * @returns {KeyringFetchResult}
   */
  function hit(): KeyringFetchResult {
    return {
      controller: 'did:key:zClientA',
      unlockSpaceId: 'unlock-1',
      pointer,
      clientKeys: { clientSeed, controller: 'did:key:zClientA' }
    } as unknown as KeyringFetchResult
  }

  it('wipes the residue and throws when the verified document no longer lists this client', async () => {
    vi.stubGlobal(
      'BroadcastChannel',
      class {
        postMessage() {}
        close() {}
      }
    )
    const agents = await agentsFromSeed({ seed: clientSeed })
    const { deriveSpaceId } = await import('@interop/was-client/sync')
    const dbPrefix = deriveSpaceId(agents.keyAgent.id)
    const { deleted } = stubIndexedDb({ names: [`${dbPrefix}-wallet-db`] })
    stubLocalStorage({ entries: {} })
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc: { verificationMethod: [{ id: `${pointer.did}#zSomeOtherClient` }] },
      log: [],
      updateKeys: [],
      nextKeyHashes: []
    } as never)
    await expect(assertClientStillEnrolled({ found: hit() })).rejects.toThrow(
      BrowserForgottenError
    )
    expect(deleted).toContain(`${dbPrefix}-wallet-db`)
  })

  it('does nothing while the document still lists this client', async () => {
    const agents = await agentsFromSeed({ seed: clientSeed })
    const [, , multibase] = agents.keyAgent.id.split(':')
    const { deleted } = stubIndexedDb({ names: ['x-wallet-db'] })
    stubLocalStorage({ entries: {} })
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc: { verificationMethod: [{ id: `${pointer.did}#${multibase}` }] },
      log: [],
      updateKeys: [],
      nextKeyHashes: []
    } as never)
    // The verification is handed back so the login can prime its memo with
    // it rather than verifying the same log again.
    await expect(
      assertClientStillEnrolled({ found: hit() })
    ).resolves.toMatchObject({
      doc: { verificationMethod: [{ id: `${pointer.did}#${multibase}` }] }
    })
    expect(deleted).toEqual([])
  })

  it('skips detection when the log cannot be verified', async () => {
    const { deleted } = stubIndexedDb({ names: ['x-wallet-db'] })
    stubLocalStorage({ entries: {} })
    vi.mocked(verifyAccountLog).mockRejectedValue(new Error('network down'))
    await expect(
      assertClientStillEnrolled({ found: hit() })
    ).resolves.toBeUndefined()
    expect(deleted).toEqual([])
  })

  it('is a no-op for a hit without client keys or a webvh pointer', async () => {
    stubIndexedDb({ names: [] })
    stubLocalStorage({ entries: {} })
    await expect(
      assertClientStillEnrolled({
        found: {
          controller: 'did:key:zClientA',
          unlockSpaceId: 'unlock-1'
        } as unknown as KeyringFetchResult
      })
    ).resolves.toBeUndefined()
    expect(vi.mocked(verifyAccountLog)).not.toHaveBeenCalled()
  })
})

describe('forgetThisBrowser (the ceremony grades)', () => {
  const pointer = {
    did: 'did:webvh:scid-a:example.com:space-1',
    spaceId: 'space-1',
    host: 'https://storage.example'
  }

  /**
   * A minimal live durable session, shaped as the forget prelude reads it:
   * the standing members, the ladder seed, this client's key-agreement
   * multibase, and the persistence handle's pin stores.
   *
   * @param options {object}
   * @param [options.withRebind] {boolean}   carry the hit's record re-bind
   *   closure (false exercises the transition's refusal)
   * @returns {object}   the session and the closures worth asserting on
   */
  function fakeSession({ withRebind = true }: { withRebind?: boolean } = {}) {
    const rebindRecord = vi.fn()
    const saveFromDescriptor = vi.fn()
    const persistClientKeys = vi.fn()
    const session = {
      user: { id: 'did:key:zClientA' },
      isGuest: false,
      storage: { wipeLocalStorage: vi.fn() },
      profile: {
        zcapClient: { zcapClient: true },
        clientKeyAgreementKey: { publicKeyMultibase: 'zClientKak' },
        userKey: { id: 'did:key:zUserKey' },
        ladderSeed: new Uint8Array(32).fill(3),
        persistClientKeys,
        standingUnlock: {
          delegation: { id: 'urn:zcap:bridge' },
          delegatedClients: { id: 'urn:zcap:sibling' },
          standingClient: {
            clientDid: 'did:key:zStanding',
            agents: {
              zcapClient: { standingZcapClient: true },
              keyAgreementKey: { id: 'did:key:zStandingKak' }
            }
          },
          unlockSpaceId: 'unlock-1',
          ...(withRebind ? { rebindRecord } : {})
        },
        persistence: {
          epochPins: {
            load: vi.fn(async () => 'epoch-1'),
            saveFromDescriptor
          },
          logPins: { logPins: true }
        }
      }
    } as unknown as Session
    return { session, rebindRecord, saveFromDescriptor, persistClientKeys }
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(requireEnrolledClientContext).mockReturnValue({
      remoteStore: { remoteStore: true },
      pointer,
      clientWebvhKeys: { updateSeed: new Uint8Array(32).fill(1) },
      keyAgent: { id: 'did:key:zClientA' }
    } as never)
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passphrase',
          unlockSpaceId: 'unlock-1',
          updateKeyMultibase: 'zRung'
        }
      ]
    } as never)
    vi.mocked(verifiedAccountLog).mockResolvedValue({ doc: {} } as never)
    vi.mocked(delegatedClientsPointer).mockReturnValue(
      'did:webvh:scid-b:example.com:annex-space' as never
    )
    // Both parts: the reach's log pin id is built from them, and the pin-id
    // builder asserts every segment.
    vi.mocked(clientAnnexDidParts).mockReturnValue({
      spaceId: 'annex-space',
      generationId: 'gen-1'
    } as never)
    vi.mocked(forgetDurableClient).mockResolvedValue({
      rotated: true
    } as never)
    vi.mocked(forgetLastDurableClient).mockResolvedValue({
      installed: true
    } as never)
    vi.mocked(executeLocalWipe).mockResolvedValue({
      failed: [],
      unverified: []
    })
  })

  it('runs the ordinary ceremony and wipes strictly after it', async () => {
    const { session } = fakeSession()
    const order: string[] = []
    vi.mocked(forgetDurableClient).mockImplementation(async () => {
      order.push('ceremony')
      return { rotated: true } as never
    })
    vi.mocked(executeLocalWipe).mockImplementation(async () => {
      order.push('wipe')
      return { failed: ['session-db'], unverified: [] }
    })
    const outcome = await forgetThisBrowser({ session })
    expect(outcome).toEqual({
      lastClient: false,
      ceremony: { rotated: true },
      wipeFailed: ['session-db'],
      wipeUnverified: []
    })
    expect(vi.mocked(forgetDurableClient)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(forgetLastDurableClient)).not.toHaveBeenCalled()
    expect(order).toEqual(['ceremony', 'wipe'])
    expect(vi.mocked(executeLocalWipe).mock.calls[0]![0]).toMatchObject({
      targets: WIPE_TARGETS,
      clearWriter: true
    })
    expect(vi.mocked(snapshotWipeTargets).mock.calls[0]![0]).toMatchObject({
      clientAnnexSpaceId: 'annex-space'
    })
    expect(vi.mocked(assertAccountCeremonyAllowed)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(invalidateVerifiedLog)).toHaveBeenCalled()
  })

  it('rethrows the last-client refusal without wiping anything', async () => {
    const { session } = fakeSession()
    const refusal = Object.assign(new Error('another ceremony applies'), {
      name: 'LastDurableClientForgetError'
    })
    vi.mocked(forgetDurableClient).mockRejectedValue(refusal)
    await expect(forgetThisBrowser({ session })).rejects.toBe(refusal)
    expect(vi.mocked(executeLocalWipe)).not.toHaveBeenCalled()
  })

  it('rethrows the record re-mint refusal without wiping anything', async () => {
    const { session } = fakeSession()
    const refusal = Object.assign(new Error('record unreachable'), {
      name: 'RecordRemintFailedError',
      failed: [{ label: 'Other method', outcome: 'failed' }]
    })
    vi.mocked(forgetLastDurableClient).mockRejectedValue(refusal)
    await expect(forgetThisBrowser({ session, lastClient: true })).rejects.toBe(
      refusal
    )
    expect(vi.mocked(executeLocalWipe)).not.toHaveBeenCalled()
    expect(vi.mocked(invalidateVerifiedLog)).toHaveBeenCalled()
  })

  it('refuses the transition when the session carries no record re-bind', async () => {
    const { session } = fakeSession({ withRebind: false })
    await expect(
      forgetThisBrowser({ session, lastClient: true })
    ).rejects.toThrow(/record re-bind/)
    expect(vi.mocked(forgetLastDurableClient)).not.toHaveBeenCalled()
    expect(vi.mocked(forgetDurableClient)).not.toHaveBeenCalled()
    expect(vi.mocked(executeLocalWipe)).not.toHaveBeenCalled()
  })

  it('runs the last-client transition with the annex reach and wipes after it', async () => {
    const { session } = fakeSession()
    const order: string[] = []
    vi.mocked(forgetLastDurableClient).mockImplementation(async () => {
      order.push('ceremony')
      return { installed: true } as never
    })
    vi.mocked(executeLocalWipe).mockImplementation(async () => {
      order.push('wipe')
      return { failed: [], unverified: [] }
    })
    const outcome = await forgetThisBrowser({ session, lastClient: true })
    expect(outcome).toEqual({
      lastClient: true,
      ceremony: { installed: true },
      wipeFailed: [],
      wipeUnverified: []
    })
    expect(vi.mocked(forgetDurableClient)).not.toHaveBeenCalled()
    expect(order).toEqual(['ceremony', 'wipe'])
    const options = vi.mocked(forgetLastDurableClient).mock.calls[0]![0]
    expect(options.annex).toMatchObject({
      wasServerUrl: pointer.host,
      accountSpaceId: pointer.spaceId,
      pinStore: session.profile.persistence.logPins
    })
    expect(typeof options.annex.storeFor).toBe('function')
    expect(typeof options.annex.revoke).toBe('function')
    expect(typeof options.rosterStoreFor).toBe('function')
    expect(typeof options.onBeforeRemoval).toBe('function')
    expect(options.expectedDid).toBe(pointer.did)
    expect(options.knownLatentHashes).toEqual(['hash:zRung'])
    // The account log's chain-head pin rides every read the ceremony makes.
    expect(options.pinStore).toBe(session.profile.persistence.logPins)
  })

  it('hands the transition the other unlock methods as its re-mint reach', async () => {
    const { session } = fakeSession()
    const registry = {
      methods: [
        { type: 'passphrase', unlockSpaceId: 'unlock-1' },
        { type: 'passkey', unlockSpaceId: 'unlock-2' },
        { type: 'recovery-code', unlockSpaceId: 'unlock-3' }
      ]
    }
    vi.mocked(getUnlockMethods).mockResolvedValue(registry as never)
    const otherEntries = [
      { label: 'passkey', unlockSpaceId: 'unlock-2', source: {} },
      { label: 'recovery-code', unlockSpaceId: 'unlock-3', source: {} }
    ]
    vi.mocked(remintEntriesOf).mockReturnValue(otherEntries as never)
    await forgetThisBrowser({ session, lastClient: true })
    // The login credential's own record is the onBeforeRemoval seam's.
    expect(vi.mocked(remintEntriesOf)).toHaveBeenCalledWith({
      record: registry,
      excludeUnlockSpaceIds: ['unlock-1']
    })
    const { unlockMethods } = vi.mocked(forgetLastDurableClient).mock
      .calls[0]![0]
    expect(unlockMethods).toMatchObject({
      entries: otherEntries,
      pointer,
      storageServerUrl: expect.any(String)
    })
    const capability = { id: 'urn:zcap:manage' } as never
    expect(unlockMethods!.managementZcapClient({ capability })).toEqual({
      managementZcapClient: true
    })
    expect(vi.mocked(managementZcapClient)).toHaveBeenCalledWith({
      session,
      capability
    })
    await unlockMethods!.recordEntry({ entry: otherEntries[1] as never })
    expect(vi.mocked(recordRemintedEntry)).toHaveBeenCalledWith({
      session,
      entry: otherEntries[1]
    })
  })

  it('threads an unverified wipe onto the outcome instead of reading clean', async () => {
    const { session } = fakeSession()
    vi.mocked(executeLocalWipe).mockResolvedValue({
      failed: [],
      unverified: ['replica']
    })
    const outcome = await forgetThisBrowser({ session })
    expect(outcome.wipeFailed).toEqual([])
    expect(outcome.wipeUnverified).toEqual(['replica'])
  })

  it('still wipes the login credential trio and reports an unread registry', async () => {
    const { session } = fakeSession()
    vi.mocked(getUnlockMethods).mockRejectedValue(new Error('503'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.mocked(executeLocalWipe).mockResolvedValue({
      failed: ['unlock-methods-registry'],
      unverified: []
    })
    const outcome = await forgetThisBrowser({ session })
    warn.mockRestore()
    // The ordinary forget proceeds, with the wipe snapshot told the read
    // failed (the snapshot itself always enumerates the session's own
    // unlock Space) and the narrowing reported on the outcome.
    expect(vi.mocked(forgetDurableClient)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(snapshotWipeTargets).mock.calls[0]![0]).toMatchObject({
      registry: null,
      registryUnread: true
    })
    expect(outcome.wipeFailed).toEqual(['unlock-methods-registry'])
  })

  /**
   * A stored unlock record shaped as the frame parser reads it: version 2, a
   * fixed-shape proof, and a one-epoch descriptor whose only recipient is the
   * named key-agreement key.
   *
   * @param options {object}
   * @param options.keyAgreementKeyMultibase {string}   the sealing recipient
   * @returns {object}
   */
  function sealedRecord({
    keyAgreementKeyMultibase
  }: {
    keyAgreementKeyMultibase: string
  }) {
    return {
      version: 2,
      encryption: {
        scheme: 'edv',
        currentEpoch: 'epoch-0',
        epochs: [
          {
            id: 'epoch-0',
            recipients: [
              {
                header: {
                  kid: `did:key:zUnlock#${keyAgreementKeyMultibase}`,
                  alg: 'ECDH-ES+A256KW'
                },
                encrypted_key: 'ZW5jcnlwdGVk'
              }
            ]
          }
        ]
      },
      wrapped: { jwe: true },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        proofPurpose: 'assertionMethod',
        verificationMethod: 'did:key:zUnlock#zUnlock',
        proofValue: 'zProof'
      }
    }
  }

  it('refuses the transition on a pending-shaped passphrase entry', async () => {
    const { session } = fakeSession()
    // The entry's Space and management zcap are the new credential's; its
    // identity members are the old one's, so the record served there is
    // sealed to a key the entry does not name.
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passphrase',
          unlockSpaceId: 'unlock-new',
          manageCapability: { id: 'urn:zcap:manage' },
          unlockKeyAgreementKeyMultibase: 'zOldUnlockKak'
        }
      ]
    } as never)
    vi.mocked(getUnlockKeyringWithCapability).mockResolvedValue(
      sealedRecord({ keyAgreementKeyMultibase: 'zNewUnlockKak' }) as never
    )
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(
      forgetThisBrowser({ session, lastClient: true })
    ).rejects.toMatchObject({ name: 'PendingRetirementForgetError' })
    warn.mockRestore()
    expect(vi.mocked(forgetLastDurableClient)).not.toHaveBeenCalled()
    expect(vi.mocked(executeLocalWipe)).not.toHaveBeenCalled()
  })

  it('runs the transition when the entry names the credential its record is sealed to', async () => {
    const { session } = fakeSession()
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passphrase',
          unlockSpaceId: 'unlock-1',
          manageCapability: { id: 'urn:zcap:manage' },
          unlockKeyAgreementKeyMultibase: 'zUnlockKak'
        }
      ]
    } as never)
    vi.mocked(getUnlockKeyringWithCapability).mockResolvedValue(
      sealedRecord({ keyAgreementKeyMultibase: 'zUnlockKak' }) as never
    )
    await forgetThisBrowser({ session, lastClient: true })
    expect(vi.mocked(forgetLastDurableClient)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(executeLocalWipe)).toHaveBeenCalledTimes(1)
  })

  it('runs the transition for an old passphrase entry whose record still matches it', async () => {
    // The direction the session-derived comparison would get wrong: an OLD
    // passphrase logging in after a change completed elsewhere sees an entry
    // naming another credential, on a perfectly healthy account. The record
    // at the entry's Space is sealed to the credential the entry names, so
    // the transition proceeds.
    const { session } = fakeSession()
    ;(
      session.profile as unknown as { unlockMethod: { type: string } }
    ).unlockMethod = { type: 'passphrase' }
    ;(
      session.profile.standingUnlock!.standingClient as unknown as {
        keyAgreementKeyMultibase: string
      }
    ).keyAgreementKeyMultibase = 'zOldStandingKak'
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passphrase',
          unlockSpaceId: 'unlock-new',
          manageCapability: { id: 'urn:zcap:manage' },
          keyAgreementKeyMultibase: 'zNewStandingKak',
          unlockKeyAgreementKeyMultibase: 'zNewUnlockKak'
        }
      ]
    } as never)
    vi.mocked(getUnlockKeyringWithCapability).mockResolvedValue(
      sealedRecord({ keyAgreementKeyMultibase: 'zNewUnlockKak' }) as never
    )
    await forgetThisBrowser({ session, lastClient: true })
    expect(vi.mocked(forgetLastDurableClient)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(executeLocalWipe)).toHaveBeenCalledTimes(1)
  })

  it('refuses the transition when the fetched record is malformed', async () => {
    const { session } = fakeSession()
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passphrase',
          unlockSpaceId: 'unlock-1',
          manageCapability: { id: 'urn:zcap:manage' },
          unlockKeyAgreementKeyMultibase: 'zUnlockKak'
        }
      ]
    } as never)
    // A record whose descriptor lists no epochs: unusable, not "sealed to
    // someone else", so it refuses as could-not-settle rather than as a
    // pending entry.
    const record = sealedRecord({ keyAgreementKeyMultibase: 'zUnlockKak' })
    record.encryption.epochs = []
    vi.mocked(getUnlockKeyringWithCapability).mockResolvedValue(record as never)
    await expect(
      forgetThisBrowser({ session, lastClient: true })
    ).rejects.toThrow(/sign-in record/)
    expect(vi.mocked(forgetLastDurableClient)).not.toHaveBeenCalled()
    expect(vi.mocked(executeLocalWipe)).not.toHaveBeenCalled()
  })

  it('refuses the transition when the record behind an entry cannot be read', async () => {
    const { session } = fakeSession()
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passphrase',
          unlockSpaceId: 'unlock-1',
          manageCapability: { id: 'urn:zcap:manage' },
          unlockKeyAgreementKeyMultibase: 'zUnlockKak'
        }
      ]
    } as never)
    vi.mocked(getUnlockKeyringWithCapability).mockRejectedValue(
      new Error('503')
    )
    await expect(
      forgetThisBrowser({ session, lastClient: true })
    ).rejects.toThrow(/sign-in record/)
    expect(vi.mocked(forgetLastDurableClient)).not.toHaveBeenCalled()
    expect(vi.mocked(executeLocalWipe)).not.toHaveBeenCalled()
  })

  it('settles no records for the ordinary forget', async () => {
    const { session } = fakeSession()
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passphrase',
          unlockSpaceId: 'unlock-new',
          manageCapability: { id: 'urn:zcap:manage' },
          unlockKeyAgreementKeyMultibase: 'zOldUnlockKak'
        }
      ]
    } as never)
    await forgetThisBrowser({ session })
    expect(vi.mocked(getUnlockKeyringWithCapability)).not.toHaveBeenCalled()
    expect(vi.mocked(forgetDurableClient)).toHaveBeenCalledTimes(1)
  })

  it('refuses the transition up front when the registry cannot be read', async () => {
    const { session } = fakeSession()
    vi.mocked(getUnlockMethods).mockRejectedValue(new Error('offline'))
    await expect(
      forgetThisBrowser({ session, lastClient: true })
    ).rejects.toThrow(/unlock-methods registry/)
    expect(vi.mocked(forgetLastDurableClient)).not.toHaveBeenCalled()
    expect(vi.mocked(executeLocalWipe)).not.toHaveBeenCalled()
  })

  it('re-binds the login credential record from the transition onBeforeRemoval seam', async () => {
    const { session, rebindRecord } = fakeSession()
    const bridge = { id: 'urn:zcap:bridge2', expires: '2027-01-01T00:00:00Z' }
    const sibling = { id: 'urn:zcap:sibling2', expires: '2027-02-01T00:00:00Z' }
    vi.mocked(delegateLogWrite).mockResolvedValue(bridge as never)
    vi.mocked(delegatedClientsDelegationSpaceId).mockReturnValue(
      'annex-space' as never
    )
    vi.mocked(mintDelegatedClientsDelegation).mockResolvedValue(
      sibling as never
    )
    await forgetThisBrowser({ session, lastClient: true })
    const { onBeforeRemoval } = vi.mocked(forgetLastDurableClient).mock
      .calls[0]![0]
    await onBeforeRemoval!({
      did: 'did:webvh:scid-a:example.com:space-1',
      doc: {},
      log: [] as never
    })
    expect(vi.mocked(ladderVmZcapClient)).toHaveBeenCalledWith({
      accountDid: 'did:webvh:scid-a:example.com:space-1',
      ladderSeed: session.profile.ladderSeed
    })
    expect(vi.mocked(delegateLogWrite).mock.calls[0]![0]).toMatchObject({
      zcapClient: LADDER_ZCAP_CLIENT,
      recoveryClientDid: 'did:key:zStanding'
    })
    expect(
      vi.mocked(mintDelegatedClientsDelegation).mock.calls[0]![0]
    ).toMatchObject({
      zcapClient: LADDER_ZCAP_CLIENT,
      wasServerUrl: pointer.host,
      clientAnnexSpaceId: 'annex-space',
      controller: 'did:key:zStanding'
    })
    expect(vi.mocked(rebindRecord)).toHaveBeenCalledWith({
      delegation: bridge,
      delegatedClients: sibling
    })
    expect(
      vi.mocked(refreshStandingDelegationFields).mock.calls[0]![0]
    ).toMatchObject({
      unlockSpaceId: 'unlock-1',
      delegationKeyId: delegationProofKeyId(bridge as never),
      delegationExpires: bridge.expires,
      delegatedClientsKeyId: delegationProofKeyId(sibling as never),
      delegatedClientsExpires: sibling.expires
    })
  })

  it("threads the account log's chain-head pin and slot into the ceremony", async () => {
    const { session } = fakeSession()
    await forgetThisBrowser({ session })
    const options = vi.mocked(forgetDurableClient).mock.calls[0]![0]
    expect(options.pinStore).toBe(session.profile.persistence.logPins)
    expect(options.logId).toBe(accountLogPinId({ spaceId: pointer.spaceId }))
  })

  it('adopts a rotation in band (re-seal, pin, client keys, session)', async () => {
    const { session } = fakeSession()
    await forgetThisBrowser({ session })
    const { onUserKeyAdopted } =
      vi.mocked(forgetDurableClient).mock.calls[0]![0]
    const userKey = { id: 'did:key:zFreshUserKey' }
    const descriptor = { currentEpoch: 'epoch-2' }
    await onUserKeyAdopted!({
      userKey: userKey as never,
      latestEpochId: 'epoch-2',
      descriptor: descriptor as never
    })
    // The whole adoption is the in-band helper's: the registry re-seal runs
    // ahead of the client-key record write inside it, so the callback here
    // does nothing else.
    expect(vi.mocked(adoptRotatedUserKeyInBand)).toHaveBeenCalledWith({
      session,
      spaceId: pointer.spaceId,
      accountDid: pointer.did,
      userKey,
      latestEpochId: 'epoch-2',
      descriptor
    })
  })
})
