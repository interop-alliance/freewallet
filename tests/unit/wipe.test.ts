// @vitest-environment node
/**
 * Unit tests for the shared wipe enumeration (`src/session/wipe.ts`) and its
 * sessionKey primitives: snapshot-first target derivation, deletion of every
 * unlock method's local trio across the registry, the pin families
 * (annex slots by prefix), the per-account localStorage families, and
 * the guest consumer -- asserted by DIRECT enumeration of the backing
 * stores, never by the deleter's own report.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { deriveSpaceId } from '@interop/was-client/sync'
import { accountLogPinId } from '@interop/wallet-core/webvh'
import { clientAnnexLogPinId } from '@interop/wallet-core/clientAnnex'
import { userKeyRosterPinId } from '@interop/wallet-core/keys'
import {
  deleteSessionKeysByPrefix,
  saveAccountDidForSpace,
  saveClientKeyRecord,
  saveKeyringCache,
  saveKeyringFreshnessPin,
  savePasskeySafetyNotice,
  saveUnlockMethodsCache,
  saveUserKeyEpochPin,
  sessionLogPinStore
} from '@/lib/sessionKey'
import {
  executeLocalWipe,
  snapshotWipeTargets,
  wipeGuestState
} from '@/session/wipe'
import type { UnlockMethodsRecord } from '@/session/unlockMethods'
import type { Session } from '@/types/auth'
import { createFakeSessionIdb } from './fakeSessionIdb'

const CLIENT_DID = 'did:key:z6MkClientClientClientClient'
const DB_PREFIX = deriveSpaceId(CLIENT_DID)
const ACCOUNT_DID = 'did:webvh:QmScid:example.com:space:acct-space'
const ACCOUNT_SPACE_ID = 'acct-space'
const CLIENT_ANNEX_SPACE_ID = 'comp-space'
const PASSPHRASE_UNLOCK_SPACE = 'unlock-space-passphrase'
const PASSKEY_UNLOCK_SPACE = 'unlock-space-passkey'

const registry = {
  version: 1,
  userHandle: 'u',
  methods: [
    {
      type: 'passphrase',
      createdAt: '2026-01-01T00:00:00Z',
      unlockSpaceId: PASSPHRASE_UNLOCK_SPACE
    },
    {
      type: 'passkey',
      label: 'Key',
      createdAt: '2026-01-02T00:00:00Z',
      credentialId: 'cred',
      transports: [],
      backupEligibility: true,
      backupState: true,
      unlockSpaceId: PASSKEY_UNLOCK_SPACE
    }
  ]
} as unknown as UnlockMethodsRecord

/**
 * A minimal localStorage stub for the Node environment, exposing the map
 * for direct enumeration.
 */
function createFakeLocalStorage(): {
  storage: Storage
  backing: Map<string, string>
} {
  const backing = new Map<string, string>()
  const storage = {
    get length() {
      return backing.size
    },
    key(index: number) {
      return [...backing.keys()][index] ?? null
    },
    getItem: (key: string) => backing.get(key) ?? null,
    setItem: (key: string, value: string) => void backing.set(key, value),
    removeItem: (key: string) => void backing.delete(key),
    clear: () => backing.clear()
  } as Storage
  return { storage, backing }
}

function sessionFixture({
  isGuest = false,
  storage,
  unlockSpaceId
}: {
  isGuest?: boolean
  storage?: { wipeLocalStorage: () => Promise<void> }
  unlockSpaceId?: string
} = {}): Session {
  return {
    user: { id: CLIENT_DID },
    isGuest,
    storage,
    profile: {
      ...(unlockSpaceId
        ? {
            unlockMethod: { type: 'passphrase', unlockSpaceId },
            standingUnlock: { unlockSpaceId }
          }
        : {}),
      accountPointer: isGuest
        ? undefined
        : {
            did: ACCOUNT_DID,
            spaceId: ACCOUNT_SPACE_ID,
            host: 'https://was.example'
          }
    }
  } as unknown as Session
}

/**
 * Seeds every session-database family for the account under test, plus a
 * second account's rows that must survive the wipe untouched.
 */
async function seedSessionDatabase(idb: IDBFactory): Promise<void> {
  for (const spaceId of [
    PASSPHRASE_UNLOCK_SPACE,
    PASSKEY_UNLOCK_SPACE,
    'other-unlock-space'
  ]) {
    await saveKeyringCache({ spaceId, record: { r: spaceId }, idb })
    await saveClientKeyRecord({ spaceId, record: { c: spaceId }, idb })
    await saveKeyringFreshnessPin({
      spaceId,
      createdAt: '2026-01-01T00:00:00Z',
      idb
    })
  }
  await saveUserKeyEpochPin({ accountDid: ACCOUNT_DID, epochId: 'e1', idb })
  await saveUserKeyEpochPin({
    accountDid: 'did:webvh:other',
    epochId: 'e',
    idb
  })
  const pins = sessionLogPinStore({ idb })
  const pin = { method: 'm', scid: 's', head: 'h' }
  await pins.write({
    logId: accountLogPinId({ spaceId: ACCOUNT_SPACE_ID }),
    pin
  })
  await pins.write({
    logId: userKeyRosterPinId({ spaceId: ACCOUNT_SPACE_ID }),
    pin
  })
  for (const generationId of ['gen-1', 'gen-2']) {
    await pins.write({
      logId: clientAnnexLogPinId({
        spaceId: CLIENT_ANNEX_SPACE_ID,
        generationId
      }),
      pin
    })
  }
  await pins.write({ logId: accountLogPinId({ spaceId: 'other-space' }), pin })
  await saveAccountDidForSpace({
    spaceId: ACCOUNT_SPACE_ID,
    accountDid: ACCOUNT_DID,
    idb
  })
  await saveAccountDidForSpace({
    spaceId: 'other-space',
    accountDid: 'did:webvh:other',
    idb
  })
  await saveUnlockMethodsCache({
    controller: CLIENT_DID,
    record: registry,
    idb
  })
  await saveUnlockMethodsCache({
    controller: 'did:key:z6MkOther',
    record: registry,
    idb
  })
  await savePasskeySafetyNotice({
    controller: CLIENT_DID,
    backupEligibility: true,
    backupState: true,
    idb
  })
}

function seedLocalStorage(backing: Map<string, string>): void {
  backing.set(
    `freewallet:collection-encryption:${ACCOUNT_SPACE_ID}:private-credentials`,
    '{}'
  )
  backing.set(
    `freewallet:collection-meta:${ACCOUNT_SPACE_ID}:private-credentials`,
    '{}'
  )
  backing.set(
    `freewallet:collection-encryption:local:${CLIENT_DID}:private-credentials`,
    '{}'
  )
  backing.set('freewallet:collection-encryption:other-space:contacts', '{}')
  backing.set(`freewallet:plaintext-migrated:${DB_PREFIX}`, '2026')
  backing.set(`freewallet:public-cids-migrated:${DB_PREFIX}`, '2026')
  backing.set('freewallet:plaintext-migrated:other-prefix', '2026')
  backing.set('freewallet:writerId', 'writer-1')
  backing.set('fw-theme', 'dark')
}

describe('deleteSessionKeysByPrefix', () => {
  it('deletes exactly the keys under the prefix', async () => {
    const { idb, sessionStore } = createFakeSessionIdb()
    await saveKeyringCache({ spaceId: 'a', record: {}, idb })
    const pins = sessionLogPinStore({ idb })
    const pin = { method: 'm', scid: 's', head: 'h' }
    await pins.write({ logId: 'space/one/id/did.jsonl', pin })
    await pins.write({ logId: 'space/one/gen-2/did.jsonl', pin })
    await pins.write({ logId: 'space/one-more/id/did.jsonl', pin })
    await deleteSessionKeysByPrefix({ prefix: 'log-head/space/one/', idb })
    expect([...sessionStore.keys()].sort()).toEqual([
      'keyring/a',
      'log-head/space/one-more/id/did.jsonl'
    ])
  })

  it('refuses an empty prefix', async () => {
    const { idb } = createFakeSessionIdb()
    await expect(
      deleteSessionKeysByPrefix({ prefix: '', idb })
    ).rejects.toThrow('non-empty prefix')
  })
})

describe('the shared wipe enumeration', () => {
  let localStorageBacking: Map<string, string>

  beforeEach(() => {
    const { storage, backing } = createFakeLocalStorage()
    localStorageBacking = backing
    vi.stubGlobal('localStorage', storage)
    seedLocalStorage(backing)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  for (const loginSide of ['passphrase', 'passkey'] as const) {
    it(`deletes both methods' trios and every family (from a ${loginSide} login)`, async () => {
      const { idb, sessionStore } = createFakeSessionIdb()
      await seedSessionDatabase(idb)
      const wipeLocalStorage = vi.fn(async () => {})
      // The login method does not enter the enumeration: the registry names
      // every method, so both orders derive identical targets.
      const orderedRegistry = {
        ...registry,
        methods:
          loginSide === 'passphrase'
            ? registry.methods
            : [...registry.methods].reverse()
      } as UnlockMethodsRecord
      const session = sessionFixture({ storage: { wipeLocalStorage } })
      const targets = snapshotWipeTargets({
        session,
        registry: orderedRegistry,
        clientAnnexSpaceId: CLIENT_ANNEX_SPACE_ID
      })
      expect(deriveSpaceId(targets.clientDid)).toBe(DB_PREFIX)
      expect(targets.unlockSpaceIds).toContain(PASSPHRASE_UNLOCK_SPACE)
      expect(targets.unlockSpaceIds).toContain(PASSKEY_UNLOCK_SPACE)

      const { failed } = await executeLocalWipe({
        targets,
        storage: { wipeLocalStorage },
        idb,
        clearWriter: true
      })

      expect(failed).toEqual([])
      expect(wipeLocalStorage).toHaveBeenCalledTimes(1)
      // Direct enumeration: only the OTHER account's rows survive.
      expect([...sessionStore.keys()].sort()).toEqual(
        [
          'keyring/other-unlock-space',
          'client-keys/other-unlock-space',
          'keyring-freshness/other-unlock-space',
          'user-key-epoch-pin/did:webvh:other',
          `log-head/${accountLogPinId({ spaceId: 'other-space' })}`,
          'account-did/space/other-space',
          'unlock-methods/did:key:z6MkOther'
        ].sort()
      )
      // The per-account localStorage families are gone; the other account's
      // and the global UI pref survive; the writer id was cleared (the
      // forget grade).
      expect([...localStorageBacking.keys()].sort()).toEqual(
        [
          'freewallet:collection-encryption:other-space:contacts',
          'freewallet:plaintext-migrated:other-prefix',
          'fw-theme'
        ].sort()
      )
    })
  }

  it("enumerates the login credential's unlock Space when the registry read failed", async () => {
    const { idb, sessionStore } = createFakeSessionIdb()
    await seedSessionDatabase(idb)
    const session = sessionFixture({ unlockSpaceId: PASSPHRASE_UNLOCK_SPACE })
    // The registry read rejected: no record, flagged as unread.
    const targets = snapshotWipeTargets({
      session,
      registry: null,
      registryUnread: true
    })
    expect(targets.unlockSpaceIds).toEqual([PASSPHRASE_UNLOCK_SPACE])
    expect(targets.registryUnread).toBe(true)

    const { failed } = await executeLocalWipe({ targets, idb })

    // Reported, never read as "no other methods".
    expect(failed).toEqual(['unlock-methods-registry'])
    // The login credential's trio -- the client-key record above all -- is
    // gone; the unread passkey method's trio is the stated residue.
    for (const family of ['keyring', 'client-keys', 'keyring-freshness']) {
      expect(sessionStore.has(`${family}/${PASSPHRASE_UNLOCK_SPACE}`)).toBe(
        false
      )
      expect(sessionStore.has(`${family}/${PASSKEY_UNLOCK_SPACE}`)).toBe(true)
    }
  })

  it('unions the session credential with the registry without duplicating it', () => {
    const session = sessionFixture({ unlockSpaceId: PASSPHRASE_UNLOCK_SPACE })
    const targets = snapshotWipeTargets({ session, registry })
    expect(targets.unlockSpaceIds).toEqual([
      PASSPHRASE_UNLOCK_SPACE,
      PASSKEY_UNLOCK_SPACE
    ])
    expect(targets.registryUnread).toBe(false)
  })

  it('reports an unverified replica wipe without calling it clean', async () => {
    const { idb } = createFakeSessionIdb()
    await seedSessionDatabase(idb)
    const session = sessionFixture()
    const targets = snapshotWipeTargets({ session, registry })
    const { failed, unverified } = await executeLocalWipe({
      targets,
      storage: { wipeLocalStorage: async () => ({ verified: false }) },
      idb
    })
    expect(failed).toEqual([])
    expect(unverified).toEqual(['replica'])
  })

  it('keeps the writer id unless the consumer asks (deleteAccount, guest)', async () => {
    const { idb } = createFakeSessionIdb()
    await seedSessionDatabase(idb)
    const session = sessionFixture()
    const targets = snapshotWipeTargets({ session, registry })
    await executeLocalWipe({ targets, idb })
    expect(localStorageBacking.get('freewallet:writerId')).toBe('writer-1')
  })

  it('never creates the session database on a browser that has none', async () => {
    const { idb, databaseNames } = createFakeSessionIdb()
    const session = sessionFixture()
    const targets = snapshotWipeTargets({ session, registry })
    const { failed } = await executeLocalWipe({ targets, idb })
    expect(failed).toEqual([])
    expect(databaseNames.has('freewallet-session')).toBe(false)
  })

  it('never creates the session database on an engine without databases()', async () => {
    const { idb, databaseNames } = createFakeSessionIdb({ enumerable: false })
    const session = sessionFixture()
    const targets = snapshotWipeTargets({ session, registry })
    const { failed, unverified } = await executeLocalWipe({ targets, idb })
    expect(failed).toEqual([])
    expect(unverified).toEqual([])
    // The fallback probe answered "absent" without creating anything, so
    // the trio deletes were skipped rather than run through a versioned
    // open.
    expect(databaseNames.has('freewallet-session')).toBe(false)
  })

  it('reports a failed replica wipe and still runs the other stages', async () => {
    const { idb, sessionStore } = createFakeSessionIdb()
    await seedSessionDatabase(idb)
    const session = sessionFixture()
    const targets = snapshotWipeTargets({ session, registry })
    const { failed } = await executeLocalWipe({
      targets,
      storage: {
        wipeLocalStorage: async () => {
          throw new Error('blocked by a sibling tab')
        }
      },
      idb
    })
    expect(failed).toEqual(['replica'])
    expect(sessionStore.has(`client-keys/${PASSPHRASE_UNLOCK_SPACE}`)).toBe(
      false
    )
    expect(
      localStorageBacking.has(`freewallet:plaintext-migrated:${DB_PREFIX}`)
    ).toBe(false)
  })

  it('wipes guest state: replica, markers, local-mode caches; no session rows', async () => {
    const { idb, databaseNames } = createFakeSessionIdb()
    vi.stubGlobal('indexedDB', idb)
    const wipeLocalStorage = vi.fn(async () => {})
    const session = sessionFixture({
      isGuest: true,
      storage: { wipeLocalStorage }
    })
    const { failed } = await wipeGuestState({ session })
    expect(failed).toEqual([])
    expect(wipeLocalStorage).toHaveBeenCalledTimes(1)
    // Guest targets carry no account pointer and no registry, and the
    // create-nothing guard leaves the session database uncreated.
    expect(databaseNames.has('freewallet-session')).toBe(false)
    expect(
      localStorageBacking.has(`freewallet:plaintext-migrated:${DB_PREFIX}`)
    ).toBe(false)
    expect(localStorageBacking.get('freewallet:writerId')).toBe('writer-1')
    expect(localStorageBacking.get('fw-theme')).toBe('dark')
  })
})
