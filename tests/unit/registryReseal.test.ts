// @vitest-environment node
/**
 * Unit tests for the login-time re-seal repair
 * (`src/session/registryReseal.ts`) and its detector, the typed
 * `UnlockRegistryStaleSealError` `getUnlockMethods` throws.
 *
 * The registry is stored in an in-memory fake of the data-Space helpers; the
 * real EDV cipher, the real user keys, and the real vault-key derivation run
 * unmocked, so a record genuinely sealed to a superseded generation genuinely
 * fails to open under the current one. Only the roster escrow itself
 * (`unwrapUserKeyGenerations`) is mocked -- building a real roster descriptor
 * would test wallet-core, not this repair.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { UserKey } from '@interop/wallet-core/keys'
import type { Session } from '@/types/auth'

const wasState = vi.hoisted(() => ({
  url: 'https://was.example.test' as string | undefined,
  records: new Map<string, unknown>(),
  versions: new Map<string, number>(),
  generations: [] as UserKey[],
  putError: undefined as unknown
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return wasState.url
  }
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  ensureUnlockMethodsCollection: vi.fn(async () => {}),
  putUnlockMethodsRecord: vi.fn(
    async ({
      spaceId,
      record,
      ifMatch,
      ifNoneMatch
    }: {
      spaceId: string
      record: unknown
      ifMatch?: string
      ifNoneMatch?: boolean
    }) => {
      if (wasState.putError) {
        throw wasState.putError
      }
      const { PreconditionFailedError } = await import('@interop/was-client')
      const exists = wasState.records.has(spaceId)
      const version = wasState.versions.get(spaceId) ?? 0
      if (ifNoneMatch && exists) {
        throw new PreconditionFailedError(
          'A registry record already exists (If-None-Match).'
        )
      }
      if (ifMatch !== undefined && (!exists || ifMatch !== `v${version}`)) {
        throw new PreconditionFailedError(
          'The registry record changed since the read (If-Match).'
        )
      }
      if (ifMatch === undefined && !ifNoneMatch) {
        throw new Error(
          'Unconditional registry write: every PUT must carry a precondition.'
        )
      }
      wasState.records.set(spaceId, record)
      wasState.versions.set(spaceId, version + 1)
      return { etag: `v${version + 1}` }
    }
  ),
  getUnlockMethodsRecord: vi.fn(async ({ spaceId }: { spaceId: string }) =>
    wasState.records.has(spaceId)
      ? {
          record: wasState.records.get(spaceId),
          etag: `v${wasState.versions.get(spaceId) ?? 0}`
        }
      : null
  )
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  unwrapUserKeyGenerations: vi.fn(async () => wasState.generations)
}))

import { mintUserKey, userKeyVaultKeys } from '@interop/wallet-core/keys'
import { durableSessionPersistence } from '@/session/persistence'
import {
  getUnlockMethods,
  updateUnlockMethods,
  UnlockRegistryStaleSealError,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import { repairStaleUnlockRegistrySeal } from '@/session/registryReseal'
import { adoptRotatedUserKeyInBand } from '@/session/userKeyAdoption'
import { createFakeSessionIdb } from './fakeSessionIdb'

const SPACE_ID = 'PVkVUyJ24oyQh2BebkeUOygDfR5opfhJhG4KkMYTlzU'
const ACCOUNT_DID = `did:webvh:QmScid:was.example.test:space:${SPACE_ID}`

/**
 * A session stand-in whose vault keys are the given user key's, on a promoted
 * pointer and a durable persistence handle -- the shape the repair's guards
 * expect. `swapVaultKeys` moves it onto another user key, which is exactly
 * what a rotation whose re-seal was lost leaves behind.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {Session}
 */
function makeSession({ userKey }: { userKey: UserKey }): Session {
  const vaultKeys = userKeyVaultKeys({ userKey })
  return {
    user: { id: 'did:key:z6MkDataControllerForRegistryReseal' },
    profile: {
      keyAgreementKey: vaultKeys.keyAgreementKey,
      keyResolver: vaultKeys.keyResolver,
      clientKeyAgreementKey: { id: 'did:key:z6LSclient#z6LSclient' },
      userKey,
      zcapClient: {},
      accountPointer: {
        did: ACCOUNT_DID,
        spaceId: SPACE_ID,
        host: 'https://was.example.test'
      },
      persistence: durableSessionPersistence({
        idb: createFakeSessionIdb().idb
      })
    },
    storage: {
      spaceId: SPACE_ID,
      adoptRotatedVaultKeys: async () => {}
    },
    isGuest: false
  } as unknown as Session
}

/**
 * Moves a session onto another user key WITHOUT re-sealing the registry --
 * the torn rotation this repair exists for.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.userKey {UserKey}
 * @returns {void}
 */
function swapVaultKeys({
  session,
  userKey
}: {
  session: Session
  userKey: UserKey
}): void {
  const vaultKeys = userKeyVaultKeys({ userKey })
  session.profile.userKey = userKey
  session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
  session.profile.keyResolver = vaultKeys.keyResolver
}

function sampleRecord(): UnlockMethodsRecord {
  return {
    version: 1,
    webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-abc'
      }
    ]
  }
}

/**
 * The roster read a login hands the repair. Only the descriptor is read, and
 * only by the mocked escrow unwrap.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {Parameters<typeof repairStaleUnlockRegistrySeal>[0]['rosterRead']}
 */
function rosterReadFor({ userKey }: { userKey: UserKey }) {
  return {
    descriptor: { currentEpoch: userKey.id, epochs: [] },
    userKey,
    rotated: false,
    latestEpochId: userKey.id
  } as unknown as Parameters<
    typeof repairStaleUnlockRegistrySeal
  >[0]['rosterRead']
}

beforeEach(() => {
  wasState.url = 'https://was.example.test'
  wasState.records.clear()
  wasState.versions.clear()
  wasState.generations = []
  wasState.putError = undefined
})

/**
 * Seeds the stored registry through the compare-and-swap wrapper (the bare
 * unconditional put no longer exists).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.record {UnlockMethodsRecord}
 * @returns {Promise<void>}
 */
async function seedRegistry({
  session,
  record
}: {
  session: Session
  record: UnlockMethodsRecord
}): Promise<void> {
  await updateUnlockMethods({ session, mutate: () => record })
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('the stale-seal detector', () => {
  it('throws UnlockRegistryStaleSealError when the record will not decrypt', async () => {
    const oldKey = await mintUserKey()
    const session = makeSession({ userKey: oldKey })
    await seedRegistry({ session, record: sampleRecord() })

    swapVaultKeys({ session, userKey: await mintUserKey() })

    await expect(getUnlockMethods({ session })).rejects.toBeInstanceOf(
      UnlockRegistryStaleSealError
    )
  })

  it('does not call a version mismatch a stale seal', async () => {
    const userKey = await mintUserKey()
    const session = makeSession({ userKey })
    await seedRegistry({ session, record: sampleRecord() })
    // A frame stamped by a future client: refused before any decrypt is
    // attempted, so it is not a seal problem.
    ;(wasState.records.get(SPACE_ID) as { version: number }).version = 2

    await expect(getUnlockMethods({ session })).rejects.not.toBeInstanceOf(
      UnlockRegistryStaleSealError
    )
  })

  it('reads a record sealed to the current key without complaint', async () => {
    const userKey = await mintUserKey()
    const session = makeSession({ userKey })
    await seedRegistry({ session, record: sampleRecord() })

    await expect(getUnlockMethods({ session })).resolves.toEqual(sampleRecord())
  })
})

describe('the login-time re-seal repair', () => {
  it('re-seals a stranded registry from the roster escrow', async () => {
    const oldKey = await mintUserKey()
    const currentKey = await mintUserKey()
    const session = makeSession({ userKey: oldKey })
    await seedRegistry({ session, record: sampleRecord() })
    // The rotation landed in the roster and this browser adopted the fresh
    // key, but the re-seal was lost.
    swapVaultKeys({ session, userKey: currentKey })
    wasState.generations = [oldKey, currentKey]

    const outcome = await repairStaleUnlockRegistrySeal({
      session,
      rosterRead: rosterReadFor({ userKey: currentKey })
    })

    expect(outcome).toBe('repaired')
    // The whole point: the registry opens under the current key afterwards.
    await expect(getUnlockMethods({ session })).resolves.toEqual(sampleRecord())
  })

  it('is a no-op read on a registry the current key already opens', async () => {
    const userKey = await mintUserKey()
    const session = makeSession({ userKey })
    await seedRegistry({ session, record: sampleRecord() })
    const sealed = wasState.records.get(SPACE_ID)

    const outcome = await repairStaleUnlockRegistrySeal({
      session,
      rosterRead: rosterReadFor({ userKey })
    })

    expect(outcome).toBe('ok')
    expect(wasState.records.get(SPACE_ID)).toBe(sealed)
  })

  it('reports an unrepaired seal when no escrowed generation opens it', async () => {
    const session = makeSession({ userKey: await mintUserKey() })
    await seedRegistry({ session, record: sampleRecord() })
    const currentKey = await mintUserKey()
    swapVaultKeys({ session, userKey: currentKey })
    // A generation that never sealed this record.
    wasState.generations = [await mintUserKey(), currentKey]

    const outcome = await repairStaleUnlockRegistrySeal({
      session,
      rosterRead: rosterReadFor({ userKey: currentKey })
    })

    expect(outcome).toBe('unrepaired')
  })
})

describe('the locale copy for the stale-seal state', () => {
  it('names the state in both locales', async () => {
    const en = (await import('@/i18n/locales/en.json')).default
    const es = (await import('@/i18n/locales/es.json')).default
    expect(en.settings.passkeyRegistryStaleSeal).toBeTruthy()
    expect(es.settings.passkeyRegistryStaleSeal).toBeTruthy()
  })
})

describe('the in-band adoption when its re-seal fails', () => {
  it('leaves the session on the pre-rotation keys', async () => {
    const oldKey = await mintUserKey()
    const session = makeSession({ userKey: oldKey })
    await seedRegistry({ session, record: sampleRecord() })
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    wasState.putError = new Error('503 from the storage server')

    await adoptRotatedUserKeyInBand({
      session,
      spaceId: SPACE_ID,
      accountDid: ACCOUNT_DID,
      userKey: await mintUserKey(),
      latestEpochId: 'epoch-2',
      descriptor: { epochs: [] }
    })

    // The session must NOT move onto a key the record is not sealed to: the
    // ceremony's own later registry writes (the entry drop, a re-mint's
    // field refresh) would meet a stale seal mid-run.
    expect(session.profile.userKey).toBe(oldKey)
    wasState.putError = undefined
    await expect(getUnlockMethods({ session })).resolves.toEqual(sampleRecord())
    warn.mockRestore()
  })
})
