// @vitest-environment node
/**
 * The backfill reaches its registry read on BOTH storage tiers. FW-295's
 * transient gate was retired with the account-ceremony context: a transient
 * session reads and writes the registry under the visit's generation
 * delegation rather than being turned away before the first read.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import { STORAGE_IN_MEMORY, STORAGE_INDEXEDDB } from '@/session/persistence'

const { backfillPassphraseUnlockMethod, upsertPassphraseUnlockMethod } =
  await import('@/session/unlockMethods')
type PassphraseUnlockMethod =
  import('@/session/unlockMethods').PassphraseUnlockMethod
type UnlockMethodsRecord = import('@/session/unlockMethods').UnlockMethodsRecord

/**
 * A minimal session shaped as `backfillPassphraseUnlockMethod` reads it: the
 * storage tier under test, plus just enough of `profile` and `persistence`
 * for the browser-local path to reach its first registry read (a local-cache
 * load, since no `VITE_WAS_SERVER_URL` is set in tests) without throwing.
 *
 * @param options {object}
 * @param options.storage {string}
 * @returns {{ session: Session, cacheLoad: ReturnType<typeof vi.fn> }}
 */
function fakeSession({ storage }: { storage: string }): {
  session: Session
  cacheLoad: ReturnType<typeof vi.fn>
} {
  const cacheLoad = vi.fn(async () => null)
  const session = {
    user: { id: 'did:key:zClientA' },
    isGuest: false,
    profile: {
      userKey: { id: 'did:key:zClientUserKey', secret: new Uint8Array(32) },
      keyAgreementKey: { publicKeyMultibase: 'zClientKak' },
      keyResolver: { resolve: vi.fn() },
      unlockMethod: undefined
    },
    persistence: {
      storage,
      unlockMethodsCache: {
        load: cacheLoad,
        save: vi.fn(),
        delete: vi.fn()
      }
    }
  } as unknown as Session
  return { session, cacheLoad }
}

describe('backfillPassphraseUnlockMethod (both storage tiers)', () => {
  it('proceeds to the read on a transient session', async () => {
    const { session, cacheLoad } = fakeSession({
      storage: STORAGE_IN_MEMORY
    })

    const result = await backfillPassphraseUnlockMethod({ session })

    expect(result).toBeNull()
    expect(cacheLoad).toHaveBeenCalledTimes(1)
  })

  it('proceeds to the read on a browser-local session', async () => {
    const { session, cacheLoad } = fakeSession({
      storage: STORAGE_INDEXEDDB
    })

    const result = await backfillPassphraseUnlockMethod({ session })

    expect(result).toBeNull()
    expect(cacheLoad).toHaveBeenCalledTimes(1)
  })
})

const MY_KAK = 'z6LSmine'
const OTHER_KAK = 'z6LStheirs'
const MARKER = {
  unlockSpaceId: 'unlock-space-new',
  keyAgreementKeyMultibase: OTHER_KAK
}

/**
 * A registry holding one passphrase entry.
 *
 * @param [entry] {object}   members overriding the standing entry
 * @returns {UnlockMethodsRecord}
 */
function registryWith(entry: object = {}): UnlockMethodsRecord {
  return {
    version: 1,
    webAuthnUserId: 'handle',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-old',
        kdfVersion: 1,
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkMyRung',
        ...entry
      }
    ]
  } as unknown as UnlockMethodsRecord
}

/**
 * The passphrase entry of an upsert's result.
 *
 * @param record {UnlockMethodsRecord}
 * @returns {PassphraseUnlockMethod}
 */
function passphraseEntry(record: UnlockMethodsRecord): PassphraseUnlockMethod {
  return record.methods.find(
    (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
  )!
}

describe('upsertPassphraseUnlockMethod (the establishment marker)', () => {
  it('stamps the marker the caller supplies', () => {
    const entry = passphraseEntry(
      upsertPassphraseUnlockMethod({
        record: registryWith(),
        unlockSpaceId: 'unlock-space-old',
        pendingEstablishment: MARKER
      })
    )
    expect(entry.pendingEstablishment).toEqual(MARKER)
  })

  it('carries the marker across a same-Space write naming no credential', () => {
    // A refresh, a backfill, or a re-seal: the entry still names the same
    // credential, so the change it marks is still unfinished.
    const entry = passphraseEntry(
      upsertPassphraseUnlockMethod({
        record: registryWith({ pendingEstablishment: MARKER }),
        unlockSpaceId: 'unlock-space-old'
      })
    )
    expect(entry.pendingEstablishment).toEqual(MARKER)
    expect(entry.keyAgreementKeyMultibase).toBe(MY_KAK)
  })

  it('carries the marker when the standing members name the same credential', () => {
    const entry = passphraseEntry(
      upsertPassphraseUnlockMethod({
        record: registryWith({ pendingEstablishment: MARKER }),
        unlockSpaceId: 'unlock-space-old',
        standing: {
          keyAgreementKeyMultibase: MY_KAK,
          updateKeyMultibase: 'z6MkMyFreshRung'
        }
      })
    )
    expect(entry.pendingEstablishment).toEqual(MARKER)
  })

  it('drops the marker when the write names another credential', () => {
    // The change's completing write: the entry now names the credential the
    // marker was announcing, so the marker has nothing left to arm.
    const entry = passphraseEntry(
      upsertPassphraseUnlockMethod({
        record: registryWith({ pendingEstablishment: MARKER }),
        unlockSpaceId: 'unlock-space-old',
        standing: {
          keyAgreementKeyMultibase: OTHER_KAK,
          updateKeyMultibase: 'z6MkTheirRung'
        }
      })
    )
    expect(entry).not.toHaveProperty('pendingEstablishment')
  })

  it('drops the marker on a repoint to another unlock Space', () => {
    const entry = passphraseEntry(
      upsertPassphraseUnlockMethod({
        record: registryWith({ pendingEstablishment: MARKER }),
        unlockSpaceId: 'unlock-space-new',
        standing: {
          keyAgreementKeyMultibase: OTHER_KAK,
          updateKeyMultibase: 'z6MkTheirRung'
        }
      })
    )
    expect(entry).not.toHaveProperty('pendingEstablishment')
    expect(entry.unlockSpaceId).toBe('unlock-space-new')
  })

  it('never carries the marker in as a standing member', () => {
    // The carry rule sweeps every non-standing member out of the entry
    // before spreading the rest; a marker that leaked through would be
    // re-stamped by a repoint that is supposed to drop it.
    const entry = passphraseEntry(
      upsertPassphraseUnlockMethod({
        record: registryWith({ pendingEstablishment: MARKER }),
        unlockSpaceId: 'unlock-space-new'
      })
    )
    expect(entry).not.toHaveProperty('pendingEstablishment')
    // The repoint drops the carried standing members with it.
    expect(entry).not.toHaveProperty('keyAgreementKeyMultibase')
  })
})
