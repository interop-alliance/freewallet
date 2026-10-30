// @vitest-environment node
/**
 * The backfill reaches its registry read on BOTH storage tiers. FW-295's
 * transient gate was retired with the account-ceremony context: a transient
 * session reads and writes the registry under the visit's generation
 * delegation rather than being turned away before the first read.
 */
import { describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'
import { STORAGE_IN_MEMORY, STORAGE_INDEXEDDB } from '@/session/persistence'

const {
  backfillPassphraseUnlockMethod,
  upsertUnlockMethod,
  isStandingCredentialEntry,
  standingUnlockFields,
  upsertPassphraseUnlockMethod
} = await import('@/session/unlockMethods')
type PassphraseUnlockMethod =
  import('@/session/unlockMethods').PassphraseUnlockMethod
type UnlockMethodsRecord = import('@/session/unlockMethods').UnlockMethodsRecord
type UnlockMethod = import('@/session/unlockMethods').UnlockMethod

/**
 * A minimal session shaped as `backfillPassphraseUnlockMethod` reads it: the
 * storage tier under test, plus just enough of `profile` and `persistence`
 * for the browser-local path to reach its first registry read (a local-cache
 * load, since no `VITE_WAS_SERVER_URL` -- the base server URL -- is
 * set in tests) without throwing.
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

describe('backup-credential entries', () => {
  const passphrase: UnlockMethod = {
    type: 'passphrase',
    createdAt: '2026-09-01T00:00:00Z',
    unlockSpaceId: 'unlock-space-passphrase',
    kdfVersion: 1
  }
  const backupA: UnlockMethod = {
    type: 'backup-credential',
    label: '2026-09-01',
    createdAt: '2026-09-01T00:00:00Z',
    unlockSpaceId: 'unlock-space-backup-a'
  }
  const backupB: UnlockMethod = {
    type: 'backup-credential',
    label: '2026-09-02',
    createdAt: '2026-09-02T00:00:00Z',
    unlockSpaceId: 'unlock-space-backup-b'
  }

  it('upserts a backup entry by its unlock Space alone', () => {
    // Two backup exports leave two entries; a write naming one of them must
    // replace that one in place and leave the other standing.
    const record = {
      webAuthnUserId: 'HANDLE',
      methods: [passphrase, backupA, backupB] as UnlockMethod[]
    } as UnlockMethodsRecord
    const renamed = { ...backupA, label: 'renamed' }
    expect(upsertUnlockMethod({ record, entry: renamed }).methods).toEqual([
      passphrase,
      renamed,
      backupB
    ])
  })

  it('counts the three standing kinds as standing credentials', () => {
    expect(isStandingCredentialEntry(passphrase)).toBe(true)
    expect(
      isStandingCredentialEntry({
        type: 'passkey',
        label: 'Laptop',
        createdAt: '2026-09-01T00:00:00Z',
        credentialId: 'cred-1',
        transports: [],
        backupEligibility: false,
        backupState: false,
        unlockSpaceId: 'unlock-space-passkey'
      })
    ).toBe(true)
    expect(isStandingCredentialEntry(backupA)).toBe(true)
    expect(
      isStandingCredentialEntry({
        type: 'recovery-code',
        label: 'Code 1',
        createdAt: '2026-09-01T00:00:00Z',
        unlockSpaceId: 'unlock-space-code',
        recoveryKid: 'kid-1',
        keyAgreementKeyMultibase: 'z6LSCode',
        updateKeyMultibase: 'z6MkCode'
      })
    ).toBe(false)
  })
})

describe('standingUnlockFields (the one builder of the standing literal)', () => {
  const standing = {
    clientDid: 'did:key:z6MkStanding',
    keyAgreementKeyMultibase: 'z6LSStanding',
    recipientKid: 'did:key:z6MkStanding#z6LSStanding'
  }
  const bridge = {
    id: 'urn:zcap:bridge',
    expires: '2027-01-01T00:00:00Z',
    proof: { verificationMethod: 'did:webvh:acct#ladder-1' }
  } as unknown as IZcap
  const sibling = {
    id: 'urn:zcap:sibling',
    expires: '2027-02-01T00:00:00Z',
    proof: [{ verificationMethod: 'did:webvh:acct#ladder-2' }]
  } as unknown as IZcap

  it('builds every member from full inputs, deriving the delegation members from the zcaps', () => {
    expect(
      standingUnlockFields({
        standing,
        rung0KeyMultibase: 'z6MkRung0',
        delegation: bridge,
        delegatedClients: sibling,
        unlockKeyAgreementKeyId: 'did:key:z6MkUnlock#z6LSUnlock',
        unlockKeyAgreementKeyMultibase: 'z6LSUnlock'
      })
    ).toStrictEqual({
      rosterKid: standing.recipientKid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      updateKeyMultibase: 'z6MkRung0',
      delegationKeyId: 'did:webvh:acct#ladder-1',
      delegationExpires: '2027-01-01T00:00:00Z',
      delegatedClientsKeyId: 'did:webvh:acct#ladder-2',
      delegatedClientsExpires: '2027-02-01T00:00:00Z',
      unlockClientDid: standing.clientDid,
      unlockKeyAgreementKeyId: 'did:key:z6MkUnlock#z6LSUnlock',
      unlockKeyAgreementKeyMultibase: 'z6LSUnlock'
    })
  })

  it('leaves every member absent (not undefined-valued) when its input is', () => {
    const fields = standingUnlockFields({})
    expect(fields).toStrictEqual({})
  })

  it('records the standing triple and rung 0 alone when no delegation is passed', () => {
    const fields = standingUnlockFields({
      standing,
      rung0KeyMultibase: 'z6MkRung0'
    })
    expect(fields).toStrictEqual({
      rosterKid: standing.recipientKid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      updateKeyMultibase: 'z6MkRung0',
      unlockClientDid: standing.clientDid
    })
  })

  it('omits the members a zcap without a proof key or an expiry cannot supply', () => {
    const bare = { id: 'urn:zcap:bare' } as unknown as IZcap
    const fields = standingUnlockFields({
      delegation: bare,
      delegatedClients: bare
    })
    expect(fields).toStrictEqual({})
  })
})
