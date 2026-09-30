// @vitest-environment node
/**
 * The kind-agnostic completion and failure cleanup around a standing
 * credential's establishment: the completion write merges the entry by its
 * own identity, and the cleanup completes a lost-response success or
 * retires a partial establishment, whichever the entry's kind.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import type { AccountCeremonyContext } from '@/session/accountCeremonyContext'
import type { UnlockCredential } from '@/session/keyring'
import type {
  BackupCredentialUnlockMethod,
  UnlockMethodsRecord
} from '@/session/unlockMethods'

const state: { registry: UnlockMethodsRecord | null; writeFails: boolean } = {
  registry: null,
  writeFails: false
}

vi.mock('@/session/unlockMethods', () => ({
  isLoginEntry: (entry: { type: string }) => entry.type !== 'backup-credential',
  upsertUnlockMethod: vi.fn(
    ({
      record,
      entry: upserted
    }: {
      record: UnlockMethodsRecord
      entry: BackupCredentialUnlockMethod
    }): UnlockMethodsRecord => ({
      ...record,
      methods: [
        ...record.methods.filter(
          method => method.unlockSpaceId !== upserted.unlockSpaceId
        ),
        upserted
      ]
    })
  ),
  dropRegistryEntry: vi.fn(
    async ({ entry: dropped }: { entry: BackupCredentialUnlockMethod }) => {
      if (state.registry) {
        state.registry = {
          ...state.registry,
          methods: state.registry.methods.filter(
            method => method.unlockSpaceId !== dropped.unlockSpaceId
          )
        }
      }
    }
  ),
  updateUnlockMethods: vi.fn(
    async ({
      mutate
    }: {
      mutate: (
        current: UnlockMethodsRecord | null
      ) => UnlockMethodsRecord | null
    }) => {
      if (state.writeFails) {
        throw new Error('registry write refused')
      }
      const next = mutate(state.registry)
      if (next) {
        state.registry = next
      }
      return next
    }
  )
}))
vi.mock('@/session/keyring', () => ({
  fetchKeyring: vi.fn(),
  deleteUnlockMethod: vi.fn(async () => {}),
  keyAgreementPublicationOf: vi.fn(() => 'verbatim')
}))
vi.mock('@/session/standingUnlock', () => ({
  establishStandingUnlock: vi.fn(),
  standingFieldsOfKeyringHit: vi.fn(async () => ({
    keyAgreementKeyMultibase: 'z6LSBackupKak',
    updateKeyMultibase: 'z6MkBackupRung0'
  }))
}))
vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(),
  verifiedAccountLog: vi.fn(async () => ({ doc: { id: 'did:webvh:acct' } }))
}))
vi.mock('@/session/pendingRetirement', () => ({
  documentListsCredential: vi.fn()
}))
vi.mock('@/session/credentialRotation', () => ({
  isUnclaimedLadderVmRefusal: vi.fn(() => false),
  rotateOffUnlockCredential: vi.fn(async () => ({
    rotated: false,
    mended: []
  }))
}))
vi.mock('@/session/menders/ceremonyTail', () => ({
  reportCeremonyTail: vi.fn()
}))
vi.mock('@/session/userKeyAdoption', () => {
  const withOwnUserKeyRotation = vi.fn(
    async ({ run }: { run: () => Promise<unknown> }) => await run()
  )
  return {
    withOwnUserKeyRotation,
    heldAsOwnUserKeyRotation:
      (body: (options: { session: unknown }) => Promise<unknown>) =>
      async (options: { session: unknown }) =>
        await withOwnUserKeyRotation({
          run: () => body(options)
        }),
    adoptRotatedUserKey: vi.fn(),
    rotationSpaceId: vi.fn(() => 'space-account')
  }
})
vi.mock('@interop/wallet-core/clientAnnex', () => ({
  ladderRung: vi.fn(async () => ({ keyMultibase: 'z6MkRung0' }))
}))

const { fetchKeyring, deleteUnlockMethod } = await import('@/session/keyring')
const { verifiedAccountLog } = await import('@/session/verifiedLog')
const { documentListsCredential } = await import('@/session/pendingRetirement')
const { rotateOffUnlockCredential } =
  await import('@/session/credentialRotation')
const { completeStandingEntry, recoverFailedStandingEstablishment } =
  await import('@/session/standingEstablishment')

const deleteNotice = vi.fn(async () => {})
const session = {
  user: { id: 'did:webvh:acct' },
  profile: {},
  persistence: { logPins: {}, passkeyNotices: { delete: deleteNotice } }
} as unknown as Session
const context = {
  pointer: { did: 'did:webvh:acct', spaceId: 'space-account' },
  rosterStore: { read: vi.fn(async () => null) }
} as unknown as AccountCeremonyContext
const credential = {
  unlock: { spaceId: 'space-backup' },
  standing: {
    keyAgreementKeyMultibase: 'z6LSBackupKak',
    recipientKid: 'did:key:zBackup#z6LSBackupKak'
  }
} as unknown as UnlockCredential
const entry: BackupCredentialUnlockMethod = {
  type: 'backup-credential',
  label: 'Backup 2026-09-25',
  createdAt: '2026-09-25T00:00:00.000Z',
  unlockSpaceId: 'space-backup'
}
const passphraseEntry = {
  type: 'passphrase',
  unlockSpaceId: 'space-passphrase'
} as unknown as UnlockMethodsRecord['methods'][number]

/**
 * @returns {UnlockMethodsRecord}   a registry holding the passphrase entry
 *   and the bare backup-credential entry
 */
function registryWithBareEntry(): UnlockMethodsRecord {
  return {
    webAuthnUserId: 'HANDLE',
    methods: [passphraseEntry, entry]
  } as unknown as UnlockMethodsRecord
}

beforeEach(() => {
  vi.clearAllMocks()
  state.registry = registryWithBareEntry()
  state.writeFails = false
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('completeStandingEntry', () => {
  it('merges the entry into a fresh read', async () => {
    const completed = { ...entry, keyAgreementKeyMultibase: 'z6LSBackupKak' }
    const { record, recorded } = await completeStandingEntry({
      session,
      base: registryWithBareEntry(),
      entry: completed
    })
    expect(recorded).toBe(true)
    expect(record.methods).toContainEqual(completed)
    expect(state.registry!.methods).toContainEqual(completed)
    // A backup credential is not a method a login accepts, so the account
    // still has one: the passkey-safety notice stands.
    expect(deleteNotice).not.toHaveBeenCalled()
  })

  it('clears the passkey-safety notice once a second login method stands', async () => {
    const passkey = {
      type: 'passkey',
      credentialId: 'cred-1',
      unlockSpaceId: 'space-passkey'
    } as unknown as UnlockMethodsRecord['methods'][number]
    state.registry = {
      webAuthnUserId: 'HANDLE',
      methods: [passphraseEntry, passkey]
    } as unknown as UnlockMethodsRecord
    await completeStandingEntry({
      session,
      base: state.registry,
      entry: passkey as never
    })
    expect(deleteNotice).toHaveBeenCalledWith({ controller: 'did:webvh:acct' })
  })

  it('reports recorded: false when the registry write fails', async () => {
    state.writeFails = true
    const { record, recorded } = await completeStandingEntry({
      session,
      base: registryWithBareEntry(),
      entry
    })
    expect(recorded).toBe(false)
    // The in-memory merge onto the base is still returned.
    expect(record.methods).toContainEqual(entry)
    expect(deleteNotice).not.toHaveBeenCalled()
  })
})

describe('recoverFailedStandingEstablishment', () => {
  /**
   * @returns {Promise<unknown>}   the cleanup's outcome
   */
  async function runRecovery() {
    return await recoverFailedStandingEstablishment({
      session,
      context,
      secret: new Uint8Array(32).fill(1),
      kdf: { version: 1 } as never,
      credential,
      ladderSeed: new Uint8Array(32).fill(2),
      entry,
      base: registryWithBareEntry()
    })
  }

  it('completes the entry when the record is standing and the document lists it', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue({
      standing: { ladderSeed: new Uint8Array(32).fill(3) },
      manageCapability: { id: 'urn:zcap:refetched' }
    } as never)
    vi.mocked(documentListsCredential).mockResolvedValue(true)

    const outcome = await runRecovery()

    expect(outcome).toEqual(expect.objectContaining({ recorded: true }))
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(deleteUnlockMethod)).not.toHaveBeenCalled()
    const completed = state.registry!.methods.find(
      method => method.type === 'backup-credential'
    )
    expect(completed).toEqual(
      expect.objectContaining({
        keyAgreementKeyMultibase: 'z6LSBackupKak',
        manageCapability: { id: 'urn:zcap:refetched' }
      })
    )
  })

  it('retires a published establishment, then deletes the Space and drops the entry', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue(null)
    vi.mocked(documentListsCredential).mockResolvedValue(true)

    const outcome = await runRecovery()

    expect(outcome).toBeNull()
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({
          type: 'backup-credential',
          keyAgreementKeyMultibase: 'z6LSBackupKak',
          updateKeyMultibase: 'z6MkRung0',
          unlockSpaceId: 'space-backup'
        }),
        verb: 'cleaning up a failed backup-credential addition'
      })
    )
    expect(vi.mocked(deleteUnlockMethod)).toHaveBeenCalledOnce()
    expect(
      state.registry!.methods.some(
        method => method.type === 'backup-credential'
      )
    ).toBe(false)
    expect(state.registry!.methods).toEqual([passphraseEntry])
    // One fresh read of the account document decides both the lost-response
    // arm and the published check.
    expect(vi.mocked(verifiedAccountLog)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(documentListsCredential)).toHaveBeenCalledTimes(1)
  })
})
