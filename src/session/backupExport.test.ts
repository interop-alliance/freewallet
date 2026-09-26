/**
 * Unit tests for the backup-export ceremony: which Spaces it lists and in
 * what order, the capability each kind of session exports them under, the
 * fail-whole rule, and what the log is allowed to carry.
 *
 * The package's own `exportBundle` runs for real, so the order it enforces
 * (the credential first, then the listing, then one export per Space) is
 * part of what these tests observe. Everything the ceremony reaches for --
 * the establishment, the registry, the ceremony context, the export requests
 * -- is a stub.
 *
 * @vitest-environment node
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { addSink, captureSink } from '@interop/logger'
import type { Session } from '@/types/auth'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

vi.mock('@/session/backupCredential', () => {
  /**
   * The stub of the establishment's annex-commit refusal. The ceremony
   * matches it by `name`, so the stub carries the real one.
   */
  class BackupAnnexCommitError extends Error {
    readonly reason: string
    constructor({ reason }: { reason: string }) {
      super(`annex commit refused: ${reason}`)
      this.name = 'BackupAnnexCommitError'
      this.reason = reason
    }
  }
  return {
    BackupAnnexCommitError,
    establishBackupCredential: vi.fn(async () => ({
      secret: new Uint8Array(32).fill(7),
      unlockSpaceId: 'unlock-backup'
    }))
  }
})

vi.mock('@/session/unlockMethods', () => ({
  getUnlockMethods: vi.fn(async () => ({ methods: [] })),
  unlockSpaceCapabilityRefusal: vi.fn(() => undefined),
  unlockSpaceVerbInvocation: vi.fn(async () => ({
    zcapClient: { id: 'management-client' },
    capability: { id: 'minted-child' }
  }))
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  accountCeremonyContext: vi.fn(async () => null),
  canRunUserKeyCeremonies: vi.fn(() => true),
  requireEnrolledCeremonyContext: vi.fn(() => {
    throw new Error('No account-ceremony context in this test.')
  })
}))

/**
 * The pointed generation the stubbed reach resolves, on both branches.
 */
const ANNEX_REACH = {
  spaceId: 'annex-space',
  clientAnnexDid: 'did:webvh:example:annex-space:gen-1',
  generationId: 'gen-1',
  logStore: () => ({ store: 'annex-log' })
}

vi.mock('@/session/annexReach', () => ({
  pointedClientAnnexReach: vi.fn(async () => ANNEX_REACH),
  standingClientAnnexReachOf: vi.fn(() => ANNEX_REACH)
}))

vi.mock('@/lib/wasService', () => ({
  wasServiceDescription: vi.fn(async () => ({}))
}))

vi.mock('@interop/wallet-core/clientAnnex', () => ({
  clientAnnexRungAdmitted: vi.fn(async () => true),
  delegatedClientsDelegationSpaceId: vi.fn(() => 'annex-space')
}))

const { collectBytes, fileNameFor, packSpaceArchive } =
  await import('@interop/space-archive')
const { pointedClientAnnexReach } = await import('@/session/annexReach')
const { clientAnnexRungAdmitted, delegatedClientsDelegationSpaceId } =
  await import('@interop/wallet-core/clientAnnex')

const { establishBackupCredential } = await import('@/session/backupCredential')
const {
  getUnlockMethods,
  unlockSpaceCapabilityRefusal,
  unlockSpaceVerbInvocation
} = await import('@/session/unlockMethods')
const { accountCeremonyContext, canRunUserKeyCeremonies } =
  await import('@/session/accountCeremonyContext')
const {
  backupExportErrorKey,
  backupExportErrorLabel,
  canExportBackup,
  exportBackup,
  BackupCapabilityMissingError,
  BackupCapabilityUnsupportedError,
  BackupContinuityError,
  BackupCredentialNotListedError,
  BackupSpaceExportError
} = await import('@/session/backupExport')

const ACCOUNT_SPACE = 'account-space'

/**
 * One export request, as the stubbed remote store records it.
 */
interface RecordedExport {
  spaceId: string
  capabilityId?: string
  clientId?: string
}

/**
 * The secret the stubbed establishment hands the package.
 */
const SECRET = new Uint8Array(32).fill(7)

/**
 * A session over a stubbed remote store, plus the log of what each export
 * was invoked with.
 *
 * @param [options] {object}
 * @param [options.hasRemoteStorage] {boolean}
 * @param [options.accountLogPin] {object}
 * @param [options.withLadderSeed] {boolean}   whether the session holds a
 *   ladder seed to commit the new credential's rung with
 * @returns {object}
 */
function makeSession({
  hasRemoteStorage = true,
  accountLogPin,
  withLadderSeed = true
}: {
  hasRemoteStorage?: boolean
  accountLogPin?: { method: string; scid: string; head: string }
  withLadderSeed?: boolean
} = {}): {
  session: Session
  exports: RecordedExport[]
  remoteStore: { exportSpace: ReturnType<typeof vi.fn> }
} {
  const exports: RecordedExport[] = []
  const bytes = () =>
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]))
        controller.close()
      }
    })
  // The store's own Space under its own binding by default, exactly as the
  // real store's `exportSpace` reads its arguments.
  const remoteStore = {
    exportSpace: vi.fn(
      async ({
        spaceId = ACCOUNT_SPACE,
        zcapClient,
        capability
      }: {
        spaceId?: string
        zcapClient?: { id?: string }
        capability?: { id?: string }
      } = {}) => {
        exports.push({
          spaceId,
          ...(capability?.id ? { capabilityId: capability.id } : {}),
          ...(zcapClient?.id ? { clientId: zcapClient.id } : {})
        })
        return bytes()
      }
    )
  }
  const session = {
    registryReady: Promise.resolve(),
    mends: Promise.resolve(),
    isGuest: false,
    storage: {
      hasRemoteStorage,
      spaceId: hasRemoteStorage ? ACCOUNT_SPACE : undefined,
      remoteStore
    },
    profile: {
      zcapClient: { id: 'root-client' },
      userKey: { id: 'user-key' },
      ...(withLadderSeed ? { ladderSeed: new Uint8Array(32).fill(3) } : {}),
      invocationCapability: {
        id: 'urn:zcap:delegated:generation',
        allowedAction: ['GET', 'PUT', 'POST']
      },
      standingUnlock: {
        standingClient: { agents: { zcapClient: { id: 'standing-client' } } }
      }
    },
    // The visit's chain-head pins. A cell that holds none for the account log
    // exercises the unpinned path, where the archive is accepted unread.
    persistence: {
      logPins: {
        read: vi.fn(async () => accountLogPin ?? null),
        write: vi.fn(async () => {})
      }
    }
  } as unknown as Session
  return { session, exports, remoteStore }
}

/**
 * A ladder-kind context over the stubbed remote store.
 *
 * @param options {object}
 * @param options.remoteStore {object}
 * @returns {object}
 */
function ladderContext({ remoteStore }: { remoteStore: unknown }) {
  return {
    kind: 'ladder',
    remoteStore,
    pointer: {
      did: 'did:webvh:example:account',
      spaceId: ACCOUNT_SPACE,
      host: 'https://was.example'
    },
    sibling: {
      id: 'delegated-clients',
      allowedAction: ['GET', 'PUT', 'POST']
    },
    ladderDeleter: {
      zcapClient: { id: 'ladder-vm' },
      invoker: { id: 'ladder-did-key' },
      controller: 'did:key:zLadder'
    }
  }
}

/**
 * An enrolled-kind context over the stubbed remote store.
 *
 * @param options {object}
 * @param options.remoteStore {object}
 * @returns {object}
 */
function enrolledContext({ remoteStore }: { remoteStore: unknown }) {
  return {
    kind: 'enrolled',
    remoteStore,
    pointer: {
      did: 'did:webvh:example:account',
      spaceId: ACCOUNT_SPACE,
      host: 'https://was.example'
    }
  }
}

/**
 * Two registry entries, both carrying a management zcap: the passphrase, and
 * the backup credential this run establishes.
 *
 * @returns {Array<object>}
 */
function registryMethods() {
  return [
    {
      type: 'passphrase',
      unlockSpaceId: 'unlock-passphrase',
      manageCapability: {
        id: 'manage-passphrase',
        controller: 'did:key:zManage'
      }
    },
    {
      type: 'backup-credential',
      label: 'Backup 2026-09-20',
      unlockSpaceId: 'unlock-backup',
      manageCapability: { id: 'manage-backup', controller: 'did:key:zManage' }
    }
  ]
}

/**
 * The registry entries minus the passphrase: the credential this run
 * established alone, which every cell needs, since a listing that does not
 * name it refuses.
 *
 * @returns {Array<object>}
 */
function credentialEntryOnly() {
  return registryMethods().slice(1)
}

/**
 * A real account-Space archive carrying one `id/did.jsonl` whose entries are
 * the given version ids, so the continuity check reads the same layout the
 * server writes.
 *
 * @param options {object}
 * @param options.versionIds {string[]}
 * @returns {Promise<Uint8Array>}
 */
async function accountArchiveBytes({
  versionIds
}: {
  versionIds: string[]
}): Promise<Uint8Array> {
  const lines = versionIds
    .map(versionId => JSON.stringify({ versionId }))
    .join('\n')
  const pack = await packSpaceArchive({
    spaceId: ACCOUNT_SPACE,
    entries: [
      {
        name: 'id',
        files: [
          {
            name: fileNameFor({
              resourceId: 'did.jsonl',
              contentType: 'application/jsonl'
            }),
            bytes: new TextEncoder().encode(lines)
          }
        ]
      }
    ]
  })
  return await collectBytes(pack)
}

/**
 * Drains a bundle stream, so nothing is left unread between tests.
 *
 * @param stream {ReadableStream<Uint8Array>}
 * @returns {Promise<number>}   the byte count
 */
async function drain(stream: ReadableStream<Uint8Array>): Promise<number> {
  const reader = stream.getReader()
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) {
      return total
    }
    total += value.byteLength
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(canRunUserKeyCeremonies).mockReturnValue(true)
  vi.mocked(unlockSpaceCapabilityRefusal).mockReturnValue(undefined)
  vi.mocked(establishBackupCredential).mockResolvedValue({
    secret: SECRET,
    unlockSpaceId: 'unlock-backup'
  } as never)
  vi.mocked(getUnlockMethods).mockResolvedValue({
    methods: registryMethods()
  } as never)
  vi.mocked(unlockSpaceVerbInvocation).mockResolvedValue({
    zcapClient: { id: 'management-client' },
    capability: { id: 'minted-child' }
  } as never)
  // The account document points at one annex Space, and the ladder context's
  // sibling delegation targets that same Space.
  vi.mocked(pointedClientAnnexReach).mockResolvedValue(ANNEX_REACH as never)
  vi.mocked(delegatedClientsDelegationSpaceId).mockReturnValue('annex-space')
  vi.mocked(clientAnnexRungAdmitted).mockResolvedValue(true)
})

describe('canExportBackup', () => {
  it('offers the backup to a session that can run account ceremonies, holds the user key and has remote storage', () => {
    const { session } = makeSession()
    expect(canExportBackup({ session })).toBe(true)
  })

  it('refuses a session with no remote storage', () => {
    const { session } = makeSession({ hasRemoteStorage: false })
    expect(canExportBackup({ session })).toBe(false)
  })

  it('refuses a session that cannot run a user-key ceremony', () => {
    const { session } = makeSession()
    vi.mocked(canRunUserKeyCeremonies).mockReturnValue(false)
    expect(canExportBackup({ session })).toBe(false)
  })
})

describe('exportBackup', () => {
  it('establishes the credential first, then exports the account, annex and unlock Spaces in order', async () => {
    const { session, exports, remoteStore } = makeSession()
    const context = ladderContext({ remoteStore })
    vi.mocked(accountCeremonyContext).mockResolvedValue(context as never)
    const order: string[] = []
    vi.mocked(establishBackupCredential).mockImplementation(async () => {
      order.push(`establish:${exports.length}`)
      return { secret: SECRET, unlockSpaceId: 'unlock-backup' } as never
    })
    vi.mocked(getUnlockMethods).mockImplementation(async () => {
      order.push('list')
      return { methods: registryMethods() } as never
    })
    const stages: string[] = []

    const stream = await exportBackup({
      session,
      credentialLabel: 'Backup 2026-09-20',
      onProgress: ({ stage }) => stages.push(stage)
    })
    expect(await drain(stream)).toBeGreaterThan(0)

    // The pre-flight reads the registry before anything is minted; the
    // listing reads it back from the server once the credential is
    // established, before any export request; and one read at the end
    // settles the registry against that listing.
    expect(order).toEqual(['list', 'establish:0', 'list', 'list'])
    expect(stages[0]).toBe('establishing-credential')
    expect(
      stages.slice(1, -1).every(stage => stage === 'exporting-space')
    ).toBe(true)
    expect(stages.at(-1)).toBe('packing')
    expect(exports.map(entry => entry.spaceId)).toEqual([
      ACCOUNT_SPACE,
      'annex-space',
      'unlock-passphrase',
      'unlock-backup'
    ])
    expect(
      vi.mocked(establishBackupCredential).mock.calls[0]?.[0]
    ).toMatchObject({
      session,
      context,
      label: 'Backup 2026-09-20'
    })
  })

  it('exports the annex under the delegatedClients delegation on a ladder session', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: credentialEntryOnly()
    } as never)

    await drain(await exportBackup({ session, credentialLabel: 'Backup' }))

    expect(exports[1]).toEqual({
      spaceId: 'annex-space',
      capabilityId: 'delegated-clients',
      clientId: 'standing-client'
    })
  })

  it('mints a POST-only child per unlock Space on a ladder session', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(unlockSpaceVerbInvocation).mockResolvedValue({
      zcapClient: { id: 'ladder-did-key' },
      capability: { id: 'minted-child' }
    } as never)

    await drain(await exportBackup({ session, credentialLabel: 'Backup' }))

    // The mint is the deletion walk's own, handed the ladder's signer: the
    // ladder VM signs the child and its bare did:key sends the request.
    expect(vi.mocked(unlockSpaceVerbInvocation)).toHaveBeenCalledTimes(2)
    expect(
      vi.mocked(unlockSpaceVerbInvocation).mock.calls[0]?.[0]
    ).toMatchObject({
      verb: 'POST',
      signer: { controller: 'did:key:zLadder' },
      entry: { unlockSpaceId: 'unlock-passphrase' }
    })
    expect(exports[2]).toEqual({
      spaceId: 'unlock-passphrase',
      capabilityId: 'minted-child',
      clientId: 'ladder-did-key'
    })
  })

  it('fails the whole export when an unlock zcap allows no POST', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(unlockSpaceCapabilityRefusal).mockReturnValue(
      'unsupported-capability' as never
    )

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    // The passphrase entry is the first one exported, so its kind picks the
    // message.
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.passphrase'
    )
    expect(vi.mocked(unlockSpaceVerbInvocation)).not.toHaveBeenCalled()
  })

  it('refuses an enrolled session a stored zcap that carries no POST', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      enrolledContext({ remoteStore }) as never
    )
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: credentialEntryOnly()
    } as never)
    vi.mocked(unlockSpaceCapabilityRefusal).mockReturnValue(
      'unsupported-capability' as never
    )

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    // The enrolled branch invokes the stored zcap rather than minting a
    // child, and runs the same pre-flight over it, so the refusal is this
    // ceremony's own rather than a server 404 read as a Space failure.
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.backupCredential'
    )
    expect(backupExportErrorLabel(failure)).toBe('Backup 2026-09-20')
    expect(remoteStore.exportSpace).not.toHaveBeenCalledWith(
      expect.objectContaining({ spaceId: 'unlock-backup' })
    )
  })

  it('fails the whole export when an entry records no management zcap', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    // The read-only pre-flight is what reports a missing zcap.
    vi.mocked(unlockSpaceCapabilityRefusal).mockImplementation(({ entry }) =>
      entry.manageCapability ? undefined : 'no-capability'
    )
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: [
        {
          type: 'passkey',
          label: 'Laptop passkey',
          unlockSpaceId: 'unlock-pk'
        },
        ...credentialEntryOnly()
      ]
    } as never)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.missingCapability.passkey'
    )
    expect(backupExportErrorLabel(failure)).toBe('Laptop passkey')
  })

  it('refuses when the registry read back does not list the credential just established', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    // The establishment recorded `unlock-backup`. The server's registry is
    // what the listing reads, and it names the passphrase alone.
    vi.mocked(getUnlockMethods)
      .mockResolvedValueOnce({ methods: registryMethods() } as never)
      .mockResolvedValueOnce({
        methods: registryMethods().slice(0, 1)
      } as never)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(failure).toBeInstanceOf(BackupCredentialNotListedError)
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.credentialNotListed'
    )
    // Nothing is exported: the refusal lands in the listing stage.
    expect(exports).toEqual([])
  })

  it('refuses when the registry read back is absent', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(getUnlockMethods)
      .mockResolvedValueOnce({ methods: registryMethods() } as never)
      .mockResolvedValueOnce(null as never)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.credentialNotListed'
    )
  })

  it('refuses when an unlock method is added or removed during the run', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    // The pre-flight read, the listing read, then the settling read once the
    // archives are in hand: a credential was removed while they were written.
    vi.mocked(getUnlockMethods)
      .mockResolvedValueOnce({ methods: registryMethods() } as never)
      .mockResolvedValueOnce({ methods: registryMethods() } as never)
      .mockResolvedValueOnce({ methods: credentialEntryOnly() } as never)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.registryChanged'
    )
  })

  it('fails the whole export when one Space export is refused', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    remoteStore.exportSpace.mockRejectedValue(new Error('403 Forbidden'))

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.spaceExportFailed'
    )
  })

  it('root-invokes the annex and mints a POST-only child per unlock Space on an enrolled session', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      enrolledContext({ remoteStore }) as never
    )

    await drain(await exportBackup({ session, credentialLabel: 'Backup' }))

    expect(exports).toEqual([
      { spaceId: ACCOUNT_SPACE },
      { spaceId: 'annex-space', clientId: 'root-client' },
      {
        spaceId: 'unlock-passphrase',
        capabilityId: 'minted-child',
        clientId: 'management-client'
      },
      {
        spaceId: 'unlock-backup',
        capabilityId: 'minted-child',
        clientId: 'management-client'
      }
    ])
    // The child is minted with no signer of the ceremony's own, so the
    // deletion walk's enrolled arm mints it to the stored zcap's delegatee.
    expect(vi.mocked(unlockSpaceVerbInvocation)).toHaveBeenCalledTimes(2)
    expect(
      vi.mocked(unlockSpaceVerbInvocation).mock.calls[0]?.[0]
    ).toMatchObject({
      verb: 'POST',
      entry: { unlockSpaceId: 'unlock-passphrase' }
    })
    expect(
      vi.mocked(unlockSpaceVerbInvocation).mock.calls[0]?.[0]
    ).not.toHaveProperty('signer')
  })

  it('establishes no credential when a stored zcap cannot carry the export', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(unlockSpaceCapabilityRefusal).mockReturnValue(
      'unsupported-capability' as never
    )

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.passphrase'
    )
    // The pre-flight runs before the pivot, so a refused run leaves no
    // orphan "Backup <date>" credential behind.
    expect(vi.mocked(establishBackupCredential)).not.toHaveBeenCalled()
    expect(exports).toEqual([])
  })

  it('refuses a ladder session holding no delegation into the named annex', async () => {
    const { session, remoteStore } = makeSession()
    const context = ladderContext({ remoteStore }) as Record<string, unknown>
    delete context.sibling
    vi.mocked(accountCeremonyContext).mockResolvedValue(context as never)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    // The document names an annex Space this session cannot reach, so the
    // run refuses rather than writing a bundle that reads as complete.
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.missingCapability.generic'
    )
    expect(vi.mocked(establishBackupCredential)).not.toHaveBeenCalled()
  })

  it('refuses a sibling delegation naming a different Space than the pointer', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(delegatedClientsDelegationSpaceId).mockReturnValue('other-annex')

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.generic'
    )
    expect(vi.mocked(establishBackupCredential)).not.toHaveBeenCalled()
  })

  it('refuses a sibling delegation that carries no POST', async () => {
    const { session, remoteStore } = makeSession()
    const context = ladderContext({ remoteStore })
    context.sibling = {
      id: 'delegated-clients',
      allowedAction: ['GET', 'PUT']
    }
    vi.mocked(accountCeremonyContext).mockResolvedValue(context as never)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    // A record sealed before the delegated-clients action set gained POST:
    // the pre-flight catches it, so no orphan credential is left behind.
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.generic'
    )
    expect(vi.mocked(establishBackupCredential)).not.toHaveBeenCalled()
  })

  it('refuses a generation delegation that carries no POST', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    ;(
      session.profile as unknown as { invocationCapability: unknown }
    ).invocationCapability = {
      id: 'urn:zcap:delegated:generation',
      allowedAction: ['GET', 'PUT']
    }

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.generic'
    )
    expect(vi.mocked(establishBackupCredential)).not.toHaveBeenCalled()
  })

  it('exports no annex archive when the account names none', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(pointedClientAnnexReach).mockResolvedValue(null as never)

    await drain(await exportBackup({ session, credentialLabel: 'Backup' }))

    // An account with no annex inventory is an ordinary state, so the
    // archive is skipped rather than refused.
    expect(exports.map(entry => entry.spaceId)).toEqual([
      ACCOUNT_SPACE,
      'unlock-passphrase',
      'unlock-backup'
    ])
  })

  it('refuses before the establishment when the session holds no ladder seed and the account names an annex', async () => {
    const { session, exports, remoteStore } = makeSession({
      withLadderSeed: false
    })
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      enrolledContext({ remoteStore }) as never
    )

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    // The new credential's rung cannot be committed into the pointed annex
    // generation, so the run refuses before anything is minted.
    expect((failure as Error).name).toBe('BackupAnnexCommitError')
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.annexCommit.noLadderSeed'
    )
    expect(vi.mocked(establishBackupCredential)).not.toHaveBeenCalled()
    expect(exports).toEqual([])
  })

  it('refuses before the establishment when the pointed generation does not admit the session rung', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      enrolledContext({ remoteStore }) as never
    )
    vi.mocked(clientAnnexRungAdmitted).mockResolvedValueOnce(false)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    // Read-only: the admission is asked of the generation the pre-flight
    // resolved, with this session's own ladder seed, and nothing is written.
    expect((failure as Error).name).toBe('BackupAnnexCommitError')
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.annexCommit.rungUncommitted'
    )
    expect(vi.mocked(clientAnnexRungAdmitted)).toHaveBeenCalledWith({
      store: { store: 'annex-log' },
      ladderSeed: new Uint8Array(32).fill(3),
      generationId: 'gen-1',
      expectedDid: ANNEX_REACH.clientAnnexDid
    })
    expect(vi.mocked(establishBackupCredential)).not.toHaveBeenCalled()
    expect(exports).toEqual([])
  })

  it('hands the pre-flight generation to the establishment', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      enrolledContext({ remoteStore }) as never
    )

    await drain(await exportBackup({ session, credentialLabel: 'Backup' }))

    // The commit targets the generation the pre-flight checked the session's
    // rung against, never a second resolution.
    expect(vi.mocked(establishBackupCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        clientAnnexDid: ANNEX_REACH.clientAnnexDid,
        registry: expect.objectContaining({ methods: registryMethods() })
      })
    )
  })

  it('exports without a ladder seed when the account names no annex', async () => {
    const { session, exports, remoteStore } = makeSession({
      withLadderSeed: false
    })
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      enrolledContext({ remoteStore }) as never
    )
    vi.mocked(pointedClientAnnexReach).mockResolvedValue(null as never)

    await drain(await exportBackup({ session, credentialLabel: 'Backup' }))

    expect(vi.mocked(establishBackupCredential)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(clientAnnexRungAdmitted)).not.toHaveBeenCalled()
    expect(vi.mocked(establishBackupCredential)).toHaveBeenCalledWith(
      expect.objectContaining({ clientAnnexDid: null })
    )
    expect(exports.map(entry => entry.spaceId)).toEqual([
      ACCOUNT_SPACE,
      'unlock-passphrase',
      'unlock-backup'
    ])
  })

  it('fails the whole export when the establishment fails', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    const notEstablished = new Error('establishment failed')
    notEstablished.name = 'BackupCredentialNotEstablishedError'
    vi.mocked(establishBackupCredential).mockRejectedValue(notEstablished)

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.notEstablished'
    )
    expect(exports).toEqual([])
  })

  it('refuses an account archive missing the log entry this visit pinned', async () => {
    const { session, remoteStore } = makeSession({
      accountLogPin: { method: 'did:webvh:1.0', scid: 'zScid', head: '2-zTwo' }
    })
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    const archive = await accountArchiveBytes({
      versionIds: ['1-zOne', '2-zForked']
    })
    remoteStore.exportSpace.mockImplementation(
      async ({ spaceId }: { spaceId?: string } = {}) =>
        spaceId === undefined
          ? archive
          : new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array([1, 2, 3]))
                controller.close()
              }
            })
    )

    const failure = await exportBackup({
      session,
      credentialLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.continuity'
    )
  })

  it('accepts an account archive carrying the pinned entry ahead of its tail', async () => {
    const { session, remoteStore } = makeSession({
      accountLogPin: { method: 'did:webvh:1.0', scid: 'zScid', head: '2-zTwo' }
    })
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    // The archive is one entry ahead of the pin: this run's own
    // establishment appended it.
    const archive = await accountArchiveBytes({
      versionIds: ['1-zOne', '2-zTwo', '3-zThree']
    })
    remoteStore.exportSpace.mockImplementation(
      async ({ spaceId }: { spaceId?: string } = {}) =>
        spaceId === undefined
          ? archive
          : new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array([1, 2, 3]))
                controller.close()
              }
            })
    )

    expect(
      await drain(await exportBackup({ session, credentialLabel: 'Backup' }))
    ).toBeGreaterThan(0)
  })

  it('never logs the secret', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: credentialEntryOnly()
    } as never)
    const capture = captureSink()
    const removeSink = addSink(capture.sink)
    try {
      await drain(
        await exportBackup({
          session,
          credentialLabel: 'Backup',
          exportPassphrase: 'an-export-password'
        })
      )
    } finally {
      removeSink()
    }

    const logged = JSON.stringify(capture.events)
    expect(logged).not.toContain(base64urlnopad.encode(SECRET))
    expect(logged).not.toContain(Buffer.from(SECRET).toString('hex'))
    expect(logged).not.toContain(Array.from(SECRET).join(','))
    expect(logged).not.toContain(JSON.stringify(SECRET))
    expect(logged).not.toContain('an-export-password')
  })
})

describe('backupExportErrorKey', () => {
  it('maps a cancelled run', () => {
    const cancelled = new Error('cancelled')
    cancelled.name = 'AbortError'
    expect(backupExportErrorKey(cancelled)).toBe(
      'storage.backup.errors.cancelled'
    )
  })

  it('reads a wrapped cause rather than the outermost error alone', () => {
    const wrapped = new Error('Exporting Space "x" failed.', {
      cause: new BackupSpaceExportError('refused')
    })
    expect(backupExportErrorKey(wrapped)).toBe(
      'storage.backup.errors.spaceExportFailed'
    )
  })

  it('maps the two capability refusals apart, by the entry they name', () => {
    expect(backupExportErrorKey(new BackupCapabilityMissingError('x'))).toBe(
      'storage.backup.errors.missingCapability.generic'
    )
    expect(
      backupExportErrorKey(
        new BackupCapabilityUnsupportedError('x', {
          entryType: 'recovery-code',
          entryLabel: 'Backup 2026-09-20'
        })
      )
    ).toBe('storage.backup.errors.unsupportedCapability.recoveryCode')
    expect(
      backupExportErrorLabel(
        new BackupCapabilityMissingError('x', {
          entryType: 'passkey',
          entryLabel: 'Laptop passkey'
        })
      )
    ).toBe('Laptop passkey')
    const backupRefusal = new BackupCapabilityMissingError('x', {
      entryType: 'backup-credential',
      entryLabel: 'Backup 2026-09-20'
    })
    expect(backupExportErrorKey(backupRefusal)).toBe(
      'storage.backup.errors.missingCapability.backupCredential'
    )
    expect(backupExportErrorLabel(backupRefusal)).toBe('Backup 2026-09-20')
  })

  it('maps the two annex-commit refusals apart, by reason, wrapped or not', () => {
    const noSeed = Object.assign(new Error('x'), {
      name: 'BackupAnnexCommitError',
      reason: 'no-ladder-seed'
    })
    expect(backupExportErrorKey(noSeed)).toBe(
      'storage.backup.errors.annexCommit.noLadderSeed'
    )
    const uncommitted = Object.assign(new Error('x'), {
      name: 'BackupAnnexCommitError',
      reason: 'rung-uncommitted'
    })
    expect(
      backupExportErrorKey(new Error('wrapped', { cause: uncommitted }))
    ).toBe('storage.backup.errors.annexCommit.rungUncommitted')
  })

  it('maps a failed establishment, wrapped or not', () => {
    const notEstablished = new Error('x')
    notEstablished.name = 'BackupCredentialNotEstablishedError'
    expect(backupExportErrorKey(notEstablished)).toBe(
      'storage.backup.errors.notEstablished'
    )
    expect(
      backupExportErrorKey(new Error('wrapped', { cause: notEstablished }))
    ).toBe('storage.backup.errors.notEstablished')
  })

  it('maps a registry that does not list the credential just established', () => {
    expect(backupExportErrorKey(new BackupCredentialNotListedError('x'))).toBe(
      'storage.backup.errors.credentialNotListed'
    )
  })

  it('maps the account archive continuity refusal', () => {
    expect(backupExportErrorKey(new BackupContinuityError('x'))).toBe(
      'storage.backup.errors.continuity'
    )
  })

  it('falls back to the generic key', () => {
    expect(backupExportErrorKey(new Error('something else'))).toBe(
      'storage.backup.errors.failed'
    )
  })
})
