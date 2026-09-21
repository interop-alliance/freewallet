/**
 * Unit tests for the backup-export ceremony: which Spaces it lists and in
 * what order, the capability each kind of session exports them under, the
 * fail-whole rule, and what the log is allowed to carry.
 *
 * The package's own `exportBundle` runs for real, so the order it enforces
 * (the code first, then the listing, then one export per Space) is part of
 * what these tests observe. Everything the ceremony reaches for -- the
 * issuance, the registry, the ceremony context, the export requests -- is a
 * stub.
 *
 * @vitest-environment node
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import type { Session } from '@/types/auth'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

vi.mock('@/session/recovery', () => ({
  canIssueRecoveryCode: vi.fn(() => true),
  generateRecoveryCode: vi.fn(() => 'test-recovery-code-abcdef'),
  issueRecoveryCode: vi.fn(async () => ({
    entry: { unlockSpaceId: 'unlock-code' },
    registry: { methods: [] }
  }))
}))

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
  requireEnrolledCeremonyContext: vi.fn(() => {
    throw new Error('No account-ceremony context in this test.')
  })
}))

vi.mock('@/session/annexReach', () => ({
  pointedClientAnnexReach: vi.fn(async () => ({ spaceId: 'annex-space' }))
}))

vi.mock('@interop/wallet-core/clientAnnex', () => ({
  delegatedClientsDelegationSpaceId: vi.fn(() => 'annex-space')
}))

const { collectBytes, fileNameFor, packSpaceArchive } =
  await import('@interop/space-archive')
const { pointedClientAnnexReach } = await import('@/session/annexReach')
const { delegatedClientsDelegationSpaceId } =
  await import('@interop/wallet-core/clientAnnex')

const { canIssueRecoveryCode, generateRecoveryCode, issueRecoveryCode } =
  await import('@/session/recovery')
const {
  getUnlockMethods,
  unlockSpaceCapabilityRefusal,
  unlockSpaceVerbInvocation
} = await import('@/session/unlockMethods')
const { accountCeremonyContext } =
  await import('@/session/accountCeremonyContext')
const {
  backupExportErrorKey,
  backupExportErrorLabel,
  canExportBackup,
  exportBackup,
  BackupCapabilityMissingError,
  BackupCapabilityUnsupportedError,
  BackupContinuityError,
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
 * A session over a stubbed remote store, plus the log of what each export
 * was invoked with.
 *
 * @param [options] {object}
 * @param [options.hasRemoteStorage] {boolean}
 * @returns {object}
 */
function makeSession({
  hasRemoteStorage = true,
  accountLogPin
}: {
  hasRemoteStorage?: boolean
  accountLogPin?: { method: string; scid: string; head: string }
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
 * Two registry entries, both carrying a management zcap.
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
      type: 'recovery-code',
      label: 'Backup 2026-09-20',
      unlockSpaceId: 'unlock-code',
      manageCapability: { id: 'manage-code', controller: 'did:key:zManage' }
    }
  ]
}

/**
 * The registry entries minus the passphrase: the code this run issued alone,
 * which every cell needs, since a listing that does not name it refuses.
 *
 * @returns {Array<object>}
 */
function codeEntryOnly() {
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
  vi.mocked(canIssueRecoveryCode).mockReturnValue(true)
  vi.mocked(generateRecoveryCode).mockReturnValue('test-recovery-code-abcdef')
  vi.mocked(unlockSpaceCapabilityRefusal).mockReturnValue(undefined)
  vi.mocked(issueRecoveryCode).mockResolvedValue({
    entry: { unlockSpaceId: 'unlock-code' },
    registry: { methods: registryMethods() }
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
  vi.mocked(pointedClientAnnexReach).mockResolvedValue({
    spaceId: 'annex-space'
  } as never)
  vi.mocked(delegatedClientsDelegationSpaceId).mockReturnValue('annex-space')
})

describe('canExportBackup', () => {
  it('offers the backup to a session that can issue a code and has remote storage', () => {
    const { session } = makeSession()
    expect(canExportBackup({ session })).toBe(true)
  })

  it('refuses a session with no remote storage', () => {
    const { session } = makeSession({ hasRemoteStorage: false })
    expect(canExportBackup({ session })).toBe(false)
  })

  it('refuses a session that cannot issue a recovery code', () => {
    const { session } = makeSession()
    vi.mocked(canIssueRecoveryCode).mockReturnValue(false)
    expect(canExportBackup({ session })).toBe(false)
  })
})

describe('exportBackup', () => {
  it('issues the code first, then exports the account, annex and unlock Spaces in order', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    const order: string[] = []
    vi.mocked(issueRecoveryCode).mockImplementation(async () => {
      order.push('issue')
      return {
        entry: { unlockSpaceId: 'unlock-code' },
        registry: { methods: registryMethods() }
      } as never
    })
    vi.mocked(getUnlockMethods).mockImplementation(async () => {
      order.push('list')
      return { methods: registryMethods() } as never
    })

    const stream = await exportBackup({
      session,
      codeLabel: 'Backup 2026-09-20'
    })
    expect(await drain(stream)).toBeGreaterThan(0)

    // The pre-flight reads the registry before anything is minted; the
    // listing reads it back from the server once the code is issued; and one
    // read at the end settles the registry against that listing.
    expect(order).toEqual(['list', 'issue', 'list', 'list'])
    expect(exports.map(entry => entry.spaceId)).toEqual([
      ACCOUNT_SPACE,
      'annex-space',
      'unlock-passphrase',
      'unlock-code'
    ])
    expect(vi.mocked(issueRecoveryCode).mock.calls[0]?.[0]).toMatchObject({
      code: 'test-recovery-code-abcdef',
      label: 'Backup 2026-09-20'
    })
  })

  it('exports the annex under the delegatedClients delegation on a ladder session', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(issueRecoveryCode).mockResolvedValue({
      entry: { unlockSpaceId: 'unlock-code' },
      registry: { methods: codeEntryOnly() }
    } as never)
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: codeEntryOnly()
    } as never)

    await drain(await exportBackup({ session, codeLabel: 'Backup' }))

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

    await drain(await exportBackup({ session, codeLabel: 'Backup' }))

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
      codeLabel: 'Backup'
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
      methods: codeEntryOnly()
    } as never)
    vi.mocked(unlockSpaceCapabilityRefusal).mockReturnValue(
      'unsupported-capability' as never
    )

    const failure = await exportBackup({
      session,
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    // The enrolled branch invokes the stored zcap rather than minting a
    // child, and runs the same pre-flight over it, so the refusal is this
    // ceremony's own rather than a server 404 read as a Space failure.
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.recoveryCode'
    )
    expect(backupExportErrorLabel(failure)).toBe('Backup 2026-09-20')
    expect(remoteStore.exportSpace).not.toHaveBeenCalledWith(
      expect.objectContaining({ spaceId: 'unlock-code' })
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
        ...codeEntryOnly()
      ]
    } as never)

    const failure = await exportBackup({
      session,
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.missingCapability.passkey'
    )
    expect(backupExportErrorLabel(failure)).toBe('Laptop passkey')
  })

  it('refuses when the registry read back does not list the code just issued', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    // The issuance's own record would name the code, since its write appended
    // the entry in memory. The server's is what the listing reads, and it
    // names another set.
    vi.mocked(issueRecoveryCode).mockResolvedValue({
      entry: { unlockSpaceId: 'unlock-code-2' },
      registry: {
        methods: [
          ...registryMethods(),
          { type: 'recovery-code', unlockSpaceId: 'unlock-code-2' }
        ]
      }
    } as never)

    const failure = await exportBackup({
      session,
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.codeNotListed'
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
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.codeNotListed'
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
      .mockResolvedValueOnce({ methods: codeEntryOnly() } as never)

    const failure = await exportBackup({
      session,
      codeLabel: 'Backup'
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
      codeLabel: 'Backup'
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

    await drain(await exportBackup({ session, codeLabel: 'Backup' }))

    expect(exports).toEqual([
      { spaceId: ACCOUNT_SPACE },
      { spaceId: 'annex-space', clientId: 'root-client' },
      {
        spaceId: 'unlock-passphrase',
        capabilityId: 'minted-child',
        clientId: 'management-client'
      },
      {
        spaceId: 'unlock-code',
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

  it('issues no recovery code when a stored zcap cannot carry the export', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(unlockSpaceCapabilityRefusal).mockReturnValue(
      'unsupported-capability' as never
    )

    const failure = await exportBackup({
      session,
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.passphrase'
    )
    // The pre-flight runs before the pivot, so a refused run leaves no
    // orphan "Backup <date>" code behind.
    expect(vi.mocked(issueRecoveryCode)).not.toHaveBeenCalled()
    expect(exports).toEqual([])
  })

  it('refuses a ladder session holding no delegation into the named annex', async () => {
    const { session, remoteStore } = makeSession()
    const context = ladderContext({ remoteStore }) as Record<string, unknown>
    delete context.sibling
    vi.mocked(accountCeremonyContext).mockResolvedValue(context as never)

    const failure = await exportBackup({
      session,
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    // The document names an annex Space this session cannot reach, so the
    // run refuses rather than writing a bundle that reads as complete.
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.missingCapability.generic'
    )
    expect(vi.mocked(issueRecoveryCode)).not.toHaveBeenCalled()
  })

  it('refuses a sibling delegation naming a different Space than the pointer', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(delegatedClientsDelegationSpaceId).mockReturnValue('other-annex')

    const failure = await exportBackup({
      session,
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.generic'
    )
    expect(vi.mocked(issueRecoveryCode)).not.toHaveBeenCalled()
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
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    // A record sealed before the delegated-clients action set gained POST:
    // the pre-flight catches it, so no orphan code is left behind.
    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.generic'
    )
    expect(vi.mocked(issueRecoveryCode)).not.toHaveBeenCalled()
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
      codeLabel: 'Backup'
    }).catch((err: unknown) => err)

    expect(backupExportErrorKey(failure)).toBe(
      'storage.backup.errors.unsupportedCapability.generic'
    )
    expect(vi.mocked(issueRecoveryCode)).not.toHaveBeenCalled()
  })

  it('exports no annex archive when the account names none', async () => {
    const { session, exports, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(pointedClientAnnexReach).mockResolvedValue(null as never)

    await drain(await exportBackup({ session, codeLabel: 'Backup' }))

    // An account with no annex inventory is an ordinary state, so the
    // archive is skipped rather than refused.
    expect(exports.map(entry => entry.spaceId)).toEqual([
      ACCOUNT_SPACE,
      'unlock-passphrase',
      'unlock-code'
    ])
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
      codeLabel: 'Backup'
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
    // The archive is one entry ahead of the pin: this run's own code
    // issuance appended it.
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
      await drain(await exportBackup({ session, codeLabel: 'Backup' }))
    ).toBeGreaterThan(0)
  })

  it('never logs the recovery code', async () => {
    const { session, remoteStore } = makeSession()
    vi.mocked(accountCeremonyContext).mockResolvedValue(
      ladderContext({ remoteStore }) as never
    )
    vi.mocked(issueRecoveryCode).mockResolvedValue({
      entry: { unlockSpaceId: 'unlock-code' },
      registry: { methods: codeEntryOnly() }
    } as never)
    vi.mocked(getUnlockMethods).mockResolvedValue({
      methods: codeEntryOnly()
    } as never)
    const capture = captureSink()
    const removeSink = addSink(capture.sink)
    try {
      await drain(
        await exportBackup({
          session,
          codeLabel: 'Backup',
          exportPassphrase: 'an-export-password'
        })
      )
    } finally {
      removeSink()
    }

    const logged = JSON.stringify(capture.events)
    expect(logged).not.toContain('test-recovery-code-abcdef')
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
