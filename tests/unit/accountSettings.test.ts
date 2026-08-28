// @vitest-environment node
/**
 * Unit tests for the account-settings orchestrators
 * (`src/session/accountSettings.ts`): the account-deletion phase order (verify
 * the passphrase, wipe the data, retire the keyring) and its refusals, and the
 * passphrase change adopting the rebind into the live session. Every durable
 * seam is mocked; only the ordering is under test.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { base64urlnopad } from '@scure/base'

const state = vi.hoisted(() => ({
  calls: [] as string[],
  verifyFails: null as 'wrong' | 'other' | null,
  wipeFails: false,
  // What the credential-rotation ceremony reports back: a rotation with a
  // fresh key, a skip (nothing standing to retire), or a failure.
  rotation: 'skipped' as 'rotated' | 'skipped' | 'failed',
  // The deletion's (a2)/(b0)/(b1) seams: the registry snapshot, the account
  // document the annex is discovered through, and the auxiliary Space's
  // collection listing.
  registry: null as unknown,
  registryFails: false,
  accountDoc: { id: 'did:webvh:account' } as unknown,
  accountLogFails: false,
  clientAnnexCollections: [] as string[],
  clientAnnexDeleteFails: false,
  artifactFailures: [] as string[],
  // What the shared wipe enumeration reports back to `deleteAccount`.
  localWipeFailed: [] as string[],
  localWipeUnverified: [] as string[],
  // Whether the session resolves an enrolled-client context at all: a session
  // that cannot run a retirement never reads the registry.
  enrolled: true,
  // The key-agreement multibases the typed passphrases derive. The old one
  // matches `registryWithPassphraseStanding`'s entry unless a test says
  // otherwise (a mismatch is a pending retirement).
  newKeyAgreementKeyMultibase: 'z6LSNewPassphraseKak',
  oldKeyAgreementKeyMultibase: 'z6LSOldPassphraseKak',
  // Whether the account document still lists the typed OLD credential -- what
  // the bare-entry guard consults when the registry names no inventory.
  oldCredentialInDocument: false,
  // The old record's ladder seed, as the read-only verification (and, on the
  // no-context arm, the rebind) hands it back (absent unless a test says
  // otherwise).
  oldLadderSeed: undefined as Uint8Array | undefined,
  // Whether the standing establishment succeeds. When it does not, the
  // establishment REJECTS (fatal both places: the change fails with the old
  // credential untouched, the passkey add runs its cleanup and fails).
  standingEstablished: true,
  // The passkey-add cleanup's verify-then-act seams: the re-fetched record
  // (null = absent or plain), whether the re-fetch itself fails, whether the
  // account document lists the passkey credential's verbatim keyAgreement
  // entry, and the roster read's descriptor (null = no roster/wrap).
  refetchedRecord: null as unknown,
  refetchFails: false,
  passkeyCredentialInDocument: false,
  rosterRead: null as unknown,
  // The options the WebAuthn registration was called with.
  registerPasskeyOptions: null as {
    userHandle?: Uint8Array
    excludeCredentialIds?: Uint8Array[]
  } | null,
  // Whether a failing retirement fires `onInventoryRemoved` first (its document
  // edit landed and it died afterwards) or not (it failed at the edit).
  inventoryRemovedBeforeFailure: false,
  // Every record handed to `putUnlockMethods`, newest last -- what the
  // read-first merge is asserted on.
  puts: [] as UnlockRecord[],
  // The unlock Space the standing establishment reports for the passphrase
  // and passkey add ceremonies.
  boundUnlockSpaceId: 'space-bound',
  // The credential id the WebAuthn registration hands back.
  passkeyCredentialId: 'Y3JlZC1uZXc'
}))

/**
 * The registry shape the assertions below read -- the stored record's own
 * members, without importing the module under mock.
 */
interface UnlockRecord {
  version: 1
  webAuthnUserId: string
  methods: {
    type: string
    unlockSpaceId?: string
    credentialId?: string
    label?: string
    [key: string]: unknown
  }[]
}

const FRESH_USER_KEY = { id: 'did:key:z6LSFreshUserKey' }
const NEW_LADDER_SEED = new Uint8Array(32).fill(7)
const OLD_LADDER_SEED = new Uint8Array(32).fill(3)

vi.mock('@/session/credentialRotation', () => ({
  rotateOffUnlockCredential: vi.fn(
    async (options: { onInventoryRemoved?: () => void }) => {
      state.calls.push('rotateOffUnlockCredential')
      if (state.rotation === 'failed') {
        if (state.inventoryRemovedBeforeFailure) {
          options.onInventoryRemoved?.()
        }
        throw new Error('log conflict')
      }
      // The real ceremony fires this once its document edit has landed.
      options.onInventoryRemoved?.()
      return state.rotation === 'rotated'
        ? {
            rotated: true,
            collections: { outcomes: {}, failed: [] },
            userKey: FRESH_USER_KEY
          }
        : { rotated: false, collections: { outcomes: {}, failed: [] } }
    }
  )
}))

vi.mock('@/session/userKeyAdoption', () => ({
  adoptRotatedUserKey: vi.fn(async () => {
    state.calls.push('adoptRotatedUserKey')
  })
}))

vi.mock('@/session/standingUnlock', () => ({
  establishStandingUnlock: vi.fn(
    async ({
      secret,
      credential,
      ladderSeed
    }: {
      secret: string | Uint8Array
      credential?: unknown
      ladderSeed?: Uint8Array
    }) => {
      state.calls.push('establishStandingUnlock')
      if (!state.standingEstablished) {
        throw new Error('establishment failed')
      }
      // The passkey add hands the PRF output bytes; the passphrase change
      // hands a string plus its pre-derived credential; the add-a-passphrase
      // ceremony hands the string alone.
      if (typeof secret === 'string' && !credential) {
        return {
          unlockSpaceId: state.boundUnlockSpaceId,
          manageCapability: {
            id: 'urn:zcap:wide',
            allowedAction: ['GET', 'PUT', 'DELETE']
          },
          persistClientKeys: async () => {},
          ladderSeed: NEW_LADDER_SEED,
          standingFields: {}
        }
      }
      if (typeof secret === 'string') {
        return {
          unlockSpaceId: 'space-new',
          manageCapability: {
            id: 'urn:zcap:wide',
            allowedAction: ['GET', 'PUT', 'DELETE']
          },
          persistClientKeys: async () => {},
          ladderSeed: NEW_LADDER_SEED,
          standingFields: {
            keyAgreementKeyMultibase: state.newKeyAgreementKeyMultibase,
            updateKeyMultibase: 'z6MkNewRung0'
          }
        }
      }
      return {
        unlockSpaceId: state.boundUnlockSpaceId,
        manageCapability: {
          id: 'urn:zcap:passkey-wide',
          allowedAction: ['GET', 'PUT', 'DELETE']
        },
        persistClientKeys: async () => {},
        ladderSeed: ladderSeed ?? new Uint8Array(32),
        standingFields: {
          rosterKid: 'did:key:zPasskeyClient#z6LSPasskeyKak',
          keyAgreementKeyMultibase: 'z6LSPasskeyKak',
          updateKeyMultibase: 'z6MkPasskeyRung0',
          unlockClientDid: 'did:key:zPasskeyClient'
        }
      }
    }
  ),
  standingFieldsOfKeyringHit: vi.fn(async () => ({
    rosterKid: 'did:key:zPasskeyClient#z6LSPasskeyKak',
    keyAgreementKeyMultibase: 'z6LSPasskeyKak',
    updateKeyMultibase: 'z6MkPasskeyRung0',
    unlockClientDid: 'did:key:zPasskeyClient'
  }))
}))

vi.mock('@/lib/passkey', () => ({
  assertPasskeyPrf: vi.fn(async () => ({ prfOutput: new Uint8Array(32) })),
  registerPasskey: vi.fn(
    async (options: {
      userHandle?: Uint8Array
      excludeCredentialIds?: Uint8Array[]
    }) => {
      state.calls.push('registerPasskey')
      state.registerPasskeyOptions = options
      return {
        credentialId: base64urlnopad.decode(state.passkeyCredentialId),
        transports: ['internal'],
        prfOutput: new Uint8Array(32).fill(5),
        backupEligibility: true,
        backupState: true
      }
    }
  )
}))

vi.mock('@/session/rosterStore', () => ({
  sessionRosterStore: vi.fn(() => ({
    read: vi.fn(async () => state.rosterRead)
  }))
}))

class FakeWrongPassphraseError extends Error {}

vi.mock('@/session/keyring', () => ({
  WrongPassphraseError: FakeWrongPassphraseError,
  verifyPassphrase: vi.fn(async () => {
    state.calls.push('verifyPassphrase')
    if (state.verifyFails === 'wrong') {
      throw new FakeWrongPassphraseError('nope')
    }
    if (state.verifyFails === 'other') {
      throw new Error('remote unreachable')
    }
    // A standing record's ladder seed rides the verification, so the change
    // ceremony's read-only verify hands the retirement its attribution seed.
    return state.oldLadderSeed ? { ladderSeed: state.oldLadderSeed } : {}
  }),
  deleteKeyring: vi.fn(async () => {
    state.calls.push('deleteKeyring')
    return { unlockSpaceDeleted: true }
  }),
  changePassphrase: vi.fn(async () => {
    state.calls.push('changePassphrase')
    return {
      oldPassphraseRetired: true,
      unlockSpaceId: 'space-new',
      manageCapability: {
        id: 'urn:zcap:narrow',
        allowedAction: ['GET', 'DELETE']
      },
      persistClientKeys: async () => {},
      ...(state.oldLadderSeed ? { oldLadderSeed: state.oldLadderSeed } : {})
    }
  }),
  bindPassphrase: vi.fn(async () => ({ unlockSpaceId: 'space-bound' })),
  bindUnlockSecret: vi.fn(async () => ({ unlockSpaceId: 'space-bound' })),
  fetchKeyring: vi.fn(async () => {
    state.calls.push('fetchKeyring')
    if (state.refetchFails) {
      throw new Error('unlock record unreachable')
    }
    return state.refetchedRecord
  }),
  deleteUnlockMethod: vi.fn(async () => {
    state.calls.push('deleteUnlockMethod')
    return { unlockSpaceDeleted: true }
  }),
  deriveUnlockCredential: vi.fn(
    async ({ secret }: { secret: string | Uint8Array }) => {
      if (typeof secret !== 'string') {
        // The passkey add's PRF-output credential.
        return {
          unlock: { secret, spaceId: state.boundUnlockSpaceId },
          standing: {
            keyAgreementKeyMultibase: 'z6LSPasskeyKak',
            recipientKid: 'did:key:zPasskeyClient#z6LSPasskeyKak',
            clientDid: 'did:key:zPasskeyClient'
          }
        }
      }
      return {
        unlock: { secret, spaceId: `space-unlock-${secret}` },
        standing: {
          keyAgreementKeyMultibase:
            secret === 'old'
              ? state.oldKeyAgreementKeyMultibase
              : state.newKeyAgreementKeyMultibase,
          recipientKid:
            secret === 'old'
              ? 'did:key:zOldPassphraseClient#z6LSOldPassphraseKak'
              : 'did:key:zNewPassphraseClient#z6LSNewPassphraseKak',
          clientDid:
            secret === 'old'
              ? 'did:key:zOldPassphraseClient'
              : 'did:key:zNewPassphraseClient'
        }
      }
    }
  ),
  unlockKeyAgreementMembers: vi.fn(
    ({ unlock }: { unlock: { secret?: string } }) =>
      unlock.secret === 'old'
        ? {
            unlockKeyAgreementKeyId: 'did:key:zOldUnlock#z6LSOldUnlockKak',
            unlockKeyAgreementKeyMultibase: 'z6LSOldUnlockKak'
          }
        : {}
  ),
  unlockManagementGrantee: vi.fn(() => 'did:key:grantee')
}))

vi.mock('@/session/unlockMethods', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@/session/unlockMethods')>()
  return {
    // The merge helpers are pure and are exactly what the read-first writes
    // are built on, so the real ones run here; only the durable seams are
    // faked. The passphrase upsert stays a spy over the real implementation,
    // since tests assert what the ceremonies hand it.
    ...actual,
    upsertPassphraseUnlockMethod: vi.fn(actual.upsertPassphraseUnlockMethod),
    adoptPassphraseRebind: vi.fn(() => {
      state.calls.push('adoptPassphraseRebind')
    }),
    backfillPassphraseUnlockMethod: vi.fn(async () => null),
    canRevokeWithoutCeremony: vi.fn(() => true),
    emptyUnlockMethodsRegistry: vi.fn(() => ({
      version: 1,
      webAuthnUserId: 'MINTEDHANDLEMINTEDHAAA',
      methods: []
    })),
    deleteUnlockMethodArtifacts: vi.fn(
      async ({ entry }: { entry: { type: string } }) => {
        state.calls.push(`deleteUnlockMethodArtifacts:${entry.type}`)
        if (state.artifactFailures.includes(entry.type)) {
          throw new Error(`could not delete the ${entry.type} artifacts`)
        }
      }
    ),
    getUnlockMethods: vi.fn(async () => {
      if (state.registryFails) {
        throw new Error('registry unreadable')
      }
      return state.registry
    }),
    updateUnlockMethods: vi.fn(
      async ({
        mutate
      }: {
        mutate: (
          current: UnlockRecord | null
        ) => UnlockRecord | null | Promise<UnlockRecord | null>
      }) => {
        if (state.registryFails) {
          throw new Error('registry unreadable')
        }
        const current = state.registry as UnlockRecord | null
        const next = await mutate(current)
        if (next === null) {
          return current
        }
        state.calls.push('putUnlockMethods')
        state.puts.push(next)
        // Persist: a ceremony that writes twice (the passkey add's bare
        // entry then its completion or drop) reads its own first write back.
        state.registry = next
        return next
      }
    ),
    refreshStandingDelegationFields: vi.fn(async () => {}),
    revokeUnlockMethod: vi.fn(async () => {
      state.calls.push('revokeUnlockMethod')
      return state.rotation === 'rotated'
        ? {
            rotated: true,
            collections: { outcomes: {}, failed: [] },
            userKey: FRESH_USER_KEY
          }
        : null
    }),
    revokeUnlockMethodByCeremony: vi.fn(async () => {
      state.calls.push('revokeUnlockMethodByCeremony')
      return state.rotation === 'rotated'
        ? {
            rotated: true,
            collections: { outcomes: {}, failed: [] },
            userKey: FRESH_USER_KEY
          }
        : null
    })
  }
})

vi.mock('@/lib/sessionKey', () => ({
  deletePasskeySafetyNotice: vi.fn(async () => {
    state.calls.push('deletePasskeySafetyNotice')
  }),
  deleteUserKeyEpochPin: vi.fn(async () => {
    state.calls.push('deleteUserKeyEpochPin')
  }),
  deleteLogPin: vi.fn(async ({ logId }: { logId: string }) => {
    state.calls.push(`deleteLogPin:${logId}`)
  }),
  deleteAccountDidForSpace: vi.fn(async () => {
    state.calls.push('deleteAccountDidForSpace')
  }),
  saveUserKeyEpochPin: vi.fn(async () => {}),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  rotateWebvhUpdateKey: vi.fn(async () => {})
}))

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(),
  verifiedAccountLog: vi.fn(async () => {
    if (state.accountLogFails) {
      throw new Error('account log unreachable')
    }
    return { doc: state.accountDoc }
  })
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  // The auxiliary annex Space handle: its `gen-` collection listing (the
  // pin slots to drop) and the one recursive delete.
  WasClient: class {
    space(spaceId: string) {
      return {
        collectionsPages: async function* () {
          yield {
            items: state.clientAnnexCollections.map(id => ({ id }))
          }
        },
        delete: async () => {
          state.calls.push(`clientAnnexSpaceDelete:${spaceId}`)
          if (state.clientAnnexDeleteFails) {
            throw new Error('auxiliary Space delete failed')
          }
        }
      }
    }
  }
}))

vi.mock('@/lib/loginCredential', () => ({
  findLoginCredential: vi.fn(() => null),
  loginHandleOf: vi.fn(() => '')
}))

vi.mock('@/session/pendingRetirement', () => ({
  documentListsCredential: vi.fn(
    async ({ published }: { published?: 'commitment' | 'verbatim' }) =>
      // The verbatim form is the passkey cleanup's published-check; the
      // commitment form is the passphrase change's bare-entry guard.
      published === 'verbatim'
        ? state.passkeyCredentialInDocument
        : state.oldCredentialInDocument
  )
}))

vi.mock('@/session/enrolledContext', () => ({
  enrolledClientContext: vi.fn(() =>
    state.enrolled
      ? {
          controller: 'did:key:zAccount',
          pointer: {
            did: 'did:webvh:account',
            spaceId: 'space-123',
            host: 'https://was.example.test'
          }
        }
      : null
  ),
  requireEnrolledClientContext: vi.fn(() => ({
    controller: 'did:key:zAccount'
  }))
}))

vi.mock('@/session/wipe', () => ({
  snapshotWipeTargets: vi.fn(
    ({
      session,
      registry
    }: {
      session: { user: { id: string } }
      registry?: { methods?: { unlockSpaceId: string }[] } | null
    }) => {
      state.calls.push('snapshotWipeTargets')
      return {
        clientDid: session.user.id,
        dbPrefix: 'db-prefix',
        unlockSpaceIds: (registry?.methods ?? []).map(
          entry => entry.unlockSpaceId
        ),
        cacheScopes: []
      }
    }
  ),
  executeLocalWipe: vi.fn(async () => {
    state.calls.push('executeLocalWipe')
    return {
      failed: state.localWipeFailed,
      unverified: state.localWipeUnverified
    }
  })
}))

const {
  addAccountPasskey,
  addAccountPassphrase,
  changeAccountPassphrase,
  deleteAccount,
  removeAccountPasskey,
  renameAccountPasskey,
  PasskeyNotEstablishedError,
  PendingPassphraseRetirementError,
  SamePassphraseError
} = await import('@/session/accountSettings')
const { rotateOffUnlockCredential } =
  await import('@/session/credentialRotation')
const { adoptRotatedUserKey } = await import('@/session/userKeyAdoption')
const {
  revokeUnlockMethod,
  revokeUnlockMethodByCeremony,
  canRevokeWithoutCeremony
} = await import('@/session/unlockMethods')
const {
  deleteUnlockMethodArtifacts,
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  updateUnlockMethods,
  upsertPassphraseUnlockMethod
} = await import('@/session/unlockMethods')
const { deleteUnlockMethod } = await import('@/session/keyring')
const { establishStandingUnlock } = await import('@/session/standingUnlock')
const { registerPasskey } = await import('@/lib/passkey')
const { executeLocalWipe, snapshotWipeTargets } = await import('@/session/wipe')
const { browserLocalSessionPersistence } = await import('@/session/persistence')

const ACCOUNT_DID = 'did:webvh:QmScid:was.example.test:space:space-123:id'
const CLIENT_ANNEX_SPACE_ID = 'clientAnnex-space-1'
const GENERATION_ID = 'gen-Ux3v0kQf9aPmB2hZ'
const CLIENT_ANNEX_DID =
  'did:webvh:QmClientAnnexScid:was.example.test:space:' +
  `${CLIENT_ANNEX_SPACE_ID}:${GENERATION_ID}`

/**
 * An account document whose `#DelegatedClients` service entry points at the
 * annex above -- what the deletion's discovery step reads.
 *
 * @returns {object}
 */
function docWithClientAnnexPointer(): object {
  return {
    id: ACCOUNT_DID,
    service: [
      {
        id: `${ACCOUNT_DID}#delegated-clients`,
        type: 'https://w3id.org/byoe#DelegatedClients',
        serviceEndpoint: CLIENT_ANNEX_DID
      }
    ]
  }
}

/**
 * Two registry entries, so the walk's per-entry best-effort is observable.
 *
 * @returns {object}
 */
function registryWithTwoMethods(): object {
  return {
    version: 1,
    webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-passphrase'
      },
      {
        type: 'passkey',
        label: 'Passkey',
        createdAt: '2026-08-02T00:00:00.000Z',
        credentialId: 'Y3JlZC1pZA',
        transports: ['internal'],
        backupEligibility: true,
        backupState: true,
        unlockSpaceId: 'unlock-space-passkey'
      }
    ]
  }
}

/**
 * A registry whose passphrase entry records a standing configuration -- the
 * multibases the retirement must hold before the rebind overwrites them.
 *
 * @param options {object}
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {object}
 */
function registryWithPassphraseStanding({
  keyAgreementKeyMultibase
}: {
  keyAgreementKeyMultibase: string
}): object {
  return {
    version: 1,
    webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-passphrase',
        keyAgreementKeyMultibase,
        updateKeyMultibase: 'z6MkOldPassphraseUpdateKey',
        unlockClientDid: 'did:key:zOldPassphraseClient',
        rosterKid: 'did:key:zOldPassphraseClient#z6LSOldPassphraseKak'
      }
    ]
  }
}

function makeSession() {
  return {
    user: { id: 'did:key:zClient' },
    isGuest: false,
    profile: {
      persistence: {
        ...browserLocalSessionPersistence(),
        // The add ceremonies clear the passkey-only safety notice; the store
        // itself reaches IndexedDB, which this node-environment suite has
        // none of.
        passkeyNotices: { delete: vi.fn(async () => {}) }
      },
      clientSeed: new Uint8Array(32),
      accountController: 'did:key:zAccount',
      accountPointer: {
        did: 'did:webvh:QmScid:was.example.test:space:space-123:id',
        spaceId: 'space-123',
        host: 'https://was.example.test'
      }
    },
    storage: {
      wipeRemoteStorage: vi.fn(async () => {
        state.calls.push('wipeRemoteStorage')
        if (state.wipeFails) {
          throw new Error('wipe failed')
        }
      })
    }
    // The orchestrators read a small, stable slice of the session.
  } as unknown as Parameters<typeof deleteAccount>[0]['session']
}

beforeEach(() => {
  state.calls = []
  state.verifyFails = null
  state.wipeFails = false
  state.rotation = 'skipped'
  state.registry = null
  state.registryFails = false
  state.accountDoc = { id: ACCOUNT_DID }
  state.accountLogFails = false
  state.clientAnnexCollections = []
  state.clientAnnexDeleteFails = false
  state.artifactFailures = []
  state.localWipeFailed = []
  state.localWipeUnverified = []
  state.enrolled = true
  state.newKeyAgreementKeyMultibase = 'z6LSNewPassphraseKak'
  state.oldKeyAgreementKeyMultibase = 'z6LSOldPassphraseKak'
  state.oldCredentialInDocument = false
  state.oldLadderSeed = undefined
  state.standingEstablished = true
  state.refetchedRecord = null
  state.refetchFails = false
  state.passkeyCredentialInDocument = false
  state.rosterRead = null
  state.registerPasskeyOptions = null
  state.inventoryRemovedBeforeFailure = false
  state.puts = []
  state.boundUnlockSpaceId = 'space-bound'
  state.passkeyCredentialId = 'Y3JlZC1uZXc'
  vi.clearAllMocks()
})

describe('deleteAccount', () => {
  it('verifies the passphrase, wipes the data, and only then retires the keyring', async () => {
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    // The remote wipe is fatal-first; the local half (every pin, cache, trio,
    // and replica) is one call into the shared wipe enumeration, over targets
    // snapshotted before anything was deleted.
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'snapshotWipeTargets',
      'wipeRemoteStorage',
      'deleteKeyring',
      'executeLocalWipe'
    ])
    expect(vi.mocked(executeLocalWipe)).toHaveBeenCalledWith(
      expect.objectContaining({
        targets: expect.objectContaining({ clientDid: 'did:key:zClient' })
      })
    )
  })

  it('refuses a wrong passphrase without touching any data', async () => {
    state.verifyFails = 'wrong'
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'wrong'
    })
    expect(result).toBe('wrong-passphrase')
    expect(state.calls).toEqual(['verifyPassphrase'])
  })

  it('reports a verification failure as a generic failure, data untouched', async () => {
    state.verifyFails = 'other'
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('failed')
    expect(state.calls).toEqual(['verifyPassphrase'])
  })

  it("deletes every unlock method's artifacts before the wipe", async () => {
    state.registry = registryWithTwoMethods()
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenCalledTimes(2)
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        entry: expect.objectContaining({ type: 'passphrase' })
      })
    )
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        entry: expect.objectContaining({ type: 'passkey' })
      })
    )
    // The dangling existence-oracle Spaces go before the fatal wipe, and the
    // registry snapshot reaches the enumeration (every method's local trio).
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'deleteUnlockMethodArtifacts:passphrase',
      'deleteUnlockMethodArtifacts:passkey',
      'snapshotWipeTargets',
      'wipeRemoteStorage',
      'deleteKeyring',
      'executeLocalWipe'
    ])
    expect(vi.mocked(snapshotWipeTargets)).toHaveBeenCalledWith(
      expect.objectContaining({
        registry: expect.objectContaining({
          methods: expect.arrayContaining([
            expect.objectContaining({ unlockSpaceId: 'unlock-space-passkey' })
          ])
        })
      })
    )
  })

  it('walks past an entry whose artifacts cannot be deleted', async () => {
    state.registry = registryWithTwoMethods()
    state.artifactFailures = ['passphrase']
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    // One entry failing stops neither the next entry nor the deletion.
    expect(result).toBe('deleted')
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenCalledTimes(2)
    expect(state.calls).toContain('deleteUnlockMethodArtifacts:passkey')
    expect(state.calls).toContain('wipeRemoteStorage')
    warn.mockRestore()
  })

  it('tears the auxiliary Space down before the wipe', async () => {
    state.accountDoc = docWithClientAnnexPointer()
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    // Before the wipe: once the account Space is gone the server can no
    // longer resolve the auxiliary Space's did:webvh controller.
    expect(state.calls).toEqual([
      'verifyPassphrase',
      `clientAnnexSpaceDelete:${CLIENT_ANNEX_SPACE_ID}`,
      'snapshotWipeTargets',
      'wipeRemoteStorage',
      'deleteKeyring',
      'executeLocalWipe'
    ])
  })

  it('deletes the account even when the discovery steps fail', async () => {
    state.registryFails = true
    state.accountLogFails = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    // Warn-only: an unreadable registry or log narrows the teardown.
    expect(result).toBe('deleted')
    expect(vi.mocked(deleteUnlockMethodArtifacts)).not.toHaveBeenCalled()
    expect(state.calls).toContain('wipeRemoteStorage')
    // The failed read reaches the wipe snapshot, which still enumerates the
    // session's own unlock Space and reports the narrowing.
    expect(vi.mocked(snapshotWipeTargets).mock.calls[0]![0]).toMatchObject({
      registry: null,
      registryUnread: true
    })
    warn.mockRestore()
  })

  it('survives a failing auxiliary-Space delete, leaving a typed orphan', async () => {
    state.accountDoc = docWithClientAnnexPointer()
    state.clientAnnexDeleteFails = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    expect(state.calls).toContain('wipeRemoteStorage')
    // The wipe still runs: a failed auxiliary-Space delete leaves an orphan
    // Space, not an unwiped browser.
    expect(state.calls).toContain('executeLocalWipe')
    warn.mockRestore()
  })

  it('keeps the keyring when the remote wipe fails, so the Space is never orphaned', async () => {
    state.wipeFails = true
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('failed')
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'snapshotWipeTargets',
      'wipeRemoteStorage'
    ])
  })

  it('reports failure when the enumeration could not delete the replica', async () => {
    state.localWipeFailed = ['replica']
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    // The local data is still there, so the caller must not log out; any
    // other stage failure is hygiene residue and stays 'deleted'.
    expect(result).toBe('failed')
    expect(state.calls).toContain('executeLocalWipe')
  })

  it('reports the deletion unconfirmed when the replica wipe could not be verified', async () => {
    state.localWipeUnverified = ['replica']
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    // The account really is deleted, so this is not 'failed'; the local
    // replica delete simply could not be confirmed on this browser.
    expect(result).toBe('deleted-unverified')
  })

  it('treats a non-replica stage failure as hygiene residue', async () => {
    state.localWipeFailed = ['unlock-methods-cache']
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
  })

  it('threads the Storage Access factory through every local delete', async () => {
    // A session begun from the CHAPI popup carries the unpartitioned
    // factory; the registry walk, the keyring retirement, and the
    // enumeration must all land in that bucket, not the partitioned global.
    const idb = { sentinel: true } as unknown as IDBFactory
    state.registry = registryWithTwoMethods()
    const session = makeSession()
    ;(session.profile as unknown as { persistence: unknown }).persistence =
      browserLocalSessionPersistence({ idb })
    const result = await deleteAccount({
      session,
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenCalledWith(
      expect.objectContaining({ idb })
    )
    expect(vi.mocked(executeLocalWipe)).toHaveBeenCalledWith(
      expect.objectContaining({ idb })
    )
  })
})

describe('changeAccountPassphrase', () => {
  it('establishes the new passphrase standing before touching the old one', async () => {
    const { oldPassphraseRetired, unlockSpaceId, rotation } =
      await changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'new'
      })
    expect(oldPassphraseRetired).toBe(true)
    expect(unlockSpaceId).toBe('space-new')
    expect(rotation).toBe('skipped')
    // Establish-first: the old passphrase is verified read-only, the new one
    // gets its whole standing configuration, and only then is the old unlock
    // identity torn down and the old credential retired -- so the account is
    // never left with no standing credential.
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'establishStandingUnlock',
      'adoptPassphraseRebind',
      'deleteKeyring',
      'rotateOffUnlockCredential'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({ type: 'passphrase' }),
        verb: 'changing the passphrase',
        survivingLadderSeed: NEW_LADDER_SEED
      })
    )
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })

  it('adopts the rotated user key when the retirement rotated', async () => {
    state.rotation = 'rotated'
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('rotated')
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'establishStandingUnlock',
      'adoptPassphraseRebind',
      'deleteKeyring',
      'rotateOffUnlockCredential',
      'adoptRotatedUserKey'
    ])
    expect(vi.mocked(adoptRotatedUserKey)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: 'space-123',
        userKey: FRESH_USER_KEY
      })
    )
  })

  it('reports a failed retirement without failing the change', async () => {
    state.rotation = 'failed'
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { oldPassphraseRetired, rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // The passphrase change itself has landed and cannot roll back.
    expect(oldPassphraseRetired).toBe(true)
    expect(rotation).toBe('failed')
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
    error.mockRestore()
  })

  it('refuses the change when the old standing configuration cannot be read', async () => {
    state.registryFails = true
    await expect(
      changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'new'
      })
    ).rejects.toThrow('the passphrase was not changed')
    // Nothing was written: the rebind would have replaced the registry entry
    // with the new passphrase's multibases, leaving the old credential
    // standing with nothing left to name it by.
    expect(state.calls).toEqual([])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('reads the old standing configuration before any write and retires by it', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('skipped')
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'establishStandingUnlock',
      'adoptPassphraseRebind',
      'deleteKeyring',
      'rotateOffUnlockCredential',
      'putUnlockMethods'
    ])
    // The read is the first thing that happens, ahead of the establishment.
    expect(
      vi.mocked(getUnlockMethods).mock.invocationCallOrder[0]
    ).toBeLessThan(
      vi.mocked(establishStandingUnlock).mock.invocationCallOrder[0]
    )
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({
          type: 'passphrase',
          keyAgreementKeyMultibase: 'z6LSOldPassphraseKak',
          updateKeyMultibase: 'z6MkOldPassphraseUpdateKey'
        })
      })
    )
  })

  it('writes the registry entry only after the retirement', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    const { registry } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // The entry can only be written once the retirement has reported: what
    // standing configuration it must name depends on how the retirement ended.
    expect(
      vi.mocked(rotateOffUnlockCredential).mock.invocationCallOrder[0]
    ).toBeLessThan(vi.mocked(updateUnlockMethods).mock.invocationCallOrder[0])
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        unlockSpaceId: 'space-new',
        keepAbsentManageCapability: true,
        standing: {
          keyAgreementKeyMultibase: 'z6LSNewPassphraseKak',
          updateKeyMultibase: 'z6MkNewRung0'
        }
      })
    )
    expect(registry).not.toBeNull()
  })

  it("records the standing establishment's wide management zcap, not the bind's", async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // The bind mints GET/DELETE; the establishment re-mints with PUT, which
    // the revocation cascade's record re-PUT needs.
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        unlockSpaceId: 'space-new',
        manageCapability: expect.objectContaining({ id: 'urn:zcap:wide' })
      })
    )
  })

  it('records the OLD standing configuration when the retirement failed at its edit', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    state.rotation = 'failed'
    state.inventoryRemovedBeforeFailure = false
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('failed')
    // The old credential is still standing, so the entry keeps naming it --
    // under the NEW unlock Space, which is what the login-time completer
    // detects.
    // The WHOLE standing set is restated, not just the two multibases: an
    // entry that lost `unlockClientDid` would drop out of every delegation
    // re-mint pass while it stands pending.
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        unlockSpaceId: 'space-new',
        standing: {
          keyAgreementKeyMultibase: 'z6LSOldPassphraseKak',
          updateKeyMultibase: 'z6MkOldPassphraseUpdateKey',
          unlockClientDid: 'did:key:zOldPassphraseClient',
          rosterKid: 'did:key:zOldPassphraseClient#z6LSOldPassphraseKak'
        }
      })
    )
    error.mockRestore()
  })

  it('records the new standing configuration when the retirement failed after its edit', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    state.rotation = 'failed'
    state.inventoryRemovedBeforeFailure = true
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('failed')
    // The old credential's document inventory is already gone, so any login's
    // completion sweep finishes the roster rotation and the cascade.
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        standing: {
          keyAgreementKeyMultibase: 'z6LSNewPassphraseKak',
          updateKeyMultibase: 'z6MkNewRung0'
        }
      })
    )
    error.mockRestore()
  })

  it('treats a registry that resolves to null as nothing to retire', async () => {
    state.registry = null
    await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // No standing configuration recorded is not a refusal: the ceremony runs, and the
    // retirement is handed a method carrying no multibases.
    expect(vi.mocked(getUnlockMethods)).toHaveBeenCalled()
    expect(state.calls).toContain('rotateOffUnlockCredential')
    const [call] = vi.mocked(rotateOffUnlockCredential).mock.calls
    expect(call[0].method).toEqual({ type: 'passphrase' })
  })

  it('refuses a new passphrase deriving the same credential as the old', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSSameKak'
    })
    state.oldKeyAgreementKeyMultibase = 'z6LSSameKak'
    state.newKeyAgreementKeyMultibase = 'z6LSSameKak'
    await expect(
      changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'derives-the-same'
      })
    ).rejects.toThrow(expect.objectContaining({ name: 'SamePassphraseError' }))
    // Neither outcome is a change: retiring would strip the standing configuration the
    // establishment just re-published, and skipping the retirement would
    // orphan the old ladder's committed rung.
    expect(state.calls).toEqual([])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('refuses a change over an entry naming another credential', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSSomeEarlierKak'
    })
    await expect(
      changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'new'
      })
    ).rejects.toThrow(PendingPassphraseRetirementError)
    // An earlier change's retirement never finished: this run would be
    // handed that credential's standing configuration beside the record's own ladder seed.
    expect(state.calls).toEqual([])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('refuses a same-string change before anything is written', async () => {
    // The plain case, caught without needing a recorded inventory at all.
    await expect(
      changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'same',
        newPassphrase: 'same'
      })
    ).rejects.toThrow(SamePassphraseError)
    expect(state.calls).toEqual([])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('refuses to report clean when a bare entry hides a standing credential', async () => {
    // The registry names no inventory at all, but the typed old credential's
    // commitment is right there in the account document: nothing would name
    // it after this change, so the outcome is not clean.
    state.registry = { version: 1, webAuthnUserId: 'AAAA', methods: [] }
    state.oldCredentialInDocument = true
    state.oldLadderSeed = OLD_LADDER_SEED
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('unretired')
    // There is nothing to retire BY: the retirement names its subject through
    // the entry's members, and the entry has none.
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    // The entry is rebuilt in the shape the login-time repair detects: the
    // NEW unlock Space naming the OLD credential's members.
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        unlockSpaceId: 'space-new',
        standing: {
          rosterKid: 'did:key:zOldPassphraseClient#z6LSOldPassphraseKak',
          keyAgreementKeyMultibase: 'z6LSOldPassphraseKak',
          unlockClientDid: 'did:key:zOldPassphraseClient',
          updateKeyMultibase: expect.stringMatching(/^z/),
          unlockKeyAgreementKeyId: 'did:key:zOldUnlock#z6LSOldUnlockKak',
          unlockKeyAgreementKeyMultibase: 'z6LSOldUnlockKak'
        }
      })
    )
    warn.mockRestore()
  })

  it('fails the change with the old credential untouched when the establishment fails', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    state.standingEstablished = false
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    await expect(
      changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'new'
      })
    ).rejects.toThrow('the passphrase was not changed')
    // Establish-first: the failure lands before the old unlock identity or
    // its standing configuration is touched, so "not changed" is true --
    // the old record, its Space, and its registry entry all stand.
    expect(state.calls).toEqual(['verifyPassphrase', 'establishStandingUnlock'])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(upsertPassphraseUnlockMethod)).not.toHaveBeenCalled()
    error.mockRestore()
  })

  it('refuses a wrong old passphrase before the establishment runs', async () => {
    state.verifyFails = 'wrong'
    await expect(
      changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'wrong-old',
        newPassphrase: 'new'
      })
    ).rejects.toThrow(FakeWrongPassphraseError)
    expect(state.calls).toEqual(['verifyPassphrase'])
    expect(vi.mocked(upsertPassphraseUnlockMethod)).not.toHaveBeenCalled()
  })

  it('a retry of the same change converges after a failed establishment', async () => {
    // First run: the establishment fails; nothing about either credential
    // was written durably beside the establishment's own idempotent stages.
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    state.standingEstablished = false
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    await expect(
      changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'new'
      })
    ).rejects.toThrow('the passphrase was not changed')
    error.mockRestore()
    // The retry types the same passphrases: the old one still verifies (its
    // record was never deleted), the registry still names it, and the
    // retirement completes this time.
    state.standingEstablished = true
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('skipped')
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({
          type: 'passphrase',
          keyAgreementKeyMultibase: 'z6LSOldPassphraseKak',
          updateKeyMultibase: 'z6MkOldPassphraseUpdateKey'
        })
      })
    )
  })

  it('mints a registry for the rebuilt bare shape when none was written', async () => {
    // A registry absent at the start has no entry for the deferred write to
    // update, so the one state that needs a durable name for the old
    // credential mints the record rather than no-oping.
    state.registry = null
    state.oldCredentialInDocument = true
    state.oldLadderSeed = OLD_LADDER_SEED
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { rotation, registry } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('unretired')
    expect(registry).not.toBeNull()
    expect(lastPut()).toEqual(registry)
    expect(
      (registry as unknown as UnlockRecord).methods.find(
        method => method.type === 'passphrase'
      )
    ).toEqual(
      expect.objectContaining({
        unlockSpaceId: 'space-new',
        keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
      })
    )
    warn.mockRestore()
  })

  it('keeps an absent registry absent on every other path', async () => {
    // The mint is the rebuilt bare shape's alone: an ordinary change over an
    // absent registry still writes nothing.
    state.registry = null
    const { rotation, registry } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('skipped')
    expect(registry).toBeNull()
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('reports a bare entry whose credential is not in the document as skipped', async () => {
    state.registry = { version: 1, webAuthnUserId: 'AAAA', methods: [] }
    state.oldCredentialInDocument = false
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // Nothing standing, nothing to retire: the ordinary skip.
    expect(rotation).toBe('skipped')
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalled()
  })

  it('does not report clean when the document cannot be read for a bare entry', async () => {
    state.registry = { version: 1, webAuthnUserId: 'AAAA', methods: [] }
    state.accountLogFails = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // Unknown is treated exactly like standing: the change lands, the outcome
    // is not clean.
    expect(rotation).toBe('unretired')
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('does not read the old standing configuration when the session cannot retire at all', async () => {
    state.enrolled = false
    state.registryFails = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { rotation, registry } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // No WAS, a guest, or an unpromoted account: there is no standing configuration to
    // read, so an unreadable registry cannot refuse the change. The one read
    // left is the entry write's own, which is best-effort.
    expect(rotation).toBe('skipped')
    expect(registry).toBeNull()
    expect(
      vi.mocked(updateUnlockMethods).mock.invocationCallOrder[0]
    ).toBeGreaterThan(
      vi.mocked(rotateOffUnlockCredential).mock.invocationCallOrder[0]
    )
    expect(state.calls).toEqual([
      'changePassphrase',
      'adoptPassphraseRebind',
      'rotateOffUnlockCredential'
    ])
    warn.mockRestore()
  })
})

describe('removeAccountPasskey', () => {
  const ENTRY = {
    type: 'passkey',
    label: 'Passkey',
    createdAt: '2026-08-01T00:00:00.000Z',
    credentialId: 'Y3JlZC1pZA',
    transports: ['internal'],
    backupEligibility: true,
    backupState: true,
    unlockSpaceId: 'unlock-space-abc'
  } as Parameters<typeof removeAccountPasskey>[0]['entry']

  it('revokes tap-free and adopts the rotated user key', async () => {
    state.rotation = 'rotated'
    await removeAccountPasskey({ session: makeSession(), entry: ENTRY })
    expect(state.calls).toEqual(['revokeUnlockMethod', 'adoptRotatedUserKey'])
    expect(vi.mocked(revokeUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({ entry: ENTRY, verb: 'removing a passkey' })
    )
    expect(vi.mocked(adoptRotatedUserKey)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: 'space-123',
        userKey: FRESH_USER_KEY
      })
    )
  })

  it('falls back to the ceremony path and skips adoption with no rotation', async () => {
    vi.mocked(canRevokeWithoutCeremony).mockReturnValueOnce(false)
    await removeAccountPasskey({ session: makeSession(), entry: ENTRY })
    expect(state.calls).toEqual(['revokeUnlockMethodByCeremony'])
    expect(vi.mocked(revokeUnlockMethodByCeremony)).toHaveBeenCalledOnce()
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })

  it('propagates a failed revocation, so a retry can converge', async () => {
    vi.mocked(revokeUnlockMethod).mockRejectedValueOnce(new Error('down'))
    await expect(
      removeAccountPasskey({ session: makeSession(), entry: ENTRY })
    ).rejects.toThrow('down')
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })
})

/**
 * A registry the page never saw: the passphrase entry it loaded plus a
 * recovery-code entry written afterwards by another client. The read-first
 * merge must carry the second one forward.
 *
 * @returns {UnlockRecord}
 */
function registryWithConcurrentEntry(): UnlockRecord {
  return {
    version: 1,
    webAuthnUserId: 'FRESHHANDLEFRESHHANDAA',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-passphrase'
      },
      {
        type: 'recovery-code',
        label: 'Recovery code',
        createdAt: '2026-08-20T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-recovery',
        recoveryKid: 'did:key:zRecovery#z6LSRecoveryKak',
        keyAgreementKeyMultibase: 'z6LSRecoveryKak',
        updateKeyMultibase: 'z6MkRecoveryUpdateKey'
      }
    ]
  }
}

/**
 * The newest record handed to `putUnlockMethods`.
 *
 * @returns {UnlockRecord}
 */
function lastPut(): UnlockRecord {
  return state.puts[state.puts.length - 1]
}

/**
 * Runs the add-a-passkey ceremony with the boilerplate options.
 *
 * @returns {Promise<{ record: UnlockRecord, recorded: boolean }>}
 */
async function runAddPasskey() {
  return await addAccountPasskey({
    session: makeSession(),
    locale: 'en',
    userName: 'user@example.test',
    promptForPrfRetry: async () => false
  })
}

describe('addAccountPasskey', () => {
  it('merges the new passkey into a fresh read, keeping a concurrent entry', async () => {
    state.registry = registryWithConcurrentEntry()
    const { recorded } = await runAddPasskey()
    expect(recorded).toBe(true)
    const record = lastPut()
    expect(record.methods.map(method => method.type)).toEqual([
      'passphrase',
      'recovery-code',
      'passkey'
    ])
    // The stored record is the source of truth, handle included.
    expect(record.webAuthnUserId).toBe('FRESHHANDLEFRESHHANDAA')
    expect(vi.mocked(updateUnlockMethods)).toHaveBeenCalled()
  })

  it('reuses the stored handle and excludes its passkeys, minting nothing', async () => {
    const stored = registryWithConcurrentEntry()
    stored.methods.push({
      type: 'passkey',
      label: 'Old passkey',
      createdAt: '2026-08-02T00:00:00.000Z',
      credentialId: 'Y3JlZC1vbGQ',
      transports: ['internal'],
      backupEligibility: true,
      backupState: true,
      unlockSpaceId: 'unlock-space-old-passkey'
    })
    state.registry = stored
    await runAddPasskey()
    expect(vi.mocked(registerPasskey)).toHaveBeenCalledOnce()
    const options = state.registerPasskeyOptions!
    expect(options.userHandle).toEqual(
      base64urlnopad.decode('FRESHHANDLEFRESHHANDAA')
    )
    expect(options.excludeCredentialIds).toEqual([
      base64urlnopad.decode('Y3JlZC1vbGQ')
    ])
    expect(vi.mocked(emptyUnlockMethodsRegistry)).not.toHaveBeenCalled()
  })

  it('mints and persists a fresh handle when nothing is stored yet', async () => {
    state.registry = null
    await runAddPasskey()
    // The minted registry's handle is what the passkey registered under, and
    // the entry-first write durably persists it.
    expect(state.registerPasskeyOptions!.userHandle).toEqual(
      base64urlnopad.decode('MINTEDHANDLEMINTEDHAAA')
    )
    expect(state.puts[0]!.webAuthnUserId).toBe('MINTEDHANDLEMINTEDHAAA')
  })

  it('writes the bare entry before the establishment and completes it after', async () => {
    state.registry = registryWithConcurrentEntry()
    const { recorded } = await runAddPasskey()
    expect(recorded).toBe(true)
    expect(state.calls).toEqual([
      'registerPasskey',
      'putUnlockMethods',
      'establishStandingUnlock',
      'putUnlockMethods'
    ])
    // The bare write carries no identity member and no management zcap -- an
    // early key-agreement member would be a third partial shape no repair
    // mends. The completion adds them to the same entry.
    const bare = state.puts[0]!.methods.find(
      method => method.type === 'passkey'
    )!
    expect(bare.keyAgreementKeyMultibase).toBeUndefined()
    expect(bare.manageCapability).toBeUndefined()
    expect(bare.unlockSpaceId).toBe('space-bound')
    const completed = state.puts[1]!.methods.find(
      method => method.type === 'passkey'
    )!
    expect(completed).toEqual(
      expect.objectContaining({
        credentialId: bare.credentialId,
        keyAgreementKeyMultibase: 'z6LSPasskeyKak',
        updateKeyMultibase: 'z6MkPasskeyRung0',
        manageCapability: expect.objectContaining({
          id: 'urn:zcap:passkey-wide'
        })
      })
    )
  })

  it('rejects when the establishment rejects, with no plain bind anywhere', async () => {
    state.registry = registryWithConcurrentEntry()
    state.standingEstablished = false
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(runAddPasskey()).rejects.toThrow(PasskeyNotEstablishedError)
    error.mockRestore()
    warn.mockRestore()
  })

  it('treats a standing record on the re-fetch as a lost-response success', async () => {
    state.registry = registryWithConcurrentEntry()
    state.standingEstablished = false
    state.refetchedRecord = {
      standing: { ladderSeed: new Uint8Array(32).fill(4) },
      manageCapability: { id: 'urn:zcap:refetched' }
    }
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { recorded } = await runAddPasskey()
    expect(recorded).toBe(true)
    // The establishment succeeded server-side; nothing is deleted or
    // retired, and the entry is completed from the re-fetched hit.
    expect(vi.mocked(deleteUnlockMethod)).not.toHaveBeenCalled()
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    const completed = lastPut().methods.find(
      method => method.type === 'passkey'
    )!
    expect(completed).toEqual(
      expect.objectContaining({
        keyAgreementKeyMultibase: 'z6LSPasskeyKak',
        manageCapability: expect.objectContaining({ id: 'urn:zcap:refetched' })
      })
    )
    error.mockRestore()
    warn.mockRestore()
  })

  it('deletes the unlock Space and drops the bare entry only when nothing was published', async () => {
    state.registry = registryWithConcurrentEntry()
    state.standingEstablished = false
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(runAddPasskey()).rejects.toThrow(PasskeyNotEstablishedError)
    // No document entry, no roster wrap, no record: the credential never
    // exists -- no retirement runs.
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(deleteUnlockMethod)).toHaveBeenCalledOnce()
    expect(lastPut().methods.some(method => method.type === 'passkey')).toBe(
      false
    )
    error.mockRestore()
    warn.mockRestore()
  })

  it('cleans a partial establishment by an actual retirement', async () => {
    state.registry = registryWithConcurrentEntry()
    state.standingEstablished = false
    state.passkeyCredentialInDocument = true
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(runAddPasskey()).rejects.toThrow(PasskeyNotEstablishedError)
    // The document entry landed, so the cleanup is the retirement (with the
    // ceremony-minted ladder seed), then the Space delete and entry drop.
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({
          type: 'passkey',
          keyAgreementKeyMultibase: 'z6LSPasskeyKak',
          ladderSeed: expect.any(Uint8Array)
        }),
        verb: 'cleaning up a failed passkey addition'
      })
    )
    expect(vi.mocked(deleteUnlockMethod)).toHaveBeenCalledOnce()
    expect(lastPut().methods.some(method => method.type === 'passkey')).toBe(
      false
    )
    error.mockRestore()
    warn.mockRestore()
  })

  it('retires when only the roster wrap landed', async () => {
    state.registry = registryWithConcurrentEntry()
    state.standingEstablished = false
    state.rosterRead = {
      descriptor: {
        epochs: [
          {
            id: 'did:key:zEpoch',
            recipients: [
              { header: { kid: 'did:key:zPasskeyClient#z6LSPasskeyKak' } }
            ]
          }
        ]
      }
    }
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(runAddPasskey()).rejects.toThrow(PasskeyNotEstablishedError)
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledOnce()
    error.mockRestore()
    warn.mockRestore()
  })

  it('keeps the mendable residue when the cleanup retirement fails', async () => {
    state.registry = registryWithConcurrentEntry()
    state.standingEstablished = false
    state.passkeyCredentialInDocument = true
    state.rotation = 'failed'
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(runAddPasskey()).rejects.toThrow(PasskeyNotEstablishedError)
    // The record and the bare entry stay standing -- the state the standing
    // menders already own. Nothing is deleted.
    expect(vi.mocked(deleteUnlockMethod)).not.toHaveBeenCalled()
    expect(lastPut().methods.some(method => method.type === 'passkey')).toBe(
      true
    )
    error.mockRestore()
    warn.mockRestore()
  })

  it('leaves everything standing when the re-fetch itself fails', async () => {
    state.registry = registryWithConcurrentEntry()
    state.standingEstablished = false
    state.refetchFails = true
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(runAddPasskey()).rejects.toThrow(PasskeyNotEstablishedError)
    // Cannot verify, so nothing is acted on.
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(deleteUnlockMethod)).not.toHaveBeenCalled()
    expect(lastPut().methods.some(method => method.type === 'passkey')).toBe(
      true
    )
    error.mockRestore()
    warn.mockRestore()
  })

  it('refuses before the WebAuthn ceremony when the registry cannot be read', async () => {
    state.registryFails = true
    await expect(runAddPasskey()).rejects.toThrow('registry unreadable')
    // Nothing exists on the authenticator: the refusal costs nothing.
    expect(vi.mocked(registerPasskey)).not.toHaveBeenCalled()
  })
})

describe('addAccountPassphrase', () => {
  it('merges the passphrase entry into a fresh read, keeping a concurrent entry', async () => {
    state.registry = registryWithConcurrentEntry()
    state.boundUnlockSpaceId = 'unlock-space-new-passphrase'
    await addAccountPassphrase({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    const record = lastPut()
    expect(record.methods.some(method => method.type === 'recovery-code')).toBe(
      true
    )
    const passphrases = record.methods.filter(
      method => method.type === 'passphrase'
    )
    expect(passphrases).toHaveLength(1)
    expect(passphrases[0].unlockSpaceId).toBe('unlock-space-new-passphrase')
  })

  it('upserts rather than appends, so two runs leave one passphrase entry', async () => {
    state.registry = null
    state.boundUnlockSpaceId = 'unlock-space-first'
    await addAccountPassphrase({
      session: makeSession(),
      passphrase: 'first passphrase'
    })
    // The second run reads back what the first one wrote.
    state.registry = lastPut()
    state.boundUnlockSpaceId = 'unlock-space-second'
    await addAccountPassphrase({
      session: makeSession(),
      passphrase: 'second passphrase'
    })
    const passphrases = lastPut().methods.filter(
      method => method.type === 'passphrase'
    )
    expect(passphrases).toHaveLength(1)
    expect(passphrases[0].unlockSpaceId).toBe('unlock-space-second')
  })
})

describe('renameAccountPasskey', () => {
  const ENTRY = {
    type: 'passkey',
    label: 'Passkey',
    createdAt: '2026-08-02T00:00:00.000Z',
    credentialId: 'Y3JlZC1vbGQ',
    transports: ['internal'],
    backupEligibility: true,
    backupState: true,
    unlockSpaceId: 'unlock-space-old-passkey'
  }

  it('maps the label onto a fresh read, keeping a concurrent entry', async () => {
    const fresh = registryWithConcurrentEntry()
    fresh.methods.push({ ...ENTRY })
    state.registry = fresh
    const record = await renameAccountPasskey({
      session: makeSession(),
      entry: ENTRY as never,
      label: 'Yubikey'
    })
    expect(record.methods.some(method => method.type === 'recovery-code')).toBe(
      true
    )
    expect(
      record.methods.find(
        method =>
          method.type === 'passkey' && method.credentialId === 'Y3JlZC1vbGQ'
      )
    ).toMatchObject({ label: 'Yubikey' })
    expect(lastPut()).toEqual(record)
  })

  it('writes nothing when the fresh read no longer lists the passkey', async () => {
    state.registry = registryWithConcurrentEntry()
    const record = await renameAccountPasskey({
      session: makeSession(),
      entry: ENTRY as never,
      label: 'Yubikey'
    })
    expect(record).toEqual(state.registry)
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('refuses when no registry has been written at all', async () => {
    state.registry = null
    await expect(
      renameAccountPasskey({
        session: makeSession(),
        entry: ENTRY as never,
        label: 'Yubikey'
      })
    ).rejects.toThrow('no unlock-methods registry')
    expect(state.calls).not.toContain('putUnlockMethods')
  })
})

describe('the SettingsPage reload-after-mutation race', () => {
  it('merges each mutation into a fresh read, not into the page-held record', async () => {
    // A concurrent write landed R1 = R0 + a recovery-code entry.
    state.registry = registryWithConcurrentEntry()
    state.boundUnlockSpaceId = 'unlock-space-new-passphrase'
    // The page, still holding R0, runs the add.
    await addAccountPassphrase({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    const afterAdd = lastPut()
    expect(
      afterAdd.methods.some(method => method.type === 'recovery-code')
    ).toBe(true)
    // The page's reload has not landed yet -- and the next mutation reads
    // the newest stored record for itself regardless of page state.
    state.registry = afterAdd
    await addAccountPasskey({
      session: makeSession(),
      locale: 'en',
      userName: 'user@example.test',
      promptForPrfRetry: async () => false
    })
    const afterPasskey = lastPut()
    expect(afterPasskey.methods.map(method => method.type)).toEqual([
      'passphrase',
      'recovery-code',
      'passkey'
    ])
    expect(
      afterPasskey.methods.find(method => method.type === 'passphrase')
        ?.unlockSpaceId
    ).toBe('unlock-space-new-passphrase')
  })
})
