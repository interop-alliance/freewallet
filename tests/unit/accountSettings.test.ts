// @vitest-environment node
/**
 * Unit tests for the account-settings orchestrators
 * (`src/session/accountSettings.ts`): the account-deletion phase order (verify
 * the passphrase, wipe the data, retire the keyring) and its refusals, and the
 * passphrase change adopting the rebind into the live session. Every durable
 * seam is mocked; only the ordering is under test.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { base64urlnopad } from '@scure/base'

const state = vi.hoisted(() => ({
  calls: [] as string[],
  // The deployment's storage URL. Absent is the no-WAS deployment, whose
  // deletion must still complete with every remote arm skipped by scope; the
  // deletion suites set it, and the other ceremonies' suites run without one.
  wasUrl: undefined as string | undefined,
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
  // Every capability the registry read rode, in order.
  registryCapabilities: [] as unknown[],
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
  // The deletion walk's seams.
  assertedCredentialIds: null as Uint8Array[] | null,
  ladderVmAnchored: true,
  accountLogMissing: false,
  registryStaleSeal: false,
  resealResult: 'repaired' as 'repaired' | 'unrepaired' | 'reseal-failed',
  pendingEntries: [] as string[],
  unrecorded: [] as string[],
  coverageReadFails: false,
  // Whether the unrecorded-credential detector throws.
  unrecordedThrows: false,
  annexHistory: [] as { did: string; host: string; spaceId: string }[],
  siblingTarget: undefined as string | undefined,
  // Per-Space discovery and DELETE behaviour, keyed by Space id.
  probe: {} as Record<string, 'present' | 'absent'>,
  probeThrows: [] as string[],
  spaceDeleteOutcome: {} as Record<string, 'deleted' | 'not-found'>,
  spaceDeleteThrows: [] as string[],
  // What `deleteUnlockMethodSpace` reports per entry type.
  artifactOutcome: {} as Record<string, string>,
  // Per unlock Space id, the read-only refusal `unlockSpaceDeletionRefusal`
  // reports (a lapsed or unusable management zcap).
  entryRefusal: {} as Record<string, string>,
  // The same read-only refusal for a GET child: a management zcap allowing
  // DELETE but not GET leaves its Space deletable and unprobeable.
  entryGetRefusal: {} as Record<string, string>,
  // Every single-verb capability minted, in order.
  mints: [] as {
    shape: 'root' | 'child'
    verb: string
    spaceId: string
    controller?: string
  }[],
  wipeOutcome: 'deleted' as 'deleted' | 'not-found',
  // Whether the account Space's world-readable log still answers -- the 404
  // rule's one independent corroboration of an absence.
  accountLogGone: false,
  // The delegation (a2)'s renewal installs on the profile, when a test says
  // the visit's generation delegation was stale.
  renewedDelegation: null as unknown,
  // Whether the renewal fails (it reports failure by returning null).
  renewalFails: false,
  // Whether the account-Space DELETE rode an explicit capability.
  wipeRodeCapability: false,
  // The options the WebAuthn registration was called with.
  registerPasskeyOptions: null as {
    userHandle?: Uint8Array
    excludeCredentialIds?: Uint8Array[]
  } | null,
  // The retirement gate's two firing points: the read-only pre-flight the
  // passphrase change runs before establishment, and the ceremony itself
  // (defense in depth, a log entry having landed between the two reads).
  preflightRefuses: false,
  rotationRefusesByGate: false,
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
 * A stubbed `ZcapClient` whose `read` stands in for the status-exact Space
 * probe: `probeSpace` no longer uses was-client's `describe()` (which
 * collapses a 404 and an unparseable 2xx into the same `null`), so the stub
 * throws a 404-carrying error for an absent Space and resolves for a present
 * one.
 */
const zcapStub = vi.hoisted(() => (id: string) => ({
  id,
  read: async ({ url }: { url: string }) => {
    const spaceId = decodeURIComponent(
      new URL(url).pathname.split('/').filter(Boolean).pop() ?? ''
    )
    state.calls.push(`probe:${spaceId}`)
    if (state.probeThrows.includes(spaceId)) {
      throw new Error('probe failed')
    }
    if (state.probe[spaceId] === 'absent') {
      const err = new Error('not found') as Error & { status?: number }
      err.status = 404
      throw err
    }
    return { status: 200 }
  }
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
const LADDER_SEED = new Uint8Array(32).fill(11)
const LADDER_DID_KEY = 'did:key:zLadderVm'
const NEW_LADDER_SEED = new Uint8Array(32).fill(7)
const OLD_LADDER_SEED = new Uint8Array(32).fill(3)

/**
 * wallet-core's retirement-gate refusal, carrying the two members the callers
 * read. Built here rather than imported: every caller matches it by NAME.
 *
 * @returns {Error}
 */
function gateRefusal(): Error {
  const err = new Error(
    "did:webvh: the credential's ladder VM could not be claimed."
  )
  err.name = 'UnclaimedLadderVmRetirementError'
  Object.assign(err, {
    unclaimedLadderVmIds: ['did:webvh:account#z6MkStandingLadderVm'],
    retryableWithLadderSeed: true
  })
  return err
}

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  readUserKeyRoster: vi.fn(async () => state.rosterRead)
}))

vi.mock('@/session/credentialRotation', () => ({
  isUnclaimedLadderVmRefusal: (err: unknown) =>
    (err as { name?: string })?.name === 'UnclaimedLadderVmRetirementError',
  preflightCredentialRetirement: vi.fn(async () => {
    if (state.preflightRefuses) {
      throw gateRefusal()
    }
  }),
  rotateOffUnlockCredential: vi.fn(
    async (options: { onInventoryRemoved?: () => void }) => {
      state.calls.push('rotateOffUnlockCredential')
      if (state.rotationRefusesByGate) {
        throw gateRefusal()
      }
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
  assertPasskeyPrf: vi.fn(
    async (options: { credentialIds?: Uint8Array[] } = {}) => {
      state.calls.push('assertPasskeyPrf')
      state.assertedCredentialIds = options.credentialIds ?? null
      return { prfOutput: new Uint8Array(32).fill(9) }
    }
  ),
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
  verifyUnlockSecret: vi.fn(async () => {
    state.calls.push('verifyUnlockSecret')
    if (state.verifyFails === 'wrong') {
      throw new FakeWrongPassphraseError('nope')
    }
    if (state.verifyFails === 'other') {
      throw new Error('remote unreachable')
    }
    return { ladderSeed: LADDER_SEED }
  }),
  deriveUnlockCredential: vi.fn(
    async ({ secret }: { secret: string | Uint8Array }) => {
      if (typeof secret !== 'string') {
        // The passkey add's PRF-output credential, and the passkey deletion
        // confirm's.
        return {
          unlock: {
            secret,
            spaceId: state.boundUnlockSpaceId,
            zcapClient: zcapStub('unlock-client-passkey')
          },
          standing: {
            keyAgreementKeyMultibase: 'z6LSPasskeyKak',
            recipientKid: 'did:key:zPasskeyClient#z6LSPasskeyKak',
            clientDid: 'did:key:zPasskeyClient'
          }
        }
      }
      return {
        unlock: {
          secret,
          spaceId: `space-unlock-${secret}`,
          zcapClient: zcapStub(`unlock-client-${secret}`)
        },
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
    deleteUnlockMethodSpace: vi.fn(
      async ({ entry }: { entry: { type: string; unlockSpaceId: string } }) => {
        state.calls.push(`deleteUnlockMethodSpace:${entry.type}`)
        if (state.artifactFailures.includes(entry.type)) {
          throw new Error(`could not delete the ${entry.type} artifacts`)
        }
        return {
          unlockSpaceId: entry.unlockSpaceId,
          space: state.artifactOutcome[entry.type] ?? 'deleted'
        }
      }
    ),
    unlockSpaceDeletionRefusal: vi.fn(
      ({ entry, verb }: { entry: { unlockSpaceId: string }; verb?: string }) =>
        verb === 'GET'
          ? state.entryGetRefusal[entry.unlockSpaceId]
          : state.entryRefusal[entry.unlockSpaceId]
    ),
    managementZcapClient: vi.fn(() => zcapStub('management-client')),
    getUnlockMethods: vi.fn(
      async ({ capability }: { capability?: unknown }) => {
        state.registryCapabilities.push(capability)
        if (state.registryFails) {
          throw new Error('registry unreadable')
        }
        if (state.registryStaleSeal) {
          throw new actual.UnlockRegistryStaleSealError({})
        }
        return state.registry
      }
    ),
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
  deleteUnlockLocalState: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    state.calls.push(`deleteUnlockLocalState:${spaceId}`)
  }),
  sessionDatabaseExists: vi.fn(async () => false),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  rotateWebvhUpdateKey: vi.fn(async () => {}),
  didKeyZcapClient: vi.fn(() => zcapStub('ladder-did-key-client')),
  ladderVmIds: vi.fn(() =>
    state.ladderVmAnchored ? [`${ACCOUNT_DID}#z6MkLadderVm`] : []
  ),
  relationIds: vi.fn(() => ['did:webvh:account#z6MkClientOne'])
}))

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(),
  verifiedAccountLog: vi.fn(async () => {
    if (state.accountLogMissing) {
      const err = new Error('the account log answered 404')
      err.name = 'AccountLogMissingError'
      throw err
    }
    if (state.accountLogFails) {
      throw new Error('account log unreachable')
    }
    return { doc: state.accountDoc, log: [] }
  })
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  // Every Space the deletion walk probes or deletes goes through this handle:
  // the discovery describe, and the root-invoked deletes (an auxiliary annex
  // Space on a remembered session, and the acting credential's own unlock
  // Space on both).
  WasClient: class {
    space(spaceId: string) {
      return {
        deleteWithOutcome: async () => {
          state.calls.push(`spaceDelete:${spaceId}`)
          if (state.spaceDeleteThrows.includes(spaceId)) {
            throw new Error('Space delete failed')
          }
          return { outcome: state.spaceDeleteOutcome[spaceId] ?? 'deleted' }
        },
        collectionsPages: async function* () {
          yield {
            items: state.clientAnnexCollections.map(id => ({ id }))
          }
        },
        delete: async () => {
          state.calls.push(`spaceDelete:${spaceId}`)
        }
      }
    }
  }
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  ladderVmZcapClient: vi.fn(async () => zcapStub('ladder-vm-client')),
  ladderVmAgent: vi.fn(async () => ({ id: LADDER_DID_KEY })),
  ladderVmKeyMultibase: vi.fn(async () => 'z6MkLadderVm'),
  delegatedClientsSpaceHistory: vi.fn(() => state.annexHistory),
  mintSpaceVerbCapability: vi.fn(
    async ({
      parent,
      verb,
      controller
    }: {
      parent: { spaceId?: string }
      verb: string
      controller: string
    }) => {
      const spaceId = parent.spaceId ?? 'unknown'
      state.mints.push({ shape: 'child', verb, spaceId, controller })
      state.calls.push(`mintChild:${verb}:${spaceId}`)
      return { id: `urn:uuid:child-${verb}-${spaceId}`, spaceId }
    }
  ),
  mintSpaceRootVerbCapability: vi.fn(
    async ({
      spaceId,
      verb,
      controller
    }: {
      spaceId: string
      verb: string
      controller: string
    }) => {
      state.mints.push({ shape: 'root', verb, spaceId, controller })
      state.calls.push(`mintRoot:${verb}:${spaceId}`)
      return { id: `urn:uuid:root-${verb}-${spaceId}`, spaceId }
    }
  ),
  deleteSpaceWithCapability: vi.fn(
    async ({
      spaceId,
      capability
    }: {
      spaceId: string
      capability: { id: string }
    }) => {
      state.calls.push(`spaceDelete:${spaceId}:${capability.id}`)
      if (state.spaceDeleteThrows.includes(spaceId)) {
        throw new Error('Space delete failed')
      }
      return { outcome: state.spaceDeleteOutcome[spaceId] ?? 'deleted' }
    }
  )
}))

vi.mock('@/session/annexReach', () => ({
  renewTransientGenerationDelegation: vi.fn(
    async ({ session }: { session: { profile: Record<string, unknown> } }) => {
      state.calls.push('renewTransientGenerationDelegation')
      if (state.renewalFails) {
        // The renewal reports failure by returning null (it never throws).
        return null
      }
      if (!state.renewedDelegation) {
        // The healthy case: the standing delegation is still current, and
        // the ensure hands it back unchanged.
        return GENERATION_DELEGATION
      }
      // The real renewal installs the fresh delegation on the profile in
      // place; every read past it must ride that one.
      session.profile.invocationCapability = state.renewedDelegation
      return state.renewedDelegation
    }
  )
}))

vi.mock('@/session/credentialCoverage', () => ({
  findPendingPassphraseEntries: vi.fn(
    async ({
      readerFor
    }: {
      readerFor: (entry: {
        manageCapability: unknown
        unlockSpaceId: string
      }) => Promise<unknown>
    }) => {
      if (state.coverageReadFails) {
        throw new Error('could not read an unlock record')
      }
      // Exercise the reader seam once, so the GET-child mint is observable.
      await readerFor({
        manageCapability: { id: 'urn:zcap:manage', spaceId: 'unlock-space-x' },
        unlockSpaceId: 'unlock-space-x'
      })
      return state.pendingEntries.map(type => ({ type }))
    }
  ),
  findUnrecordedCredentials: vi.fn(async () => {
    if (state.unrecordedThrows) {
      throw new Error('could not resolve the document key-agreement methods')
    }
    return state.unrecorded
  })
}))

vi.mock('@/session/registryReseal', () => ({
  resealRegistryFromEscrow: vi.fn(async () => {
    state.calls.push('resealRegistryFromEscrow')
    if (state.resealResult === 'repaired') {
      // The record now opens under the current key, so the re-read that
      // follows the repair succeeds where the first read refused.
      state.registryStaleSeal = false
    }
    return state.resealResult
  })
}))

vi.mock('@/stores/syncController', () => ({
  syncController: { stop: vi.fn(async () => state.calls.push('stopSync')) }
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
  accountDeletionRefusalKey,
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
const { deleteSpaceWithCapability } =
  await import('@interop/wallet-core/clientAnnex')
const { deleteUnlockLocalState } = await import('@/lib/sessionKey')
const { invalidateVerifiedLog } = await import('@/session/verifiedLog')
const { resealRegistryFromEscrow } = await import('@/session/registryReseal')
const { preflightCredentialRetirement, rotateOffUnlockCredential } =
  await import('@/session/credentialRotation')
const { adoptRotatedUserKey } = await import('@/session/userKeyAdoption')
const {
  revokeUnlockMethod,
  revokeUnlockMethodByCeremony,
  canRevokeWithoutCeremony
} = await import('@/session/unlockMethods')
const {
  deleteUnlockMethodSpace,
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  updateUnlockMethods,
  upsertPassphraseUnlockMethod
} = await import('@/session/unlockMethods')
const { deleteUnlockMethod } = await import('@/session/keyring')
const { establishStandingUnlock } = await import('@/session/standingUnlock')
const { registerPasskey } = await import('@/lib/passkey')
const { executeLocalWipe, snapshotWipeTargets } = await import('@/session/wipe')
const {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores
} = await import('@/session/persistence')

const ACCOUNT_DID = 'did:webvh:QmScid:was.example.test:space:space-123:id'
/** The confirm passphrase every deletion test types; short, since the mocked
 * `deriveUnlockCredential` builds the unlock Space id out of it. */
const PASSPHRASE = 'pw'
const ACTING_SPACE = `space-unlock-${PASSPHRASE}`
const PASSKEY_SPACE = 'unlock-space-passkey'
/** The transient visit's generation delegation, which every (a2) read rides. */
const GENERATION_DELEGATION = {
  id: 'urn:uuid:generation-delegation',
  invocationTarget: 'https://was.example.test/space/space-123/'
} as unknown as import('@interop/data-integrity-core').IZcap
const CLIENT_ANNEX_SPACE_ID = 'clientAnnex-space-1'
const GENERATION_ID = 'gen-Ux3v0kQf9aPmB2hZ'
const CLIENT_ANNEX_DID =
  'did:webvh:QmClientAnnexScid:was.example.test:space:' +
  `${CLIENT_ANNEX_SPACE_ID}:${GENERATION_ID}`

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

/**
 * The session slice the orchestrators read. The deletion walk reads more of
 * it than the other ceremonies do, so its options name only what the walk
 * branches on: the storage tier (a transient session holds no root
 * invocation and signs every DELETE as the ladder VM), the acting unlock
 * method, and whether this is a guest.
 *
 * @param [options] {object}
 * @param [options.transient] {boolean}   the in-memory strategy
 * @param [options.guest] {boolean}
 * @param [options.passkey] {boolean}   the acting unlock method is a passkey
 * @param [options.unpromoted] {boolean}   the account pointer names no
 *   did:webvh (a signup whose promotion never landed)
 * @param [options.noSpace] {boolean}   the session names no account Space, so
 *   the whole remote half is out of scope
 * @returns {Session}
 */
function makeSession({
  transient = false,
  guest = false,
  passkey = false,
  unpromoted = false,
  noSpace = false
}: {
  transient?: boolean
  guest?: boolean
  passkey?: boolean
  unpromoted?: boolean
  noSpace?: boolean
} = {}) {
  const persistence = transient
    ? inMemorySessionPersistence({
        stores: transientSessionStores(),
        clientAnnex: {
          clientAnnexDid: CLIENT_ANNEX_DID,
          invocationCapability: GENERATION_DELEGATION
        }
      })
    : {
        ...browserLocalSessionPersistence(),
        // The add ceremonies clear the passkey-only safety notice; the store
        // itself reaches IndexedDB, which this node-environment suite has
        // none of.
        passkeyNotices: { delete: vi.fn(async () => {}) }
      }
  return {
    user: { id: 'did:key:zClient' },
    isGuest: guest,
    registryReady: Promise.resolve(),
    profile: {
      persistence,
      ...(transient ? { invocationCapability: GENERATION_DELEGATION } : {}),
      clientSeed: new Uint8Array(32),
      ...(transient ? { ladderSeed: LADDER_SEED } : {}),
      accountController: 'did:key:zAccount',
      zcapClient: zcapStub('session-client'),
      userKey: { id: 'did:key:z6MkUserKey' },
      clientKeyAgreementKey: { id: 'did:key:z6LSClientKak' },
      unlockMethod: {
        type: passkey ? 'passkey' : 'passphrase',
        unlockSpaceId: passkey ? PASSKEY_SPACE : ACTING_SPACE
      },
      standingUnlock: {
        unlockSpaceId: passkey ? PASSKEY_SPACE : ACTING_SPACE,
        // A standing credential always carries the sibling delegation (the
        // generation-delegation renewal needs it), so it is always present.
        // Its DEFAULT target is on another host, so it contributes no annex
        // Space of its own and a test that cares names its own target.
        delegatedClients: {
          invocationTarget:
            state.siblingTarget ??
            'https://other.example.test/space/annex-elsewhere/'
        }
      },
      accountPointer: {
        ...(unpromoted ? {} : { did: ACCOUNT_DID }),
        spaceId: 'space-123',
        host: 'https://was.example.test'
      }
    },
    storage: {
      spaceId: noSpace ? undefined : 'space-123',
      wipeRemoteStorage: vi.fn(
        async (options: { capability?: { id: string } } = {}) => {
          state.calls.push('wipeRemoteStorage')
          state.wipeRodeCapability = !!options.capability
          if (state.wipeFails) {
            throw new Error('wipe failed')
          }
          return { outcome: state.wipeOutcome }
        }
      )
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
  state.preflightRefuses = false
  state.rotationRefusesByGate = false
  state.puts = []
  state.boundUnlockSpaceId = 'space-bound'
  state.passkeyCredentialId = 'Y3JlZC1uZXc'
  // The deletion walk's seams.
  state.wasUrl = undefined
  state.assertedCredentialIds = null
  state.ladderVmAnchored = true
  state.accountLogMissing = false
  state.registryStaleSeal = false
  state.resealResult = 'repaired'
  state.pendingEntries = []
  state.unrecorded = []
  state.coverageReadFails = false
  state.unrecordedThrows = false
  state.annexHistory = []
  state.siblingTarget = undefined
  state.probe = {}
  state.probeThrows = []
  state.spaceDeleteOutcome = {}
  state.spaceDeleteThrows = []
  state.artifactOutcome = {}
  state.entryRefusal = {}
  state.entryGetRefusal = {}
  state.mints = []
  state.wipeOutcome = 'deleted'
  state.accountLogGone = false
  state.renewedDelegation = null
  state.renewalFails = false
  state.registryCapabilities = []
  state.wipeRodeCapability = false
  // The world-readable `did.jsonl` probe: an unauthenticated GET, so it is
  // stubbed rather than mocked through a module seam.
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      state.calls.push('accountLogProbe')
      expect(String(url)).toContain('did.jsonl')
      return { status: state.accountLogGone ? 404 : 200 } as Response
    })
  )
  vi.clearAllMocks()
})

const ANNEX_SPACE_A = 'clientAnnex-space-1'
const ANNEX_SPACE_B = 'clientAnnex-space-superseded'
const FOREIGN_ANNEX_SPACE = 'clientAnnex-space-elsewhere'

/**
 * The registry the deletion walk enumerates: the acting passphrase entry and
 * one sibling passkey entry, each carrying the management zcap the walk mints
 * its single-verb children from.
 *
 * @returns {object}
 */
function deletionRegistry(): object {
  return {
    version: 1,
    webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: ACTING_SPACE,
        manageCapability: {
          id: 'urn:zcap:manage-passphrase',
          spaceId: ACTING_SPACE
        }
      },
      {
        type: 'passkey',
        label: 'Phone passkey',
        createdAt: '2026-08-02T00:00:00.000Z',
        credentialId: 'Y3JlZC1pZA',
        transports: ['internal'],
        backupEligibility: true,
        backupState: true,
        unlockSpaceId: PASSKEY_SPACE,
        manageCapability: {
          id: 'urn:zcap:manage-passkey',
          spaceId: PASSKEY_SPACE
        }
      }
    ]
  }
}

/**
 * One annex Space history entry, in the shape
 * `delegatedClientsSpaceHistory` returns.
 *
 * @param spaceId {string}
 * @param [host] {string}
 * @returns {object}
 */
function annexHistoryEntry(spaceId: string, host = 'was.example.test') {
  return { did: `did:webvh:QmA:${host}:space:${spaceId}:gen-1`, host, spaceId }
}

/**
 * Every Space DELETE the run sent that rode a minted capability, paired with
 * the call that immediately preceded it. The 7.4 rule is that each such
 * DELETE is preceded by its OWN mint, so the ten-minute window is spent on
 * the one request the capability exists for.
 *
 * @returns {Array<{ deleteCall: string; precededBy: string }>}
 */
function capabilityDeletes(): Array<{
  deleteCall: string
  precededBy: string
}> {
  return state.calls.flatMap((call, index) =>
    /^spaceDelete:[^:]+:/.test(call)
      ? [{ deleteCall: call, precededBy: state.calls[index - 1] ?? '' }]
      : []
  )
}

describe('deleteAccount (the transient walk)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
  })

  it('runs the phases in the order (a) (a1) (a2) (b3) (b1) (b5) (b6) (w)', async () => {
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.keystore).toBe('skipped')
    expect(state.calls).toEqual([
      // (a) authenticate and derive fresh from the typed secret.
      'verifyUnlockSecret',
      // (a2) discover. A transient session drives no replication, so (a1)
      // has nothing to quiesce.
      'renewTransientGenerationDelegation',
      'mintChild:GET:unlock-space-x',
      `mintRoot:GET:${ANNEX_SPACE_A}`,
      `probe:${ANNEX_SPACE_A}`,
      `probe:${ACTING_SPACE}`,
      `mintChild:GET:${PASSKEY_SPACE}`,
      `probe:${PASSKEY_SPACE}`,
      // (b3) the auxiliary annex Space.
      `mintRoot:DELETE:${ANNEX_SPACE_A}`,
      `spaceDelete:${ANNEX_SPACE_A}:urn:uuid:root-DELETE-${ANNEX_SPACE_A}`,
      // (b1) the sibling unlock Space.
      'deleteUnlockMethodSpace:passkey',
      // (b5) the pivot.
      'mintRoot:DELETE:space-123',
      'wipeRemoteStorage',
      // (b6) the acting credential's own unlock Space, past the pivot.
      `spaceDelete:${ACTING_SPACE}`,
      `deleteUnlockLocalState:${ACTING_SPACE}`,
      // (w) the local half.
      'snapshotWipeTargets',
      'executeLocalWipe'
    ])
  })

  it('mints each DELETE-only capability immediately before its own request', async () => {
    state.annexHistory = [
      annexHistoryEntry(ANNEX_SPACE_A),
      annexHistoryEntry(ANNEX_SPACE_B)
    ]
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    for (const { deleteCall, precededBy } of capabilityDeletes()) {
      const spaceId = deleteCall.split(':')[1]
      expect(precededBy).toBe(`mintRoot:DELETE:${spaceId}`)
    }
    // Every mint is a single-verb child delegated to the ladder VM's own bare
    // did:key, which is what invokes it.
    for (const mint of state.mints) {
      expect(mint.controller).toBe(LADDER_DID_KEY)
      expect(['GET', 'DELETE']).toContain(mint.verb)
    }
    expect(vi.mocked(deleteSpaceWithCapability)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: ANNEX_SPACE_A,
        capability: expect.objectContaining({
          id: `urn:uuid:root-DELETE-${ANNEX_SPACE_A}`
        }),
        zcapClient: expect.objectContaining({
          id: 'ladder-did-key-client'
        })
      })
    )
  })

  it('mints no DELETE capability before the first destructive phase', async () => {
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    const firstDelete = state.calls.findIndex(call =>
      call.startsWith('spaceDelete:')
    )
    const firstDeleteMint = state.calls.findIndex(call =>
      /^mint(Root|Child):DELETE:/.test(call)
    )
    // Discovery mints reads only; the first DELETE-only capability in the run
    // belongs to (b3)'s own request.
    expect(firstDeleteMint).toBe(firstDelete - 1)
    expect(
      state.calls
        .slice(0, firstDeleteMint)
        .filter(call => call.includes(':DELETE:'))
    ).toEqual([])
  })

  it("rides the account Space's DELETE on an explicit capability", async () => {
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(state.wipeRodeCapability).toBe(true)
    expect(state.mints).toContainEqual(
      expect.objectContaining({
        shape: 'root',
        verb: 'DELETE',
        spaceId: 'space-123',
        controller: LADDER_DID_KEY
      })
    )
  })

  it('enumerates every pointer the log history names, and the sibling target', async () => {
    state.annexHistory = [
      annexHistoryEntry(ANNEX_SPACE_A),
      annexHistoryEntry(ANNEX_SPACE_B),
      annexHistoryEntry(FOREIGN_ANNEX_SPACE, 'other.example.test')
    ]
    state.siblingTarget =
      'https://was.example.test/space/clientAnnex-space-sibling/'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    const annexes = outcome.spaces.filter(space => space.kind === 'annex')
    expect(
      annexes
        .filter(space => space.outcome === 'deleted')
        .map(space => space.spaceId)
        .sort()
    ).toEqual(
      [ANNEX_SPACE_A, ANNEX_SPACE_B, 'clientAnnex-space-sibling'].sort()
    )
    // A Space on a host this deployment does not address is reported rather
    // than deleted: the same id here would name a different Space.
    expect(annexes).toContainEqual(
      expect.objectContaining({
        spaceId: FOREIGN_ANNEX_SPACE,
        outcome: 'unreachable',
        reason: 'foreign-host'
      })
    )
  })

  it('deletes a sibling unlock Space through its own management zcap', async () => {
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(vi.mocked(deleteUnlockMethodSpace)).toHaveBeenCalledWith(
      expect.objectContaining({
        entry: expect.objectContaining({ unlockSpaceId: PASSKEY_SPACE }),
        // The delegator signs the child; the ladder VM's own bare did:key
        // sends it. Mixing them comes back as a masked 404.
        signer: expect.objectContaining({
          controller: LADDER_DID_KEY,
          zcapClient: expect.objectContaining({ id: 'ladder-vm-client' }),
          invoker: expect.objectContaining({ id: 'ladder-did-key-client' })
        })
      })
    )
    expect(outcome.spaces).toContainEqual({
      kind: 'unlock',
      spaceId: PASSKEY_SPACE,
      outcome: 'deleted',
      method: 'passkey',
      label: 'Phone passkey'
    })
  })

  it('reports a sibling with no usable management zcap and carries on', async () => {
    state.entryRefusal[PASSKEY_SPACE] = 'expired'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces).toContainEqual(
      expect.objectContaining({
        kind: 'unlock',
        spaceId: PASSKEY_SPACE,
        outcome: 'unreachable',
        reason: 'expired'
      })
    )
    // Nothing was probed or deleted remotely for it, but its local state goes.
    expect(state.calls).not.toContain(`probe:${PASSKEY_SPACE}`)
    // Its browser-local state is the local wipe's to remove, past the pivot.
    expect(state.calls).not.toContain(`deleteUnlockLocalState:${PASSKEY_SPACE}`)
  })

  it("asserts against this session's own passkey credential id", async () => {
    state.boundUnlockSpaceId = PASSKEY_SPACE
    const outcome = await deleteAccount({
      session: makeSession({ transient: true, passkey: true }),
      passphrase: ''
    })
    expect(outcome.result).toBe('deleted')
    expect(state.assertedCredentialIds).toEqual([
      base64urlnopad.decode('Y3JlZC1pZA')
    ])
    // The acting Space is the passkey's; the passphrase entry is the sibling.
    expect(outcome.spaces).toContainEqual(
      expect.objectContaining({ kind: 'acting-unlock', spaceId: PASSKEY_SPACE })
    )
    expect(outcome.spaces).toContainEqual(
      expect.objectContaining({ kind: 'unlock', spaceId: ACTING_SPACE })
    )
  })

  it('creates no session database on a residue-zero visit', async () => {
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    // The browser-local factory is the ONLY way to open `freewallet-session`,
    // and a transient strategy carries none; every deleter is handed
    // `undefined` rather than a factory that would create the database.
    for (const call of vi.mocked(deleteUnlockLocalState).mock.calls) {
      expect(call[0].idb).toBeUndefined()
    }
    expect(vi.mocked(executeLocalWipe).mock.calls[0]?.[0].idb).toBeUndefined()
  })
})

describe('deleteAccount (the (a2) refusals)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
  })

  /**
   * Asserts a refusal deleted nothing: no Space DELETE was sent and the local
   * wipe never ran.
   *
   * @param outcome {object}
   */
  function expectNothingDeleted(outcome: { spaces: unknown[] }) {
    expect(state.calls.filter(call => call.startsWith('spaceDelete:'))).toEqual(
      []
    )
    expect(state.calls).not.toContain('wipeRemoteStorage')
    expect(state.calls).not.toContain('executeLocalWipe')
    expect(
      (outcome.spaces as { outcome: string }[]).filter(
        space => space.outcome === 'deleted'
      )
    ).toEqual([])
  }

  it("refuses when the document anchors no ladder VM of this credential's", async () => {
    state.ladderVmAnchored = false
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('ladder-vm-not-anchored')
    expect(accountDeletionRefusalKey(outcome.refusal!)).toBe(
      'settings.deleteRefusal.ladderVmNotAnchored'
    )
    expectNothingDeleted(outcome)
  })

  it('refuses on an unreadable registry', async () => {
    state.registryFails = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('registry-unreadable')
    expect(accountDeletionRefusalKey(outcome.refusal!)).toBe(
      'settings.deleteRefusal.registryUnreadable'
    )
    expectNothingDeleted(outcome)
  })

  it('repairs a stale registry seal in place and completes', async () => {
    state.registryStaleSeal = true
    state.resealResult = 'repaired'
    state.rosterRead = { descriptor: { epochs: [] } }
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    // One refused read, the repair, then the read that opens.
    expect(vi.mocked(getUnlockMethods)).toHaveBeenCalledTimes(2)
    expect(state.calls).toContain('resealRegistryFromEscrow')
    const [firstRead, secondRead] =
      vi.mocked(getUnlockMethods).mock.invocationCallOrder
    const [repair] = vi.mocked(resealRegistryFromEscrow).mock
      .invocationCallOrder
    expect(repair).toBeGreaterThan(firstRead!)
    expect(secondRead).toBeGreaterThan(repair!)
  })

  it('refuses when the stale seal cannot be repaired', async () => {
    state.registryStaleSeal = true
    state.resealResult = 'reseal-failed'
    state.rosterRead = { descriptor: { epochs: [] } }
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('registry-stale-seal')
    expect(accountDeletionRefusalKey(outcome.refusal!)).toBe(
      'settings.deleteRefusal.registryStaleSeal'
    )
    expectNothingDeleted(outcome)
  })

  it('refuses on a discovery read that failed for anything but a 404', async () => {
    state.probeThrows = [ANNEX_SPACE_A]
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('discovery-failed')
    expectNothingDeleted(outcome)
  })

  it('finishes the local half on an account already deleted', async () => {
    // Design 7.5/R13: the credential is already derived and the remote half
    // is done, so the run completes (b6) and (w) rather than refusing and
    // stranding this credential's own unlock Space and local state.
    state.accountLogMissing = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(state.calls).not.toContain('wipeRemoteStorage')
    expect(state.calls).toContain(`spaceDelete:${ACTING_SPACE}`)
    expect(state.calls).toContain('executeLocalWipe')
  })

  it('verifies the account log FRESH, not from the session memo', async () => {
    // A Settings session verified its log at login; reusing that memo would
    // hide an account deleted since, from another tab or by an earlier run
    // of this same walk whose 2xx was lost.
    state.accountLogMissing = true
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(vi.mocked(invalidateVerifiedLog)).toHaveBeenCalled()
  })

  it('refuses a wrong passphrase without touching any data', async () => {
    state.verifyFails = 'wrong'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: 'wrong'
    })
    expect(outcome.result).toBe('wrong-passphrase')
    expect(state.calls).toEqual(['verifyUnlockSecret'])
  })

  it('reports a verification failure as a generic failure, data untouched', async () => {
    state.verifyFails = 'other'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('failed')
    expect(state.calls).toEqual(['verifyUnlockSecret'])
  })
})

describe('deleteAccount (coverage residues and the scoped confirm)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
  })

  it('reports a pending-shaped entry and an unrecorded credential, and carries on', async () => {
    state.pendingEntries = ['passphrase']
    state.unrecorded = ['did:webvh:account#z6LSUnrecordedKak']
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.unnamed).toEqual([
      { reason: 'pending-entry', method: 'passphrase' },
      { reason: 'unrecorded-credential' }
    ])
    expect(state.calls).toContain('wipeRemoteStorage')
  })

  it('refuses the run when a pending-entry record cannot be read', async () => {
    // The detector THROWS on a record it could not settle, and a walk that
    // cannot tell a pending entry from a healthy one names neither: refuse
    // with nothing deleted rather than report an anonymous residue.
    state.coverageReadFails = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('discovery-failed')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })

  it('reports each phase it enters', async () => {
    const phases: string[] = []
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE,
      onPhase: phase => phases.push(phase.phase)
    })
    expect(phases).toEqual([
      'authenticate',
      'discover',
      'annex-space',
      'keystore',
      'unlock-space',
      'account-space',
      'acting-unlock-space',
      'local-wipe'
    ])
  })
})

describe('deleteAccount (the visit authority and the enumeration)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
  })

  it('reads the registry under the RENEWED generation delegation', async () => {
    // (a2) renews before anything destructive runs, and the renewal replaces
    // the delegation on the profile: a read that captured the old one would
    // ride a delegation the walk deliberately replaced.
    const renewed = { id: 'urn:uuid:renewed-generation-delegation' }
    state.renewedDelegation = renewed
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(state.registryCapabilities.length).toBeGreaterThan(0)
    for (const capability of state.registryCapabilities) {
      expect(capability).toBe(renewed)
    }
  })

  it('contributes no annex id from a sibling target on another host', async () => {
    state.annexHistory = []
    state.siblingTarget = 'https://elsewhere.example.test/space/annex-alien/'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces.filter(space => space.kind === 'annex')).toEqual([])
    expect(state.calls).not.toContain('spaceDelete:annex-alien')
  })

  it('takes the annex id from the sibling delegation the deployment addresses', async () => {
    state.annexHistory = []
    state.siblingTarget = 'https://was.example.test/space/annex-here/'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.spaces).toContainEqual({
      kind: 'annex',
      spaceId: 'annex-here',
      outcome: 'deleted'
    })
  })

  it('deletes a sibling whose management zcap allows no GET, unprobed', async () => {
    state.entryGetRefusal[PASSKEY_SPACE] = 'unsupported-capability'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    // Deletable and unprobeable: the probe is skipped rather than minted (the
    // mint would throw and refuse the whole run), and the DELETE still runs.
    expect(outcome.result).toBe('deleted')
    expect(state.calls).not.toContain(`probe:${PASSKEY_SPACE}`)
    expect(state.calls).toContain('deleteUnlockMethodSpace:passkey')
  })
})

describe('deleteAccount (the masked-404 registry read)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.annexHistory = []
  })

  it('refuses a null registry read on a promoted account', async () => {
    // `getUnlockMethods` maps the server's masked 404 to `null`. Reading that
    // as "no registry" would empty the sibling walk: (b1) deletes nothing,
    // (b5) still succeeds, and every sibling unlock Space is stranded behind
    // a dead account while the run reports a clean deletion.
    state.registry = null
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('registry-unreadable')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })

  it('accepts a null registry read where no registry can be demanded', async () => {
    // An unpromoted account is the one remote shape that may genuinely carry
    // no registry, so the absence is an absence rather than a refusal.
    state.registry = null
    const outcome = await deleteAccount({
      session: makeSession({ unpromoted: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(state.calls).toContain('wipeRemoteStorage')
  })

  it('refuses when the visit delegation could not be renewed', async () => {
    // Every read past the renewal would ride a delegation the server may
    // already refuse, and that refusal arrives as the same masked 404.
    state.registry = deletionRegistry()
    state.renewalFails = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })

  it('renews before the passkey arm reads the registry for its credential id', async () => {
    state.registry = deletionRegistry()
    const renewed = { id: 'urn:uuid:renewed-generation-delegation' }
    state.renewedDelegation = renewed
    await deleteAccount({
      session: makeSession({ transient: true, passkey: true }),
      passphrase: ''
    })
    // (a)'s own registry read is the earliest one, and it must not ride a
    // delegation the walk is about to replace.
    expect(
      state.calls.indexOf('renewTransientGenerationDelegation')
    ).toBeLessThan(state.calls.indexOf('verifyUnlockSecret'))
    for (const capability of state.registryCapabilities) {
      expect(capability).toBe(renewed)
    }
  })
})

describe('deleteAccount (the pre-pivot local state)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
  })

  it('leaves every sibling local state intact when the run refuses at the pivot', async () => {
    // (b1) runs before the pivot, so a refusal there must leave this browser
    // exactly as it found it: the refusal copy says the account is still
    // there, and un-remembering every other credential would contradict it.
    state.wipeOutcome = 'not-found'
    state.accountLogGone = false
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(state.calls).toContain('deleteUnlockMethodSpace:passkey')
    expect(state.calls).not.toContain(`deleteUnlockLocalState:${PASSKEY_SPACE}`)
    expect(state.calls).not.toContain('executeLocalWipe')
  })
})

describe('deleteAccount (the discovery probe and the coverage checks)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
  })

  it('reads a probe as absent only on a 404, never on an unreadable body', async () => {
    // was-client's `describe()` resolves `null` for a 404 AND for a 2xx whose
    // body did not parse, so the walk asks status-exactly instead: a probe
    // that fails for anything but a 404 refuses rather than recording an
    // absence a later 404 would grade as a deletion.
    state.probeThrows = [ANNEX_SPACE_A]
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('discovery-failed')
  })

  it('refuses when the unrecorded-credential check throws', async () => {
    // Its sibling detector's rule: a coverage check the walk could not settle
    // names no unlock Space either way.
    state.unrecordedThrows = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('discovery-failed')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })
})

describe('deleteAccount (an unpromoted account 404 corroborator)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = []
  })

  it('corroborates a (b5) 404 by the controller root-invoked probe', async () => {
    // An unpromoted account publishes no log, so its corroborator is the root
    // invocation: the Space's controller is this client's own did:key, and no
    // refusal can be masked for the controller. Without this the run could
    // never converge on a re-run.
    state.wipeOutcome = 'not-found'
    state.probe['space-123'] = 'absent'
    const outcome = await deleteAccount({
      session: makeSession({ unpromoted: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces).toContainEqual({
      kind: 'account',
      spaceId: 'space-123',
      outcome: 'deleted'
    })
    expect(state.calls).toContain('executeLocalWipe')
  })

  it('refuses an unpromoted (b5) 404 while the Space still answers', async () => {
    state.wipeOutcome = 'not-found'
    state.probe['space-123'] = 'present'
    const outcome = await deleteAccount({
      session: makeSession({ unpromoted: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('space-delete-failed')
  })
})

describe('deleteAccount (the enrolled clients local wipe)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = []
  })

  it("enumerates every enrolled client's own did:key for the wipe", async () => {
    // A sibling enrolled client's replica and caches live under ITS did:key,
    // which the verified document publishes as `<accountDid>#<multibase>`.
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(vi.mocked(snapshotWipeTargets)).toHaveBeenCalledWith(
      expect.objectContaining({
        enrolledClientDids: ['did:key:z6MkClientOne']
      })
    )
  })
})

describe('deleteAccount (an unpromoted account)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
  })

  it('deletes the Space by root invocation from a remembered session', async () => {
    // HEAD wiped the remote Space unconditionally; the pointer naming no
    // did:webvh must not turn the whole remote half into a silent skip.
    const outcome = await deleteAccount({
      session: makeSession({ unpromoted: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(state.calls).toContain('wipeRemoteStorage')
    expect(state.wipeRodeCapability).toBe(false)
    expect(outcome.spaces).toContainEqual({
      kind: 'account',
      spaceId: 'space-123',
      outcome: 'deleted'
    })
  })

  it('refuses from a transient session, which holds only ladder authority', async () => {
    const outcome = await deleteAccount({
      session: makeSession({ transient: true, unpromoted: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('ladder-vm-not-anchored')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })

  it('never reaches (b6) when (b5) was skipped', async () => {
    const outcome = await deleteAccount({
      session: makeSession({ noSpace: true }),
      passphrase: PASSPHRASE
    })
    expect(state.calls).not.toContain('wipeRemoteStorage')
    // No account Space was deleted, so the acting credential's own unlock
    // Space must survive: it is the only way back in.
    expect(state.calls).not.toContain(`spaceDelete:${ACTING_SPACE}`)
    expect(
      outcome.spaces.filter(space => space.kind === 'acting-unlock')
    ).toEqual([])
  })
})

describe('deleteAccount (the 404 rule)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
  })

  it('fails the run on a 404 for a Space it read successfully', async () => {
    state.spaceDeleteOutcome[ANNEX_SPACE_A] = 'not-found'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    // The server masks an authorization refusal as a 404, so a Space that
    // answered its discovery read cannot be reported as cleanly deleted.
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('space-delete-failed')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })

  it('grades an uncorroborated 404 as unconfirmed rather than deleted', async () => {
    state.probe[ANNEX_SPACE_A] = 'absent'
    state.spaceDeleteOutcome[ANNEX_SPACE_A] = 'not-found'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    // The account Space still answered at (a2), so the absence has no
    // independent corroboration yet.
    expect(outcome.spaces).toContainEqual({
      kind: 'annex',
      spaceId: ANNEX_SPACE_A,
      outcome: 'unconfirmed'
    })
  })

  it('grades a corroborated 404 as deleted once the account Space is gone', async () => {
    state.probe[ACTING_SPACE] = 'absent'
    state.spaceDeleteOutcome[ACTING_SPACE] = 'not-found'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces).toContainEqual(
      expect.objectContaining({
        kind: 'acting-unlock',
        spaceId: ACTING_SPACE,
        outcome: 'deleted'
      })
    )
  })

  it('grades a sibling 404 found absent at discovery as unconfirmed', async () => {
    state.probe[PASSKEY_SPACE] = 'absent'
    state.artifactOutcome.passkey = 'not-found'
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces).toContainEqual(
      expect.objectContaining({
        kind: 'unlock',
        spaceId: PASSKEY_SPACE,
        outcome: 'unconfirmed'
      })
    )
  })
})

describe('deleteAccount (failure policy)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
  })

  it('refuses on a failed annex delete, leaving the account enterable', async () => {
    state.spaceDeleteThrows = [ANNEX_SPACE_A]
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('space-delete-failed')
    expect(state.calls).not.toContain('deleteUnlockMethodSpace:passkey')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })

  it('refuses on a failed sibling delete with a live capability', async () => {
    state.artifactFailures = ['passkey']
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('space-delete-failed')
    expect(state.calls).not.toContain('wipeRemoteStorage')
  })

  it('stays put when the account Space is still there after a failed wipe', async () => {
    state.wipeFails = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('failed')
    // The re-probe found it, so the account is not gone and (b6) never ran.
    expect(state.calls).not.toContain(`spaceDelete:${ACTING_SPACE}`)
  })

  it('carries on past a failed wipe whose Space is already gone', async () => {
    state.wipeFails = true
    state.probe['space-123'] = 'absent'
    state.accountLogGone = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    // The DELETE landed and only its response was lost: (b6) and (w) must run.
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces).toContainEqual({
      kind: 'account',
      spaceId: 'space-123',
      outcome: 'deleted'
    })
    expect(state.calls).toContain('executeLocalWipe')
  })

  it('stays put when a probed-absent account Space still serves its log', async () => {
    // The probe's own 404 is the same masked answer the DELETE's is, so it
    // corroborates nothing: only the world-readable log settles it.
    state.wipeFails = true
    state.probe['space-123'] = 'absent'
    state.accountLogGone = false
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('failed')
    expect(state.calls).not.toContain('executeLocalWipe')
  })

  it('re-probes a failed account-Space wipe under its own GET-only child', async () => {
    state.wipeFails = true
    state.probe['space-123'] = 'present'
    await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    // The visit's generation delegation is scoped to the items subtree and
    // can never name the bare Space URL, so the probe mints its own child.
    expect(state.mints).toContainEqual(
      expect.objectContaining({
        shape: 'root',
        verb: 'GET',
        spaceId: 'space-123'
      })
    )
  })

  it('refuses rather than reporting a clean deletion on a masked account 404', async () => {
    // (a2) read the Space and its log still answers, so the DELETE's 404 is
    // an authorization refusal. Reporting it as deleted would destroy every
    // unlock record over a living account.
    state.wipeOutcome = 'not-found'
    state.accountLogGone = false
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('refused')
    expect(outcome.refusal).toBe('space-delete-failed')
    expect(outcome.spaces).toContainEqual({
      kind: 'account',
      spaceId: 'space-123',
      outcome: 'unconfirmed'
    })
    expect(state.calls).not.toContain(`spaceDelete:${ACTING_SPACE}`)
    expect(state.calls).not.toContain('executeLocalWipe')
  })

  it('treats a corroborated account 404 as the deletion it is', async () => {
    state.wipeOutcome = 'not-found'
    state.accountLogGone = true
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces).toContainEqual({
      kind: 'account',
      spaceId: 'space-123',
      outcome: 'deleted'
    })
    expect(state.calls).toContain('executeLocalWipe')
  })

  it("never reports 'failed' when the acting unlock Space delete fails", async () => {
    state.spaceDeleteThrows = [ACTING_SPACE]
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    // Past the pivot: the account IS gone, so the run reports the standing
    // Space rather than telling the user their account survived.
    expect(outcome.result).toBe('deleted')
    expect(outcome.spaces).toContainEqual(
      expect.objectContaining({
        kind: 'acting-unlock',
        spaceId: ACTING_SPACE,
        outcome: 'unreachable'
      })
    )
  })

  it('reports an unverifiable local replica without claiming a clean wipe', async () => {
    state.localWipeUnverified = ['replica']
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted-unverified')
  })

  it('reports a surviving local replica as a residue, not a failure', async () => {
    // Past the pivot the remote account is gone, so 'failed' would tell the
    // user it survived -- and send a retry into a re-derivation whose record
    // fetch finds nothing at the deleted unlock Space.
    state.localWipeFailed = ['replica']
    const outcome = await deleteAccount({
      session: makeSession({ transient: true }),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted-unverified')
  })

  it('keeps the fatal reading for a guest, which never reaches a pivot', async () => {
    // A guest owns no Space, so its local replica IS the account: a delete
    // that failed there is a genuine failure and the caller stays put.
    state.localWipeFailed = ['replica']
    const outcome = await deleteAccount({
      session: makeSession({ guest: true }),
      passphrase: ''
    })
    expect(outcome.result).toBe('failed')
  })
})

describe('deleteAccount (the remembered and scope-skipped sessions)', () => {
  beforeEach(() => {
    state.wasUrl = 'https://was.example.test'
  })

  it('root-invokes every delete and mints no DELETE-only capability', async () => {
    state.registry = deletionRegistry()
    state.annexHistory = [annexHistoryEntry(ANNEX_SPACE_A)]
    const outcome = await deleteAccount({
      session: makeSession(),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(state.mints.filter(mint => mint.verb === 'DELETE')).toEqual([])
    expect(state.wipeRodeCapability).toBe(false)
    // A remembered session quiesces replication first, then root-invokes.
    expect(state.calls).toEqual([
      'verifyUnlockSecret',
      'stopSync',
      // The pending-entry check reads each record through the stored
      // management zcap itself, so a remembered session mints nothing for it.
      `probe:${ANNEX_SPACE_A}`,
      `probe:${ACTING_SPACE}`,
      `mintChild:GET:${PASSKEY_SPACE}`,
      `probe:${PASSKEY_SPACE}`,
      `spaceDelete:${ANNEX_SPACE_A}`,
      'deleteUnlockMethodSpace:passkey',
      'wipeRemoteStorage',
      `spaceDelete:${ACTING_SPACE}`,
      `deleteUnlockLocalState:${ACTING_SPACE}`,
      'snapshotWipeTargets',
      'executeLocalWipe'
    ])
  })

  it('completes for a guest, whose account owns no Space', async () => {
    const outcome = await deleteAccount({
      session: makeSession({ guest: true }),
      passphrase: ''
    })
    expect(outcome.result).toBe('deleted')
    // No credential to derive, no log to verify, no Space to delete; a guest
    // session is browser-local, so it still quiesces its replica first.
    expect(state.calls).toEqual([
      'stopSync',
      'snapshotWipeTargets',
      'executeLocalWipe'
    ])
  })

  it('completes on a no-WAS deployment with every remote arm skipped', async () => {
    state.wasUrl = undefined
    const outcome = await deleteAccount({
      session: makeSession(),
      passphrase: PASSPHRASE
    })
    expect(outcome.result).toBe('deleted')
    expect(state.calls).toEqual([
      'verifyUnlockSecret',
      'stopSync',
      `deleteUnlockLocalState:${ACTING_SPACE}`,
      'snapshotWipeTargets',
      'executeLocalWipe'
    ])
    expect(outcome.spaces).toEqual([])
  })
})

describe('the deletion confirm field', () => {
  it('disables autofill, so the confirm stays the ceremony authentication', () => {
    // No DOM test harness in this repo, so the assertion is on the source:
    // a manager that saved the passphrase at login would otherwise offer it
    // to whoever holds the tab, on exactly the shared machine the hazard copy
    // is about.
    const page = readFileSync(
      path.resolve(
        __dirname,
        '..',
        '..',
        'src/pages/dashboard/SettingsPage.tsx'
      ),
      'utf8'
    )
    const field = page.slice(
      page.indexOf("label={t('settings.deletePassphraseLabel')}")
    )
    const dialogField = field.slice(0, field.indexOf('/>'))
    expect(dialogField).toContain('autoComplete="off"')
    expect(dialogField).not.toContain('current-password')
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

  it('refuses on the retirement gate before anything is established', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    state.oldLadderSeed = OLD_LADDER_SEED
    state.preflightRefuses = true

    const thrown = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    }).catch((err: unknown) => err)

    // The refusal keeps its identity and its two members all the way out to
    // the dialog, which reads them to decide what to offer (FW-404).
    expect(thrown).toMatchObject({
      name: 'UnclaimedLadderVmRetirementError',
      unclaimedLadderVmIds: ['did:webvh:account#z6MkStandingLadderVm'],
      retryableWithLadderSeed: true
    })
    // Nothing was written: the old passphrase was only verified, and the
    // establishment, the teardown, the retirement and the registry write all
    // stayed behind the refusal. A refusal after establishment would leave
    // the pending-shaped entry no seedless repair can clear.
    expect(state.calls).toEqual(['verifyPassphrase'])
    expect(state.puts).toEqual([])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    // The pre-flight asks with the seed the verification just captured, so
    // it is as strong as the retirement it stands in for.
    expect(vi.mocked(preflightCredentialRetirement)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({
          type: 'passphrase',
          keyAgreementKeyMultibase: 'z6LSOldPassphraseKak',
          updateKeyMultibase: 'z6MkOldPassphraseUpdateKey',
          ladderSeed: OLD_LADDER_SEED
        })
      })
    )
  })

  it('writes no pending entry when the gate fires inside the retirement', async () => {
    state.registry = registryWithPassphraseStanding({
      keyAgreementKeyMultibase: 'z6LSOldPassphraseKak'
    })
    state.rotationRefusesByGate = true

    const thrown = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    }).catch((err: unknown) => err)

    expect(thrown).toMatchObject({
      name: 'UnclaimedLadderVmRetirementError',
      retryableWithLadderSeed: true
    })
    // A `failed` report here would write the entry naming the OLD credential
    // under the NEW unlock Space -- the pending shape that locks the next
    // passphrase change, the last-client transition, and the torn-retirement
    // repair for good.
    expect(vi.mocked(upsertPassphraseUnlockMethod)).not.toHaveBeenCalled()
    expect(state.puts).toEqual([])
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
