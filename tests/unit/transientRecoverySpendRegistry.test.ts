// @vitest-environment node
/**
 * The TRANSIENT recovery spend's registry step (`recoverAccountTransient`,
 * reached by `recoverAccountWithCode` with `rememberBrowser: false` in
 * `src/session/recovery.ts`). A transient spend leaves no pending carrier,
 * so no later resume re-runs the step: a failed first write is retried once
 * in the tail, and the retired credentials' entries are dropped and their
 * unlock Spaces deleted when that retry lands. A second failure is reported
 * on the outcome and deletes nothing.
 *
 * The continuation, the annex halves, the roster, and the registry are
 * mocked at their module seams; the codes, the unlock identities, and the
 * stored records are real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'

const state = vi.hoisted(() => ({
  records: new Map<string, unknown>(),
  registryRecord: null as { methods: Array<{ unlockSpaceId?: string }> } | null,
  registryWriteFailures: 0,
  registryMutations: 0,
  deletedEntrySpaceIds: [] as string[],
  retiredCredentialVmIds: [] as string[]
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  getUnlockKeyring: vi.fn(
    async ({ spaceId }: { spaceId: string }) =>
      state.records.get(spaceId) ?? null
  ),
  ensureUnlockSpace: vi.fn(async () => {}),
  putUnlockKeyring: vi.fn(
    async ({ spaceId, record }: { spaceId: string; record: unknown }) => {
      state.records.set(spaceId, record)
    }
  ),
  deleteUnlockSpace: vi.fn(async () => {})
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn(async () => ({
    doc: { verificationMethod: [] },
    log: [],
    updateKeys: [],
    nextKeyHashes: []
  }))
}))

// The continuation runs the seam and returns, reporting the fixture
// credential retired; the annex halves around it are remote work.
vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  recoverWebvhLadderAnchored: vi.fn(
    async ({
      onCommitted
    }: {
      onCommitted: () => Promise<{ clientAnnexDid: string }>
    }) => {
      await onCommitted()
      return {
        did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
        doc: { verificationMethod: [] },
        log: [],
        retiredCredentialVmIds: state.retiredCredentialVmIds,
        struckRungHashes: [],
        unclaimedCredentialVmIds: []
      }
    }
  ),
  mintCredentialClientAnnexGeneration: vi.fn(async () => ({
    did: 'did:webvh:QmAnnexScid:was.example.test:space:annex-space:gen-1',
    generationId: 'gen-1',
    log: [],
    doc: { verificationMethod: [] },
    spaceDescription: { controller: 'did:key:z6MkBootstrap' }
  })),
  ensureGenerationDelegationCurrent: vi.fn(async () => ({ minted: false })),
  clientAnnexLogStore: vi.fn(() => ({})),
  enrollClientAnnexTransientClient: vi.fn(async () => ({
    did: 'did:webvh:QmAnnexScid:was.example.test:space:annex-space:gen-1',
    doc: { verificationMethod: [] },
    log: []
  })),
  embeddedGenerationDelegation: vi.fn(
    () => ({ id: 'urn:zcap:delegated:generation' }) as unknown as IZcap
  ),
  mintGenerationDelegation: vi.fn(async () => ({}) as IZcap),
  mintDelegatedClientsDelegation: vi.fn(
    async () => ({ id: 'urn:zcap:delegated:sibling' }) as unknown as IZcap
  )
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  WasClient: class {
    space() {
      return { async configure() {} }
    }
  }
}))

vi.mock('@interop/was-client/edv', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client/edv')>()),
  unwrapEpochSecret: vi.fn(async () => new Uint8Array(32).fill(3))
}))

// The mandatory rotation: two epochs, the prior one escrowed to every
// recipient the append named, so the pre-rotation key unwraps.
vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  userKeyRosterDescriptorStore: vi.fn(() => ({})),
  userKeyRosterLogSigner: vi.fn(() => ({})),
  accountCollectionStores: vi.fn(() => () => ({})),
  replaceUserKeyRosterRecipients: vi.fn(
    async ({ recipients }: { recipients: Array<{ id: string }> }) => ({
      currentEpoch: 'epoch-1',
      epochs: [
        {
          id: 'epoch-0',
          recipients: recipients.map(recipient => ({
            header: { kid: recipient.id }
          }))
        },
        { id: 'epoch-1', recipients: [] }
      ]
    })
  ),
  readUserKeyRoster: vi.fn(async () => {
    const { mintUserKey } = await import('@interop/wallet-core/keys')
    const userKey = await mintUserKey()
    return {
      userKey,
      descriptor: { currentEpoch: userKey.id, epochs: [{ id: userKey.id }] },
      rotated: false,
      latestEpochId: userKey.id
    }
  })
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  mintSpaceId: vi.fn(() => 'annex-space'),
  WASRemoteStore: class {
    webvhIdStore() {
      return { putIdResource: vi.fn(async () => {}) }
    }
  }
}))

vi.mock('@/session/rosterStore', () => ({
  accountRosterStore: vi.fn(() => ({})),
  sessionRosterStore: vi.fn(() => ({}))
}))

vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollectionsToUserKey: vi.fn(async () => {})
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  getUnlockMethodsWithClient: vi.fn(async () => state.registryRecord),
  updateUnlockMethodsWithClient: vi.fn(
    async ({
      mutate
    }: {
      mutate: (current: unknown) => unknown | Promise<unknown>
    }) => {
      state.registryMutations += 1
      const next = (await mutate(
        state.registryRecord
      )) as typeof state.registryRecord
      if (state.registryWriteFailures > 0) {
        state.registryWriteFailures -= 1
        throw new Error('registry write failed (simulated lost CAS race)')
      }
      state.registryRecord = next
      return next
    }
  ),
  deleteUnlockSpaceForEntry: vi.fn(
    async ({ entry }: { entry: { unlockSpaceId: string } }) => {
      state.deletedEntrySpaceIds.push(entry.unlockSpaceId)
      return 'deleted' as const
    }
  )
}))

import {
  deriveUnlockIdentity,
  type AccountPointer
} from '@interop/wallet-core/keyring'
import {
  generateRecoveryCode,
  recoveryClientFromCode,
  RECOVERY_KDF,
  wrapUnlockRecord
} from '@interop/wallet-core/recovery'
import { agentsFromSeed } from '@interop/was-client/identity'
import { recoverAccountWithCode } from '@/session/recovery'

// The codes and the passphrase derive through the real Argon2id KDF.
vi.setConfig({ testTimeout: 30_000 })

const POINTER: AccountPointer = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const DELEGATION = {
  id: 'urn:zcap:delegated:test',
  controller: 'did:key:z6MkRecoveryClient',
  invocationTarget: `${POINTER.host}/space/${POINTER.spaceId}/id/did.jsonl`,
  parentCapability: 'urn:zcap:root:test',
  proof: { verificationMethod: `${POINTER.did}#z6MkIssuingClient` }
} as unknown as IZcap

// A real X25519 key-agreement multibase, so the retired-entry detector hashes
// decodable multikey bytes.
const { keyAgreementKey: RETIRED_KEY_AGREEMENT_KEY } = await agentsFromSeed({
  seed: new Uint8Array(32).fill(7)
})
const RETIRED_KEY_AGREEMENT_MULTIBASE = (
  RETIRED_KEY_AGREEMENT_KEY as unknown as { publicKeyMultibase: string }
).publicKeyMultibase

/**
 * Issues a real recovery record for a fresh code into the mocked unlock
 * Space, the way issuance writes it.
 *
 * @returns {Promise<string>}   the code
 */
async function storeRecordForCode(): Promise<string> {
  const code = generateRecoveryCode()
  const client = await recoveryClientFromCode({ code })
  const unlock = await deriveUnlockIdentity({
    secret: client.codeBytes,
    kdf: RECOVERY_KDF
  })
  const record = await wrapUnlockRecord({
    controller: 'did:key:z6MkAccountController',
    pointer: POINTER,
    delegation: DELEGATION,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    signer: unlock.recordSigner,
    bindingMacKey: client.bindingMacKey
  })
  state.records.set(unlock.spaceId, record)
  return code
}

beforeEach(() => {
  state.records.clear()
  state.registryWriteFailures = 0
  state.registryMutations = 0
  state.deletedEntrySpaceIds = []
  // The add-and-retire entry struck the passkey below, verbatim form.
  state.retiredCredentialVmIds = [
    `${POINTER.did}#${RETIRED_KEY_AGREEMENT_MULTIBASE}`
  ]
  state.registryRecord = {
    methods: [
      {
        type: 'passkey',
        label: 'a passkey the recovery retired',
        createdAt: '2026-09-01T00:00:00.000Z',
        credentialId: 'retired-passkey',
        transports: [],
        backupEligibility: false,
        backupState: false,
        unlockSpaceId: 'unlock-retired-passkey',
        keyAgreementKeyMultibase: RETIRED_KEY_AGREEMENT_MULTIBASE,
        manageCapability: {
          id: 'urn:zcap:delegated:manage',
          controller: POINTER.did,
          invocationTarget: `${POINTER.host}/space/unlock-retired-passkey`,
          allowedAction: ['GET', 'PUT', 'DELETE']
        }
      } as { unlockSpaceId: string }
    ]
  }
  vi.clearAllMocks()
})

describe('the transient spend -- the registry step', () => {
  it('retries a failed first write once, then drops the entries and deletes their Spaces', async () => {
    const code = await storeRecordForCode()
    state.registryWriteFailures = 1

    const outcome = await recoverAccountWithCode({
      code,
      newPassphrase: 'a fresh passphrase for the recovered account',
      rememberBrowser: false
    })

    expect(state.registryMutations).toBe(2)
    expect(outcome.registry).toBe('written')
    expect(
      state.registryRecord?.methods.map(method => method.unlockSpaceId)
    ).not.toContain('unlock-retired-passkey')
    expect(state.deletedEntrySpaceIds).toEqual(['unlock-retired-passkey'])
  })

  it('reports the residue when the retry fails too, and deletes nothing', async () => {
    const code = await storeRecordForCode()
    state.registryWriteFailures = 2

    const outcome = await recoverAccountWithCode({
      code,
      newPassphrase: 'a fresh passphrase for the recovered account',
      rememberBrowser: false
    })

    expect(state.registryMutations).toBe(2)
    expect(outcome.registry).toBe('failed')
    expect(
      state.registryRecord?.methods.map(method => method.unlockSpaceId)
    ).toContain('unlock-retired-passkey')
    expect(state.deletedEntrySpaceIds).toEqual([])
  })
})
