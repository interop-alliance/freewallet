// @vitest-environment node
/**
 * The TRANSIENT recovery spend's replacement-code ladder wiring
 * (`recoverAccountTransient`, reached by `recoverAccountWithCode` with
 * `rememberBrowser: false` in `src/session/recovery.ts`):
 *
 * - the replacement code's ladder VM multibase is handed to the shared
 *   continuation as `replacement.ladderVmKeyMultibase`, so the
 *   add-and-retire entry publishes that VM;
 * - the replacement code's BRIDGE delegation, minted inside the
 *   `onCommitted` persist-before-publish seam, is signed by the replacement
 *   code's OWN ladder VM (`<accountDid>#<its ladder VM multibase>`) rather
 *   than by the fresh passphrase's ladder, so no later strike of another
 *   credential's inventory can rot it.
 *
 * The continuation is mocked to invoke the seam and then throw, so the
 * ceremony's post-entry tail (the roster rotation, the epoch cascade, the
 * registry update) never runs; the test awaits that rejection and asserts on
 * what the seam recorded. The codes, the unlock identities, the ladder
 * derivations, the stored records, and `delegateLogWrite` itself are all
 * real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'

const CONTINUATION_SENTINEL =
  'the transient continuation stopped after the seam'

const state = vi.hoisted(() => ({
  records: new Map<string, unknown>(),
  generatedCodes: [] as string[],
  logWriteCalls: [] as Array<{
    recoveryClientDid: string
    signerId?: string
  }>,
  replacementOption: null as {
    keyAgreementKeyMultibase?: string
    updateKeyMultibase?: string
    ladderVmKeyMultibase?: string
  } | null,
  spaceConfigures: [] as Array<{ spaceId: string; controller?: string }>,
  accountDoc: { verificationMethod: [] } as unknown
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
    doc: state.accountDoc,
    log: [],
    updateKeys: [],
    nextKeyHashes: []
  }))
}))

// `delegateLogWrite` and `generateRecoveryCode` stay REAL -- wrapped only so
// the test can see which ZcapClient signed each bridge, and which code the
// run minted as the replacement.
vi.mock('@interop/wallet-core/recovery', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@interop/wallet-core/recovery')>()
  return {
    ...actual,
    delegateLogWrite: vi.fn(
      async (options: Parameters<typeof actual.delegateLogWrite>[0]) => {
        const signer = (
          options.zcapClient as unknown as {
            delegationSigner?: { id?: string }
          }
        ).delegationSigner
        state.logWriteCalls.push({
          recoveryClientDid: options.recoveryClientDid,
          ...(signer?.id !== undefined ? { signerId: signer.id } : {})
        })
        return actual.delegateLogWrite(options)
      }
    ),
    generateRecoveryCode: vi.fn(() => {
      const code = actual.generateRecoveryCode()
      state.generatedCodes.push(code)
      return code
    })
  }
})

// The annex halves of the seam: the fresh generation, its delegation, and
// the per-visit key's enrollment are remote work. The ladder derivations
// (`ladderVmAgent`, `ladderVmZcapClient`, `ladderRung`) and the pin-slot key
// stay real -- they are what the assertions rest on.
vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  recoverWebvhLadderAnchored: vi.fn(
    async ({
      replacement,
      onCommitted
    }: {
      replacement: {
        keyAgreementKeyMultibase?: string
        updateKeyMultibase?: string
        ladderVmKeyMultibase?: string
      }
      onCommitted: () => Promise<{ clientAnnexDid: string }>
    }) => {
      state.replacementOption = replacement
      await onCommitted()
      throw new Error(CONTINUATION_SENTINEL)
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
  mintGenerationDelegation: vi.fn(async () => ({}) as IZcap),
  mintDelegatedClientsDelegation: vi.fn(
    async () => ({ id: 'urn:zcap:delegated:sibling' }) as unknown as IZcap
  )
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  WasClient: class {
    space(spaceId: string) {
      return {
        async configure({ controller }: { controller?: string } = {}) {
          state.spaceConfigures.push({
            spaceId,
            ...(controller !== undefined ? { controller } : {})
          })
        }
      }
    }
  }
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

vi.mock('@/session/userKeyAdoption', () => ({
  rewrapUnlockRegistryToUserKey: vi.fn(async () => true),
  adoptRotatedUserKeyInBand: vi.fn(async () => {})
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  getUnlockMethodsWithClient: vi.fn(async () => null),
  updateUnlockMethodsWithClient: vi.fn(async () => null)
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
import { recoverWebvhLadderAnchored } from '@interop/wallet-core/clientAnnex'
import { recoverAccountWithCode } from '@/session/recovery'

const POINTER: AccountPointer = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const CONTROLLER = 'did:key:z6MkAccountController'
const DELEGATION = {
  id: 'urn:zcap:delegated:test',
  controller: 'did:key:z6MkRecoveryClient',
  invocationTarget: `${POINTER.host}/space/${POINTER.spaceId}/id/did.jsonl`,
  parentCapability: 'urn:zcap:root:test',
  proof: { verificationMethod: `${POINTER.did}#z6MkIssuingClient` }
} as unknown as IZcap
const NEW_PASSPHRASE = 'a fresh passphrase for the recovered account'

/**
 * Issues a real recovery record for a fresh code into the mocked unlock
 * Space, the way issuance writes it.
 *
 * @returns {Promise<{ code: string }>}
 */
async function storeRecordForCode(): Promise<{ code: string }> {
  const code = generateRecoveryCode()
  const client = await recoveryClientFromCode({ code })
  const unlock = await deriveUnlockIdentity({
    secret: client.codeBytes,
    kdf: RECOVERY_KDF
  })
  const record = await wrapUnlockRecord({
    controller: CONTROLLER,
    pointer: POINTER,
    delegation: DELEGATION,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    signer: unlock.recordSigner,
    bindingMacKey: client.bindingMacKey
  })
  state.records.set(unlock.spaceId, record)
  return { code }
}

/**
 * Runs the transient spend up to the sentinel the mocked continuation throws
 * after the seam, and hands back the replacement code the run minted.
 *
 * @returns {Promise<{ replacementCode: string }>}
 */
async function runTransientSpendToSeam(): Promise<{
  replacementCode: string
}> {
  const { code } = await storeRecordForCode()
  // Only the codes minted from here on belong to the run itself.
  state.generatedCodes.length = 0

  await expect(
    recoverAccountWithCode({
      code,
      newPassphrase: NEW_PASSPHRASE,
      rememberBrowser: false
    })
  ).rejects.toThrow(CONTINUATION_SENTINEL)

  expect(vi.mocked(recoverWebvhLadderAnchored)).toHaveBeenCalledTimes(1)
  expect(state.generatedCodes).toHaveLength(1)
  return { replacementCode: state.generatedCodes[0]! }
}

beforeEach(() => {
  state.records.clear()
  state.generatedCodes = []
  state.logWriteCalls = []
  state.replacementOption = null
  state.spaceConfigures = []
  state.accountDoc = { verificationMethod: [] }
  vi.clearAllMocks()
})

describe("the transient spend -- the replacement code's ladder VM", () => {
  it("hands the replacement code's ladder VM multibase to the continuation", async () => {
    const { replacementCode } = await runTransientSpendToSeam()
    const replacement = await recoveryClientFromCode({ code: replacementCode })

    // The add-and-retire entry publishes what this member names, so the
    // bridge signed by that VM below keeps verifying past the entry.
    expect(state.replacementOption?.ladderVmKeyMultibase).toBe(
      replacement.ladderVmKeyMultibase
    )
    // The other two public halves ride the same member.
    expect(state.replacementOption?.keyAgreementKeyMultibase).toBe(
      replacement.keyAgreementKeyMultibase
    )
    expect(state.replacementOption?.updateKeyMultibase).toBe(
      replacement.updateKeyMultibase
    )
  })

  it("signs the replacement code's bridge with that code's OWN ladder VM", async () => {
    const { replacementCode } = await runTransientSpendToSeam()
    const replacement = await recoveryClientFromCode({ code: replacementCode })

    // Two bridges are minted inside the seam: the new passphrase's first
    // (delegated to the fresh credential's standing client), then the
    // replacement code's (delegated to the code's own client did:key).
    expect(state.logWriteCalls).toHaveLength(2)
    const [passphraseBridge, replacementBridge] = state.logWriteCalls
    expect(replacementBridge!.recoveryClientDid).toBe(replacement.clientDid)
    expect(replacementBridge!.signerId).toBe(
      `${POINTER.did}#${replacement.ladderVmKeyMultibase}`
    )
    // The fresh passphrase's ladder signs its own bridge, and is a different
    // key: the replacement's bridge does not ride the passphrase's ladder.
    expect(passphraseBridge!.recoveryClientDid).not.toBe(replacement.clientDid)
    expect(passphraseBridge!.signerId).not.toBe(replacementBridge!.signerId)
    expect(passphraseBridge!.signerId).toMatch(new RegExp(`^${POINTER.did}#`))
  })
})
