// @vitest-environment node
/**
 * The recovery spend's re-seal ordering (`recoverAccountWithCode` in
 * `src/session/recovery.ts`). Unlike every other rotation site, this one has
 * no session and so no shared in-band helper enforcing the order: it calls
 * `rewrapUnlockRegistryToUserKey` explicitly, and it must do so BEFORE the
 * collection fan-out. The spent code is the only holder of the pre-rotation
 * user key left by then, so a re-seal deferred past the fan-out -- the long
 * stage a torn visit dies in -- would strand the registry.
 *
 * The ceremony's remote halves are mocked at their module seams; the code,
 * its unlock identity, and its stored record are real (the record is issued
 * into the mocked unlock Space exactly as issuance writes it).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'

const state = vi.hoisted(() => ({
  records: new Map<string, unknown>(),
  calls: [] as string[]
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

vi.mock('@interop/wallet-core/recovery', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/recovery')>()),
  recoverWebvhClient: vi.fn(async () => ({
    did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id'
  }))
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  addUserKeyRosterRecipient: vi.fn(async () => {}),
  rotateUserKeyRoster: vi.fn(async () => {
    state.calls.push('rotateUserKeyRoster')
  }),
  readUserKeyRoster: vi.fn(async () => {
    const { mintUserKey } = await import('@interop/wallet-core/keys')
    // A distinct key per read: the pre-rotation read and the post-rotation
    // read must differ, or the ceremony skips the re-seal as unnecessary.
    const userKey = await mintUserKey()
    return {
      userKey,
      descriptor: { currentEpoch: userKey.id, epochs: [{ id: userKey.id }] },
      rotated: false,
      latestEpochId: userKey.id
    }
  })
}))

vi.mock('@/session/rosterStore', () => ({
  accountRosterStore: vi.fn(() => ({})),
  sessionRosterStore: vi.fn(() => ({}))
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  mintSpaceId: vi.fn(() => 'space-fresh'),
  WASRemoteStore: class {
    webvhIdStore() {
      return { putIdResource: vi.fn(async () => {}) }
    }
  }
}))

vi.mock('@/lib/sessionKey', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/sessionKey')>()),
  loadUserKeyEpochPin: vi.fn(async () => null),
  savePinFromDescriptor: vi.fn(async () => {}),
  deleteUnlockLocalTrio: vi.fn(async () => {}),
  sessionLogPinStore: vi.fn(() => ({
    read: vi.fn(async () => null),
    write: vi.fn(async () => {})
  }))
}))

vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollectionsToUserKey: vi.fn(async () => {
    state.calls.push('cascadeCollections')
    throw new Error('the tab closed during the collection fan-out')
  })
}))

vi.mock('@/session/userKeyAdoption', () => ({
  rewrapUnlockRegistryToUserKey: vi.fn(async () => {
    state.calls.push('rewrapUnlockRegistry')
    return true
  }),
  adoptRotatedUserKeyInBand: vi.fn(async () => {})
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
import { recoverAccountWithCode } from '@/session/recovery'

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

/**
 * Issues a real recovery record for a fresh code into the mocked unlock
 * Space, the way issuance writes it: wrapped to the code's real unlock KAK,
 * signed by the code's own unlock key, its account binding MAC'd under the
 * code's binding key.
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
  state.calls = []
  vi.clearAllMocks()
})

describe('the recovery spend, torn in the collection fan-out', () => {
  it('has already re-sealed the registry when the fan-out dies', async () => {
    const code = await storeRecordForCode()

    await expect(
      recoverAccountWithCode({
        code,
        newPassphrase: 'a fresh passphrase for the recovered account',
        rememberBrowser: true
      })
    ).rejects.toThrow('the tab closed')

    expect(state.calls).toEqual([
      'rotateUserKeyRoster',
      'rewrapUnlockRegistry',
      'cascadeCollections'
    ])
  })
})
