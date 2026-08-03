// @vitest-environment node
/**
 * Unit tests for the recovery-code session glue (`src/session/recovery.ts`):
 * the error discipline of the code lookup (a malformed code, a 404-shaped
 * miss, and a network failure are three DIFFERENT states -- "could not
 * check" must never read as "no account"), the round-trip through a real
 * recovery record (wallet-core's codec under the code's real unlock
 * identity), the issuance gate (`canIssueRecoveryCode` restates the retired
 * `profile.dataSeed` gate as "an enrolled client holding its key material"),
 * and the registry bookkeeping (add, replace-on-recovery). The remote unlock
 * Space read is mocked at the wallet-core seam; every derivation (HKDF, the
 * unlock identity, the EDV record cipher) runs for real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'

const wasState = vi.hoisted(() => ({
  url: 'https://was.example.test' as string | undefined,
  records: new Map<string, unknown>(),
  getError: undefined as unknown
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return wasState.url
  }
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  getUnlockKeyring: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    if (wasState.getError) {
      throw wasState.getError
    }
    return wasState.records.get(spaceId) ?? null
  })
}))

const registryState = vi.hoisted(() => ({
  record: null as null | { version: 1; userHandle: string; methods: unknown[] }
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  getUnlockMethods: vi.fn(async () => registryState.record),
  putUnlockMethods: vi.fn(async ({ record }: { record: never }) => {
    registryState.record = record
  }),
  revokeUnlockMethod: vi.fn(async () => {})
}))

import {
  deriveUnlockIdentity,
  type AccountPointer
} from '@interop/wallet-core/keyring'
import {
  generateRecoveryCode,
  recoveryClientFromCode,
  RECOVERY_KDF,
  wrapRecoveryRecord
} from '@interop/wallet-core/recovery'
import {
  canIssueRecoveryCode,
  locateRecoveryAccount,
  recordRecoveryMethod,
  recordRecoveryOutcome,
  RecoveryCodeInvalidError,
  RecoveryCodeNotFoundError
} from '@/session/recovery'
import type { RecoveryCodeUnlockMethod } from '@/session/unlockMethods'
import type { Session } from '@/types/auth'

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
 * Space, exactly as issuance would: wrapped to the code's real unlock KAK,
 * keyed by the code's real unlock Space id.
 */
async function storeRecordForCode({ email }: { email?: string } = {}) {
  const code = generateRecoveryCode()
  const client = await recoveryClientFromCode({ code })
  const unlock = await deriveUnlockIdentity({
    secret: client.codeBytes,
    kdf: RECOVERY_KDF
  })
  const record = await wrapRecoveryRecord({
    controller: 'did:key:z6MkAccountController',
    email,
    pointer: POINTER,
    delegation: DELEGATION,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver
  })
  wasState.records.set(unlock.spaceId, record)
  return { code, client }
}

/**
 * A recovery registry entry fixture for a code's public halves.
 */
function entryFor({
  client,
  label
}: {
  client: {
    recipientKid: string
    keyAgreementKeyMultibase: string
    updateKeyMultibase: string
  }
  label: string
}): RecoveryCodeUnlockMethod {
  return {
    type: 'recovery-code',
    label,
    createdAt: new Date().toISOString(),
    unlockSpaceId: 'unlock-space-test',
    recoveryKid: client.recipientKid,
    keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
    updateKeyMultibase: client.updateKeyMultibase
  }
}

beforeEach(() => {
  wasState.url = 'https://was.example.test'
  wasState.records.clear()
  wasState.getError = undefined
  registryState.record = null
})

describe('locateRecoveryAccount error discipline', () => {
  it('rejects a malformed code without touching the network', async () => {
    const { getUnlockKeyring } = await import('@interop/wallet-core/keyring')
    await expect(
      locateRecoveryAccount({ code: 'not a code' })
    ).rejects.toBeInstanceOf(RecoveryCodeInvalidError)
    expect(vi.mocked(getUnlockKeyring)).not.toHaveBeenCalled()
  })

  it('reports a 404-shaped miss as "no account for this code"', async () => {
    await expect(
      locateRecoveryAccount({ code: generateRecoveryCode() })
    ).rejects.toBeInstanceOf(RecoveryCodeNotFoundError)
  })

  it('rethrows a network failure unchanged -- never as "no account"', async () => {
    const networkError = new TypeError('fetch failed')
    wasState.getError = networkError
    await expect(
      locateRecoveryAccount({ code: generateRecoveryCode() })
    ).rejects.toBe(networkError)
  })

  it('recovers the record email on a hit, formatted code tolerated', async () => {
    const { code } = await storeRecordForCode({ email: 'user@example.com' })
    const formatted = code.replace(/(.{4})(?=.)/g, '$1-')
    await expect(locateRecoveryAccount({ code: formatted })).resolves.toEqual({
      email: 'user@example.com'
    })
  })
})

describe('canIssueRecoveryCode', () => {
  /**
   * A minimal session shape carrying exactly the gate's inputs.
   */
  function sessionWith(overrides: {
    isGuest?: boolean
    remoteStore?: unknown
    pointerDid?: string
    clientWebvhKeys?: unknown
    clientKeyAgreementKey?: unknown
    puk?: unknown
  }): Session {
    return {
      user: { id: 'did:key:z6MkTest' },
      isGuest: overrides.isGuest ?? false,
      storage: { remoteStore: overrides.remoteStore ?? {} },
      profile: {
        accountPointer: {
          did: overrides.pointerDid ?? POINTER.did,
          spaceId: POINTER.spaceId,
          host: POINTER.host
        },
        clientWebvhKeys:
          'clientWebvhKeys' in overrides
            ? overrides.clientWebvhKeys
            : {
                updateSeed: new Uint8Array(32),
                stagedSeed: new Uint8Array(32)
              },
        clientKeyAgreementKey:
          'clientKeyAgreementKey' in overrides
            ? overrides.clientKeyAgreementKey
            : { id: 'did:key:z6LSx#z6LSx' },
        puk: 'puk' in overrides ? overrides.puk : { id: 'did:key:z6LSpuk' }
      }
    } as unknown as Session
  }

  it('permits an enrolled client on a promoted account', () => {
    expect(canIssueRecoveryCode({ session: sessionWith({}) })).toBe(true)
  })

  it('refuses a guest, a did:key pointer, and missing key material', () => {
    expect(
      canIssueRecoveryCode({ session: sessionWith({ isGuest: true }) })
    ).toBe(false)
    expect(
      canIssueRecoveryCode({
        session: sessionWith({ pointerDid: 'did:key:z6MkNotPromoted' })
      })
    ).toBe(false)
    expect(
      canIssueRecoveryCode({
        session: sessionWith({ clientWebvhKeys: undefined })
      })
    ).toBe(false)
    expect(
      canIssueRecoveryCode({ session: sessionWith({ puk: undefined }) })
    ).toBe(false)
  })
})

describe('the registry bookkeeping', () => {
  const session = { user: { id: 'did:key:z6MkTest' } } as unknown as Session

  it('mints the registry on first use and replaces on matching kid', async () => {
    const codeA = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    const entryA = entryFor({ client: codeA, label: 'Code 1' })
    await recordRecoveryMethod({ session, entry: entryA })
    expect(registryState.record?.methods).toEqual([entryA])
    expect(registryState.record?.userHandle).toBeTruthy()

    // Re-recording the same kid replaces rather than duplicates.
    const relabeled = { ...entryA, label: 'Renamed' }
    await recordRecoveryMethod({ session, entry: relabeled })
    expect(registryState.record?.methods).toEqual([relabeled])
  })

  it('drops the spent entry and records the replacement after recovery', async () => {
    const spent = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    const replacement = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    const spentEntry = entryFor({ client: spent, label: 'Spent' })
    await recordRecoveryMethod({ session, entry: spentEntry })

    const replacementEntry = entryFor({
      client: replacement,
      label: 'Replacement'
    })
    await recordRecoveryOutcome({
      session,
      outcome: {
        replacementCode: 'unused-here',
        replacementEntry,
        spentRecoveryKid: spent.recipientKid
      }
    })
    expect(registryState.record?.methods).toEqual([replacementEntry])
  })
})
