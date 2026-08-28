// @vitest-environment node
/**
 * The remembered recovery spend's persist-before-publish reorder
 * (`recoverAccountWithCode` in `src/session/recovery.ts`) and its
 * spend-completion resume (`resumeRecoverySpend`):
 *
 * - the persist hook fires between the reveal entry and the add-and-retire
 *   entry, and everything the successors need is written before the pivot;
 * - a throwing hook withholds the pivot (the code stays unspent and no
 *   post-entry stage runs);
 * - a pre-entry tear's re-run with the same code reuses the pending
 *   record's persisted replacement code, so the same replacement unlock
 *   Space address is written on every attempt;
 * - the colliding-passphrase pre-flight refuses before any entry publishes;
 * - the build-skew guard refuses a hook-less continuation;
 * - the record completion is confirm-gated, and the pending carrier (the
 *   unwrap key, the replacement-code bytes, the ceremony discriminator) is
 *   deleted exactly there;
 * - the spend resume finishes the escrows from the persisted unwrap key at
 *   the pivot-to-escrow kill points, backfills the registry, and hands the
 *   show-once prompt back until the confirm.
 *
 * The remote halves are mocked at their module seams; the codes, the unlock
 * identities, and the stored records are real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'

const state = vi.hoisted(() => ({
  records: new Map<string, unknown>(),
  calls: [] as string[],
  recordPutSpaceIds: [] as string[],
  failNextRecordPutFor: null as string | null,
  failAddEntry: false,
  omitCommitted: false,
  registryWrites: [] as unknown[],
  registryRecord: null as unknown,
  escrows: [] as Array<{ recipientId: string; ownerKid: string }>,
  rosterReads: 0,
  rosterUnwrapFailuresBeforeSuccess: 0,
  rosterRecipients: [] as string[],
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
      if (state.failNextRecordPutFor === spaceId) {
        state.failNextRecordPutFor = null
        throw new Error('record put failed (simulated tab death)')
      }
      state.recordPutSpaceIds.push(spaceId)
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

vi.mock('@interop/wallet-core/recovery', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/recovery')>()),
  // The continuation with the persist seam: the reveal entry, the hook, the
  // add-and-retire entry -- each leaving a marker so the tests can assert
  // the hook's writes land strictly between the two entries.
  recoverWebvhClient: vi.fn(
    async ({
      onCommitted
    }: {
      onCommitted: (committed: {
        builtOnHead: { scid: string; versionId: string }
      }) => Promise<void>
    }) => {
      state.calls.push('reveal-entry')
      await onCommitted({
        builtOnHead: { scid: 'QmScidForTests', versionId: '1-head' }
      })
      if (state.failAddEntry) {
        throw new Error('the add entry publish failed (simulated)')
      }
      state.calls.push('add-entry')
      return {
        did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
        ...(state.omitCommitted ? {} : { committed: true })
      }
    }
  )
}))

vi.mock('@interop/wallet-core/unlock', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/unlock')>()),
  publishUnlockKey: vi.fn(async () => {
    state.calls.push('publishUnlockKey')
    return { did: '', doc: {}, log: [] }
  })
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  addUserKeyRosterRecipient: vi.fn(
    async ({
      recipient,
      ownerKeyAgreementKey
    }: {
      recipient: { id: string }
      ownerKeyAgreementKey: { id?: string }
    }) => {
      state.calls.push('escrow')
      state.escrows.push({
        recipientId: recipient.id,
        ownerKid: ownerKeyAgreementKey.id ?? ''
      })
    }
  ),
  rotateUserKeyRoster: vi.fn(async () => {
    state.calls.push('rotateUserKeyRoster')
  }),
  readUserKeyRoster: vi.fn(async () => {
    state.rosterReads += 1
    if (state.rosterUnwrapFailuresBeforeSuccess > 0) {
      state.rosterUnwrapFailuresBeforeSuccess -= 1
      const err = new Error('no wrap for this recipient')
      err.name = 'UserKeyRosterUnwrapError'
      throw err
    }
    const { mintUserKey } = await import('@interop/wallet-core/keys')
    const userKey = await mintUserKey()
    return {
      userKey,
      descriptor: {
        currentEpoch: userKey.id,
        epochs: [
          {
            id: userKey.id,
            recipients: state.rosterRecipients.map(kid => ({
              header: { kid }
            }))
          }
        ]
      },
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

vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollectionsToUserKey: vi.fn(async () => {
    state.calls.push('cascadeCollections')
  })
}))

vi.mock('@/session/userKeyAdoption', () => ({
  rewrapUnlockRegistryToUserKey: vi.fn(async () => {
    state.calls.push('rewrapUnlockRegistry')
    return true
  }),
  adoptRotatedUserKeyInBand: vi.fn(async () => {})
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  getUnlockMethodsWithClient: vi.fn(async () => state.registryRecord),
  updateUnlockMethodsWithClient: vi.fn(async ({ mutate }) => {
    state.calls.push('registryMutation')
    const next = await mutate(state.registryRecord as never)
    state.registryWrites.push(next)
    state.registryRecord = next
    return next
  })
}))

import {
  deriveUnlockIdentity,
  type AccountPointer
} from '@interop/wallet-core/keyring'
import {
  generateRecoveryCode,
  recoveryClientFromCode,
  recoverWebvhClient,
  RECOVERY_KDF,
  wrapUnlockRecord
} from '@interop/wallet-core/recovery'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { publishUnlockKey, unlockKeyVmId } from '@interop/wallet-core/unlock'
import { readUserKeyRoster } from '@interop/wallet-core/keys'
import { generateLadderSeed } from '@interop/wallet-core/clientAnnex'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import {
  recoverAccountWithCode,
  resumeRecoverySpend,
  RecoverySpendSkewError
} from '@/session/recovery'
import {
  deriveUnlockCredential,
  fetchKeyring,
  UnlockSpaceCollisionError
} from '@/session/keyring'
import type { KeyringFetchResult } from '@/session/keyring'
import { createFakeSessionIdb } from './fakeSessionIdb'

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
 * @returns {Promise<{ code: string, codeSpaceId: string }>}
 */
async function storeRecordForCode(): Promise<{
  code: string
  codeSpaceId: string
}> {
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
  return { code, codeSpaceId: unlock.spaceId }
}

/**
 * The new passphrase's derived credential and unlock Space id.
 */
async function newPassphraseCredential() {
  const credential = await deriveUnlockCredential({
    secret: NEW_PASSPHRASE,
    kdf: KEYRING_KDF
  })
  return { credential, spaceId: credential.unlock.spaceId }
}

/**
 * An account document publishing the credential's key-agreement commitment
 * -- the shape a genuinely standing passphrase leaves, which the probe's
 * document license must refuse to overwrite.
 *
 * @param options {object}
 * @param options.credential {object}   the derived unlock credential
 * @returns {Promise<object>}
 */
async function docPublishingCommitment({
  credential
}: {
  credential: Awaited<ReturnType<typeof deriveUnlockCredential>>
}): Promise<object> {
  const commitment = await keyAgreementCommitment({
    keyAgreementKeyMultibase: credential.standing.keyAgreementKeyMultibase
  })
  return {
    keyAgreement: [
      unlockKeyVmId({ did: POINTER.did!, keyAgreement: { commitment } })
    ]
  }
}

beforeEach(() => {
  state.records.clear()
  state.calls = []
  state.recordPutSpaceIds = []
  state.failNextRecordPutFor = null
  state.failAddEntry = false
  state.omitCommitted = false
  state.registryWrites = []
  state.registryRecord = null
  state.escrows = []
  state.rosterReads = 0
  state.rosterUnwrapFailuresBeforeSuccess = 0
  state.rosterRecipients = []
  state.accountDoc = { verificationMethod: [] }
  vi.clearAllMocks()
})

describe('the remembered spend reorder -- the persist hook', () => {
  it('persists the successors between the reveal entry and the add entry', async () => {
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    const { spaceId: passphraseSpaceId } = await newPassphraseCredential()

    await recoverAccountWithCode({
      code,
      newPassphrase: NEW_PASSPHRASE,
      rememberBrowser: true,
      idb
    })

    // Both hook writes (the new passphrase's standing record and the
    // replacement code's record) land after the reveal entry and before the
    // add entry.
    const reveal = state.calls.indexOf('reveal-entry')
    const add = state.calls.indexOf('add-entry')
    expect(reveal).toBeGreaterThanOrEqual(0)
    expect(add).toBeGreaterThan(reveal)
    expect(state.recordPutSpaceIds).toContain(passphraseSpaceId)
    expect(state.recordPutSpaceIds.length).toBeGreaterThanOrEqual(2)
    // The pending client-key record is browser-local and PENDING (no user
    // key, the carrier present) until the confirm-gated completion runs.
    const found = await fetchKeyring({ passphrase: NEW_PASSPHRASE, idb })
    expect(found?.clientKeys?.userKey).toBeUndefined()
    expect(found?.clientKeys?.pending).toMatchObject({
      ceremony: 'recovery-spend',
      builtOnHead: { scid: 'QmScidForTests', versionId: '1-head' }
    })
    expect(found?.clientKeys?.pending?.unwrapKey).toHaveLength(32)
    expect(found?.clientKeys?.pending?.replacementCode).toHaveLength(16)
    // The hook wrote the STANDING layout: bridge and ladder seed present.
    expect(found?.standing?.delegation).toBeDefined()
    expect(found?.standing?.ladderSeed).toHaveLength(32)
  })

  it('deletes the pending carrier exactly at the confirm-gated completion', async () => {
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()

    const outcome = await recoverAccountWithCode({
      code,
      newPassphrase: NEW_PASSPHRASE,
      rememberBrowser: true,
      idb
    })
    expect(outcome.completeRecovery).toBeDefined()
    // The tail's establishment landed, so the outcome reports it.
    expect(outcome.standing).toBe('established')

    await outcome.completeRecovery!()

    const found = await fetchKeyring({ passphrase: NEW_PASSPHRASE, idb })
    expect(found?.clientKeys?.userKey).toBeDefined()
    expect(found?.clientKeys?.pending).toBeUndefined()
    expect(found?.clientKeys?.pointerDid).toBe(POINTER.did)
  })

  it('withholds the pivot when the hook throws: the code stays unspent, nothing post-entry runs', async () => {
    const { code, codeSpaceId } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    const { spaceId: passphraseSpaceId } = await newPassphraseCredential()
    state.failNextRecordPutFor = passphraseSpaceId

    await expect(
      recoverAccountWithCode({
        code,
        newPassphrase: NEW_PASSPHRASE,
        rememberBrowser: true,
        idb
      })
    ).rejects.toThrow('record put failed')

    expect(state.calls).toContain('reveal-entry')
    expect(state.calls).not.toContain('add-entry')
    expect(state.calls).not.toContain('rotateUserKeyRoster')
    expect(state.calls).not.toContain('cascadeCollections')
    // The typed code's record still stands -- the code is unspent and the
    // re-run with the same code converges.
    expect(state.records.has(codeSpaceId)).toBe(true)
  })

  it('re-runs after a pre-entry tear with the SAME replacement unlock Space (no orphan Space)', async () => {
    const { code, codeSpaceId } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    const { spaceId: passphraseSpaceId } = await newPassphraseCredential()

    // Attempt 1: the hook persists, the add entry publish dies.
    state.failAddEntry = true
    await expect(
      recoverAccountWithCode({
        code,
        newPassphrase: NEW_PASSPHRASE,
        rememberBrowser: true,
        idb
      })
    ).rejects.toThrow('add entry publish failed')

    // Attempt 2 with the same code and passphrase converges.
    state.failAddEntry = false
    const outcome = await recoverAccountWithCode({
      code,
      newPassphrase: NEW_PASSPHRASE,
      rememberBrowser: true,
      idb
    })

    // Across both attempts, exactly one replacement unlock Space address
    // was written: the re-run re-derived the replacement code from the
    // pending record's persisted bytes instead of minting a fresh one.
    const replacementSpaceIds = new Set(
      state.recordPutSpaceIds.filter(
        spaceId => spaceId !== codeSpaceId && spaceId !== passphraseSpaceId
      )
    )
    expect(replacementSpaceIds.size).toBe(1)
    // And the outcome's code re-derives the same registry entry kid.
    const replayed = await recoveryClientFromCode({
      code: outcome.replacementCode
    })
    expect(outcome.replacementEntry.recoveryKid).toBe(replayed.recipientKid)
  })

  it('refuses a hook-less continuation (the build-skew guard), the pending record already persisted', async () => {
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    state.omitCommitted = true

    await expect(
      recoverAccountWithCode({
        code,
        newPassphrase: NEW_PASSPHRASE,
        rememberBrowser: true,
        idb
      })
    ).rejects.toThrow(RecoverySpendSkewError)

    const found = await fetchKeyring({ passphrase: NEW_PASSPHRASE, idb })
    expect(found?.clientKeys?.pending?.ceremony).toBe('recovery-spend')
  })

  it('logs the named event when the hook re-fires on a conflict retry', async () => {
    const capture = captureSink()
    addSink(capture.sink)
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    // A lost CAS: the once-function re-runs the whole attempt, hook included.
    vi.mocked(recoverWebvhClient).mockImplementationOnce(async options => {
      const opts = options as unknown as {
        onCommitted: (committed: {
          builtOnHead: { scid: string; versionId: string }
        }) => Promise<void>
      }
      await opts.onCommitted({
        builtOnHead: { scid: 'QmScidForTests', versionId: '1-head' }
      })
      await opts.onCommitted({
        builtOnHead: { scid: 'QmScidForTests', versionId: '1-head' }
      })
      return { did: POINTER.did!, committed: true }
    })

    await recoverAccountWithCode({
      code,
      newPassphrase: NEW_PASSPHRASE,
      rememberBrowser: true,
      idb
    })

    expect(
      capture.events.some(
        event =>
          event.msg ===
          'Recovery-spend persist hook re-fired on a conflict retry'
      )
    ).toBe(true)
  })
})

describe('the remembered spend reorder -- the colliding-passphrase pre-flight', () => {
  it('refuses a standing record at the target Space before any entry publishes', async () => {
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    const { credential, spaceId } = await newPassphraseCredential()
    // The chosen "new" passphrase is already a standing credential of this
    // same account (the user reused their login passphrase): the document
    // publishes its commitment, so no license applies.
    state.accountDoc = await docPublishingCommitment({ credential })
    const standingRecord = await wrapUnlockRecord({
      controller: CONTROLLER,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      keyAgreementKey: credential.unlock.keyAgreementKey as IKeyAgreementKey,
      signer: credential.unlock.recordSigner,
      bindingMacKey: credential.standing.bindingMacKey
    })
    state.records.set(spaceId, standingRecord)

    await expect(
      recoverAccountWithCode({
        code,
        newPassphrase: NEW_PASSPHRASE,
        rememberBrowser: true,
        idb
      })
    ).rejects.toThrow(UnlockSpaceCollisionError)
    expect(recoverWebvhClient).not.toHaveBeenCalled()
  })

  it("licenses the bind window's own residue: served standing record, no local record, no pin, credential unpublished", async () => {
    // The starvation window an earlier attempt's bind order creates: the
    // remote record PUT landed, then the tab died before the local
    // client-key record and the freshness pin were written. A re-run with
    // the same code and passphrase holds no pending record and no pin, so
    // only the document license (the credential's commitment is NOT
    // published) can prove the served record this ceremony's own inert
    // residue.
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    const { credential, spaceId } = await newPassphraseCredential()
    const residueRecord = await wrapUnlockRecord({
      controller: CONTROLLER,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      keyAgreementKey: credential.unlock.keyAgreementKey as IKeyAgreementKey,
      signer: credential.unlock.recordSigner,
      bindingMacKey: credential.standing.bindingMacKey
    })
    state.records.set(spaceId, residueRecord)

    const outcome = await recoverAccountWithCode({
      code,
      newPassphrase: NEW_PASSPHRASE,
      rememberBrowser: true,
      idb
    })

    expect(recoverWebvhClient).toHaveBeenCalled()
    expect(outcome.replacementCode).toBeDefined()
  })

  it('refuses a record naming another account before any entry publishes', async () => {
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    const { credential, spaceId } = await newPassphraseCredential()
    const foreignRecord = await wrapUnlockRecord({
      controller: 'did:key:z6MkSomeoneElse',
      pointer: {
        did: 'did:webvh:QmOther:was.example.test:space:space-999:id',
        spaceId: 'space-999',
        host: POINTER.host
      },
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      keyAgreementKey: credential.unlock.keyAgreementKey as IKeyAgreementKey,
      signer: credential.unlock.recordSigner,
      bindingMacKey: credential.standing.bindingMacKey
    })
    state.records.set(spaceId, foreignRecord)

    await expect(
      recoverAccountWithCode({
        code,
        newPassphrase: NEW_PASSPHRASE,
        rememberBrowser: true,
        idb
      })
    ).rejects.toThrow(UnlockSpaceCollisionError)
    expect(recoverWebvhClient).not.toHaveBeenCalled()
  })
})

describe('the standing-establishment success gate', () => {
  it('writes a BARE registry entry when the tail establishment fails, upgraded by a later resume', async () => {
    const { code } = await storeRecordForCode()
    const { idb } = createFakeSessionIdb()
    // The tail's document entry publish dies; the registry mutation still
    // runs, but must not claim a standing configuration the account does
    // not back.
    vi.mocked(publishUnlockKey).mockRejectedValueOnce(
      new Error('document entry publish failed (simulated)')
    )

    const outcome = await recoverAccountWithCode({
      code,
      newPassphrase: NEW_PASSPHRASE,
      rememberBrowser: true,
      idb
    })

    // The continuation succeeded and reports the standing truthfully:
    // recovered, with the standing configuration pending.
    expect(outcome.standing).toBe('pending')

    const written = state.registryRecord as {
      methods: Array<Record<string, unknown>>
    }
    const bare = written.methods.find(method => method.type === 'passphrase')
    expect(bare).toBeDefined()
    expect(bare!.unlockSpaceId).toBeDefined()
    expect(bare!.keyAgreementKeyMultibase).toBeUndefined()
    expect(bare!.rosterKid).toBeUndefined()

    // A later resume (the pending record still stands -- the completion was
    // never confirmed) finishes the establishment from durable state and
    // upgrades the bare entry with the now-real standing configuration.
    const found = await fetchKeyring({ passphrase: NEW_PASSPHRASE, idb })
    expect(found?.clientKeys?.pending?.ceremony).toBe('recovery-spend')
    state.rosterRecipients = ['everyone-already-escrowed']

    const resumed = await resumeRecoverySpend({
      found: found as KeyringFetchResult
    })

    // The resume's backfill made the standing configuration real and its
    // prompt reports so.
    expect(resumed.recoverySpendPrompt?.standing).toBe('established')
    expect(state.calls).toContain('publishUnlockKey')
    const upgraded = (
      state.registryRecord as { methods: Array<Record<string, unknown>> }
    ).methods.find(method => method.type === 'passphrase')
    expect(upgraded!.keyAgreementKeyMultibase).toBeDefined()
    expect(upgraded!.rosterKid).toBeDefined()
  })
})

describe('resumeRecoverySpend -- the spend-completion resume', () => {
  // The new passphrase's derived standing client -- REAL (the standing
  // backfill computes a commitment over its key-agreement multibase), and
  // cached: one KDF run for the whole suite.
  let fixtureStanding:
    Awaited<ReturnType<typeof deriveUnlockCredential>>['standing'] | undefined

  /**
   * A keyring hit shaped like the one the pending router hands the resume:
   * a real spend-written pending record's members, with the persist closure
   * captured for assertions.
   */
  async function makeSpendFound() {
    const spentCode = generateRecoveryCode()
    const spent = await recoveryClientFromCode({ code: spentCode })
    const replacementCode = generateRecoveryCode()
    const replacement = await recoveryClientFromCode({ code: replacementCode })
    fixtureStanding ??= (
      await deriveUnlockCredential({
        secret: 'the resumed spend fixture passphrase',
        kdf: KEYRING_KDF
      })
    ).standing
    const standingClient = fixtureStanding
    const persistClientKeys = vi.fn(async () => {})
    const clientSeed = crypto.getRandomValues(new Uint8Array(32))
    const found = {
      controller: CONTROLLER,
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-new-passphrase',
      createdAt: new Date().toISOString(),
      clientKeys: {
        clientSeed,
        webvhUpdateKeys: {
          updateSeed: crypto.getRandomValues(new Uint8Array(32)),
          stagedSeed: crypto.getRandomValues(new Uint8Array(32))
        },
        controller: CONTROLLER,
        pointerDid: POINTER.did,
        pending: {
          ceremony: 'recovery-spend' as const,
          builtOnHead: { scid: 'QmScidForTests', versionId: '2-head' },
          unwrapKey: spent.clientSeed,
          replacementCode: replacement.codeBytes
        }
      },
      standing: {
        delegation: DELEGATION,
        ladderSeed: generateLadderSeed()
      },
      standingClient,
      persistClientKeys
    } as unknown as KeyringFetchResult
    return {
      found,
      persistClientKeys,
      spent,
      replacement,
      replacementCode,
      standingClient
    }
  }

  it('completes the escrows from the unwrap key at the pivot-to-escrow kill point', async () => {
    const capture = captureSink()
    addSink(capture.sink)
    const { found, spent, replacement, standingClient } = await makeSpendFound()
    // The first roster read finds no wrap for the new client: the entry
    // landed, the escrows did not (the band the unwrap-key carrier closes).
    // The credential's standing wrap already stands, so the standing
    // backfill has nothing to escrow here.
    state.rosterUnwrapFailuresBeforeSuccess = 1
    state.rosterRecipients = [
      replacement.recipientKid,
      standingClient.recipientKid
    ]

    const result = await resumeRecoverySpend({ found })

    // Both escrows ran, owned by the spent code's re-derived KAK.
    expect(state.escrows).toHaveLength(2)
    for (const escrow of state.escrows) {
      expect(escrow.ownerKid).toBe(spent.agents.keyAgreementKey.id)
    }
    expect(state.escrows.map(escrow => escrow.recipientId)).toContain(
      replacement.recipientKid
    )
    expect(
      capture.events.some(event =>
        String(event.msg).includes(
          'completing the roster escrows from the pending unwrap key'
        )
      )
    ).toBe(true)
    // The show-once obligation rides back until the confirm.
    expect(result.recoverySpendPrompt?.replacementCode).toBeDefined()
    expect(result.clientKeys.userKey).toBeDefined()
  })

  it('backfills the replacement escrow on a between-escrows tear', async () => {
    const { found, replacement, standingClient } = await makeSpendFound()
    // The read succeeds (this client's wrap stands) but the current epoch
    // carries no wrap for the replacement code; the standing wrap stands.
    state.rosterRecipients = [standingClient.recipientKid]

    await resumeRecoverySpend({ found })

    expect(state.escrows.map(escrow => escrow.recipientId)).toContain(
      replacement.recipientKid
    )
    // Only the replacement was escrowed -- this client's wrap already stood.
    expect(state.escrows).toHaveLength(1)
  })

  it('backfills the registry mutation when the tail never wrote it', async () => {
    const { found, standingClient } = await makeSpendFound()
    state.rosterRecipients = [
      'everyone-already-escrowed',
      standingClient.recipientKid
    ]
    state.registryRecord = null

    await resumeRecoverySpend({ found })

    expect(state.calls).toContain('registryMutation')
    const written = state.registryWrites[0] as {
      methods: Array<{ type: string; unlockSpaceId?: string }>
    }
    expect(
      written.methods.some(method => method.type === 'recovery-code')
    ).toBe(true)
    expect(
      written.methods.some(
        method =>
          method.type === 'passphrase' &&
          method.unlockSpaceId === 'unlock-space-new-passphrase'
      )
    ).toBe(true)
  })

  it('gates the record completion on the confirm and clears the carrier there', async () => {
    const { found, persistClientKeys, standingClient } = await makeSpendFound()
    state.rosterRecipients = [
      'everyone-already-escrowed',
      standingClient.recipientKid
    ]

    const result = await resumeRecoverySpend({ found })

    // Nothing persisted until the confirm.
    expect(persistClientKeys).not.toHaveBeenCalled()
    expect(result.recoverySpendPrompt).toBeDefined()

    await result.recoverySpendPrompt!.complete()

    expect(persistClientKeys).toHaveBeenCalledWith(
      expect.objectContaining({
        userKey: expect.anything(),
        pointerDid: POINTER.did,
        pending: null
      })
    )
  })

  it('backfills the standing establishment (wrap + document entry) when the tail was torn before it', async () => {
    const { found, standingClient } = await makeSpendFound()
    // Everything else stands; the credential's standing wrap and document
    // commitment do not (the tail died before the establishment stages).
    state.rosterRecipients = ['everyone-already-escrowed']

    const result = await resumeRecoverySpend({ found })

    // The backfill finished both halves, so the prompt reports established.
    expect(result.recoverySpendPrompt?.standing).toBe('established')
    // The wrap escrow ran, owned by this client's own key (which holds a
    // wrap in every epoch), and the document entry published.
    const standingEscrow = state.escrows.find(
      escrow => escrow.recipientId === standingClient.recipientKid
    )
    expect(standingEscrow).toBeDefined()
    expect(standingEscrow!.ownerKid).not.toBe('')
    expect(state.calls).toContain('publishUnlockKey')
  })

  it('skips the standing backfill when wrap and commitment already stand', async () => {
    const { found, standingClient } = await makeSpendFound()
    state.rosterRecipients = [
      'everyone-already-escrowed',
      standingClient.recipientKid
    ]
    // The commitment VM stands in the verified document.
    const { keyAgreementCommitment } =
      await import('@interop/wallet-core/webvh')
    const { unlockKeyVmId } = await import('@interop/wallet-core/unlock')
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: standingClient.keyAgreementKeyMultibase
    })
    const vmId = unlockKeyVmId({
      did: POINTER.did!,
      keyAgreement: { commitment }
    })
    const { verifyAccountLog } = await import('@interop/wallet-core/webvh')
    vi.mocked(verifyAccountLog).mockResolvedValueOnce({
      doc: { verificationMethod: [{ id: vmId }] },
      log: [],
      updateKeys: [],
      nextKeyHashes: []
    } as never)

    await resumeRecoverySpend({ found })

    expect(
      state.escrows.some(
        escrow => escrow.recipientId === standingClient.recipientKid
      )
    ).toBe(false)
    expect(state.calls).not.toContain('publishUnlockKey')
  })

  it('writes a bare passphrase entry when its own establishment backfill fails', async () => {
    const { found, standingClient } = await makeSpendFound()
    // The standing wrap is missing, so the backfill attempts the
    // establishment -- and its document entry publish dies.
    state.rosterRecipients = ['everyone-already-escrowed']
    state.registryRecord = null
    vi.mocked(publishUnlockKey).mockRejectedValueOnce(
      new Error('document entry publish failed (simulated)')
    )

    const result = await resumeRecoverySpend({ found })

    // The failed backfill never fails the resume; the prompt reports the
    // standing as still pending.
    expect(result.recoverySpendPrompt?.standing).toBe('pending')

    const written = state.registryWrites.at(-1) as {
      methods: Array<Record<string, unknown>>
    }
    const entry = written.methods.find(method => method.type === 'passphrase')
    expect(entry).toBeDefined()
    expect(entry!.keyAgreementKeyMultibase).toBeUndefined()
    // The wrap escrow itself may have run; only the registry claim is
    // withheld until the whole establishment is real.
    expect(
      state.escrows.some(
        escrow => escrow.recipientId === standingClient.recipientKid
      )
    ).toBe(true)
  })

  it('rethrows a roster refusal other than the unwrap miss unchanged', async () => {
    const { found } = await makeSpendFound()
    const refusal = new Error('roster rolled back')
    refusal.name = 'UserKeyRosterContinuityError'
    vi.mocked(readUserKeyRoster).mockRejectedValueOnce(refusal)

    await expect(resumeRecoverySpend({ found })).rejects.toBe(refusal)
  })
})
