// @vitest-environment node
/**
 * The bind's recovery-spend obligations (`src/session/keyring.ts`): the
 * read-first collision refusal (`probeUnlockSpaceCollision`, shared with the
 * spend's pre-flight), the fetch-and-advance stamp (the bind's `createdAt`
 * supersedes a served record written by a faster clock), and the `pending`
 * member threading through `bindPassphrase` into the local client-key
 * record. The unlock identities and records are real; only the unlock-Space
 * HTTP seam is mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'

const state = vi.hoisted(() => ({
  records: new Map<string, unknown>(),
  failGet: false
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  getUnlockKeyring: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    if (state.failGet) {
      throw new TypeError('fetch failed')
    }
    return state.records.get(spaceId) ?? null
  }),
  ensureUnlockSpace: vi.fn(async () => {}),
  putUnlockKeyring: vi.fn(
    async ({ spaceId, record }: { spaceId: string; record: unknown }) => {
      state.records.set(spaceId, record)
    }
  ),
  deleteUnlockSpace: vi.fn(async () => {})
}))

import { KEYRING_KDF, wrapKeyringRecord } from '@interop/wallet-core/keyring'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { unlockKeyVmId, wrapUnlockRecord } from '@interop/wallet-core/unlock'
import { generateLadderSeed } from '@interop/wallet-core/clientAnnex'
import {
  bindPassphrase,
  deriveUnlockCredential,
  fetchKeyring,
  probeUnlockSpaceCollision,
  UnlockSpaceCollisionError,
  type UnlockCredential
} from '@/session/keyring'
import { createFakeSessionIdb } from './fakeSessionIdb'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const OTHER_POINTER = {
  did: 'did:webvh:QmOther:was.example.test:space:space-999:id',
  spaceId: 'space-999',
  host: 'https://was.example.test'
}
const CONTROLLER = 'did:key:z6MkAccountController'
const PASSPHRASE = 'the chosen new passphrase for the spend bind'
const DELEGATION = {
  id: 'urn:zcap:delegated:test',
  controller: 'did:key:z6MkGrantee',
  invocationTarget: `${POINTER.host}/space/${POINTER.spaceId}/id/did.jsonl`,
  parentCapability: 'urn:zcap:root:test',
  proof: { verificationMethod: `${POINTER.did}#z6MkIssuingClient` }
} as unknown as IZcap
const PENDING = {
  ceremony: 'recovery-spend' as const,
  builtOnHead: { scid: 'QmScidForTests', versionId: '1-head' },
  unwrapKey: new Uint8Array(32).fill(9),
  replacementCode: new Uint8Array(16).fill(4)
}

/**
 * A served STANDING record at the credential's own unlock Space, as another
 * standing credential's bind would have written it (same passphrase, so the
 * same Space and keys).
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}
 * @param [options.controller] {string}
 * @param [options.pointer] {object}
 * @param [options.createdAt] {string}
 * @returns {Promise<void>}
 */
async function serveStandingRecord({
  credential,
  controller = CONTROLLER,
  pointer = POINTER,
  createdAt
}: {
  credential: UnlockCredential
  controller?: string
  pointer?: typeof POINTER
  createdAt?: string
}): Promise<void> {
  const record = await wrapUnlockRecord({
    controller,
    pointer,
    delegation: DELEGATION,
    ladderSeed: generateLadderSeed(),
    keyAgreementKey: credential.unlock.keyAgreementKey as IKeyAgreementKey,
    signer: credential.unlock.recordSigner,
    bindingMacKey: credential.standing.bindingMacKey,
    ...(createdAt ? { createdAt } : {})
  })
  state.records.set(credential.unlock.spaceId, record)
}

beforeEach(() => {
  state.records.clear()
  state.failGet = false
  vi.clearAllMocks()
})

describe('probeUnlockSpaceCollision', () => {
  it('proceeds on a 404-shaped miss', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    const probed = await probeUnlockSpaceCollision({
      credential,
      controller: CONTROLLER,
      pointer: POINTER,
      idb
    })
    expect(probed.servedCreatedAt).toBeUndefined()
    expect(probed.ownPending).toBeUndefined()
  })

  it('refuses a served record naming another account', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    await serveStandingRecord({
      credential,
      controller: 'did:key:z6MkSomeoneElse',
      pointer: OTHER_POINTER
    })

    await expect(
      probeUnlockSpaceCollision({
        credential,
        controller: CONTROLLER,
        pointer: POINTER,
        idb
      })
    ).rejects.toThrow(UnlockSpaceCollisionError)
  })

  it('refuses a same-account STANDING record nothing licenses overwriting', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    await serveStandingRecord({ credential })

    await expect(
      probeUnlockSpaceCollision({
        credential,
        controller: CONTROLLER,
        pointer: POINTER,
        idb
      })
    ).rejects.toThrow(UnlockSpaceCollisionError)
  })

  it("returns this ceremony's own pending record for the re-run to reuse", async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    // The earlier attempt's own bind: standing record + pending client-key
    // record at the same Space. The document license (no published
    // inventory backs the served record) is what lets the probe proceed.
    await bindPassphrase({
      clientSeed: new Uint8Array(32).fill(1),
      controller: CONTROLLER,
      passphrase: PASSPHRASE,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      pending: PENDING,
      credential,
      idb
    })

    const probed = await probeUnlockSpaceCollision({
      credential,
      controller: CONTROLLER,
      pointer: POINTER,
      accountDoc: { verificationMethod: [], keyAgreement: [] },
      idb
    })
    expect(probed.ownPending?.ceremony).toBe('recovery-spend')
    expect(probed.ownPending?.replacementCode).toEqual(PENDING.replacementCode)
    expect(probed.servedCreatedAt).toBeDefined()
  })

  it('transient license: accepts a same-account standing record the verified document does not back', async () => {
    // The transient spend reads no local records; its own-residue license is
    // the verified account document. A served standing record whose
    // credential inventory the document does not publish is a torn earlier
    // attempt's inert residue.
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    await serveStandingRecord({ credential })

    const probed = await probeUnlockSpaceCollision({
      credential,
      controller: CONTROLLER,
      pointer: POINTER,
      accountDoc: { verificationMethod: [], keyAgreement: [] },
      readLocalRecord: false
    })
    expect(probed.ownPending).toBeUndefined()
    expect(probed.servedCreatedAt).toBeDefined()
  })

  it('transient license: refuses a standing record whose commitment the document publishes (live credential)', async () => {
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    await serveStandingRecord({ credential })
    // The account document lists the credential's key-agreement commitment:
    // the served record backs a live standing credential, not residue.
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: credential.standing.keyAgreementKeyMultibase
    })
    const vmId = unlockKeyVmId({
      did: POINTER.did,
      keyAgreement: { commitment }
    })

    await expect(
      probeUnlockSpaceCollision({
        credential,
        controller: CONTROLLER,
        pointer: POINTER,
        accountDoc: { keyAgreement: [vmId] },
        readLocalRecord: false
      })
    ).rejects.toThrow(UnlockSpaceCollisionError)
  })

  it('accepts a same-account PLAIN pointer record', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    const record = await wrapKeyringRecord({
      controller: CONTROLLER,
      pointer: POINTER,
      keyAgreementKey: credential.unlock.keyAgreementKey as IKeyAgreementKey,
      signer: credential.unlock.recordSigner
    })
    state.records.set(credential.unlock.spaceId, record)

    const probed = await probeUnlockSpaceCollision({
      credential,
      controller: CONTROLLER,
      pointer: POINTER,
      idb
    })
    expect(probed.servedCreatedAt).toBeDefined()
  })

  it('rethrows a transport failure unchanged', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    state.failGet = true

    await expect(
      probeUnlockSpaceCollision({
        credential,
        controller: CONTROLLER,
        pointer: POINTER,
        idb
      })
    ).rejects.toThrow('fetch failed')
  })
})

describe('the bind under the spend obligations', () => {
  it('advances the stamp past a fast-clock served record (fetch-and-advance)', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    // An earlier attempt's own record, written on a fast clock: stamped an
    // hour ahead, and backed by no published inventory, so the document
    // license lets this bind rewrite it.
    const fastCreatedAt = new Date(Date.now() + 60 * 60 * 1000).toISOString()
    await serveStandingRecord({ credential, createdAt: fastCreatedAt })

    await bindPassphrase({
      clientSeed: new Uint8Array(32).fill(1),
      controller: CONTROLLER,
      passphrase: PASSPHRASE,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      pending: PENDING,
      refuseCollidingRecord: {
        accountDoc: { verificationMethod: [], keyAgreement: [] }
      },
      credential,
      idb
    })

    // The freshly written record supersedes the fast-clock one: its stamp is
    // strictly newer, so no reader sees the rewrite as the older of the two.
    const found = await fetchKeyring({ passphrase: PASSPHRASE, idb })
    expect(Date.parse(found!.createdAt)).toBeGreaterThan(
      Date.parse(fastCreatedAt)
    )
  })

  it('refuses the guarded bind when the credential was re-established elsewhere', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    // This browser's own earlier attempt leaves a pending client-key record.
    await bindPassphrase({
      clientSeed: new Uint8Array(32).fill(1),
      controller: CONTROLLER,
      passphrase: PASSPHRASE,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      pending: PENDING,
      credential,
      idb
    })
    // The code was spent elsewhere and the same passphrase re-established
    // from another browser. A stale pending record licenses nothing on its
    // own, so the live credential's standing members stand.
    const laterCreatedAt = new Date(Date.now() + 60 * 60 * 1000).toISOString()
    await serveStandingRecord({ credential, createdAt: laterCreatedAt })
    const established = state.records.get(credential.unlock.spaceId)

    await expect(
      bindPassphrase({
        clientSeed: new Uint8Array(32).fill(1),
        controller: CONTROLLER,
        passphrase: PASSPHRASE,
        pointer: POINTER,
        delegation: DELEGATION,
        ladderSeed: generateLadderSeed(),
        pending: PENDING,
        refuseCollidingRecord: true,
        credential,
        idb
      })
    ).rejects.toThrow(UnlockSpaceCollisionError)
    // Nothing overwritten: the other browser's record still stands verbatim.
    expect(state.records.get(credential.unlock.spaceId)).toBe(established)
  })

  it('threads `pending` through bindPassphrase into the client-key record', async () => {
    const { idb } = createFakeSessionIdb()
    await bindPassphrase({
      clientSeed: new Uint8Array(32).fill(2),
      controller: CONTROLLER,
      passphrase: PASSPHRASE,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      pending: PENDING,
      idb
    })

    const found = await fetchKeyring({ passphrase: PASSPHRASE, idb })
    expect(found?.clientKeys?.userKey).toBeUndefined()
    expect(found?.clientKeys?.pending).toMatchObject({
      ceremony: 'recovery-spend',
      builtOnHead: PENDING.builtOnHead
    })
    expect(found?.clientKeys?.pending?.unwrapKey).toEqual(PENDING.unwrapKey)
    expect(found?.clientKeys?.pending?.replacementCode).toEqual(
      PENDING.replacementCode
    )
    expect(found?.clientKeys?.pointerDid).toBe(POINTER.did)
  })

  it('refuses the guarded bind over a foreign standing record', async () => {
    const { idb } = createFakeSessionIdb()
    const credential = await deriveUnlockCredential({
      secret: PASSPHRASE,
      kdf: KEYRING_KDF
    })
    await serveStandingRecord({
      credential,
      controller: 'did:key:z6MkSomeoneElse',
      pointer: OTHER_POINTER
    })

    await expect(
      bindPassphrase({
        clientSeed: new Uint8Array(32).fill(3),
        controller: CONTROLLER,
        passphrase: PASSPHRASE,
        pointer: POINTER,
        delegation: DELEGATION,
        ladderSeed: generateLadderSeed(),
        pending: PENDING,
        refuseCollidingRecord: true,
        credential,
        idb
      })
    ).rejects.toThrow(UnlockSpaceCollisionError)
    // Nothing overwritten: the foreign record still stands.
    const served = state.records.get(credential.unlock.spaceId)
    expect(served).toBeDefined()
  })
})
