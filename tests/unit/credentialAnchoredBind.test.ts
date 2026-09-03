// @vitest-environment node
/**
 * The credential-anchored bind's Space-provisioning discriminator
 * (`bindCredentialAnchoredUnlockSecret` in `src/session/keyring.ts`). The
 * establishment binds the unlock record twice, and the second bind carries
 * the first's stamp as `priorCreatedAt`. That stamp is proof the unlock
 * Space and its keyring collection exist, so the re-bind skips the ensure
 * and PUTs straight away; the first bind, which carries no stamp,
 * provisions. The unlock identity and the record are real; only the
 * unlock-Space HTTP seam is mocked, and each mocked call records the
 * requests it would have made.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'

const state = vi.hoisted(() => ({
  requests: [] as string[],
  records: new Map<string, unknown>(),
  putFails: false
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  // The four no-op round trips the ensure makes on an existing Space, named
  // so an assertion can read the stage's whole request list.
  ensureUnlockSpace: vi.fn(async () => {
    state.requests.push(
      'space-describe',
      'space-configure',
      'collection-describe',
      'collection-configure'
    )
  }),
  putUnlockKeyring: vi.fn(
    async ({ spaceId, record }: { spaceId: string; record: unknown }) => {
      state.requests.push('record-put')
      if (state.putFails) {
        // What the server answers for a Space that is not there. The masked
        // 404 covers absent and unauthorized alike.
        throw new Error('Not Found')
      }
      state.records.set(spaceId, record)
    }
  )
}))

import {
  ensureUnlockSpace,
  putUnlockKeyring,
  KEYRING_KDF
} from '@interop/wallet-core/keyring'
import { generateLadderSeed } from '@interop/wallet-core/clientAnnex'
import {
  bindCredentialAnchoredUnlockSecret,
  deriveUnlockCredential,
  type UnlockCredential
} from '@/session/keyring'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const CONTROLLER = 'did:key:z6MkLadderVmBootstrapIdentity'
const PASSPHRASE = 'the chosen passphrase for the credential-anchored bind'
const DELEGATION = {
  id: 'urn:zcap:delegated:test',
  controller: 'did:key:z6MkGrantee',
  invocationTarget: `${POINTER.host}/space/${POINTER.spaceId}/id/did.jsonl`,
  parentCapability: 'urn:zcap:root:test',
  proof: { verificationMethod: `${POINTER.did}#z6MkLadderVm` }
} as unknown as IZcap

let credential: UnlockCredential

beforeEach(async () => {
  state.requests.length = 0
  state.records.clear()
  state.putFails = false
  vi.clearAllMocks()
  credential = await deriveUnlockCredential({
    secret: PASSPHRASE,
    kdf: KEYRING_KDF
  })
})

describe('the credential-anchored bind', () => {
  it('provisions the Space on the first bind (no prior stamp)', async () => {
    const bound = await bindCredentialAnchoredUnlockSecret({
      controller: CONTROLLER,
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host },
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      credential
    })

    expect(ensureUnlockSpace).toHaveBeenCalledTimes(1)
    expect(putUnlockKeyring).toHaveBeenCalledTimes(1)
    expect(state.requests).toEqual([
      'space-describe',
      'space-configure',
      'collection-describe',
      'collection-configure',
      'record-put'
    ])
    expect(bound.createdAt).toBeDefined()
  })

  it('skips the ensure on a re-bind carrying the first bind stamp', async () => {
    const first = await bindCredentialAnchoredUnlockSecret({
      controller: CONTROLLER,
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host },
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      credential
    })
    state.requests.length = 0
    vi.clearAllMocks()

    // The establishment's re-bind: the full pointer, the ladder-VM-signed
    // bridge and sibling, and the management zcap to the account DID. The
    // delegation is pure signing, so the whole stage is one request.
    const rebound = await bindCredentialAnchoredUnlockSecret({
      controller: CONTROLLER,
      pointer: POINTER,
      delegation: DELEGATION,
      delegatedClients: DELEGATION,
      ladderSeed: generateLadderSeed(),
      delegateManagementTo: POINTER.did,
      priorCreatedAt: first.createdAt,
      credential
    })

    expect(ensureUnlockSpace).not.toHaveBeenCalled()
    expect(state.requests).toEqual(['record-put'])
    expect(rebound.manageCapability).toBeDefined()
    expect(Date.parse(rebound.createdAt)).toBeGreaterThan(
      Date.parse(first.createdAt)
    )
  })

  it('skips the ensure on a heal re-run started from a standing hit', async () => {
    // The other re-bind shape: no interim bind ran this visit, and the prior
    // stamp comes from the served standing record the heal read.
    await bindCredentialAnchoredUnlockSecret({
      controller: CONTROLLER,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      priorCreatedAt: '2026-09-01T00:00:00.000Z',
      credential
    })

    expect(ensureUnlockSpace).not.toHaveBeenCalled()
    expect(state.requests).toEqual(['record-put'])
  })

  it('fails loudly when a re-bind meets a Space that is gone', async () => {
    state.putFails = true

    await expect(
      bindCredentialAnchoredUnlockSecret({
        controller: CONTROLLER,
        pointer: POINTER,
        delegation: DELEGATION,
        ladderSeed: generateLadderSeed(),
        priorCreatedAt: '2026-09-01T00:00:00.000Z',
        credential
      })
    ).rejects.toThrow('Not Found')

    // The 404 surfaces as a bind failure rather than being answered by a
    // silent re-creation under the bootstrap key.
    expect(ensureUnlockSpace).not.toHaveBeenCalled()
    expect(state.records.size).toBe(0)
  })
})
