// @vitest-environment node
/**
 * The transient chain's keystore promotion (`TRANSIENT_KEYSTORE_PROMOTION`
 * in `src/session/menders/registrations.ts`). The torn state is a
 * credential-anchored establishment torn between the unlock-record re-bind
 * and its promotion tail, which leaves the WebKMS keystore controlled by the
 * ladder VM's bare did:key. The registration re-derives that did:key from
 * the login credential's ladder seed, lists under it, and promotes the
 * keystore it finds to the account did:webvh. A miss, a session with no
 * ladder seed (which the transient login refuses before the block runs), and
 * a deployment with no KMS each report a no-op and promote nothing.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import type { KeystoreAgent } from '@interop/webkms-client'
import type { Session } from '@/types/auth'

const kms = vi.hoisted(() => ({ url: undefined as string | undefined }))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get KMS_SERVER_URL() {
    return kms.url
  }
}))

vi.mock('@/lib/kms', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/kms')>()),
  findKeystoreAgent: vi.fn(),
  promoteKeystoreController: vi.fn()
}))

import { findKeystoreAgent, promoteKeystoreController } from '@/lib/kms'
import {
  TRANSIENT_KEYSTORE_PROMOTION,
  TRANSIENT_REGISTRATIONS,
  TRANSIENT_REGISTRY_REGISTRATIONS,
  type LoginMenderDeps
} from '@/session/menders/registrations'

const KMS_URL = 'https://was.example.test/kms'
const ACCOUNT_DID =
  'did:webvh:QmScidForTests:was.example.test:space:space-123:id'
const LADDER_SEED = new Uint8Array(32).fill(7)
const INVARIANT = 'keystore-controller-is-the-account-did'

/**
 * The transient deps the registration reads: the session's account pointer
 * and the keyring hit's ladder seed.
 *
 * @param options {object}
 * @param [options.ladderSeed] {Uint8Array}
 * @param [options.did] {string}   the pointer's account DID
 * @returns {LoginMenderDeps}
 */
function depsFor({
  ladderSeed,
  did = ACCOUNT_DID
}: {
  ladderSeed?: Uint8Array
  did?: string
}): LoginMenderDeps {
  const session = {
    profile: {
      accountPointer: {
        spaceUrl: 'https://was.example.test/space/space-123/',
        did
      }
    }
  } as unknown as Session
  return {
    chain: 'transient',
    session,
    found: {
      unlockSpaceId: 'unlock-space',
      ...(ladderSeed ? { standing: { delegation: {}, ladderSeed } } : {})
    },
    context: async () => null,
    rosterRead: {},
    generationDelegation: {}
  } as unknown as LoginMenderDeps
}

const STRANDED = { keystoreId: 'stranded' } as unknown as KeystoreAgent

beforeEach(() => {
  kms.url = KMS_URL
  vi.mocked(findKeystoreAgent).mockReset()
  vi.mocked(promoteKeystoreController).mockReset()
})

describe('the transient keystore promotion', () => {
  it('promotes a keystore listed under the ladder VM did:key to the account DID', async () => {
    vi.mocked(findKeystoreAgent).mockResolvedValue(STRANDED)
    vi.mocked(promoteKeystoreController).mockResolvedValue(true)

    const report = await TRANSIENT_KEYSTORE_PROMOTION.converge(
      depsFor({ ladderSeed: LADDER_SEED })
    )

    expect(report).toEqual([
      { invariant: INVARIANT, outcome: 'clean', detail: { promoted: true } }
    ])
    // The lookup lists under the did:key the establishment created the
    // keystore under, re-derived from the same ladder seed.
    const expected = await ladderVmAgent({ ladderSeed: LADDER_SEED })
    const lookup = vi.mocked(findKeystoreAgent).mock.calls[0]![0]
    expect(lookup.kmsServerUrl).toBe(KMS_URL)
    expect(lookup.keyAgent.id).toBe(expected.id)
    expect(lookup.controller).toBeUndefined()
    expect(promoteKeystoreController).toHaveBeenCalledWith({
      keystoreAgent: STRANDED,
      controller: ACCOUNT_DID
    })
  })

  it('reports a keystore already on the account DID as a no-op', async () => {
    vi.mocked(findKeystoreAgent).mockResolvedValue(STRANDED)
    vi.mocked(promoteKeystoreController).mockResolvedValue(false)

    const report = await TRANSIENT_KEYSTORE_PROMOTION.converge(
      depsFor({ ladderSeed: LADDER_SEED })
    )

    expect(report).toEqual([
      {
        invariant: INVARIANT,
        outcome: 'noop',
        detail: { reason: 'already-promoted' }
      }
    ])
  })

  it('reports a miss as a no-op and promotes nothing', async () => {
    vi.mocked(findKeystoreAgent).mockResolvedValue(undefined)

    const report = await TRANSIENT_KEYSTORE_PROMOTION.converge(
      depsFor({ ladderSeed: LADDER_SEED })
    )

    expect(report).toEqual([
      {
        invariant: INVARIANT,
        outcome: 'noop',
        detail: { reason: 'no-keystore-under-ladder-did-key' }
      }
    ])
    expect(promoteKeystoreController).not.toHaveBeenCalled()
  })

  it('reports a session with no ladder seed as a no-op', async () => {
    const report = await TRANSIENT_KEYSTORE_PROMOTION.converge(depsFor({}))

    expect(report).toEqual([
      {
        invariant: INVARIANT,
        outcome: 'noop',
        detail: { reason: 'no-ladder-seed' }
      }
    ])
    expect(findKeystoreAgent).not.toHaveBeenCalled()
  })

  it('reports a deployment with no KMS as a no-op', async () => {
    kms.url = undefined

    const report = await TRANSIENT_KEYSTORE_PROMOTION.converge(
      depsFor({ ladderSeed: LADDER_SEED })
    )

    expect(report).toEqual([
      { invariant: INVARIANT, outcome: 'noop', detail: { reason: 'no-kms' } }
    ])
    expect(findKeystoreAgent).not.toHaveBeenCalled()
  })

  it('reports an account still on a did:key as a no-op', async () => {
    const report = await TRANSIENT_KEYSTORE_PROMOTION.converge(
      depsFor({ ladderSeed: LADDER_SEED, did: 'did:key:z6MkBootstrap' })
    )

    expect(report).toEqual([
      {
        invariant: INVARIANT,
        outcome: 'noop',
        detail: { reason: 'unpromoted-account' }
      }
    ])
    expect(findKeystoreAgent).not.toHaveBeenCalled()
  })

  it('runs in the transient tail, outside the registry-writing list', () => {
    expect(TRANSIENT_REGISTRY_REGISTRATIONS).not.toContain(
      TRANSIENT_KEYSTORE_PROMOTION
    )
    expect(TRANSIENT_REGISTRATIONS.at(-1)).toBe(TRANSIENT_KEYSTORE_PROMOTION)
  })
})
