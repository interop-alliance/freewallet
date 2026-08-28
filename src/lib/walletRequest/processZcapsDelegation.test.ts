// @vitest-environment node
import { describe, it, expect, vi, afterEach } from 'vitest'

vi.mock('@/session/annexReach', () => ({
  renewTransientGenerationDelegation: vi.fn(async () => null)
}))

import type { Session } from '@/types/auth'
import { renewTransientGenerationDelegation } from '@/session/annexReach'
import { ZCAP_RENEWAL_WINDOW_MS } from '@interop/wallet-core/webvh'
import { RP_ZCAP_WRITE_TTL_MS } from '@/app.config'
import { GenerationDelegationStaleError, processZcaps } from './processZcaps'
import type { ICapabilityQueryDetail, IZcap } from './types'

const SPACE_URL = 'https://was.example/space/abc'
const NOW = Date.parse('2026-08-22T12:00:00Z')
const DAY_MS = 24 * 60 * 60 * 1000
const WRITE_DESCRIPTOR: ICapabilityQueryDetail = {
  referenceId: 'docs',
  allowedAction: ['GET', 'PUT'],
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'docs'
  },
  controller: 'did:key:z6MkTest'
}

/**
 * A generation delegation expiring the given number of days after `NOW`.
 *
 * @param daysOut {number}
 * @returns {IZcap}
 */
function delegationExpiringIn(daysOut: number): IZcap {
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id: 'urn:zcap:delegated:generation',
    controller: 'did:webvh:annex',
    invocationTarget: SPACE_URL,
    parentCapability: `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`,
    expires: new Date(NOW + daysOut * DAY_MS).toISOString()
  } as unknown as IZcap
}

/**
 * The minimal session `processZcaps` delegates from: `hasZcapStorage` needs
 * `hasRemoteStorage` and a resolved `spaceUrl`; the delegate mock echoes its
 * arguments so the parent and expiry it was handed can be asserted.
 *
 * @param options {object}
 * @param [options.invocationCapability] {IZcap}
 * @returns {{ session: Session, delegate: ReturnType<typeof vi.fn> }}
 */
function fakeSession({
  invocationCapability
}: { invocationCapability?: IZcap } = {}) {
  const delegate = vi.fn(async (args: Record<string, unknown>) => ({
    id: 'urn:zcap:delegated',
    ...args
  }))
  const listCollectionPublicStates = vi.fn(async () => [])
  const session = {
    user: { id: 'did:key:z6MkUser' },
    storage: {
      hasRemoteStorage: true,
      spaceUrl: SPACE_URL,
      listCollectionPublicStates,
      ensureCollection: vi.fn(async () => {}),
      provisionAppCollection: vi.fn(async () => {})
    },
    profile: {
      zcapClient: { delegate },
      invocationCapability
    }
  } as unknown as Session
  return { session, delegate, listCollectionPublicStates }
}

describe('processZcaps delegation parent', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.mocked(renewTransientGenerationDelegation).mockResolvedValue(null)
  })

  it('delegates under the generation delegation with the full write TTL when the parent outlives it', async () => {
    vi.useFakeTimers({ now: NOW })
    const invocationCapability = delegationExpiringIn(100)
    const { session, delegate } = fakeSession({ invocationCapability })
    const zcaps = await processZcaps({
      zcapRequests: [WRITE_DESCRIPTOR],
      session
    })
    expect(zcaps).toHaveLength(1)
    expect(delegate).toHaveBeenCalledTimes(1)
    const args = delegate.mock.calls[0][0]
    expect(args.capability).toBe(invocationCapability)
    expect((args.expires as Date).getTime()).toBe(NOW + RP_ZCAP_WRITE_TTL_MS)
  })

  it('clamps the grant expiry to the parent when the parent expires first', async () => {
    vi.useFakeTimers({ now: NOW })
    const invocationCapability = delegationExpiringIn(
      ZCAP_RENEWAL_WINDOW_MS / DAY_MS + 2
    )
    const { session, delegate } = fakeSession({ invocationCapability })
    await processZcaps({
      zcapRequests: [WRITE_DESCRIPTOR],
      session,
      writeTtlMs: (ZCAP_RENEWAL_WINDOW_MS / DAY_MS + 7) * DAY_MS
    })
    const args = delegate.mock.calls[0][0]
    expect(args.capability).toBe(invocationCapability)
    expect((args.expires as Date).toISOString()).toBe(
      (invocationCapability as { expires: string }).expires
    )
  })

  it('refuses to mint under an expired generation delegation with nothing to renew', async () => {
    vi.useFakeTimers({ now: NOW })
    const { session, delegate } = fakeSession({
      invocationCapability: delegationExpiringIn(-1)
    })
    await expect(
      processZcaps({ zcapRequests: [WRITE_DESCRIPTOR], session })
    ).rejects.toBeInstanceOf(GenerationDelegationStaleError)
    expect(delegate).not.toHaveBeenCalled()
  })

  it('refuses to mint under a generation delegation inside its renewal window', async () => {
    vi.useFakeTimers({ now: NOW })
    const { session, delegate } = fakeSession({
      invocationCapability: delegationExpiringIn(2)
    })
    const failure = await processZcaps({
      zcapRequests: [WRITE_DESCRIPTOR],
      session
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(GenerationDelegationStaleError)
    expect((failure as Error).name).toBe('GenerationDelegationStaleError')
    expect(delegate).not.toHaveBeenCalled()
  })

  it('renews a stale generation delegation and mints under the fresh one', async () => {
    vi.useFakeTimers({ now: NOW })
    const renewed = delegationExpiringIn(100)
    vi.mocked(renewTransientGenerationDelegation).mockResolvedValue(
      renewed as never
    )
    const { session, delegate } = fakeSession({
      invocationCapability: delegationExpiringIn(2)
    })
    await processZcaps({ zcapRequests: [WRITE_DESCRIPTOR], session })
    expect(renewTransientGenerationDelegation).toHaveBeenCalledWith({ session })
    const args = delegate.mock.calls[0][0]
    expect(args.capability).toBe(renewed)
    expect((args.expires as Date).getTime()).toBe(NOW + RP_ZCAP_WRITE_TTL_MS)
  })

  it('refuses when the renewal itself returns a still-stale delegation', async () => {
    vi.useFakeTimers({ now: NOW })
    vi.mocked(renewTransientGenerationDelegation).mockResolvedValue(
      delegationExpiringIn(1) as never
    )
    const { session, delegate } = fakeSession({
      invocationCapability: delegationExpiringIn(-1)
    })
    await expect(
      processZcaps({ zcapRequests: [WRITE_DESCRIPTOR], session })
    ).rejects.toBeInstanceOf(GenerationDelegationStaleError)
    expect(delegate).not.toHaveBeenCalled()
  })

  it('renews before the collection listing rides the same delegation', async () => {
    // The listing invokes the generation delegation too, so an already
    // expired one must be replaced before it is used -- otherwise the
    // approval dies of a generic listing failure and the renewal never runs.
    vi.useFakeTimers({ now: NOW })
    vi.mocked(renewTransientGenerationDelegation).mockResolvedValue(
      delegationExpiringIn(100) as never
    )
    const { session, listCollectionPublicStates } = fakeSession({
      invocationCapability: delegationExpiringIn(-1)
    })
    await processZcaps({ zcapRequests: [WRITE_DESCRIPTOR], session })
    expect(
      vi.mocked(renewTransientGenerationDelegation).mock.invocationCallOrder[0]!
    ).toBeLessThan(listCollectionPublicStates.mock.invocationCallOrder[0]!)
  })

  it('delegates off the Space root with the unclamped TTL for a remembered session', async () => {
    vi.useFakeTimers({ now: NOW })
    const { session, delegate } = fakeSession()
    await processZcaps({ zcapRequests: [WRITE_DESCRIPTOR], session })
    const args = delegate.mock.calls[0][0]
    expect(args.capability).toBe(
      `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`
    )
    expect((args.expires as Date).getTime()).toBe(NOW + RP_ZCAP_WRITE_TTL_MS)
  })
})
