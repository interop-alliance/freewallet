// @vitest-environment node
/**
 * Unit tests for the standing-delegation self-refresh
 * (`src/session/standingDelegationRefresh.ts`).
 *
 * The refresh answers one question on two axes: is either member expiring,
 * and is its signer still listed under `capabilityDelegation` in the account
 * document. Only the second axis needs the account log, so the log arrives as
 * a thunk the expiring branch never calls -- a did.jsonl the host cannot
 * serve, or one a chain-head pin refuses, must not stand the re-mint down.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'

const state = vi.hoisted(() => ({
  expiring: false,
  listed: true
}))

// No storage server: the registry refresh at the tail of a re-mint then runs
// over this browser's cache alone, which is empty here, so it is a read and
// no write. Keeping it real is what lets this file mock no registry module
// and still assert the re-mint's whole sequence.
vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return undefined
  }
}))

vi.mock('@interop/wallet-core/recovery', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/recovery')>()),
  zcapExpiring: vi.fn(() => state.expiring),
  delegationProofKeyId: vi.fn(
    (zcap: { id?: string }) => `${zcap.id ?? 'zcap'}#key`
  ),
  delegateLogWrite: vi.fn(async () => ({ id: 'urn:zcap:fresh-bridge' }))
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  delegatedClientsDelegationSpaceId: vi.fn(() => 'annex-space-1'),
  mintDelegatedClientsDelegation: vi.fn(async () => ({
    id: 'urn:zcap:fresh-sibling'
  }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  delegationKeyInDocument: vi.fn(() => state.listed)
}))

vi.mock('@/lib/zcap', () => ({
  zcapExpires: vi.fn(() => '2027-01-01T00:00:00Z')
}))

import { delegateLogWrite } from '@interop/wallet-core/recovery'
import { delegationKeyInDocument } from '@interop/wallet-core/webvh'
import { refreshStandingDelegations } from '@/session/standingDelegationRefresh'

const POINTER = {
  did: 'did:webvh:QmScid:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const STANDING_CLIENT_DID = 'did:key:z6MkStandingCredential'

/**
 * The members the acting credential's unlock record carries today.
 */
function standingMembers() {
  return {
    delegation: { id: 'urn:zcap:stale-bridge' } as unknown as IZcap,
    delegatedClients: { id: 'urn:zcap:stale-sibling' } as unknown as IZcap
  }
}

/**
 * A session holding what the refresh reads off it, plus the members the
 * registry write at its tail needs: this browser's (empty) unlock-methods
 * cache and the vault keys that cache is read under.
 */
function fakeSession(): {
  session: Session
  loadRegistry: ReturnType<typeof vi.fn>
} {
  const loadRegistry = vi.fn(async () => null)
  const session = {
    user: { id: 'did:key:z6MkClient' },
    profile: {
      zcapClient: { isFakeZcapClient: true },
      standingUnlock: { ...standingMembers() },
      userKey: { id: 'did:key:z6LSVault', secret: new Uint8Array(32) },
      keyAgreementKey: { id: 'did:key:z6LSVault#kak' },
      keyResolver: async () => ({})
    },
    persistence: {
      unlockMethodsCache: {
        load: loadRegistry,
        save: vi.fn(async () => undefined),
        delete: vi.fn(async () => undefined)
      }
    }
  } as unknown as Session
  return { session, loadRegistry }
}

/**
 * A verified-log thunk that fails the way an unreadable did.jsonl (or a pin
 * refusal) fails, and counts its calls.
 */
function rejectingLog() {
  return vi.fn(async () => {
    throw new Error('did.jsonl could not be read')
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  state.expiring = false
  state.listed = true
})

describe('the standing-delegation self-refresh', () => {
  it('re-mints an expiring pair without reading the account log', async () => {
    state.expiring = true
    const verifiedLog = rejectingLog()
    const rebindStandingRecord = vi.fn(async () => undefined)
    const { session, loadRegistry } = fakeSession()

    const outcome = await refreshStandingDelegations({
      session,
      pointer: POINTER,
      verifiedLog: verifiedLog as never,
      rebindStandingRecord,
      ...standingMembers(),
      standingClientDid: STANDING_CLIENT_DID,
      unlockSpaceId: 'unlock-space-test'
    })

    expect(outcome).toBe('refreshed')
    // The log is the not-expiring branch's question alone.
    expect(verifiedLog).not.toHaveBeenCalled()
    expect(delegationKeyInDocument).not.toHaveBeenCalled()
    expect(delegateLogWrite).toHaveBeenCalledOnce()
    expect(rebindStandingRecord).toHaveBeenCalledWith({
      delegation: { id: 'urn:zcap:fresh-bridge' },
      delegatedClients: { id: 'urn:zcap:fresh-sibling' }
    })
    // The fresh members are recorded on the credential's registry entry.
    expect(loadRegistry).toHaveBeenCalledOnce()
    // The live session acts through the members it carries.
    expect(session.profile.standingUnlock).toMatchObject({
      delegation: { id: 'urn:zcap:fresh-bridge' }
    })
  })

  it('reads the log on the not-expiring branch, and no-ops on a listed signer', async () => {
    const verifiedLog = vi.fn(async () => ({ doc: { id: POINTER.did } }))

    const outcome = await refreshStandingDelegations({
      session: fakeSession().session,
      pointer: POINTER,
      verifiedLog: verifiedLog as never,
      rebindStandingRecord: vi.fn(async () => undefined),
      ...standingMembers(),
      standingClientDid: STANDING_CLIENT_DID,
      unlockSpaceId: 'unlock-space-test'
    })

    expect(outcome).toBe('noop')
    expect(verifiedLog).toHaveBeenCalledOnce()
    expect(delegateLogWrite).not.toHaveBeenCalled()
  })

  it('re-mints on the not-expiring branch when the signer has left the document', async () => {
    state.listed = false
    const verifiedLog = vi.fn(async () => ({ doc: { id: POINTER.did } }))

    const outcome = await refreshStandingDelegations({
      session: fakeSession().session,
      pointer: POINTER,
      verifiedLog: verifiedLog as never,
      rebindStandingRecord: vi.fn(async () => undefined),
      ...standingMembers(),
      standingClientDid: STANDING_CLIENT_DID,
      unlockSpaceId: 'unlock-space-test'
    })

    expect(outcome).toBe('refreshed')
    expect(delegateLogWrite).toHaveBeenCalledOnce()
  })

  it('lets an unreadable log through to the runner when nothing is expiring', async () => {
    const verifiedLog = rejectingLog()

    await expect(
      refreshStandingDelegations({
        session: fakeSession().session,
        pointer: POINTER,
        verifiedLog: verifiedLog as never,
        rebindStandingRecord: vi.fn(async () => undefined),
        ...standingMembers(),
        standingClientDid: STANDING_CLIENT_DID,
        unlockSpaceId: 'unlock-space-test'
      })
    ).rejects.toThrow('did.jsonl could not be read')
    expect(delegateLogWrite).not.toHaveBeenCalled()
  })
})
