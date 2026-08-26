// @vitest-environment node
/**
 * Unit tests for the grant path's generation-delegation renewal stage
 * (`renewTransientGenerationDelegation` in `src/session/annexReach.ts`): the
 * ladder-VM gate it opens with, what it hands wallet-core's ensure, and what
 * it swaps the fresh delegation into. The ensure and the account-log
 * verification are mocked at the module seam; the ladder VM's own multibase
 * derivation runs for real, so the gate is exercised against real key
 * material rather than a stubbed comparison.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  ensureGenerationDelegationCurrent: vi.fn(),
  clientAnnexLogStore: vi.fn(() => ({ isAnnexLogStore: true }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn()
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  WasClient: vi.fn(function WasClientStub(this: Record<string, unknown>) {
    this.isWasClientStub = true
  })
}))

import {
  ensureGenerationDelegationCurrent,
  ladderVmKeyMultibase
} from '@interop/wallet-core/clientAnnex'
import { verifyAccountLog } from '@interop/wallet-core/webvh'
import { renewTransientGenerationDelegation } from '@/session/annexReach'
import type { Session } from '@/types/auth'

const ACCOUNT_DID =
  'did:webvh:QmScidForTests:was.example.test:space:space-123:id'
const POINTER = {
  did: ACCOUNT_DID,
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const CLIENT_ANNEX_DID =
  'did:webvh:QmClientAnnexScid:was.example.test:space:clientAnnex-space-1:gen-Ux3v0kQf9aPmB2hZ'
const LADDER_SEED = new Uint8Array(32).fill(7)
const STALE_DELEGATION = { id: 'urn:zcap:generation-stale' }
const FRESH_DELEGATION = { id: 'urn:zcap:generation-fresh' }
const SIBLING_DELEGATION = { id: 'urn:zcap:sibling' }

/**
 * The account document as the gate reads it: `ladderVmIds` recognizes the
 * ladder VM by its relation asymmetry (`capabilityDelegation` without
 * `capabilityInvocation`).
 *
 * @param options {object}
 * @param options.vmId {string}   the ladder VM's id
 * @returns {object}
 */
function documentAnchoring({ vmId }: { vmId: string }) {
  return {
    id: ACCOUNT_DID,
    verificationMethod: [
      {
        id: vmId,
        type: 'Multikey',
        controller: ACCOUNT_DID,
        publicKeyMultibase: vmId.split('#')[1]
      }
    ],
    assertionMethod: [vmId],
    capabilityDelegation: [vmId]
  }
}

/**
 * A transient session with the standing members the login stamps.
 */
function transientSession() {
  const adoptInvocationCapability = vi.fn()
  const handle = {
    durability: 'in-memory',
    logPins: { isLogPinStore: true },
    clientAnnex: {
      clientAnnexDid: CLIENT_ANNEX_DID,
      invocationCapability: STALE_DELEGATION
    }
  }
  const session = {
    storage: { remoteStore: { adoptInvocationCapability } },
    profile: {
      accountPointer: POINTER,
      invocationCapability: STALE_DELEGATION,
      ladderSeed: LADDER_SEED,
      persistence: handle,
      standingUnlock: {
        delegation: { id: 'urn:zcap:bridge' },
        delegatedClients: SIBLING_DELEGATION,
        standingClient: {
          clientDid: 'did:key:z6MkStandingClient',
          agents: { zcapClient: { isCredentialZcapClient: true } }
        },
        unlockSpaceId: 'unlock-space-1'
      }
    }
  } as unknown as Session
  return { session, handle, adoptInvocationCapability }
}

beforeEach(() => {
  vi.mocked(ensureGenerationDelegationCurrent).mockResolvedValue({
    renewed: true,
    delegation: FRESH_DELEGATION
  } as never)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('renewTransientGenerationDelegation', () => {
  it('renews on a document anchoring this ladder, and swaps it in', async () => {
    const vmKey = await ladderVmKeyMultibase({ ladderSeed: LADDER_SEED })
    const doc = documentAnchoring({ vmId: `${ACCOUNT_DID}#${vmKey}` })
    vi.mocked(verifyAccountLog).mockResolvedValue({
      did: ACCOUNT_DID,
      doc,
      log: []
    } as never)
    const { session, handle, adoptInvocationCapability } = transientSession()

    const renewed = await renewTransientGenerationDelegation({ session })

    expect(renewed).toBe(FRESH_DELEGATION)
    // The verified document rides along as the ensure's signer-rot axis.
    const ensureCall = vi.mocked(ensureGenerationDelegationCurrent).mock
      .calls[0]![0]
    expect(ensureCall.accountDoc).toBe(doc)
    expect(ensureCall.ladderSeed).toBe(LADDER_SEED)
    expect(ensureCall.expectedDid).toBe(CLIENT_ANNEX_DID)
    expect(ensureCall.pinStore).toBe(handle.logPins)
    // The live session adopts it everywhere a reader looks.
    expect(session.profile.invocationCapability).toBe(FRESH_DELEGATION)
    expect(handle.clientAnnex.invocationCapability).toBe(FRESH_DELEGATION)
    expect(adoptInvocationCapability).toHaveBeenCalledWith({
      capability: FRESH_DELEGATION
    })
  })

  it('refuses to mint when the document anchors no ladder VM of this credential', async () => {
    // The account the transient login's fallback serves: enrolled durable
    // clients, the ladder VM struck by the self-enrollment's add entry. A
    // delegation signed by it would authorize nothing and would poison the
    // annex log for every later visit.
    vi.mocked(verifyAccountLog).mockResolvedValue({
      did: ACCOUNT_DID,
      doc: { id: ACCOUNT_DID, verificationMethod: [] },
      log: []
    } as never)
    const { session, adoptInvocationCapability } = transientSession()

    expect(await renewTransientGenerationDelegation({ session })).toBeNull()
    expect(ensureGenerationDelegationCurrent).not.toHaveBeenCalled()
    expect(session.profile.invocationCapability).toBe(STALE_DELEGATION)
    expect(adoptInvocationCapability).not.toHaveBeenCalled()
  })

  it('refuses to mint on another ladder VM than this credentials', async () => {
    const otherKey = await ladderVmKeyMultibase({
      ladderSeed: new Uint8Array(32).fill(9)
    })
    vi.mocked(verifyAccountLog).mockResolvedValue({
      did: ACCOUNT_DID,
      doc: documentAnchoring({ vmId: `${ACCOUNT_DID}#${otherKey}` }),
      log: []
    } as never)
    const { session } = transientSession()

    expect(await renewTransientGenerationDelegation({ session })).toBeNull()
    expect(ensureGenerationDelegationCurrent).not.toHaveBeenCalled()
  })

  it('reports a failed account-log verification as "cannot renew"', async () => {
    vi.mocked(verifyAccountLog).mockRejectedValue(new Error('offline'))
    const { session } = transientSession()

    expect(await renewTransientGenerationDelegation({ session })).toBeNull()
    expect(ensureGenerationDelegationCurrent).not.toHaveBeenCalled()
  })

  it('returns null for a session holding no ladder members', async () => {
    const { session } = transientSession()
    delete (session.profile as { ladderSeed?: unknown }).ladderSeed

    expect(await renewTransientGenerationDelegation({ session })).toBeNull()
    expect(verifyAccountLog).not.toHaveBeenCalled()
  })
})
