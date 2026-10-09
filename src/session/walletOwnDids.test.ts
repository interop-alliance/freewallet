// @vitest-environment node
/**
 * Unit tests for `walletOwnDids` (`src/session/clients.ts`), the set a
 * server-observed `createdBy` is checked against before it is named as a
 * foreign creator: this session's own identities, the client-annex DID a
 * transient session invokes as, and every wallet client, ladder VM, and annex
 * DID any entry of the verified account log named. The verified log is
 * mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { delegatedClientsServiceEntry } from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'

const ACCOUNT_DID = 'did:webvh:QmScid:was.example:space:s:id'
const ANNEX_DID = 'did:webvh:QmAnnex:was.example:space:a:id'
const EARLIER_ANNEX_DID = 'did:webvh:QmEarlier:was.example:space:e:id'

const state = vi.hoisted(() => ({
  log: [] as Array<{ state: Record<string, unknown> }>,
  logThrows: null as Error | null
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(async () => {
    if (state.logThrows) {
      throw state.logThrows
    }
    return { log: state.log, doc: state.log.at(-1)?.state ?? {} }
  })
}))

const { walletOwnDids } = await import('@/session/clients')
const { verifiedAccountLog } = await import('@/session/verifiedLog')

/**
 * A session on the account `did`, remembered (browser-local) unless a
 * client-annex DID is given, which makes it transient (in-memory).
 *
 * @param options {object}
 * @param [options.did] {string}
 * @param [options.keyAgentId] {string}
 * @param [options.accountController] {string}
 * @param [options.clientAnnexDid] {string}
 * @returns {Session}
 */
function makeSession({
  did = ACCOUNT_DID,
  keyAgentId,
  accountController,
  clientAnnexDid
}: {
  did?: string
  keyAgentId?: string
  accountController?: string
  clientAnnexDid?: string
} = {}): Session {
  return {
    user: { id: did },
    profile: {
      accountPointer: { did, spaceId: 's', host: 'https://was.example' },
      ...(keyAgentId !== undefined ? { keyAgent: { id: keyAgentId } } : {}),
      ...(accountController !== undefined ? { accountController } : {})
    },
    persistence:
      clientAnnexDid !== undefined
        ? {
            storage: 'in-memory',
            clientAnnex: { clientAnnexDid, invocationCapability: {} }
          }
        : { storage: 'indexeddb' }
  } as unknown as Session
}

/**
 * One log entry: enrolled clients under `capabilityInvocation` (and
 * `capabilityDelegation`), ladder VMs under `capabilityDelegation` alone, and
 * an optional delegated-clients annex pointer.
 *
 * @param options {object}
 * @param [options.clients] {string[]}   enrolled clients' key multibases
 * @param [options.ladders] {string[]}   ladder VMs' key multibases
 * @param [options.annexDid] {string}   the annex DID the document points at
 * @returns {object}
 */
function logEntry({
  clients = [],
  ladders = [],
  annexDid
}: {
  clients?: string[]
  ladders?: string[]
  annexDid?: string
}): { state: Record<string, unknown> } {
  const clientVms = clients.map(multibase => `${ACCOUNT_DID}#${multibase}`)
  const ladderVms = ladders.map(multibase => `${ACCOUNT_DID}#${multibase}`)
  return {
    state: {
      id: ACCOUNT_DID,
      verificationMethod: [...clients, ...ladders].map(multibase => ({
        id: `${ACCOUNT_DID}#${multibase}`,
        type: 'Multikey',
        controller: ACCOUNT_DID,
        publicKeyMultibase: multibase
      })),
      capabilityInvocation: clientVms,
      capabilityDelegation: [...clientVms, ...ladderVms],
      ...(annexDid !== undefined && {
        service: [
          delegatedClientsServiceEntry({
            accountDid: ACCOUNT_DID,
            clientAnnexDid: annexDid
          })
        ]
      })
    }
  }
}

beforeEach(() => {
  state.log = []
  state.logThrows = null
  vi.mocked(verifiedAccountLog).mockClear()
})

describe('walletOwnDids', () => {
  it("holds the account DID and this session's own identities", async () => {
    const dids = await walletOwnDids({
      session: makeSession({
        keyAgentId: 'did:key:z6MkOwn',
        accountController: 'did:key:z6MkBootstrap'
      })
    })
    expect(dids).toEqual(
      new Set([ACCOUNT_DID, 'did:key:z6MkOwn', 'did:key:z6MkBootstrap'])
    )
  })

  it('holds every wallet client and ladder VM any log entry listed, a revoked client included', async () => {
    state.log = [
      logEntry({ ladders: ['z6MkLadder'] }),
      logEntry({
        clients: ['z6MkFirst', 'z6MkRevoked'],
        ladders: ['z6MkLadder']
      }),
      logEntry({ clients: ['z6MkFirst'], ladders: ['z6MkLadder'] })
    ]
    const dids = await walletOwnDids({ session: makeSession() })
    expect(dids.has('did:key:z6MkFirst')).toBe(true)
    expect(dids.has('did:key:z6MkRevoked')).toBe(true)
    expect(dids.has('did:key:z6MkLadder')).toBe(true)
  })

  it('holds the client-annex DID a transient session invokes as', async () => {
    const dids = await walletOwnDids({
      session: makeSession({ clientAnnexDid: ANNEX_DID })
    })
    expect(dids.has(ANNEX_DID)).toBe(true)
  })

  it('holds every annex DID the account document pointed at', async () => {
    state.log = [
      logEntry({ annexDid: EARLIER_ANNEX_DID }),
      logEntry({ annexDid: ANNEX_DID })
    ]
    const dids = await walletOwnDids({ session: makeSession() })
    expect(dids.has(EARLIER_ANNEX_DID)).toBe(true)
    expect(dids.has(ANNEX_DID)).toBe(true)
  })

  it("reads no log when the pointer names a did:key, and keeps the session's own set", async () => {
    const dids = await walletOwnDids({
      session: makeSession({
        did: 'did:key:z6MkAccount',
        keyAgentId: 'did:key:z6MkAccount'
      })
    })
    expect(dids).toEqual(new Set(['did:key:z6MkAccount']))
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it("keeps the session's own set when the log cannot be verified", async () => {
    state.logThrows = new Error('log continuity broken')
    const dids = await walletOwnDids({
      session: makeSession({ clientAnnexDid: ANNEX_DID })
    })
    expect(dids).toEqual(new Set([ACCOUNT_DID, ANNEX_DID]))
  })
})
