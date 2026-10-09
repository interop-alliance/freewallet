// @vitest-environment node
/**
 * Unit tests for `listedClientDids` (`src/session/clients.ts`), the set the
 * interaction-URL page's enrolled-client refusal reads: the did:key of every
 * wallet client any entry of the verified account log listed, a revoked one
 * included, or this session's own did:key on an account with no account
 * document. The verified log is mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'

const ACCOUNT_DID = 'did:webvh:QmScid:was.example:space:s:id'

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

const { listedClientDids } = await import('@/session/clients')
const { verifiedAccountLog } = await import('@/session/verifiedLog')

/**
 * A session whose account pointer names `did`.
 *
 * @param options {object}
 * @param [options.did] {string}
 * @returns {Session}
 */
function makeSession({
  did = ACCOUNT_DID,
  keyAgentId
}: { did?: string; keyAgentId?: string } = {}): Session {
  return {
    user: { id: did },
    profile: {
      accountPointer: { did, spaceId: 's', host: 'https://was.example' },
      ...(keyAgentId !== undefined ? { keyAgent: { id: keyAgentId } } : {})
    }
  } as unknown as Session
}

/**
 * One log entry whose document lists the given clients' signing keys under
 * `capabilityInvocation`.
 *
 * @param options {object}
 * @param options.clients {string[]}   signing-key multibases
 * @returns {object}
 */
function logEntry({ clients }: { clients: string[] }): {
  state: Record<string, unknown>
} {
  return {
    state: {
      id: ACCOUNT_DID,
      verificationMethod: clients.map(multibase => ({
        id: `${ACCOUNT_DID}#${multibase}`,
        type: 'Multikey',
        controller: ACCOUNT_DID,
        publicKeyMultibase: multibase
      })),
      capabilityInvocation: clients.map(
        multibase => `${ACCOUNT_DID}#${multibase}`
      )
    }
  }
}

beforeEach(() => {
  state.log = []
  state.logThrows = null
  vi.mocked(verifiedAccountLog).mockClear()
})

describe('listedClientDids', () => {
  it('returns every client any log entry listed, a revoked one included', async () => {
    state.log = [
      logEntry({ clients: ['z6MkFirst'] }),
      logEntry({ clients: ['z6MkFirst', 'z6MkRevoked'] }),
      // The revocation entry: the revoked client is gone from the document.
      logEntry({ clients: ['z6MkFirst', 'z6MkLater'] })
    ]
    const dids = await listedClientDids({ session: makeSession() })
    expect([...dids].sort()).toEqual(
      ['did:key:z6MkFirst', 'did:key:z6MkLater', 'did:key:z6MkRevoked'].sort()
    )
  })

  it("resolves this session's own did:key, reading no log, when the pointer names a did:key", async () => {
    const dids = await listedClientDids({
      session: makeSession({
        did: 'did:key:z6MkAccount',
        keyAgentId: 'did:key:z6MkAccount'
      })
    })
    expect([...dids]).toEqual(['did:key:z6MkAccount'])
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it("resolves this session's own did:key when the session has no account pointer", async () => {
    const session = makeSession({ keyAgentId: 'did:key:z6MkOwn' })
    delete (session.profile as { accountPointer?: unknown }).accountPointer
    const dids = await listedClientDids({ session })
    expect([...dids]).toEqual(['did:key:z6MkOwn'])
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it('resolves an empty set when the session holds no did:key agent and names no did:webvh', async () => {
    const dids = await listedClientDids({
      session: makeSession({ did: 'did:key:z6MkGuest' })
    })
    expect(dids.size).toBe(0)
    expect(verifiedAccountLog).not.toHaveBeenCalled()
  })

  it('propagates a log that cannot be verified', async () => {
    state.logThrows = new Error('log continuity broken')
    await expect(listedClientDids({ session: makeSession() })).rejects.toThrow(
      'log continuity broken'
    )
  })
})
