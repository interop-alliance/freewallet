/**
 * @vitest-environment node
 *
 * The agent half of the connected-grantee model: which activity rows list as
 * a connected agent (`listConnectedAgents` -- the Login predicate, the Revoke
 * join, the all-expired drop, and the name / key-fingerprint fallback), and
 * the revocation `revokeAgentAccess` performs (the server revocation before
 * the recorded activity, the never-skip rule, and the forward-floored Revoke
 * stamp).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  isAgentGrantLogin,
  listConnectedAgents,
  revokeAgentAccess
} from '@/lib/connectedApps'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'
import type { StorageManager } from '@/stores/storageManager'
import type { User } from '@/types/auth'

const AGENT_DID = 'did:key:z6MkAgent'
const FUTURE = '2099-01-01T00:00:00.000Z'
const PAST = '2000-01-01T00:00:00.000Z'

/**
 * One recorded grant entry, as the request page writes it onto the Login
 * activity's `object.zcaps`.
 */
function grantEntry({
  id = 'urn:zcap:one',
  expires = FUTURE,
  controller = AGENT_DID
}: { id?: string; expires?: string; controller?: string } = {}) {
  return {
    id,
    target: 'https://was.example/space/s/collection/notes',
    allowedActions: ['read'],
    expires,
    zcap: {
      id,
      controller,
      expires,
      parentCapability: 'urn:zcap:root:x',
      invocationTarget: 'https://was.example/space/s/collection/notes',
      proof: { verificationMethod: 'did:key:z6MkWallet#z6MkWallet' }
    }
  }
}

/**
 * An agent-grant Login activity, as the interaction-URL request page records
 * one.
 */
function agentLogin({
  created = '2026-08-01T00:00:00.000Z',
  name,
  zcaps = [grantEntry()]
}: {
  created?: string
  name?: string
  zcaps?: unknown[]
} = {}) {
  return {
    id: `login-${created}`,
    doc: {
      id: `login-${created}`,
      type: ['Login'],
      created,
      object: {
        origin: EXTERNAL_REQUEST_ORIGIN,
        ...(name !== undefined && { actor: { name } }),
        zcaps
      }
    }
  }
}

/**
 * A StorageManager double serving a fixed history scan.
 */
function storageWith(items: unknown[]): StorageManager {
  return {
    listHistoryItems: vi.fn(async () => items)
  } as unknown as StorageManager
}

describe('listConnectedAgents', () => {
  it('lists an agent-grant Login', async () => {
    const agents = await listConnectedAgents({
      storage: storageWith([agentLogin({ name: 'Deploy bot' })])
    })
    expect(agents).toHaveLength(1)
    expect(agents[0]).toMatchObject({
      controller: AGENT_DID,
      name: 'Deploy bot',
      origin: EXTERNAL_REQUEST_ORIGIN,
      grantedAt: '2026-08-01T00:00:00.000Z'
    })
    expect(agents[0].grants).toHaveLength(1)
  })

  it('falls back to the grantee key when no name was declared', async () => {
    const agents = await listConnectedAgents({
      storage: storageWith([agentLogin()])
    })
    expect(agents[0].name).toBeUndefined()
    expect(agents[0].controller).toBe(AGENT_DID)
  })

  it('does not list an App Connect Login', async () => {
    const appConnect = agentLogin()
    ;(appConnect.doc.object as Record<string, unknown>).origin =
      'https://app.example'
    ;(appConnect.doc.object as Record<string, unknown>).appConnect = {
      name: 'Demo App'
    }
    expect(isAgentGrantLogin({ doc: appConnect.doc })).toBe(false)
    expect(
      await listConnectedAgents({ storage: storageWith([appConnect]) })
    ).toEqual([])
  })

  it('does not list a plain CHAPI DIDAuth Login', async () => {
    const didAuth = {
      id: 'login-didauth',
      doc: {
        id: 'login-didauth',
        type: ['Login'],
        created: '2026-08-01T00:00:00.000Z',
        object: { origin: 'https://verifier.example' }
      }
    }
    expect(isAgentGrantLogin({ doc: didAuth.doc })).toBe(false)
    expect(
      await listConnectedAgents({ storage: storageWith([didAuth]) })
    ).toEqual([])
  })

  it('hides a row whose Revoke is at or after the Login', async () => {
    const revoke = {
      id: 'revoke-1',
      doc: {
        id: 'revoke-1',
        type: ['Revoke'],
        created: '2026-08-01T00:00:00.000Z',
        object: {
          origin: EXTERNAL_REQUEST_ORIGIN,
          controller: AGENT_DID,
          zcaps: [{ id: 'urn:zcap:one' }]
        }
      }
    }
    expect(
      await listConnectedAgents({
        storage: storageWith([agentLogin(), revoke])
      })
    ).toEqual([])
  })

  it('lists again after a re-grant newer than the Revoke', async () => {
    const revoke = {
      id: 'revoke-1',
      doc: {
        id: 'revoke-1',
        type: ['Revoke'],
        created: '2026-08-01T00:00:00.000Z',
        object: { origin: EXTERNAL_REQUEST_ORIGIN, controller: AGENT_DID }
      }
    }
    const agents = await listConnectedAgents({
      storage: storageWith([
        agentLogin(),
        revoke,
        agentLogin({ created: '2026-08-02T00:00:00.000Z', name: 'Again' })
      ])
    })
    expect(agents).toHaveLength(1)
    expect(agents[0].name).toBe('Again')
  })

  it('drops a row whose every recorded grant has expired', async () => {
    const expired = agentLogin({
      zcaps: [grantEntry({ expires: PAST })]
    })
    expect(
      await listConnectedAgents({ storage: storageWith([expired]) })
    ).toEqual([])
  })

  it('unions the grants of every live Login for the controller', async () => {
    // The newest request's grant has lapsed, but an older request's has not:
    // the row stays, carrying both, since the revocation scans every Login.
    const agents = await listConnectedAgents({
      storage: storageWith([
        agentLogin({
          created: '2026-08-01T00:00:00.000Z',
          zcaps: [grantEntry({ id: 'urn:zcap:old', expires: FUTURE })]
        }),
        agentLogin({
          created: '2026-08-02T00:00:00.000Z',
          name: 'Deploy bot',
          zcaps: [grantEntry({ id: 'urn:zcap:new', expires: PAST })]
        })
      ])
    })
    expect(agents).toHaveLength(1)
    expect(agents[0].grants.map(grant => grant.id).sort()).toEqual([
      'urn:zcap:new',
      'urn:zcap:old'
    ])
    expect(agents[0].name).toBe('Deploy bot')
    expect(agents[0].grantedAt).toBe('2026-08-02T00:00:00.000Z')
  })

  it('deduplicates a grant recorded on two Logins', async () => {
    const agents = await listConnectedAgents({
      storage: storageWith([
        agentLogin({ created: '2026-08-01T00:00:00.000Z' }),
        agentLogin({ created: '2026-08-02T00:00:00.000Z' })
      ])
    })
    expect(agents[0].grants).toHaveLength(1)
  })

  it('never hides a Login that carries no created stamp', async () => {
    const undated = agentLogin()
    delete (undated.doc as { created?: string }).created
    const revoke = {
      id: 'revoke-1',
      doc: {
        id: 'revoke-1',
        type: ['Revoke'],
        created: '2026-08-05T00:00:00.000Z',
        object: { origin: EXTERNAL_REQUEST_ORIGIN, controller: AGENT_DID }
      }
    }
    const agents = await listConnectedAgents({
      storage: storageWith([undated, revoke])
    })
    expect(agents).toHaveLength(1)
    expect(agents[0].grantedAt).toBeUndefined()
  })

  it('is not hidden by a Revoke of another shape', async () => {
    // An app revocation (its own origin, an appConnect member, a cid) and a
    // Revoke naming this controller under a foreign origin: neither is this
    // row's revocation.
    const appRevoke = {
      id: 'revoke-app',
      doc: {
        id: 'revoke-app',
        type: ['Revoke'],
        created: '2026-08-05T00:00:00.000Z',
        object: {
          origin: 'https://app.example',
          appConnect: { name: 'Demo App' },
          controller: AGENT_DID,
          cid: 'cid-1'
        }
      }
    }
    const foreignRevoke = {
      id: 'revoke-foreign',
      doc: {
        id: 'revoke-foreign',
        type: ['Revoke'],
        created: '2026-08-05T00:00:00.000Z',
        object: { origin: 'https://other.example', controller: AGENT_DID }
      }
    }
    const agents = await listConnectedAgents({
      storage: storageWith([agentLogin(), appRevoke, foreignRevoke])
    })
    expect(agents).toHaveLength(1)
  })
})

describe('revokeAgentAccess', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  const user = { id: 'did:key:zUser', email: 'a@b.c' } as unknown as User
  const agent = {
    controller: AGENT_DID,
    name: 'Deploy bot',
    origin: EXTERNAL_REQUEST_ORIGIN,
    grants: [],
    grantedAt: '2026-08-01T00:00:00.000Z'
  }

  it('revokes on the server before recording the activity', async () => {
    const order: string[] = []
    const storage = {
      revokeAgentGrants: vi.fn(async () => {
        order.push('revoke')
        return { revoked: 2, skipped: 1, revokedIds: ['urn:zcap:one'] }
      }),
      addHistoryAgentRevoke: vi.fn(async () => {
        order.push('activity')
      })
    } as unknown as StorageManager

    const outcome = await revokeAgentAccess({ storage, user, agent })

    expect(outcome).toEqual({ revoked: 2, skipped: 1 })
    expect(order).toEqual(['revoke', 'activity'])
    expect(storage.addHistoryAgentRevoke).toHaveBeenCalledWith({
      user,
      origin: EXTERNAL_REQUEST_ORIGIN,
      controller: AGENT_DID,
      zcaps: [{ id: 'urn:zcap:one' }],
      actor: { name: 'Deploy bot' },
      revoked: 2,
      skipped: 1,
      created: expect.any(String)
    })
  })

  it('records nothing when the server revocation throws', async () => {
    const storage = {
      revokeAgentGrants: vi.fn(async () => {
        throw new Error('network')
      }),
      addHistoryAgentRevoke: vi.fn()
    } as unknown as StorageManager

    await expect(revokeAgentAccess({ storage, user, agent })).rejects.toThrow(
      'network'
    )
    expect(storage.addHistoryAgentRevoke).not.toHaveBeenCalled()
  })

  it('still posts the revocations for a transient-signed (orphaned) grant', async () => {
    // A grant delegated from a transient session is signed by an annex key the
    // account document never lists, so the listing marks it orphaned while it
    // is very much alive under the generation delegation. The dead-chain case
    // is what the server answers with, as a skipped no-op.
    const storage = {
      revokeAgentGrants: vi.fn(async () => ({
        revoked: 0,
        skipped: 1,
        revokedIds: []
      })),
      addHistoryAgentRevoke: vi.fn()
    } as unknown as StorageManager

    const annexSigned = {
      ...agent,
      grants: [
        {
          id: 'urn:zcap:one',
          target: 'https://was.example/space/s/collection/notes',
          allowedActions: ['read'],
          expires: FUTURE,
          signerKeyId: 'did:webvh:annex:was.example:gen-1#z6MkAnnexVisit'
        }
      ]
    }

    const outcome = await revokeAgentAccess({
      storage,
      user,
      agent: annexSigned
    })

    expect(outcome).toEqual({ revoked: 0, skipped: 1 })
    expect(storage.revokeAgentGrants).toHaveBeenCalledWith({
      controller: AGENT_DID
    })
  })

  it('floors the Revoke stamp past the Login when the clock is behind', async () => {
    const storage = {
      revokeAgentGrants: vi.fn(async () => ({
        revoked: 1,
        skipped: 0,
        revokedIds: ['urn:zcap:one']
      })),
      addHistoryAgentRevoke: vi.fn()
    } as unknown as StorageManager

    // This client's clock sits a day behind the client that granted.
    vi.spyOn(Date, 'now').mockReturnValue(
      new Date('2026-07-31T00:00:00.000Z').getTime()
    )

    await revokeAgentAccess({ storage, user, agent })

    expect(storage.addHistoryAgentRevoke).toHaveBeenCalledWith(
      expect.objectContaining({ created: '2026-08-01T00:00:00.001Z' })
    )
  })

  it('stamps the Revoke with the clock when it is already ahead', async () => {
    const storage = {
      revokeAgentGrants: vi.fn(async () => ({
        revoked: 1,
        skipped: 0,
        revokedIds: ['urn:zcap:one']
      })),
      addHistoryAgentRevoke: vi.fn()
    } as unknown as StorageManager

    vi.spyOn(Date, 'now').mockReturnValue(
      new Date('2026-09-01T00:00:00.000Z').getTime()
    )

    await revokeAgentAccess({ storage, user, agent })

    expect(storage.addHistoryAgentRevoke).toHaveBeenCalledWith(
      expect.objectContaining({ created: '2026-09-01T00:00:00.000Z' })
    )
  })
})
