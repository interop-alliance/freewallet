/**
 * @vitest-environment node
 *
 * The agent half of the connected-grantee model: which activity rows list as
 * a connected agent (`listConnectedAgents` -- the Login predicate, the Revoke
 * join, the all-expired rule (drop, or keep while a granted collection's
 * current key epoch lists the agent), and the name / key-fingerprint fallback), and
 * the revocation `revokeAgentAccess` performs (the server revocation before
 * the recorded activity, the signer check handed through so the storage
 * layer settles the skips, and the forward-floored Revoke stamp). Also the
 * consent page's known-agent lookup (`findKnownAgents`), over the same join.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  findKnownAgents,
  isAgentGrantLogin,
  listConnectedAgents,
  revokeAgentAccess,
  revokeAppAccess,
  type ConnectedApp
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
  controller = AGENT_DID,
  target = 'https://was.example/space/s/collection/notes'
}: {
  id?: string
  expires?: string
  controller?: string
  target?: string
} = {}) {
  return {
    id,
    target,
    allowedActions: ['read'],
    expires,
    zcap: {
      id,
      controller,
      expires,
      parentCapability: 'urn:zcap:root:x',
      invocationTarget: target,
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
 * A StorageManager double serving a fixed history scan, on Space `s` of
 * `https://was.example`, whose roster read reports `rosterCollections` as
 * the collections still listing the grantee (or one failed read when
 * `rosterCollections` is an Error).
 */
function storageWith(
  items: unknown[],
  rosterCollections: string[] | Error = []
): StorageManager {
  return {
    listHistoryItems: vi.fn(async () => ({ entries: items, unreadable: 0 })),
    spaceLocation: { serverUrl: 'https://was.example', spaceId: 's' },
    granteeRosterCollections: vi.fn(
      async ({ grantees }: { grantees: Array<{ controller: string }> }) =>
        grantees.map(({ controller }) =>
          rosterCollections instanceof Error
            ? { controller, collectionIds: [], failed: 1 }
            : { controller, collectionIds: rosterCollections, failed: 0 }
        )
    )
  } as unknown as StorageManager
}

const NOTES_COLLECTION = 'https://was.example/space/s/notes/'
const PUBLIC_COLLECTION = 'https://was.example/space/s/public-notes/'

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

  it('drops an expired row whose grants name no collection of this Space', async () => {
    const expired = agentLogin({
      zcaps: [grantEntry({ expires: PAST })]
    })
    expect(
      await listConnectedAgents({ storage: storageWith([expired]) })
    ).toEqual([])
  })

  it('keeps and flags an expired row still listed in a current key epoch', async () => {
    // The agent's key stays in the collection's key-epoch roster, so the row
    // must stay reachable for Revoke, which rotates the epoch off it.
    const expired = agentLogin({
      zcaps: [
        grantEntry({
          id: 'urn:zcap:pub',
          expires: PAST,
          target: PUBLIC_COLLECTION
        }),
        grantEntry({
          id: 'urn:zcap:enc',
          expires: PAST,
          target: NOTES_COLLECTION
        })
      ]
    })
    const storage = storageWith([expired], ['notes'])
    const agents = await listConnectedAgents({ storage })
    expect(agents).toHaveLength(1)
    expect(agents[0].expired).toBe(true)
    expect(agents[0].grants).toHaveLength(2)
    expect(storage.granteeRosterCollections).toHaveBeenCalledWith({
      grantees: [
        {
          controller: AGENT_DID,
          targets: [PUBLIC_COLLECTION, NOTES_COLLECTION]
        }
      ]
    })
  })

  it('reads the key epochs of every expired row in one roster read', async () => {
    // One call covers all the expired rows, so the storage layer can read a
    // collection several rows target once.
    const other = 'did:key:z6MkOtherAgent'
    const storage = storageWith(
      [
        agentLogin({
          zcaps: [grantEntry({ expires: PAST, target: NOTES_COLLECTION })]
        }),
        agentLogin({
          created: '2026-08-02T00:00:00.000Z',
          zcaps: [
            grantEntry({
              id: 'urn:zcap:two',
              expires: PAST,
              controller: other,
              target: NOTES_COLLECTION
            })
          ]
        })
      ],
      ['notes']
    )

    const agents = await listConnectedAgents({ storage })

    expect(agents.map(agent => agent.controller)).toEqual([other, AGENT_DID])
    expect(storage.granteeRosterCollections).toHaveBeenCalledTimes(1)
    expect(storage.granteeRosterCollections).toHaveBeenCalledWith({
      grantees: [
        { controller: AGENT_DID, targets: [NOTES_COLLECTION] },
        { controller: other, targets: [NOTES_COLLECTION] }
      ]
    })
  })

  it('drops an expired row no current key epoch lists', async () => {
    const expired = agentLogin({
      zcaps: [grantEntry({ expires: PAST, target: NOTES_COLLECTION })]
    })
    expect(
      await listConnectedAgents({ storage: storageWith([expired], []) })
    ).toEqual([])
  })

  it('keeps an expired row when a key epoch cannot be read', async () => {
    const expired = agentLogin({
      zcaps: [grantEntry({ expires: PAST, target: PUBLIC_COLLECTION })]
    })
    const agents = await listConnectedAgents({
      storage: storageWith([expired], new Error('offline'))
    })
    expect(agents).toHaveLength(1)
    expect(agents[0].expired).toBe(true)
  })

  it('keeps an expired row when there is no remote store', async () => {
    const expired = agentLogin({
      zcaps: [grantEntry({ expires: PAST, target: PUBLIC_COLLECTION })]
    })
    // With no remote store, `granteeRosterCollections` reports one failed
    // read per grantee, which keeps the row.
    const storage = storageWith([expired], new Error('no remote store'))
    ;(storage as unknown as { spaceLocation?: unknown }).spaceLocation =
      undefined
    const agents = await listConnectedAgents({ storage })
    expect(agents).toHaveLength(1)
    expect(agents[0].expired).toBe(true)
    expect(storage.granteeRosterCollections).toHaveBeenCalledTimes(1)
  })

  it('reads no key epoch and flags nothing when a grant is live', async () => {
    const storage = storageWith([
      agentLogin({
        zcaps: [
          grantEntry({
            id: 'urn:zcap:old',
            expires: PAST,
            target: NOTES_COLLECTION
          }),
          grantEntry({
            id: 'urn:zcap:live',
            expires: FUTURE,
            target: NOTES_COLLECTION
          })
        ]
      })
    ])
    const agents = await listConnectedAgents({ storage })
    expect(agents).toHaveLength(1)
    expect(agents[0].expired).toBeUndefined()
    expect(storage.granteeRosterCollections).not.toHaveBeenCalled()
  })

  it('reads expiry off the recorded capability, not the summary', async () => {
    // The revocation lookup reads the zcap's own `expires`; a summary that
    // disagrees (a stale display value) must not drop or keep a row on its
    // own. A summary-only legacy record still falls back to the summary.
    const summaryStale = grantEntry({ expires: FUTURE })
    summaryStale.expires = PAST
    expect(
      await listConnectedAgents({
        storage: storageWith([agentLogin({ zcaps: [summaryStale] })])
      })
    ).toHaveLength(1)

    const zcapExpired = grantEntry({ expires: PAST })
    zcapExpired.expires = FUTURE
    expect(
      await listConnectedAgents({
        storage: storageWith([agentLogin({ zcaps: [zcapExpired] })])
      })
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

describe('findKnownAgents', () => {
  const items = (rows: unknown[]) =>
    ({ entries: rows, unreadable: 0 }) as Parameters<
      typeof findKnownAgents
    >[0]['items']

  it('returns the newest live Login name and stamp for a known controller', () => {
    const known = findKnownAgents({
      items: items([
        agentLogin({ name: 'Old name' }),
        agentLogin({ created: '2026-08-03T00:00:00.000Z', name: 'Deploy bot' })
      ]),
      controllers: [AGENT_DID]
    })
    expect(known.get(AGENT_DID)).toEqual({
      name: 'Deploy bot',
      grantedAt: '2026-08-03T00:00:00.000Z'
    })
  })

  it('hides a controller whose later Revoke covers every Login', () => {
    const revoke = {
      id: 'revoke-1',
      doc: {
        id: 'revoke-1',
        type: ['Revoke'],
        created: '2026-08-02T00:00:00.000Z',
        object: { origin: EXTERNAL_REQUEST_ORIGIN, controller: AGENT_DID }
      }
    }
    const known = findKnownAgents({
      items: items([agentLogin({ name: 'Deploy bot' }), revoke]),
      controllers: [AGENT_DID]
    })
    expect(known.size).toBe(0)
  })

  it('returns no name when the Login recorded none', () => {
    const known = findKnownAgents({
      items: items([agentLogin()]),
      controllers: [AGENT_DID]
    })
    expect(known.get(AGENT_DID)).toEqual({
      grantedAt: '2026-08-01T00:00:00.000Z'
    })
  })

  it('omits a controller with no agent Login', () => {
    const known = findKnownAgents({
      items: items([agentLogin()]),
      controllers: ['did:key:z6MkStranger']
    })
    expect(known.has('did:key:z6MkStranger')).toBe(false)
    expect(known.has(AGENT_DID)).toBe(false)
  })

  it('does not count an App Connect Login', () => {
    const appConnect = agentLogin({ name: 'Demo App' })
    ;(appConnect.doc.object as Record<string, unknown>).origin =
      'https://app.example'
    ;(appConnect.doc.object as Record<string, unknown>).appConnect = {
      name: 'Demo App'
    }
    const known = findKnownAgents({
      items: items([appConnect]),
      controllers: [AGENT_DID]
    })
    expect(known.size).toBe(0)
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
  const items = { entries: [{ id: 'history-scan', doc: {} }], unreadable: 0 }

  /**
   * A storage fake for the agent revoke: one history scan, a rotation that
   * re-keys nothing, and the given overrides.
   *
   * @param overrides {object}
   * @returns {StorageManager}
   */
  function agentStorage(overrides: object): StorageManager {
    return {
      listHistoryItems: vi.fn(async () => items),
      revokeAgentCollectionRecipients: vi.fn(async () => ({
        collections: 0,
        rotated: 0,
        failed: 0,
        revokedIds: []
      })),
      ...overrides
    } as unknown as StorageManager
  }

  it('revokes on the server before recording the activity', async () => {
    const order: string[] = []
    const storage = agentStorage({
      revokeAgentGrants: vi.fn(async () => {
        order.push('revoke')
        return {
          revoked: 2,
          skipped: 1,
          revokedIds: ['urn:zcap:rotated', 'urn:zcap:one']
        }
      }),
      addHistoryAgentRevoke: vi.fn(async () => {
        order.push('activity')
      }),
      revokeAgentCollectionRecipients: vi.fn(async () => {
        order.push('rotate')
        return {
          collections: 1,
          rotated: 1,
          failed: 0,
          revokedIds: ['urn:zcap:rotated']
        }
      })
    })

    const outcome = await revokeAgentAccess({ storage, user, agent })

    expect(outcome).toEqual({ revoked: 2, skipped: 1, rotated: 1 })
    // The epoch rotation off the agent's key runs first, over the same
    // history scan the grant revocation reads.
    expect(order).toEqual(['rotate', 'revoke', 'activity'])
    expect(storage.revokeAgentCollectionRecipients).toHaveBeenCalledWith({
      controller: AGENT_DID,
      items
    })
    // The capabilities the rotation revoked are handed to the grant stage,
    // which counts them without POSTing them again.
    expect(storage.revokeAgentGrants).toHaveBeenCalledWith({
      controller: AGENT_DID,
      items,
      revokedByRotation: ['urn:zcap:rotated']
    })
    expect(storage.addHistoryAgentRevoke).toHaveBeenCalledWith({
      user,
      origin: EXTERNAL_REQUEST_ORIGIN,
      controller: AGENT_DID,
      zcaps: [{ id: 'urn:zcap:rotated' }, { id: 'urn:zcap:one' }],
      actor: { name: 'Deploy bot' },
      revoked: 2,
      skipped: 1,
      created: expect.any(String)
    })
  })

  it('records nothing when the server revocation throws', async () => {
    const storage = agentStorage({
      revokeAgentGrants: vi.fn(async () => {
        throw new Error('network')
      }),
      addHistoryAgentRevoke: vi.fn()
    })

    await expect(revokeAgentAccess({ storage, user, agent })).rejects.toThrow(
      'network'
    )
    expect(storage.addHistoryAgentRevoke).not.toHaveBeenCalled()
  })

  it('leaves the skips to the grant revocation and records them', async () => {
    // A grant delegated from a transient session is signed by an annex key the
    // account document never lists, so the row's marker says nothing about
    // it; whether its generation still stands is the storage layer's
    // reading of the verified document it holds its own resolver for, so
    // nothing gates here.
    const storage = agentStorage({
      revokeAgentGrants: vi.fn(async () => ({
        revoked: 0,
        skipped: 1,
        revokedIds: []
      })),
      addHistoryAgentRevoke: vi.fn()
    })
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

    expect(outcome).toEqual({ revoked: 0, skipped: 1, rotated: 0 })
    expect(storage.revokeAgentGrants).toHaveBeenCalledWith({
      controller: AGENT_DID,
      items,
      revokedByRotation: []
    })
  })

  it('records nothing, after revoking the grants, when a rotation fails', async () => {
    // A collection that could not be re-keyed keeps the agent a recipient of
    // its current epoch, so the row stays listed for a retry.
    const storage = agentStorage({
      revokeAgentCollectionRecipients: vi.fn(async () => ({
        collections: 2,
        rotated: 1,
        failed: 1,
        revokedIds: []
      })),
      revokeAgentGrants: vi.fn(async () => ({
        revoked: 1,
        skipped: 0,
        revokedIds: ['urn:zcap:one']
      })),
      addHistoryAgentRevoke: vi.fn()
    })

    await expect(revokeAgentAccess({ storage, user, agent })).rejects.toThrow(
      'Could not rotate every collection off the agent being revoked.'
    )
    expect(storage.revokeAgentGrants).toHaveBeenCalled()
    expect(storage.addHistoryAgentRevoke).not.toHaveBeenCalled()
  })

  it('records nothing when the server refuses a revocation', async () => {
    // A plain ValidationError is a refusal the storage layer throws after
    // its sibling POSTs settle; recording the Revoke would hide a row whose
    // grant may still be live.
    const refused = Object.assign(new Error('chain does not verify'), {
      name: 'ValidationError'
    })
    const storage = agentStorage({
      revokeAgentGrants: vi.fn(async () => {
        throw refused
      }),
      addHistoryAgentRevoke: vi.fn()
    })

    await expect(revokeAgentAccess({ storage, user, agent })).rejects.toBe(
      refused
    )
    expect(storage.addHistoryAgentRevoke).not.toHaveBeenCalled()
  })

  it('floors the Revoke stamp past the Login when the clock is behind', async () => {
    const storage = agentStorage({
      revokeAgentGrants: vi.fn(async () => ({
        revoked: 1,
        skipped: 0,
        revokedIds: ['urn:zcap:one']
      })),
      addHistoryAgentRevoke: vi.fn()
    })

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
    const storage = agentStorage({
      revokeAgentGrants: vi.fn(async () => ({
        revoked: 1,
        skipped: 0,
        revokedIds: ['urn:zcap:one']
      })),
      addHistoryAgentRevoke: vi.fn()
    })

    vi.spyOn(Date, 'now').mockReturnValue(
      new Date('2026-09-01T00:00:00.000Z').getTime()
    )

    await revokeAgentAccess({ storage, user, agent })

    expect(storage.addHistoryAgentRevoke).toHaveBeenCalledWith(
      expect.objectContaining({ created: '2026-09-01T00:00:00.000Z' })
    )
  })
})

describe('revokeAppAccess', () => {
  const user = { id: 'did:key:zUser', email: 'a@b.c' } as unknown as User
  const app = {
    cid: 'cid-app-key',
    name: 'Example App',
    origin: 'https://app.example',
    subjectDid: 'did:key:z6MkAppSubject',
    grants: []
  } as unknown as ConnectedApp

  /**
   * A structural storage fake over the three calls the revocation drives,
   * with the rotation outcome under the test's control.
   */
  function fakeStorage({
    rotation
  }: {
    rotation: {
      collections: number
      rotated: number
      failed: number
      revokedIds: string[]
    }
  }) {
    return {
      listHistoryItems: vi.fn(async () => ({ entries: [], unreadable: 0 })),
      revokeAppCollectionRecipients: vi.fn(async () => rotation),
      revokeAppGrants: vi.fn(async () => ({ revoked: 1, skipped: 0 })),
      deleteAppKey: vi.fn(async () => {}),
      addHistoryAppRevoke: vi.fn(async () => {})
    } as unknown as StorageManager
  }

  it('deletes the app key and records the revoke once every rotation landed', async () => {
    const storage = fakeStorage({
      rotation: {
        collections: 1,
        rotated: 1,
        failed: 0,
        revokedIds: ['urn:zcap:rotated']
      }
    })

    const outcome = await revokeAppAccess({ storage, user, app })

    expect(outcome).toEqual({ revoked: 1, skipped: 0, rotated: 1 })
    // The rotation's revoked capabilities are not POSTed a second time.
    expect(storage.revokeAppGrants).toHaveBeenCalledWith({
      origin: app.origin,
      subjectDid: app.subjectDid,
      items: { entries: [], unreadable: 0 },
      revokedByRotation: ['urn:zcap:rotated']
    })
    expect(storage.deleteAppKey).toHaveBeenCalledWith({ cid: 'cid-app-key' })
    expect(storage.addHistoryAppRevoke).toHaveBeenCalled()
  })

  it('keeps the app-key row when a collection rotation failed', async () => {
    const storage = fakeStorage({
      rotation: { collections: 2, rotated: 1, failed: 1, revokedIds: [] }
    })

    await expect(revokeAppAccess({ storage, user, app })).rejects.toThrow(
      /rotate every collection/
    )
    // The app is still a recipient of the collection that did not rotate, so
    // the row stays listed for a retry and no Revoke is recorded.
    expect(storage.deleteAppKey).not.toHaveBeenCalled()
    expect(storage.addHistoryAppRevoke).not.toHaveBeenCalled()
    // The grant revocation still runs before the refusal, per the JSDoc.
    expect(storage.revokeAppGrants).toHaveBeenCalledWith({
      origin: app.origin,
      subjectDid: app.subjectDid,
      items: { entries: [], unreadable: 0 },
      revokedByRotation: []
    })
  })
})
