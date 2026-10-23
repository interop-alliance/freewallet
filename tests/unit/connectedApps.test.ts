// @vitest-environment node
/**
 * Tests for the connected-parties revocations over the `connections`
 * directory, and the row grant-state reading.
 *
 * - `deriveGrantsState` reads the recorded delegation signers against the
 *   account's current key set (the current-key-set rule), deriving a
 *   client-annex signer as unknown rather than orphaned.
 * - `revokeAppAccess` runs the rotation, the grant POSTs, the app-key delete
 *   by the entry's `appKey`, the retirement, then the Revoke row; a stage
 *   that does not land throws before the retirement, so the row stays
 *   listed. A consent merged between the read and the retirement aborts the
 *   retirement, and a retry revokes both grants.
 * - `revokeAgentAccess` runs the same sequence with no app-key delete.
 * - `retireConnectionParty`, the wallet-client disconnect's and the forget's
 *   retirement, POSTs and rotates off any grants an entry carries first.
 * - `revokeAppAuthority` on a key with no entry throws before any stage.
 *
 * Every grant comes from the entry, so no history row is read on any path.
 * The entries are written through wallet-core's own upsert helpers over an
 * in-memory store; the server-side stages are spies.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import type { ConnectionGrant } from '@interop/wallet-core/connections'
import {
  ConnectionEntryMissingError,
  deriveGrantsState,
  listConnectedAgents,
  listConnectedApps,
  retireConnectionParty,
  revokeAgentAccess,
  revokeAppAccess,
  revokeAppAuthority,
  type AppGrant,
  type ConnectedAgent,
  type ConnectedApp
} from '@/lib/connectedApps'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'
import type { User } from '@/types/auth'
import {
  AGENT_DID,
  APP_DID,
  CLIENT_DID,
  SPACE_URL,
  asStorageManager,
  directoryStorage,
  entryOf,
  fixtureDirectory,
  grantZcap,
  listedConnections,
  recordConsent,
  type FixtureDirectory
} from './connectionFixtures'

const APP_ORIGIN = 'https://app.example'
const APP_URL = 'https://app.example/editor'
const user: User = { id: 'did:key:zUser', email: 'user@example.com' }

let directory: FixtureDirectory

beforeEach(() => {
  directory = fixtureDirectory()
})

/**
 * The capability ids a revocation stage was handed.
 *
 * @param grants {ConnectionGrant[]}
 * @returns {string[]}
 */
function zcapIdsOf(grants: ConnectionGrant[]): string[] {
  return grants.map(grant => grant.zcapId).sort()
}

/**
 * Records an App Connect consent for the fixture app.
 *
 * @param options {object}
 * @param [options.grantIds] {string[]}   one grant per id, on `notes`
 * @param [options.appKey] {string}
 * @param [options.at] {string}
 * @returns {Promise<void>}
 */
async function connectApp({
  grantIds = ['urn:zcap:one'],
  appKey,
  at
}: {
  grantIds?: string[]
  appKey?: string
  at?: string
} = {}): Promise<void> {
  await recordConsent({
    directory,
    did: APP_DID,
    kind: 'app',
    grants: grantIds.map(id => grantZcap({ id, controller: APP_DID })),
    ...(appKey !== undefined && { appKey }),
    name: 'Notes',
    origin: APP_ORIGIN,
    url: APP_URL,
    ...(at !== undefined && { at })
  })
}

/**
 * The app's row, as the Applications page lists it.
 *
 * @returns {Promise<ConnectedApp>}
 */
async function listedApp(): Promise<ConnectedApp> {
  const [app] = listConnectedApps({
    connections: await listedConnections(directory),
    spaceUrl: SPACE_URL
  })
  return app
}

/**
 * The agent's row, as the Applications page lists it.
 *
 * @returns {Promise<ConnectedAgent>}
 */
async function listedAgent(): Promise<ConnectedAgent> {
  const [agent] = await listConnectedAgents({
    storage: asStorageManager(directoryStorage({ directory })),
    connections: await listedConnections(directory),
    spaceUrl: SPACE_URL
  })
  return agent
}

describe('deriveGrantsState', () => {
  /**
   * Grants signed by the given verification methods.
   *
   * @param signers {Array<string | undefined>}
   * @returns {AppGrant[]}
   */
  function grantsSignedBy(signers: Array<string | undefined>): AppGrant[] {
    return signers.map((signerKeyId, index) => ({
      id: `urn:zcap:${index}`,
      target: 'https://was.example/space/x/app-data',
      allowedActions: ['GET'],
      expires: '2027-08-01T00:00:00Z',
      signerKeyId,
      grantKind: 'grant',
      grantedAt: '2026-08-01T00:00:00Z'
    }))
  }

  const ACCOUNT_DID = 'did:webvh:s:h:x'
  const ANNEX_DID = 'did:webvh:a:h:gen-1'
  const check = {
    accountDid: ACCOUNT_DID,
    currentSigningKeys: new Set(['zKey']),
    doc: {},
    annexDocument: async () => undefined
  }

  it('is unknown without a verified key set to check against', () => {
    expect(
      deriveGrantsState({ grants: grantsSignedBy([`${ACCOUNT_DID}#zKey`]) })
    ).toBe('unknown')
  })

  it('is unknown when no grant recorded a signer', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([undefined]),
        signerCheck: check
      })
    ).toBe('unknown')
  })

  it('is active when a signer is in the current key set', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([`${ACCOUNT_DID}#zGone`, `${ACCOUNT_DID}#zKey`]),
        signerCheck: check
      })
    ).toBe('active')
  })

  it('matches the did:key form of a still-enrolled key', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy(['did:key:zKey#zKey']),
        signerCheck: check
      })
    ).toBe('active')
  })

  it('is orphaned when no recorded signer is in the current key set', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([`${ACCOUNT_DID}#zGone`]),
        signerCheck: check
      })
    ).toBe('orphaned')
  })

  it('is unknown for a grant a transient session minted (annex signer)', () => {
    // The annex VM is never in the account document, so its absence is not
    // evidence of a disconnect; whether the chain under the generation
    // delegation is still alive is the pointer's question, not the signer's.
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([`${ANNEX_DID}#zVisit`]),
        signerCheck: check
      })
    ).toBe('unknown')
  })
})

describe('revokeAppAccess', () => {
  it('rotates, revokes, deletes the app key, retires, then records the revoke', async () => {
    await connectApp({ appKey: 'r-app-key' })
    const storage = directoryStorage({ directory })

    const outcome = await revokeAppAccess({
      storage: asStorageManager(storage),
      user,
      app: await listedApp()
    })

    expect(outcome).toEqual({
      revoked: 1,
      withdrawn: 1,
      skipped: 0,
      rotated: 1
    })
    expect(storage.calls).toEqual([
      'readConnectionsListing',
      'revokeCollectionRecipients',
      'revokeConnectionGrants',
      'deleteAppKeyResource',
      'retireConnectionEntry',
      'addHistoryAppRevoke'
    ])
    const [rotation] = storage.revokeCollectionRecipients.mock.calls[0]
    expect(rotation.did).toBe(APP_DID)
    expect(zcapIdsOf(rotation.grants)).toEqual(['urn:zcap:one'])
    expect(storage.revokeConnectionGrants).toHaveBeenCalledWith(
      expect.objectContaining({ revokedByRotation: [] })
    )
    expect(storage.deleteAppKeyResource).toHaveBeenCalledWith({
      appKey: 'r-app-key',
      did: APP_DID
    })
    expect(storage.retireConnectionEntry).toHaveBeenCalledWith({
      did: APP_DID,
      handledZcapIds: ['urn:zcap:one']
    })
    expect(storage.addHistoryAppRevoke).toHaveBeenCalledWith({
      user,
      origin: APP_ORIGIN,
      name: 'Notes',
      revoked: 1,
      skipped: 0
    })
    // Retired: off the listing, its names kept, its key and grants gone.
    const entry = await entryOf({ directory, did: APP_DID })
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry).toMatchObject({ name: 'Notes', origin: APP_ORIGIN })
    expect(entry?.appKey).toBeUndefined()
    expect(entry?.grants).toEqual([])
    expect(
      listConnectedApps({
        connections: await listedConnections(directory),
        spaceUrl: SPACE_URL
      })
    ).toEqual([])
  })

  it('deletes the key the entry names now, not the one the row listed', async () => {
    await connectApp({ appKey: 'r-old-key' })
    const app = await listedApp()
    // A reconnect since the listing re-pointed the entry at a new key.
    await connectApp({ appKey: 'r-new-key' })
    const storage = directoryStorage({ directory })

    await revokeAppAccess({ storage: asStorageManager(storage), user, app })

    expect(storage.deleteAppKeyResource).toHaveBeenCalledWith({
      appKey: 'r-new-key',
      did: APP_DID
    })
  })

  it('still retires when the app key the entry names is already gone', async () => {
    await connectApp({ appKey: 'r-dangling' })
    const storage = directoryStorage({ directory })
    storage.deleteAppKeyResource.mockResolvedValueOnce('absent')

    await revokeAppAccess({
      storage: asStorageManager(storage),
      user,
      app: await listedApp()
    })

    const entry = await entryOf({ directory, did: APP_DID })
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.appKey).toBeUndefined()
    expect(storage.addHistoryAppRevoke).toHaveBeenCalledTimes(1)
  })

  it('deletes no key for an entry that names none', async () => {
    await connectApp()
    const storage = directoryStorage({ directory })

    await revokeAppAccess({
      storage: asStorageManager(storage),
      user,
      app: await listedApp()
    })

    expect(storage.deleteAppKeyResource).not.toHaveBeenCalled()
    expect((await entryOf({ directory, did: APP_DID }))?.retired).toEqual(
      expect.any(String)
    )
  })

  it('POSTs every grant and rotates with no history row to read', async () => {
    // Two consents, and no history at all: the double has no history
    // method, so a path that reached for one would throw.
    await connectApp({ grantIds: ['urn:zcap:one'], at: '2026-07-01T00:00:00Z' })
    await connectApp({ grantIds: ['urn:zcap:two'], appKey: 'r-app-key' })
    const storage = directoryStorage({ directory })
    expect('listHistoryItems' in storage).toBe(false)

    await revokeAppAccess({
      storage: asStorageManager(storage),
      user,
      app: await listedApp()
    })

    const [rotation] = storage.revokeCollectionRecipients.mock.calls[0]
    expect(zcapIdsOf(rotation.grants)).toEqual(['urn:zcap:one', 'urn:zcap:two'])
    const [posted] = storage.revokeConnectionGrants.mock.calls[0]
    expect(zcapIdsOf(posted.grants)).toEqual(['urn:zcap:one', 'urn:zcap:two'])
  })

  it('retires nothing and records nothing, after the POSTs, when a rotation fails', async () => {
    await connectApp({ appKey: 'r-app-key' })
    const storage = directoryStorage({ directory })
    storage.revokeCollectionRecipients.mockResolvedValueOnce({
      collections: 2,
      rotated: 1,
      failed: 1,
      revokedIds: []
    })

    await expect(
      revokeAppAccess({
        storage: asStorageManager(storage),
        user,
        app: await listedApp()
      })
    ).rejects.toThrow('Could not rotate every collection')

    // Every grant that can be revoked is revoked now.
    expect(storage.revokeConnectionGrants).toHaveBeenCalledTimes(1)
    expect(storage.deleteAppKeyResource).not.toHaveBeenCalled()
    expect(storage.retireConnectionEntry).not.toHaveBeenCalled()
    expect(storage.addHistoryAppRevoke).not.toHaveBeenCalled()
    expect((await listedApp()).subjectDid).toBe(APP_DID)
  })

  it('retires nothing when the server refuses a revocation', async () => {
    // A plain ValidationError is a refusal, not a no-op: a read-replica lag
    // on a live grant answers the same way, so retiring here would take the
    // row off the listing while the app keeps access.
    await connectApp({ appKey: 'r-app-key' })
    const storage = directoryStorage({ directory })
    const refused = Object.assign(new Error('chain does not verify'), {
      name: 'ValidationError'
    })
    storage.revokeConnectionGrants.mockRejectedValueOnce(refused)

    await expect(
      revokeAppAccess({
        storage: asStorageManager(storage),
        user,
        app: await listedApp()
      })
    ).rejects.toBe(refused)
    expect(storage.deleteAppKeyResource).not.toHaveBeenCalled()
    expect(storage.retireConnectionEntry).not.toHaveBeenCalled()
    expect(storage.addHistoryAppRevoke).not.toHaveBeenCalled()
  })

  it('retires nothing when the app key cannot be read', async () => {
    await connectApp({ appKey: 'r-app-key' })
    const storage = directoryStorage({ directory })
    storage.deleteAppKeyResource.mockRejectedValueOnce(
      new Error('The app key this connection names could not be read')
    )

    await expect(
      revokeAppAccess({
        storage: asStorageManager(storage),
        user,
        app: await listedApp()
      })
    ).rejects.toThrow('could not be read')
    expect(storage.retireConnectionEntry).not.toHaveBeenCalled()
    expect((await entryOf({ directory, did: APP_DID }))?.appKey).toBe(
      'r-app-key'
    )
  })

  it('aborts the retirement when a consent merges a grant, and a retry revokes both', async () => {
    await connectApp({ appKey: 'r-app-key' })
    const storage = directoryStorage({ directory })
    // The consent lands between the revocation's read and its retirement.
    storage.revokeConnectionGrants.mockImplementationOnce(
      async ({ grants }) => {
        await connectApp({ grantIds: ['urn:zcap:merged'] })
        return {
          revoked: grants.length,
          withdrawn: grants.length,
          skipped: 0,
          revokedIds: grants.map(grant => grant.zcapId)
        }
      }
    )

    await expect(
      revokeAppAccess({
        storage: asStorageManager(storage),
        user,
        app: await listedApp()
      })
    ).rejects.toThrow('did not handle')
    expect(storage.addHistoryAppRevoke).not.toHaveBeenCalled()
    // The row stays listed, carrying both grants: one scope, so the older
    // record rides under the newer one.
    const app = await listedApp()
    expect(
      app.grants
        .flatMap(grant => [
          grant.id,
          ...(grant.earlier ?? []).map(earlier => earlier.id)
        ])
        .sort()
    ).toEqual(['urn:zcap:merged', 'urn:zcap:one'])

    await revokeAppAccess({ storage: asStorageManager(storage), user, app })

    const [posted] = storage.revokeConnectionGrants.mock.calls[1]
    expect(zcapIdsOf(posted.grants)).toEqual([
      'urn:zcap:merged',
      'urn:zcap:one'
    ])
    expect((await entryOf({ directory, did: APP_DID }))?.retired).toEqual(
      expect.any(String)
    )
    expect(storage.addHistoryAppRevoke).toHaveBeenCalledTimes(1)
  })
})

describe('revokeAgentAccess', () => {
  /**
   * Records an interaction-URL consent for the fixture agent.
   *
   * @param options {object}
   * @param [options.grants] {Array<object>}
   * @param [options.appKey] {string}
   * @returns {Promise<void>}
   */
  async function grantAgent({
    grants = [grantZcap({ id: 'urn:zcap:one', controller: AGENT_DID })],
    appKey
  }: {
    grants?: Array<Record<string, unknown>>
    appKey?: string
  } = {}): Promise<void> {
    await recordConsent({
      directory,
      did: AGENT_DID,
      kind: 'agent',
      grants,
      name: 'Deploy bot',
      ...(appKey !== undefined && { appKey })
    })
  }

  it('rotates and revokes before retiring and recording, with no key delete', async () => {
    await grantAgent()
    const storage = directoryStorage({ directory })

    const outcome = await revokeAgentAccess({
      storage: asStorageManager(storage),
      user,
      agent: await listedAgent()
    })

    expect(outcome).toEqual({
      revoked: 1,
      withdrawn: 1,
      skipped: 0,
      rotated: 1
    })
    expect(storage.calls).toEqual([
      'clearConnectionChannel',
      'readConnectionsListing',
      'revokeCollectionRecipients',
      'revokeConnectionGrants',
      'retireConnectionEntry',
      'addHistoryAgentRevoke'
    ])
    expect(storage.deleteAppKeyResource).not.toHaveBeenCalled()
    expect(storage.addHistoryAgentRevoke).toHaveBeenCalledWith({
      user,
      origin: EXTERNAL_REQUEST_ORIGIN,
      controller: AGENT_DID,
      zcaps: [{ id: 'urn:zcap:one' }],
      actor: { name: 'Deploy bot' },
      revoked: 1,
      skipped: 0
    })
    expect((await entryOf({ directory, did: AGENT_DID }))?.retired).toEqual(
      expect.any(String)
    )
  })

  it('POSTs every grant and rotates with no history row to read', async () => {
    // A collection the agent created and one it was only admitted to.
    await grantAgent({
      grants: [
        grantZcap({ id: 'urn:zcap:own', controller: AGENT_DID }),
        grantZcap({
          id: 'urn:zcap:admitted',
          controller: AGENT_DID,
          collection: 'private-credentials'
        })
      ]
    })
    const storage = directoryStorage({ directory })
    expect('listHistoryItems' in storage).toBe(false)

    await revokeAgentAccess({
      storage: asStorageManager(storage),
      user,
      agent: await listedAgent()
    })

    const [rotation] = storage.revokeCollectionRecipients.mock.calls[0]
    expect(rotation.grants.map(grant => grant.target).sort()).toEqual([
      `${SPACE_URL}notes/`,
      `${SPACE_URL}private-credentials/`
    ])
    const [posted] = storage.revokeConnectionGrants.mock.calls[0]
    expect(zcapIdsOf(posted.grants)).toEqual([
      'urn:zcap:admitted',
      'urn:zcap:own'
    ])
  })

  it('still retires an entry naming a dangling app key', async () => {
    await grantAgent({ appKey: 'r-dangling' })
    const storage = directoryStorage({ directory })

    await revokeAgentAccess({
      storage: asStorageManager(storage),
      user,
      agent: await listedAgent()
    })

    const entry = await entryOf({ directory, did: AGENT_DID })
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.appKey).toBeUndefined()
  })

  it('retires nothing and records nothing when a rotation fails', async () => {
    await grantAgent()
    const storage = directoryStorage({ directory })
    storage.revokeCollectionRecipients.mockResolvedValueOnce({
      collections: 1,
      rotated: 0,
      failed: 1,
      revokedIds: []
    })

    await expect(
      revokeAgentAccess({
        storage: asStorageManager(storage),
        user,
        agent: await listedAgent()
      })
    ).rejects.toThrow('Could not rotate every collection')
    expect(storage.revokeConnectionGrants).toHaveBeenCalledTimes(1)
    expect(storage.retireConnectionEntry).not.toHaveBeenCalled()
    expect(storage.addHistoryAgentRevoke).not.toHaveBeenCalled()
    expect((await listedAgent()).controller).toBe(AGENT_DID)
  })

  it('retires nothing when the server revocation throws', async () => {
    await grantAgent()
    const storage = directoryStorage({ directory })
    storage.revokeConnectionGrants.mockRejectedValueOnce(
      new Error('server unreachable')
    )

    await expect(
      revokeAgentAccess({
        storage: asStorageManager(storage),
        user,
        agent: await listedAgent()
      })
    ).rejects.toThrow('server unreachable')
    expect(storage.retireConnectionEntry).not.toHaveBeenCalled()
    expect(storage.addHistoryAgentRevoke).not.toHaveBeenCalled()
  })
})

describe('retireConnectionParty', () => {
  it('retires a wallet-client entry holding no grant without a server stage', async () => {
    await recordConsent({
      directory,
      did: CLIENT_DID,
      kind: 'wallet-client',
      name: 'Freewallet'
    })
    const storage = directoryStorage({ directory })

    await retireConnectionParty({
      storage: asStorageManager(storage),
      did: CLIENT_DID
    })

    expect(storage.calls).toEqual([
      'readConnectionsListing',
      'retireConnectionEntry'
    ])
    const entry = await entryOf({ directory, did: CLIENT_DID })
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.name).toBe('Freewallet')
  })

  it('POSTs and rotates off the grants a wallet-client entry carries before retiring', async () => {
    await recordConsent({
      directory,
      did: CLIENT_DID,
      kind: 'wallet-client',
      grants: [grantZcap({ id: 'urn:zcap:client', controller: CLIENT_DID })]
    })
    const storage = directoryStorage({ directory })

    await retireConnectionParty({
      storage: asStorageManager(storage),
      did: CLIENT_DID
    })

    expect(storage.calls).toEqual([
      'readConnectionsListing',
      'revokeCollectionRecipients',
      'revokeConnectionGrants',
      'retireConnectionEntry'
    ])
    const [rotation] = storage.revokeCollectionRecipients.mock.calls[0]
    expect(rotation.did).toBe(CLIENT_DID)
    expect(zcapIdsOf(rotation.grants)).toEqual(['urn:zcap:client'])
    expect(storage.retireConnectionEntry).toHaveBeenCalledWith({
      did: CLIENT_DID,
      handledZcapIds: ['urn:zcap:client']
    })
    const entry = await entryOf({ directory, did: CLIENT_DID })
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.grants).toEqual([])
  })

  it('leaves the entry unretired when the rotation fails', async () => {
    await recordConsent({
      directory,
      did: CLIENT_DID,
      kind: 'wallet-client',
      grants: [grantZcap({ id: 'urn:zcap:client', controller: CLIENT_DID })]
    })
    const storage = directoryStorage({ directory })
    storage.revokeCollectionRecipients.mockResolvedValueOnce({
      collections: 1,
      rotated: 0,
      failed: 1,
      revokedIds: []
    })

    await expect(
      retireConnectionParty({
        storage: asStorageManager(storage),
        did: CLIENT_DID
      })
    ).rejects.toThrow('Could not rotate every collection')
    expect(storage.retireConnectionEntry).not.toHaveBeenCalled()
    expect(
      (await entryOf({ directory, did: CLIENT_DID }))?.retired
    ).toBeUndefined()
  })

  it('still retires an entry naming a dangling app key', async () => {
    await connectApp({ appKey: 'r-dangling' })
    const storage = directoryStorage({ directory })

    await retireConnectionParty({
      storage: asStorageManager(storage),
      did: APP_DID
    })

    const entry = await entryOf({ directory, did: APP_DID })
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.appKey).toBeUndefined()
  })

  it('writes nothing for a party with no entry', async () => {
    const storage = directoryStorage({ directory })

    await retireConnectionParty({
      storage: asStorageManager(storage),
      did: CLIENT_DID
    })

    expect(storage.revokeConnectionGrants).not.toHaveBeenCalled()
    expect(directory.writes).toEqual([])
  })
})

describe('revokeAppAuthority', () => {
  it('throws for a key with no entry, rotating and revoking nothing', async () => {
    const storage = directoryStorage({ directory })

    await expect(
      revokeAppAuthority({
        storage: asStorageManager(storage),
        subjectDid: APP_DID
      })
    ).rejects.toBeInstanceOf(ConnectionEntryMissingError)

    expect(storage.revokeCollectionRecipients).not.toHaveBeenCalled()
    expect(storage.revokeConnectionGrants).not.toHaveBeenCalled()
    expect(directory.writes).toEqual([])
  })
})
