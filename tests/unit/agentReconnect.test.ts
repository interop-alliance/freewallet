// @vitest-environment node
/**
 * The agent reconnect (`src/session/agentReconnect.ts`) and the agent revoke's
 * first write (`revokeAgentAccess`, `src/lib/connectedApps.ts`).
 *
 * - A ceremony's dialog lists exactly the agents holding a grant a withdrawn
 *   key signed: root-anchored by the proof's signer, annex-anchored by the
 *   parent's minter. Each ceremony names the keys it withdraws.
 * - An unticked agent gets the decline marker and stays listed.
 * - The re-mint records a fresh consent with a Grant activity, queues the
 *   envelope on the outbox, and runs the inbox pass after. Restore clears
 *   the marker.
 * - The offers reader skips a declined entry, a retired one, and one with no
 *   channel.
 * - The revoke's first write empties the channel before any POST, and the
 *   orderings against a renewal.
 * - The listing reads the latest record per scope after a renewal.
 *
 * The directory is wallet-core's own codec and upsert helpers over an
 * in-memory store, and the pairwise did:keys derive from real seeds. The
 * Settings inbox pass is a spy.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import {
  connectionResourceId,
  dropReceivedGrant,
  readConnections,
  recordGrants,
  recordReceivedGrants,
  recordRenewedGrants,
  retireConnection,
  type ConnectionEntry
} from '@interop/wallet-core/connections'
import type { AccountSignerCheck } from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'
import { HMAC_KEY } from './memoryConnections'
import {
  ACCOUNT_DID,
  AGENT_DID,
  APP_DID,
  DAY_MS,
  INBOX_URL,
  NEWS_URL,
  OTHER_AGENT_DID,
  SPACE_URL,
  accountKeys,
  annexGrant,
  asStorageManager,
  channelZcap,
  directoryStorage,
  fakeZcapClient,
  fixtureDirectory,
  fixtureSignerCheck,
  inDays,
  pairwiseSeed,
  rootGrant,
  type AccountKeyName,
  type FixtureDirectory
} from './connectionFixtures'

const pass = vi.hoisted(() => ({
  calls: [] as string[],
  pushFailures: [] as Array<{ agentDid: string; reason: string }>
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(),
  invalidateVerifiedLog: vi.fn()
}))

vi.mock('@interop/wallet-core/unlock', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/unlock')>()),
  attributeUnlockLadderInventory: vi.fn(),
  ladderVmClaimOf: vi.fn()
}))

vi.mock('@/session/menders/encounterSites', () => ({
  renewAgentGrantsAfterCeremony: vi.fn(async () => {
    pass.calls.push('pass')
    return {
      entries: [],
      outcome: {
        invitations: [],
        renewalsPushed: [],
        refused: [],
        pushFailures: pass.pushFailures
      }
    }
  })
}))

const { delegateUnderSessionParent } = await import('@/stores/storageManager')
const { verifiedAccountLog } = await import('@/session/verifiedLog')
const { attributeUnlockLadderInventory, ladderVmClaimOf } =
  await import('@interop/wallet-core/unlock')
const {
  agentsSignedByWithdrawnAuthority,
  declineAgents,
  lapsedAgentOffers,
  reconnectAgents
} = await import('@/session/agentReconnect')
const { listConnectedAgents, revokeAgentAccess } =
  await import('@/lib/connectedApps')
const { agentsWithChannel, dueAgentGrants } =
  await import('@/session/inboxPass')
const { sessionDisposalSignal } = await import('@/session/sessionLifecycle')
const { revokedClientWithdrawnKeys } = await import('@/session/revocation')
const { forgottenClientWithdrawnKeys } = await import('@/session/forget')
const { retiredCredentialWithdrawnKeys } =
  await import('@/session/credentialRotation')

const THIRD_AGENT_DID =
  'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'

const SIGNER_CHECK = await fixtureSignerCheck()
const KEYS = await accountKeys()

const user = { id: ACCOUNT_DID, email: 'owner@example.com' }

let directory: FixtureDirectory

beforeEach(() => {
  directory = fixtureDirectory()
  pass.calls.length = 0
  pass.pushFailures.length = 0
})

afterEach(() => {
  vi.clearAllMocks()
})

/**
 * Records a consent on an entry at a fixed time.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.grants {Promise<object>[]}
 * @param [options.kind] {'agent' | 'app'}
 * @param [options.pairwise] {object}
 * @param [options.name] {string}
 * @param [options.at] {Date}
 * @returns {Promise<void>}
 */
async function consent({
  did,
  grants,
  kind = 'agent',
  pairwise,
  name,
  at = new Date(Date.now() - DAY_MS)
}: {
  did: string
  grants: Array<Promise<Record<string, unknown>>>
  kind?: 'agent' | 'app'
  pairwise?: { seed: string; seedTag: string }
  name?: string
  at?: Date
}): Promise<void> {
  const zcaps = await Promise.all(grants)
  await recordGrants({
    store: directory.store,
    hmacKey: HMAC_KEY,
    did,
    kind,
    spaceUrl: SPACE_URL,
    grants: zcaps.map(zcap => ({ zcap, grantKind: 'grant' as const })),
    ...(name !== undefined && { name }),
    ...(pairwise ? { seed: pairwise.seed, seedTag: pairwise.seedTag } : {}),
    now: at
  })
}

/**
 * A connection request's consent: a read on `news` and POST on `inbox`,
 * both signed by `signer`, with a pairwise seed and a live channel.
 *
 * @param options {object}
 * @param [options.did] {string}
 * @param [options.signer] {AccountKeyName}
 * @param [options.expires] {string}
 * @param [options.channel] {boolean}   store a live channel; default true
 * @returns {Promise<{ pairwiseDid: string }>}
 */
async function connectAgent({
  did = AGENT_DID,
  signer = 'struck',
  expires = inDays(200),
  channel = true
}: {
  did?: string
  signer?: AccountKeyName
  expires?: string
  channel?: boolean
} = {}): Promise<{ pairwiseDid: string }> {
  const pairwise = await pairwiseSeed()
  await consent({
    did,
    pairwise,
    name: `Agent ${did.slice(-4)}`,
    grants: [
      rootGrant({ id: `${did}-read`, controller: did, signer, expires }),
      rootGrant({
        id: `${did}-inbox`,
        controller: did,
        target: INBOX_URL,
        actions: ['POST'],
        signer,
        expires
      })
    ]
  })
  if (channel) {
    await recordReceivedGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did,
      pairwiseDid: pairwise.did,
      spaceUrl: SPACE_URL,
      grants: [
        {
          zcap: channelZcap({ id: `${did}-channel`, controller: pairwise.did }),
          grantKind: 'inbox'
        }
      ],
      channelMaxLifetimeMs: 365 * DAY_MS
    })
  }
  return { pairwiseDid: pairwise.did }
}

/**
 * The entry whose `id` is the DID, as the directory holds it now.
 *
 * @param did {string}
 * @returns {Promise<ConnectionEntry | undefined>}
 */
async function entryOf(did: string): Promise<ConnectionEntry | undefined> {
  const listing = await readConnections({
    store: directory.store,
    hmacKey: HMAC_KEY
  })
  return listing?.entries.find(read => read.entry.id === did)?.entry
}

/**
 * A session over the fixture directory, with a remote Space.
 *
 * @param [options] {object}
 * @param [options.signerCheck] {AccountSignerCheck | null}   `null` reads
 *   as unavailable
 * @returns {object}   the session and its storage double
 */
function fakeSession({
  signerCheck = SIGNER_CHECK
}: { signerCheck?: AccountSignerCheck | null } = {}) {
  const storage = Object.assign(directoryStorage({ directory }), {
    hasRemoteStorage: true,
    connectionsDirectory: vi.fn(async () => ({
      store: directory.store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL
    })),
    renewalSignerCheck: vi.fn(async () => signerCheck ?? undefined),
    delegateRenewalGrants: vi.fn(async options =>
      delegateUnderSessionParent({ ...options, spaceUrl: SPACE_URL })
    ),
    addHistoryGrant: vi.fn(async (_options: Record<string, unknown>) => {
      pass.calls.push('activity')
      return 'activity-id'
    })
  })
  const session = {
    user,
    isGuest: false,
    profile: {
      zcapClient: fakeZcapClient({ idPrefix: 'restored' }).zcapClient
    },
    storage,
    disposal: sessionDisposalSignal(),
    encounterGate: Promise.resolve()
  } as unknown as Session
  return { session, storage }
}

describe('the withdrawn keys each ceremony names', () => {
  it("names the revoked client's and the forgotten client's signing key", () => {
    expect(
      revokedClientWithdrawnKeys({ client: { signingKeyMultibase: 'z6MkA' } })
    ).toEqual(['z6MkA'])
    expect(
      forgottenClientWithdrawnKeys({
        session: {
          profile: { keyAgent: { id: 'did:key:z6MkSelf' } }
        } as unknown as Session
      })
    ).toEqual(['z6MkSelf'])
    expect(
      forgottenClientWithdrawnKeys({
        session: { profile: {} } as unknown as Session
      })
    ).toEqual([])
  })

  it("names a retired credential's ladder VM from the log's attribution, not the entry's proof key ids", async () => {
    const vm = `${ACCOUNT_DID}#${KEYS.struck}`
    vi.mocked(verifiedAccountLog).mockResolvedValue({
      log: [],
      doc: { id: ACCOUNT_DID }
    } as never)
    vi.mocked(attributeUnlockLadderInventory).mockResolvedValue({
      ladderVmIds: [vm]
    } as never)
    vi.mocked(ladderVmClaimOf).mockResolvedValue({
      struck: [vm],
      unclaimed: []
    })
    const { session } = fakeSession()
    const entry = {
      type: 'passphrase' as const,
      keyAgreementKeyMultibase:
        'z6LSgJbFbAEq4zhHZ7FrQKqF6ja8tcjNpVu8ZbhnxmunPkN7',
      updateKeyMultibase: 'z6MkRung0',
      // A refreshed pair's proof key ids name the enrolled client, which
      // the retirement leaves standing.
      delegationKeyId: `${ACCOUNT_DID}#${KEYS.client}`,
      delegatedClientsKeyId: `${ACCOUNT_DID}#${KEYS.client}`
    }
    expect(await retiredCredentialWithdrawnKeys({ session, entry })).toEqual([
      vm
    ])
    expect(vi.mocked(attributeUnlockLadderInventory).mock.calls[0]![0]).toEqual(
      {
        log: [],
        did: ACCOUNT_DID,
        unlockKeys: {
          keyAgreement: { commitment: expect.any(String) },
          updateKeyMultibase: 'z6MkRung0'
        }
      }
    )
    // An entry recording no anchor withdraws nothing a dialog can name.
    expect(
      await retiredCredentialWithdrawnKeys({
        session,
        entry: { type: 'passkey', keyAgreementKeyMultibase: 'z6LSother' }
      })
    ).toEqual([])
    expect(verifiedAccountLog).toHaveBeenCalledTimes(1)
  })
})

describe('agentsSignedByWithdrawnAuthority', () => {
  // The document as it stands before the withdrawal: the struck key is
  // still listed, since the read names the agents a ceremony WOULD cut off.
  beforeEach(() => {
    vi.mocked(verifiedAccountLog).mockResolvedValue({
      log: [],
      doc: {
        id: ACCOUNT_DID,
        verificationMethod: [
          {
            id: `${ACCOUNT_DID}#${KEYS.client}`,
            publicKeyMultibase: KEYS.client
          },
          {
            id: `${ACCOUNT_DID}#${KEYS.struck}`,
            publicKeyMultibase: KEYS.struck
          }
        ],
        capabilityDelegation: [
          `${ACCOUNT_DID}#${KEYS.client}`,
          `${ACCOUNT_DID}#${KEYS.struck}`
        ]
      }
    } as never)
  })

  it('lists exactly the agents a withdrawn key signed for, root- or annex-anchored', async () => {
    // Root-anchored, signed by the struck key.
    await connectAgent({ did: AGENT_DID, signer: 'struck' })
    // Signed by a key that stays.
    await connectAgent({ did: OTHER_AGENT_DID, signer: 'client' })
    // Annex-anchored, under a generation delegation the struck key minted.
    await consent({
      did: THIRD_AGENT_DID,
      grants: [
        annexGrant({
          id: 'annex-read',
          controller: THIRD_AGENT_DID,
          parentSigner: 'struck'
        })
      ]
    })
    // An app the struck key signed for is not an agent.
    await consent({
      did: APP_DID,
      kind: 'app',
      grants: [
        rootGrant({ id: 'app-read', controller: APP_DID, signer: 'struck' })
      ]
    })
    const { session } = fakeSession()

    const listed = await agentsSignedByWithdrawnAuthority({
      session,
      keys: [KEYS.struck]
    })
    expect(listed.map(agent => agent.did).sort()).toEqual(
      [AGENT_DID, THIRD_AGENT_DID].sort()
    )
    // The verification-method form names the same agents.
    const byVmId = await agentsSignedByWithdrawnAuthority({
      session,
      keys: [`${ACCOUNT_DID}#${KEYS.struck}`]
    })
    expect(byVmId.map(agent => agent.did).sort()).toEqual(
      listed.map(agent => agent.did).sort()
    )
  })

  it('leaves out a retired agent, and reads nothing for no keys', async () => {
    await connectAgent({ did: AGENT_DID, signer: 'struck' })
    await retireConnection({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      handledZcapIds: [`${AGENT_DID}-read`, `${AGENT_DID}-inbox`],
      spaceUrl: SPACE_URL
    })
    const { session, storage } = fakeSession()

    expect(
      await agentsSignedByWithdrawnAuthority({ session, keys: [KEYS.struck] })
    ).toEqual([])
    storage.readConnectionsListing.mockClear()
    expect(
      await agentsSignedByWithdrawnAuthority({ session, keys: [] })
    ).toEqual([])
    expect(storage.readConnectionsListing).not.toHaveBeenCalled()
  })
})

describe('declineAgents', () => {
  it('marks an unticked agent declined, and its row stays listed', async () => {
    await connectAgent({ did: AGENT_DID })
    const { session } = fakeSession()

    const result = await declineAgents({ session, dids: [AGENT_DID] })

    expect(result).toEqual({ declined: [AGENT_DID], failed: [] })
    const entry = await entryOf(AGENT_DID)
    expect(entry?.declined).toEqual(expect.any(String))
    expect(entry?.retired).toBeUndefined()
    const listing = await readConnections({
      store: directory.store,
      hmacKey: HMAC_KEY
    })
    const [row] = await listConnectedAgents({
      storage: asStorageManager(directoryStorage({ directory })),
      connections: listing!.entries,
      spaceUrl: SPACE_URL
    })
    expect(row.controller).toBe(AGENT_DID)
    expect(row.declined).toBe(entry?.declined)
  })
})

describe('declineAgents, a failed write', () => {
  it('reports and logs the agent whose marker did not land, and marks the rest', async () => {
    await connectAgent({ did: AGENT_DID })
    await connectAgent({ did: OTHER_AGENT_DID })
    const failing = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: AGENT_DID
    })
    const put = directory.store.put.bind(directory.store)
    vi.spyOn(directory.store, 'put').mockImplementation(async options => {
      if (options.resourceId === failing) {
        throw Object.assign(new Error('offline'), { name: 'NetworkError' })
      }
      return await put(options)
    })
    const capture = captureSink()
    const stopCapture = addSink(capture.sink)
    const { session } = fakeSession()

    try {
      const result = await declineAgents({
        session,
        dids: [AGENT_DID, OTHER_AGENT_DID]
      })

      expect(result).toEqual({
        declined: [OTHER_AGENT_DID],
        failed: [AGENT_DID]
      })
      expect(capture.events).toContainEqual(
        expect.objectContaining({
          ns: 'fw:inbox',
          msg: "Could not record the owner's decline of an agent"
        })
      )
      expect((await entryOf(OTHER_AGENT_DID))?.declined).toEqual(
        expect.any(String)
      )
    } finally {
      stopCapture()
    }
  })
})

describe('reconnectAgents', () => {
  it('re-mints the in-scope grants as a fresh consent, queues them, records a Grant activity, then runs the pass', async () => {
    const { pairwiseDid } = await connectAgent({ did: AGENT_DID })
    await declineAgents({ session: fakeSession().session, dids: [AGENT_DID] })
    const { session, storage } = fakeSession()

    const result = await reconnectAgents({ session, dids: [AGENT_DID] })

    expect(result.agents).toEqual([
      { did: AGENT_DID, name: expect.any(String), outcome: 'restored' }
    ])
    const entry = await entryOf(AGENT_DID)
    // The fresh consent clears the decline marker.
    expect(entry?.declined).toBeUndefined()
    const restored = entry!.grants.filter(grant =>
      grant.zcap.id.startsWith('urn:uuid:restored-')
    )
    expect(restored.map(grant => grant.zcap.invocationTarget).sort()).toEqual(
      [INBOX_URL, NEWS_URL].sort()
    )
    // One consent: one `grantedAt`, later than the first consent's.
    expect(new Set(restored.map(grant => grant.grantedAt)).size).toBe(1)
    expect(Date.parse(restored[0].grantedAt)).toBeGreaterThan(
      Date.now() - 60_000
    )
    // The envelope carrying exactly those grants waits on the outbox.
    expect(entry!.outbox).toHaveLength(1)
    const message = entry!.outbox[0].message as {
      actor: string
      object: { zcaps: Array<{ id: string }> }
    }
    expect(message.actor).toBe(pairwiseDid)
    expect(message.object.zcaps.map(zcap => zcap.id).sort()).toEqual(
      restored.map(grant => grant.zcap.id).sort()
    )
    expect(storage.addHistoryGrant).toHaveBeenCalledTimes(1)
    expect(storage.addHistoryGrant.mock.calls[0][0]).toMatchObject({
      origin: EXTERNAL_REQUEST_ORIGIN,
      actor: { name: expect.any(String) }
    })
    // The activity lands before the pass that pushes the envelope.
    expect(pass.calls).toEqual(['activity', 'pass'])
  })

  it("re-mints an earlier consent's reads after a later connection request superseded its inbox grant", async () => {
    const { pairwiseDid } = await connectAgent({ did: AGENT_DID })
    const photos = `${SPACE_URL}photos/`
    // A second connection request: a new read, and an inbox grant that
    // supersedes the first consent's. The first consent's read stays in the
    // renewal's scope, the same selection the inbox pass renews.
    await consent({
      did: AGENT_DID,
      grants: [
        rootGrant({
          id: `${AGENT_DID}-photos`,
          controller: AGENT_DID,
          target: photos,
          signer: 'struck'
        }),
        rootGrant({
          id: `${AGENT_DID}-inbox-2`,
          controller: AGENT_DID,
          target: INBOX_URL,
          actions: ['POST'],
          signer: 'struck'
        })
      ],
      at: new Date()
    })
    const { session } = fakeSession()

    const result = await reconnectAgents({ session, dids: [AGENT_DID] })

    expect(result.agents[0]).toMatchObject({
      did: AGENT_DID,
      outcome: 'restored'
    })
    const entry = await entryOf(AGENT_DID)
    const restored = entry!.grants.filter(grant =>
      grant.zcap.id.startsWith('urn:uuid:restored-')
    )
    expect(restored.map(grant => grant.zcap.invocationTarget).sort()).toEqual(
      [INBOX_URL, NEWS_URL, photos].sort()
    )
    expect(entry!.outbox[0].message).toMatchObject({ actor: pairwiseDid })
  })

  it('does not un-retire an agent a revoke retired while the restore ran', async () => {
    await connectAgent({ did: AGENT_DID })
    await declineAgents({ session: fakeSession().session, dids: [AGENT_DID] })
    const { session, storage } = fakeSession()
    const mint = storage.delegateRenewalGrants.getMockImplementation()!
    // The revoke lands between the restore's listing and its record.
    storage.delegateRenewalGrants.mockImplementation(async options => {
      await retireConnection({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT_DID,
        handledZcapIds: (await entryOf(AGENT_DID))!.grants.map(
          grant => grant.zcap.id
        ),
        spaceUrl: SPACE_URL
      })
      return mint(options)
    })

    const result = await reconnectAgents({ session, dids: [AGENT_DID] })

    expect(result.agents).toEqual([
      {
        did: AGENT_DID,
        name: expect.any(String),
        outcome: 'not-restored',
        reason: 'not-found'
      }
    ])
    const entry = await entryOf(AGENT_DID)
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.grants).toEqual([])
    expect(entry?.outbox).toEqual([])
    expect(storage.addHistoryGrant).not.toHaveBeenCalled()
  })

  it('runs only the pass when no agent is ticked', async () => {
    const { session, storage } = fakeSession()

    const result = await reconnectAgents({ session, dids: [] })

    expect(result.agents).toEqual([])
    expect(pass.calls).toEqual(['pass'])
    expect(storage.connectionsDirectory).not.toHaveBeenCalled()
  })

  it('names an agent whose push the pass could not deliver', async () => {
    await connectAgent({ did: AGENT_DID })
    pass.pushFailures.push({ agentDid: AGENT_DID, reason: 'network' })
    const { session } = fakeSession()

    const result = await reconnectAgents({ session, dids: [AGENT_DID] })

    expect(result.agents[0]).toMatchObject({
      outcome: 'not-restored',
      reason: 'push-failed'
    })
  })

  it('clears the marker on a declined agent with nothing in scope, and restores nothing', async () => {
    await consent({
      did: AGENT_DID,
      grants: [rootGrant({ id: 'old-read', signer: 'struck' })]
    })
    await declineAgents({ session: fakeSession().session, dids: [AGENT_DID] })
    const { session, storage } = fakeSession()

    const result = await reconnectAgents({ session, dids: [AGENT_DID] })

    expect(result.agents[0]).toMatchObject({
      outcome: 'not-restored',
      reason: 'nothing-in-scope'
    })
    expect((await entryOf(AGENT_DID))?.declined).toBeUndefined()
    expect(storage.delegateRenewalGrants).not.toHaveBeenCalled()
  })

  it('writes nothing when the account document cannot be read', async () => {
    await connectAgent({ did: AGENT_DID })
    const before = await entryOf(AGENT_DID)
    const { session, storage } = fakeSession({ signerCheck: null })

    const result = await reconnectAgents({ session, dids: [AGENT_DID] })

    expect(result.agents[0]).toMatchObject({ reason: 'no-signer-check' })
    expect(storage.delegateRenewalGrants).not.toHaveBeenCalled()
    expect((await entryOf(AGENT_DID))?.grants).toEqual(before?.grants)
  })
})

describe('lapsedAgentOffers', () => {
  it('offers a lapsed or cut-off agent, and skips a declined, a retired, a channel-less, and a live one', async () => {
    // Cut off: signed by a struck key.
    await connectAgent({ did: AGENT_DID, signer: 'struck' })
    // Live: signed by a key that stays.
    await connectAgent({ did: OTHER_AGENT_DID, signer: 'client' })
    // Lapsed: past its expiry.
    await connectAgent({
      did: THIRD_AGENT_DID,
      signer: 'client',
      expires: new Date(Date.now() - DAY_MS).toISOString()
    })
    // Declined, though cut off.
    const declinedDid =
      'did:key:z6MkqEPctyQs9MofPZCw2XdeFi2dTMoMqHKhfoWsfitrnprw'
    await connectAgent({ did: declinedDid, signer: 'struck' })
    await declineAgents({ session: fakeSession().session, dids: [declinedDid] })
    // No channel, though cut off.
    const channelless =
      'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp'
    await connectAgent({ did: channelless, signer: 'struck', channel: false })
    // Retired, though cut off.
    const retired = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJF'
    await connectAgent({ did: retired, signer: 'struck' })
    await retireConnection({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: retired,
      handledZcapIds: [`${retired}-read`, `${retired}-inbox`],
      spaceUrl: SPACE_URL
    })
    const { session } = fakeSession()

    const offers = await lapsedAgentOffers({ session })

    expect(offers.map(offer => offer.did).sort()).toEqual(
      [AGENT_DID, THIRD_AGENT_DID].sort()
    )
  })

  it('stops offering a lapsed agent whose refused channel was dropped, until a new channel is stored', async () => {
    const { pairwiseDid } = await connectAgent({
      did: AGENT_DID,
      signer: 'client',
      expires: new Date(Date.now() - DAY_MS).toISOString()
    })
    const { session } = fakeSession()
    expect(
      (await lapsedAgentOffers({ session })).map(offer => offer.did)
    ).toEqual([AGENT_DID])

    // The push's channel refusal drops the record.
    await dropReceivedGrant({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      zcapId: `${AGENT_DID}-channel`
    })
    expect(await lapsedAgentOffers({ session })).toEqual([])

    // The agent's next invitation stores a replacement channel.
    await recordReceivedGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      pairwiseDid,
      spaceUrl: SPACE_URL,
      grants: [
        {
          zcap: channelZcap({
            id: `${AGENT_DID}-channel-2`,
            controller: pairwiseDid,
            expires: inDays(30)
          }),
          grantKind: 'inbox'
        }
      ],
      channelMaxLifetimeMs: 365 * DAY_MS
    })
    expect(
      (await lapsedAgentOffers({ session })).map(offer => offer.did)
    ).toEqual([AGENT_DID])
  })

  it('offers nothing when the account document cannot be read', async () => {
    await connectAgent({ did: AGENT_DID, signer: 'struck' })
    const { session } = fakeSession({ signerCheck: null })

    expect(await lapsedAgentOffers({ session })).toEqual([])
  })
})

describe('revokeAgentAccess against renewal', () => {
  /**
   * The agent's row, as the Applications page lists it.
   *
   * @returns {Promise<object>}
   */
  async function listedAgent() {
    const listing = await readConnections({
      store: directory.store,
      hmacKey: HMAC_KEY
    })
    const [agent] = await listConnectedAgents({
      storage: asStorageManager(directoryStorage({ directory })),
      connections: listing!.entries,
      spaceUrl: SPACE_URL
    })
    return agent
  }

  /**
   * A renewal of the agent's read grant, as the pass mints one.
   *
   * @param options {object}
   * @param options.pairwiseDid {string}
   * @returns {Promise<unknown>}
   */
  async function renewRead({
    pairwiseDid
  }: {
    pairwiseDid: string
  }): Promise<unknown> {
    const zcap = await rootGrant({
      id: 'renewed-read',
      signer: 'client',
      expires: inDays(365)
    })
    return await recordRenewedGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      pairwiseDid,
      spaceUrl: SPACE_URL,
      renewals: [{ zcap, sourceZcapId: `${AGENT_DID}-read` }],
      message: { type: 'Grant', actor: pairwiseDid, object: { zcaps: [zcap] } },
      channelMaxLifetimeMs: 365 * DAY_MS
    })
  }

  it('empties the channel and the outbox first, so a torn revoke leaves nothing to renew', async () => {
    const { pairwiseDid } = await connectAgent({
      did: AGENT_DID,
      signer: 'client',
      expires: inDays(60)
    })
    await renewRead({ pairwiseDid })
    expect((await entryOf(AGENT_DID))?.outbox).toHaveLength(1)
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

    expect(storage.calls[0]).toBe('clearConnectionChannel')
    const entry = await entryOf(AGENT_DID)
    expect(entry?.retired).toBeUndefined()
    expect(entry?.grantsReceived).toEqual([])
    expect(entry?.outbox).toEqual([])
    // The next login's renewal finds no candidate.
    const listing = await readConnections({
      store: directory.store,
      hmacKey: HMAC_KEY
    })
    expect(
      await agentsWithChannel({
        entries: listing!.entries,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        now: new Date()
      })
    ).toEqual([])
    // And a renewal racing it is refused, with nothing recorded.
    await expect(renewRead({ pairwiseDid })).rejects.toThrow(
      'no live inbox channel'
    )
  })

  it('revoke first, renewal second: the renewal meets a retired entry and records nothing', async () => {
    const { pairwiseDid } = await connectAgent({
      did: AGENT_DID,
      signer: 'client'
    })
    const storage = directoryStorage({ directory })
    await revokeAgentAccess({
      storage: asStorageManager(storage),
      user,
      agent: await listedAgent()
    })

    await expect(renewRead({ pairwiseDid })).rejects.toThrow()
    const entry = await entryOf(AGENT_DID)
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.grants).toEqual([])
    expect(entry?.outbox).toEqual([])
  })

  it('renewal first, revoke second: the revoke POSTs the renewal and its superseded source', async () => {
    const { pairwiseDid } = await connectAgent({
      did: AGENT_DID,
      signer: 'client',
      expires: inDays(60)
    })
    await renewRead({ pairwiseDid })
    const storage = directoryStorage({ directory })

    await revokeAgentAccess({
      storage: asStorageManager(storage),
      user,
      agent: await listedAgent()
    })

    const [posted] = storage.revokeConnectionGrants.mock.calls[0]
    expect(posted.grants.map(grant => grant.zcapId).sort()).toEqual(
      [`${AGENT_DID}-inbox`, `${AGENT_DID}-read`, 'renewed-read'].sort()
    )
    const entry = await entryOf(AGENT_DID)
    expect(entry?.retired).toEqual(expect.any(String))
    expect(entry?.grantsReceived).toEqual([])
    expect(entry?.outbox).toEqual([])
  })

  it('a consent merged mid-revoke aborts the retire, and the re-run POSTs it and retires', async () => {
    await connectAgent({ did: AGENT_DID, signer: 'client' })
    const storage = directoryStorage({ directory })
    storage.revokeConnectionGrants.mockImplementationOnce(
      async ({ grants }) => {
        await consent({
          did: AGENT_DID,
          grants: [
            rootGrant({ id: 'merged-read', target: `${SPACE_URL}more/` })
          ]
        })
        return {
          revoked: grants.length,
          withdrawn: grants.length,
          skipped: 0,
          revokedIds: grants.map(grant => grant.zcapId)
        }
      }
    )

    await expect(
      revokeAgentAccess({
        storage: asStorageManager(storage),
        user,
        agent: await listedAgent()
      })
    ).rejects.toThrow('did not handle')
    await revokeAgentAccess({
      storage: asStorageManager(storage),
      user,
      agent: await listedAgent()
    })

    const [posted] = storage.revokeConnectionGrants.mock.calls[1]
    expect(posted.grants.map(grant => grant.zcapId)).toContain('merged-read')
    expect((await entryOf(AGENT_DID))?.retired).toEqual(expect.any(String))
  })

  it('pins the stated residue: an entry restored from before the revoke is renewed again', async () => {
    const { pairwiseDid } = await connectAgent({
      did: AGENT_DID,
      signer: 'client',
      expires: inDays(60)
    })
    const resourceId = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: AGENT_DID
    })
    const snapshot = structuredClone(directory.rows.get(resourceId)!)
    await revokeAgentAccess({
      storage: asStorageManager(directoryStorage({ directory })),
      user,
      agent: await listedAgent()
    })
    // A lost directory restored from a copy taken before the revoke.
    directory.rows.set(resourceId, { ...snapshot, etag: 'restored' })

    const listing = await readConnections({
      store: directory.store,
      hmacKey: HMAC_KEY
    })
    const withChannel = await agentsWithChannel({
      entries: listing!.entries,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      now: new Date()
    })
    expect(withChannel.map(({ pairwiseDid: did }) => did)).toEqual([
      pairwiseDid
    ])
    const { candidates } = await dueAgentGrants({
      withChannel,
      spaceUrl: SPACE_URL,
      signerCheck: SIGNER_CHECK,
      now: new Date()
    })
    expect(candidates).toHaveLength(1)
  })
})

describe('the listing after a renewal', () => {
  it('counts each scope once and names the renewed lapse date, the superseded record under it', async () => {
    const { pairwiseDid } = await connectAgent({
      did: AGENT_DID,
      signer: 'client',
      expires: inDays(60)
    })
    const renewed = await rootGrant({
      id: 'renewed-read',
      signer: 'client',
      expires: inDays(365)
    })
    await recordRenewedGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      pairwiseDid,
      spaceUrl: SPACE_URL,
      renewals: [{ zcap: renewed, sourceZcapId: `${AGENT_DID}-read` }],
      message: {
        type: 'Grant',
        actor: pairwiseDid,
        object: { zcaps: [renewed] }
      },
      channelMaxLifetimeMs: 365 * DAY_MS
    })
    const listing = await readConnections({
      store: directory.store,
      hmacKey: HMAC_KEY
    })

    const [agent] = await listConnectedAgents({
      storage: asStorageManager(directoryStorage({ directory })),
      connections: listing!.entries,
      spaceUrl: SPACE_URL
    })

    expect(agent.grants).toHaveLength(2)
    const read = agent.grants.find(grant => grant.target === NEWS_URL)!
    expect(read.id).toBe('renewed-read')
    expect(read.expires).toBe(renewed.expires)
    expect(read.earlier?.map(grant => grant.id)).toEqual([`${AGENT_DID}-read`])
    const inbox = agent.grants.find(grant => grant.target === INBOX_URL)!
    expect(inbox.earlier).toBeUndefined()
  })
})
