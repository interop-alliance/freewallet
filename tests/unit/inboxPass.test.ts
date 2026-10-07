// @vitest-environment node
/**
 * The inbox pass (`src/session/inboxPass.ts`): the drain of the account's
 * own `inbox`, the renewal of the connected agents' grants, the outbox push,
 * and the parent rule the renewal mints under
 * (`delegateUnderSessionParent`, `src/stores/storageManager.ts`). The
 * directory is wallet-core's own codec and upsert helpers over an in-memory
 * store, and the pairwise did:keys are derived from real seeds. The storage
 * manager's inbox reads, the generation log read, and the push to an
 * agent's server are fakes the tests drive.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import {
  clearReceivedGrants,
  connectionResourceId,
  readConnections,
  recordGrants,
  recordReceivedGrants,
  recordRenewedGrants,
  removeGrants,
  retireConnection,
  verifyRecordedGrantProof,
  type ConnectionEntry
} from '@interop/wallet-core/connections'
import type { IZcap } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'
import type {
  InboxMessageMeta,
  InboxRead,
  UntrustedInboxReason
} from '@/stores/storageManager'
import { HMAC_KEY, memoryConnectionsStore } from './memoryConnections'
import {
  ACCOUNT_DID,
  AGENT_DID,
  DAY_MS,
  INBOX_URL,
  NEWS_URL,
  OTHER_AGENT_DID,
  POINTED_DELEGATION,
  SPACE_URL,
  annexGrant,
  channelZcap,
  fakeZcapClient,
  fixtureSignerCheck,
  generationDelegation,
  inDays,
  pairwiseSeed,
  rootGrant
} from './connectionFixtures'

const { delegateUnderSessionParent } = await import('@/stores/storageManager')
const { runInboxPass, inboxVisitOutcome } = await import('@/session/inboxPass')
const { sessionDisposalSignal } = await import('@/session/sessionLifecycle')

const PHOTOS_URL = `${SPACE_URL}photos/`
const NOTES_URL = `${SPACE_URL}notes/`
const COLLECTED_ANNEX_DID =
  'did:webvh:scid:was.example:space:aux:gen-BBBBBBBBBBBBBBBB'

const SIGNER_CHECK = await fixtureSignerCheck()

/**
 * One message in the fake inbox.
 */
type Message = { meta: Omit<InboxMessageMeta, 'resourceId'>; body: unknown }

/**
 * A fake session over an in-memory directory and a fake inbox.
 *
 * @param [options] {object}
 * @param [options.trust] {'trusted' | 'absent' | UntrustedInboxReason}
 * @param [options.noSignerCheck] {boolean}   the signer check reads
 *   `undefined`
 * @param [options.invocationCapability] {object}
 * @param [options.listingFails] {boolean}
 * @returns {object}
 */
function fixture({
  trust = 'trusted',
  noSignerCheck = false,
  invocationCapability,
  listingFails = false
}: {
  trust?: 'trusted' | 'absent' | UntrustedInboxReason
  noSignerCheck?: boolean
  invocationCapability?: Record<string, unknown>
  listingFails?: boolean
} = {}) {
  const signerCheck = noSignerCheck ? undefined : SIGNER_CHECK
  const directory = memoryConnectionsStore()
  const inbox = new Map<string, Message>()
  const { zcapClient, calls } = fakeZcapClient()
  let posted = 0

  /**
   * The inbox listing, two ids a page, read as it stands when each page is
   * reached.
   *
   * @returns {AsyncGenerator<string[]>}
   */
  async function* pages(): AsyncGenerator<string[]> {
    if (listingFails) {
      throw Object.assign(new Error('listing failed'), { name: 'NetworkError' })
    }
    const ids = [...inbox.keys()]
    for (let index = 0; index < ids.length; index += 2) {
      yield ids.slice(index, index + 2)
    }
  }

  const storage = {
    hasRemoteStorage: true,
    connectionsDirectory: vi.fn(async () => ({
      store: directory.store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL
    })),
    readConnectionsListing: vi.fn(async () => {
      const listing = await readConnections({
        store: directory.store,
        hmacKey: HMAC_KEY
      })
      if (!listing) {
        throw new Error('The connections directory could not be listed.')
      }
      return {
        store: directory.store,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        listing
      }
    }),
    readInbox: vi.fn(async (): Promise<InboxRead> => {
      if (trust === 'absent') {
        return { trust: 'absent' }
      }
      if (trust !== 'trusted') {
        return { trust: 'untrusted', reason: trust }
      }
      return { trust: 'trusted', pages: pages() }
    }),
    readInboxMessageMeta: vi.fn(async ({ resourceId }) => {
      const message = inbox.get(resourceId)
      return message ? { resourceId, ...message.meta } : null
    }),
    readInboxMessageBody: vi.fn(async ({ resourceId }) => {
      const message = inbox.get(resourceId)
      return message ? structuredClone(message.body) : null
    }),
    deleteInboxMessage: vi.fn(async ({ resourceId }) => {
      inbox.delete(resourceId)
    }),
    renewalSignerCheck: vi.fn(async () => signerCheck),
    delegateRenewalGrants: vi.fn(async options =>
      delegateUnderSessionParent({ ...options, spaceUrl: SPACE_URL })
    ),
    addHistoryGrant: vi.fn(
      async (_options: { grants: Array<{ target: string }> }) => 'activity-id'
    )
  }
  const session = {
    user: { id: ACCOUNT_DID, email: 'owner@example.com' },
    isGuest: false,
    profile: {
      zcapClient,
      ...(invocationCapability ? { invocationCapability } : {})
    },
    storage,
    disposal: sessionDisposalSignal(),
    encounterGate: Promise.resolve()
  } as unknown as Session

  const deps = {
    readPointedDelegationId: vi.fn(async () => POINTED_DELEGATION),
    push: vi.fn(
      async (_options: {
        channel: Record<string, unknown>
        message: Record<string, unknown>
      }) => undefined
    ),
    renewParent: vi.fn(async () => null as IZcap | null),
    now: () => new Date()
  }

  /**
   * Posts a message into the fake inbox.
   *
   * @param options {object}
   * @param [options.createdBy] {string}
   * @param [options.contentType] {string}
   * @param [options.size] {number}
   * @param options.body {unknown}
   * @returns {string}   its resource id
   */
  function post({
    createdBy,
    contentType = 'application/json',
    size = 900,
    body
  }: {
    createdBy?: string
    contentType?: string
    size?: number
    body: unknown
  }): string {
    posted += 1
    const resourceId = `m${String(posted).padStart(3, '0')}`
    inbox.set(resourceId, {
      meta: {
        ...(createdBy !== undefined ? { createdBy } : {}),
        contentType,
        size
      },
      body
    })
    return resourceId
  }

  /**
   * The party's entry as the directory holds it now.
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
   * Runs one pass with the fixture's seams.
   *
   * @returns {Promise<object>}
   */
  async function pass() {
    return await runInboxPass({ session, deps })
  }

  return {
    directory,
    inbox,
    storage,
    session,
    deps,
    calls,
    post,
    entryOf,
    pass
  }
}

/**
 * Records a connection request's consent on an agent's entry: a read on an
 * audience collection and POST on this Space's inbox, one `grantedAt`, with
 * the pairwise seed.
 *
 * @param options {object}
 * @param options.directory {object}
 * @param [options.did] {string}
 * @param options.pairwise {object}   the seed and its tag
 * @param [options.grants] {Promise<object>[]}   the zcaps; a connection's two
 *   by default
 * @param [options.name] {string}
 * @param [options.at] {Date}   the consent's time, its one `grantedAt`
 * @returns {Promise<void>}
 */
async function connect({
  directory,
  did = AGENT_DID,
  pairwise,
  grants,
  name = 'News agent',
  at = new Date()
}: {
  directory: ReturnType<typeof memoryConnectionsStore>
  did?: string
  pairwise?: { seed: string; seedTag: string }
  grants?: Array<Promise<Record<string, unknown>>>
  name?: string
  at?: Date
}): Promise<void> {
  const zcaps = await Promise.all(
    grants ?? [
      rootGrant({ id: `${did}-read`, controller: did }),
      rootGrant({
        id: `${did}-inbox`,
        controller: did,
        target: INBOX_URL,
        actions: ['POST']
      })
    ]
  )
  await recordGrants({
    store: directory.store,
    hmacKey: HMAC_KEY,
    did,
    kind: 'agent',
    spaceUrl: SPACE_URL,
    grants: zcaps.map(zcap => ({ zcap, grantKind: 'grant' as const })),
    name,
    ...(pairwise ? { seed: pairwise.seed, seedTag: pairwise.seedTag } : {}),
    now: at
  })
}

/**
 * Stores a live channel on an agent's entry, as a drain would.
 *
 * @param options {object}
 * @param options.directory {object}
 * @param options.pairwiseDid {string}
 * @param [options.did] {string}
 * @returns {Promise<void>}
 */
async function storeChannel({
  directory,
  pairwiseDid,
  did = AGENT_DID
}: {
  directory: ReturnType<typeof memoryConnectionsStore>
  pairwiseDid: string
  did?: string
}): Promise<void> {
  await recordReceivedGrants({
    store: directory.store,
    hmacKey: HMAC_KEY,
    did,
    pairwiseDid,
    spaceUrl: SPACE_URL,
    grants: [
      {
        zcap: channelZcap({ id: `${did}-channel`, controller: pairwiseDid }),
        grantKind: 'inbox'
      }
    ],
    channelMaxLifetimeMs: 365 * DAY_MS
  })
}

/**
 * A Grant envelope an agent posts.
 *
 * @param options {object}
 * @param options.actor {string}
 * @param options.zcaps {object[]}
 * @returns {object}
 */
function envelope({
  actor,
  zcaps
}: {
  actor: string
  zcaps: Array<Record<string, unknown>>
}): Record<string, unknown> {
  return { type: 'Grant', actor, object: { zcaps } }
}

let stopCapture: (() => void) | undefined
afterEach(() => {
  stopCapture?.()
  stopCapture = undefined
})

describe('the drain', () => {
  it('stores an invitation channel, deletes the message, and reports it', async () => {
    const { directory, inbox, post, entryOf, pass, session } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    post({
      createdBy: AGENT_DID,
      body: envelope({
        actor: AGENT_DID,
        zcaps: [channelZcap({ id: 'channel-1', controller: pairwise.did })]
      })
    })

    const { entries, outcome } = await pass()

    expect(entries[0]).toMatchObject({
      invariant: 'inbox-is-drained',
      outcome: 'clean',
      detail: { deleted: 1, refused: 0 }
    })
    expect(inbox.size).toBe(0)
    const entry = await entryOf(AGENT_DID)
    expect(entry?.grantsReceived.map(record => record.zcap.id)).toEqual([
      'channel-1'
    ])
    expect(outcome.invitations).toEqual([
      expect.objectContaining({ agentDid: AGENT_DID, agentName: 'News agent' })
    ])
    expect(inboxVisitOutcome({ session }).invitations).toHaveLength(1)
  })

  it.each([
    {
      reason: 'actor-mismatch',
      message: (did: string) => ({
        createdBy: AGENT_DID,
        body: envelope({
          actor: OTHER_AGENT_DID,
          zcaps: [channelZcap({ id: 'c', controller: did })]
        })
      })
    },
    {
      reason: 'no-creator',
      message: (did: string) => ({
        body: envelope({
          actor: AGENT_DID,
          zcaps: [channelZcap({ id: 'c', controller: did })]
        })
      })
    },
    {
      reason: 'content-type',
      message: () => ({
        createdBy: AGENT_DID,
        contentType: 'text/plain',
        body: 'hello'
      })
    },
    {
      reason: 'oversized',
      message: (did: string) => ({
        createdBy: AGENT_DID,
        size: 64 * 1024 + 1,
        body: envelope({
          actor: AGENT_DID,
          zcaps: [channelZcap({ id: 'c', controller: did })]
        })
      })
    },
    {
      reason: 'malformed',
      message: () => ({
        createdBy: AGENT_DID,
        body: { type: 'Grant', actor: AGENT_DID, object: { zcaps: [] } }
      })
    }
  ])(
    'refuses a message ($reason), deleting it and storing nothing',
    async ({ reason, message }) => {
      const { directory, inbox, post, entryOf, pass } = fixture()
      const pairwise = await pairwiseSeed()
      await connect({ directory, pairwise })
      post(message(pairwise.did))

      const { entries, outcome } = await pass()

      expect(inbox.size).toBe(0)
      expect((await entryOf(AGENT_DID))?.grantsReceived).toEqual([])
      expect(outcome.refused).toEqual([
        expect.objectContaining({ reason, count: 1 })
      ])
      expect(entries[0].outcome).toBe('clean')
    }
  )

  it('refuses an unknown sender from the listing, with no body read', async () => {
    const { directory, inbox, post, storage, pass } = fixture()
    await connect({ directory, pairwise: await pairwiseSeed() })
    post({
      createdBy: OTHER_AGENT_DID,
      body: envelope({ actor: OTHER_AGENT_DID, zcaps: [{}] })
    })

    const { outcome } = await pass()

    expect(storage.readInboxMessageBody).not.toHaveBeenCalled()
    expect(inbox.size).toBe(0)
    expect(outcome.refused).toEqual([
      { sender: OTHER_AGENT_DID, reason: 'unknown-sender', count: 1 }
    ])
  })

  it('refuses a seedless sender and a sender whose seed fails its tag', async () => {
    const { directory, post, pass } = fixture()
    await connect({ directory })
    const other = await pairwiseSeed()
    await connect({ directory, did: OTHER_AGENT_DID, pairwise: other })
    // A host-planted seed: the stored tag belongs to another seed.
    const resourceId = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: OTHER_AGENT_DID
    })
    const row = directory.rows.get(resourceId)!
    ;(row.body as { seedTag: string }).seedTag = (await pairwiseSeed()).seedTag
    post({
      createdBy: AGENT_DID,
      body: envelope({ actor: AGENT_DID, zcaps: [{}] })
    })
    post({
      createdBy: OTHER_AGENT_DID,
      body: envelope({ actor: OTHER_AGENT_DID, zcaps: [{}] })
    })

    const { outcome } = await pass()

    expect(outcome.refused).toEqual([
      { sender: AGENT_DID, reason: 'seedless-sender', count: 1 },
      { sender: OTHER_AGENT_DID, reason: 'seed-tag', count: 1 }
    ])
  })

  it('ignores a capability for another controller or targeting this Space', async () => {
    const capture = captureSink()
    stopCapture = addSink(capture.sink)
    const { directory, inbox, post, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    post({
      createdBy: AGENT_DID,
      body: envelope({
        actor: AGENT_DID,
        zcaps: [
          channelZcap({ id: 'elsewhere', controller: OTHER_AGENT_DID }),
          channelZcap({
            id: 'renewed',
            controller: pairwise.did,
            target: NEWS_URL
          })
        ]
      })
    })

    await pass()

    expect(inbox.size).toBe(0)
    expect((await entryOf(AGENT_DID))?.grantsReceived).toEqual([])
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:inbox',
        msg: 'Ignored a capability targeting this Space; no renewed grant is accepted from an agent'
      })
    )
  })

  it('keeps an invitation whose entry was written after the listing read', async () => {
    const { directory, post, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    post({
      createdBy: AGENT_DID,
      body: envelope({
        actor: AGENT_DID,
        zcaps: [channelZcap({ id: 'channel-1', controller: pairwise.did })]
      })
    })
    // The consent lands after the pass's first listing read.
    const list = directory.store.list.bind(directory.store)
    let reads = 0
    directory.store.list = async () => {
      reads += 1
      if (reads === 1) {
        const first = await list()
        await connect({ directory, pairwise })
        return first
      }
      return await list()
    }

    await pass()

    expect(reads).toBe(2)
    expect(
      (await entryOf(AGENT_DID))?.grantsReceived.map(record => record.zcap.id)
    ).toEqual(['channel-1'])
  })

  it("leaves a sender's rest past its budget, and reads another sender's invitation", async () => {
    const { directory, inbox, post, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    // Five junk messages at the size bound: four spend the 256 KiB budget.
    const junk = Array.from({ length: 5 }, () =>
      post({
        createdBy: OTHER_AGENT_DID,
        contentType: 'text/plain',
        size: 64 * 1024,
        body: 'junk'
      })
    )
    post({
      createdBy: AGENT_DID,
      body: envelope({
        actor: AGENT_DID,
        zcaps: [channelZcap({ id: 'channel-1', controller: pairwise.did })]
      })
    })

    const { entries } = await pass()

    expect([...inbox.keys()]).toEqual([junk[4]])
    expect(
      (await entryOf(AGENT_DID))?.grantsReceived.map(record => record.zcap.id)
    ).toEqual(['channel-1'])
    expect(entries[0]).toMatchObject({
      outcome: 'partial',
      detail: { deferred: 1 }
    })
  })

  it.each([
    { trust: 'absent' as const, reason: 'no-inbox' },
    { trust: 'public' as const, reason: 'untrusted-inbox' },
    { trust: 'encrypted' as const, reason: 'untrusted-inbox' },
    { trust: 'attributed' as const, reason: 'untrusted-inbox' }
  ])(
    'refuses an inbox read as $trust, and still renews',
    async ({ trust, reason }) => {
      const { directory, storage, pass } = fixture({ trust })
      const pairwise = await pairwiseSeed()
      await connect({ directory, pairwise })
      await storeChannel({ directory, pairwiseDid: pairwise.did })

      const { entries } = await pass()

      expect(entries[0]).toMatchObject({
        invariant: 'inbox-is-drained',
        outcome: 'refused',
        detail: { reason }
      })
      expect(storage.readInboxMessageMeta).not.toHaveBeenCalled()
      expect(entries[1]).toMatchObject({
        invariant: 'agent-grants-are-current',
        outcome: 'clean'
      })
    }
  )

  it('grades a listing failure partial', async () => {
    const { pass } = fixture({ listingFails: true })
    const { entries } = await pass()
    expect(entries[0]).toMatchObject({
      outcome: 'partial',
      detail: { listingFailed: true }
    })
  })
})

describe('the renewal', () => {
  it('renews a due in-scope grant once, records before pushing, and writes one Grant activity', async () => {
    const { directory, deps, storage, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    // The push sees the renewed records already on the entry.
    let recordedAtPush: number | undefined
    deps.push.mockImplementation(async () => {
      recordedAtPush = (await entryOf(AGENT_DID))?.grants.length
    })

    const first = await pass()

    expect(first.entries[1]).toMatchObject({
      outcome: 'clean',
      detail: { renewedEntries: 1, renewedGrants: 2, pushed: 1 }
    })
    expect(recordedAtPush).toBe(4)
    expect(deps.push).toHaveBeenCalledTimes(1)
    const entry = await entryOf(AGENT_DID)
    expect(entry?.grants.filter(grant => grant.renewedAt)).toHaveLength(2)
    expect(entry?.outbox).toEqual([])
    expect(storage.addHistoryGrant).toHaveBeenCalledTimes(1)
    expect(
      storage.addHistoryGrant.mock.calls[0]![0].grants.map(
        grant => grant.target
      )
    ).toEqual([NEWS_URL, INBOX_URL])
    expect(first.outcome.renewalsPushed).toEqual([
      expect.objectContaining({ agentDid: AGENT_DID, agentName: 'News agent' })
    ])

    // A second login in a row reads the renewed records as latest.
    const second = await pass()
    expect(second.entries[1].outcome).toBe('noop')
    expect(deps.push).toHaveBeenCalledTimes(1)
  })

  it('renews nothing on a retired entry, a channel-less entry, or a grant past expiry', async () => {
    const { directory, deps, pass } = fixture()
    const retired = await pairwiseSeed()
    await connect({ directory, pairwise: retired })
    await storeChannel({ directory, pairwiseDid: retired.did })
    await retireConnection({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      handledZcapIds: [`${AGENT_DID}-read`, `${AGENT_DID}-inbox`],
      spaceUrl: SPACE_URL
    })
    await connect({
      directory,
      did: OTHER_AGENT_DID,
      pairwise: await pairwiseSeed()
    })

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'noop',
      detail: { reason: 'no-channel' }
    })
    expect(deps.push).not.toHaveBeenCalled()
  })

  it('renews no grant past its expiry and no write or later non-connection grant', async () => {
    const { directory, deps, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({
      directory,
      pairwise,
      grants: [
        rootGrant({ id: 'lapsed', expires: inDays(-1) }),
        rootGrant({
          id: 'write',
          target: `${SPACE_URL}notes/`,
          actions: ['GET', 'HEAD', 'PUT']
        }),
        rootGrant({
          id: 'inbox',
          target: INBOX_URL,
          actions: ['POST'],
          expires: inDays(200)
        })
      ]
    })
    // A later request that was not a connection request.
    await connect({
      directory,
      grants: [rootGrant({ id: 'later', target: `${SPACE_URL}photos/` })],
      at: new Date(Date.now() + 60_000)
    })
    await storeChannel({ directory, pairwiseDid: pairwise.did })

    const { entries } = await pass()

    expect(entries[1].outcome).toBe('noop')
    expect(deps.push).not.toHaveBeenCalled()
  })

  it("renews no grant whose proof does not verify as the account's", async () => {
    const { directory, deps, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({
      directory,
      pairwise,
      grants: [
        rootGrant({ id: 'struck', signer: 'struck' }),
        rootGrant({
          id: 'inbox',
          target: INBOX_URL,
          actions: ['POST'],
          signer: 'struck'
        })
      ]
    })
    await storeChannel({ directory, pairwiseDid: pairwise.did })

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'noop',
      detail: { unverified: 2 }
    })
    expect(deps.push).not.toHaveBeenCalled()
  })

  it('renews nothing when the signer check is undefined', async () => {
    const { directory, deps, storage, pass } = fixture({
      noSignerCheck: true
    })
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'partial',
      detail: { reason: 'no-signer-check' }
    })
    expect(storage.delegateRenewalGrants).not.toHaveBeenCalled()
    expect(deps.push).not.toHaveBeenCalled()
  })

  it('renews a grant whose collected generation a still-listed key minted, and none whose parent signer left', async () => {
    const { directory, deps, pass } = fixture({
      invocationCapability: await generationDelegation()
    })
    const pairwise = await pairwiseSeed()
    await connect({
      directory,
      pairwise,
      grants: [
        annexGrant({
          id: 'collected-read',
          parentId: 'urn:uuid:collected',
          parentController: COLLECTED_ANNEX_DID
        }),
        annexGrant({
          id: 'collected-inbox',
          target: INBOX_URL,
          actions: ['POST'],
          parentId: 'urn:uuid:collected',
          parentController: COLLECTED_ANNEX_DID
        })
      ]
    })
    const other = await pairwiseSeed()
    await connect({
      directory,
      did: OTHER_AGENT_DID,
      pairwise: other,
      grants: [
        annexGrant({
          id: 'struck-read',
          controller: OTHER_AGENT_DID,
          parentId: 'urn:uuid:struck',
          parentSigner: 'struck'
        }),
        annexGrant({
          id: 'struck-inbox',
          controller: OTHER_AGENT_DID,
          target: INBOX_URL,
          actions: ['POST'],
          parentId: 'urn:uuid:struck',
          parentSigner: 'struck'
        })
      ]
    })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    await storeChannel({
      directory,
      pairwiseDid: other.did,
      did: OTHER_AGENT_DID
    })

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'clean',
      detail: { renewedEntries: 1, renewedGrants: 2, unverified: 2 }
    })
    expect(deps.readPointedDelegationId).toHaveBeenCalledTimes(1)
    expect(deps.push).toHaveBeenCalledTimes(1)
  })

  it('renews a stale parent first, and renews nothing when it cannot be renewed', async () => {
    const stale = await generationDelegation({
      id: 'urn:uuid:stale-parent',
      expires: inDays(3)
    })
    const fresh = await generationDelegation({ expires: inDays(360) })
    const renewable = fixture({ invocationCapability: stale })
    const pairwise = await pairwiseSeed()
    await connect({ directory: renewable.directory, pairwise })
    await storeChannel({
      directory: renewable.directory,
      pairwiseDid: pairwise.did
    })
    renewable.deps.renewParent.mockResolvedValue(fresh as unknown as IZcap)

    const renewed = await renewable.pass()

    expect(renewable.deps.renewParent).toHaveBeenCalledTimes(1)
    expect(renewed.entries[1].outcome).toBe('clean')
    expect(
      renewable.calls.map(call => (call.capability as { id: string }).id)
    ).toEqual([POINTED_DELEGATION, POINTED_DELEGATION])

    const stuck = fixture({ invocationCapability: stale })
    await connect({ directory: stuck.directory, pairwise })
    await storeChannel({
      directory: stuck.directory,
      pairwiseDid: pairwise.did
    })

    const refused = await stuck.pass()

    expect(refused.entries[1]).toMatchObject({
      outcome: 'partial',
      detail: { reason: 'parent-not-renewable' }
    })
    expect(stuck.calls).toEqual([])
    expect((await stuck.entryOf(AGENT_DID))?.outbox).toEqual([])
  })

  it('sees a channel the drain stored earlier in the same pass', async () => {
    const { directory, deps, post, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    post({
      createdBy: AGENT_DID,
      body: envelope({
        actor: AGENT_DID,
        zcaps: [channelZcap({ id: 'channel-1', controller: pairwise.did })]
      })
    })

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'clean',
      detail: { renewedEntries: 1 }
    })
    expect(deps.push).toHaveBeenCalledWith(
      expect.objectContaining({
        channel: expect.objectContaining({ id: 'channel-1' })
      })
    )
  })

  it('discards a renewal whose entry a revoke retired first, queuing nothing', async () => {
    const { directory, deps, storage, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    storage.delegateRenewalGrants.mockImplementation(async options => {
      const minted = await delegateUnderSessionParent({
        ...options,
        spaceUrl: SPACE_URL
      })
      await retireConnection({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT_DID,
        handledZcapIds: [`${AGENT_DID}-read`, `${AGENT_DID}-inbox`],
        spaceUrl: SPACE_URL
      })
      return minted
    })

    const { entries } = await pass()

    expect(entries[1].outcome).toBe('partial')
    const entry = await entryOf(AGENT_DID)
    expect(entry?.retired).toBeDefined()
    expect(entry?.outbox).toEqual([])
    expect(deps.push).not.toHaveBeenCalled()
  })

  it("keeps an earlier consent's reads in scope after a later connection request", async () => {
    const { directory, storage, pass } = fixture()
    const pairwise = await pairwiseSeed()
    const first = new Date()
    await connect({
      directory,
      pairwise,
      grants: [
        rootGrant({ id: 'read-a' }),
        rootGrant({ id: 'read-b', target: PHOTOS_URL }),
        rootGrant({
          id: 'inbox-1',
          target: INBOX_URL,
          actions: ['POST'],
          expires: inDays(200)
        })
      ],
      at: first
    })
    // A second connection request supersedes the first inbox grant.
    await connect({
      directory,
      grants: [
        rootGrant({ id: 'read-c', target: NOTES_URL }),
        rootGrant({
          id: 'inbox-2',
          target: INBOX_URL,
          actions: ['POST'],
          expires: inDays(250)
        })
      ],
      at: new Date(first.getTime() + 60_000)
    })
    await storeChannel({ directory, pairwiseDid: pairwise.did })

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'clean',
      detail: { renewedEntries: 1, renewedGrants: 3 }
    })
    expect(
      storage.addHistoryGrant.mock.calls[0]![0].grants.map(
        grant => grant.target
      )
    ).toEqual([NEWS_URL, PHOTOS_URL, NOTES_URL])
  })

  it('keeps a consent in scope by the stamp its renewed inbox grant carries', async () => {
    const { directory, storage, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    const first = new Date()
    await connect({
      directory,
      pairwise,
      grants: [
        rootGrant({ id: 'read-a' }),
        rootGrant({ id: 'read-b', target: PHOTOS_URL }),
        rootGrant({
          id: 'inbox-1',
          target: INBOX_URL,
          actions: ['POST'],
          expires: inDays(200)
        })
      ],
      at: first
    })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    // An earlier pass renewed the first inbox grant, and a prune then
    // dropped the original record.
    const renewedInbox = await rootGrant({
      id: 'inbox-1-renewed',
      target: INBOX_URL,
      actions: ['POST'],
      expires: inDays(220)
    })
    await recordRenewedGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      pairwiseDid: pairwise.did,
      spaceUrl: SPACE_URL,
      renewals: [{ zcap: renewedInbox, sourceZcapId: 'inbox-1' }],
      message: envelope({ actor: pairwise.did, zcaps: [renewedInbox] }),
      channelMaxLifetimeMs: 365 * DAY_MS
    })
    await removeGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      zcapIds: ['inbox-1']
    })
    await connect({
      directory,
      grants: [
        rootGrant({ id: 'read-c', target: NOTES_URL }),
        rootGrant({
          id: 'inbox-2',
          target: INBOX_URL,
          actions: ['POST'],
          expires: inDays(250)
        })
      ],
      at: new Date(first.getTime() + 60_000)
    })
    const stored = await entryOf(AGENT_DID)
    expect(
      stored?.grants.find(grant => grant.zcap.id === 'inbox-1-renewed')
    ).toMatchObject({
      grantedAt: first.toISOString(),
      renewedAt: expect.any(String)
    })
    expect(stored?.grants.some(grant => grant.zcap.id === 'inbox-1')).toBe(
      false
    )

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'clean',
      detail: { renewedEntries: 1, renewedGrants: 3 }
    })
    expect(
      storage.addHistoryGrant.mock.calls[0]![0].grants.map(
        grant => grant.target
      )
    ).toEqual([NEWS_URL, PHOTOS_URL, NOTES_URL])
  })

  it("grades partial a renewal its parent's life keeps from outlasting its source", async () => {
    const capture = captureSink()
    stopCapture = addSink(capture.sink)
    // Not stale, yet expiring before the read grant it would renew.
    const shortParent = await generationDelegation({ expires: inDays(45) })
    const { directory, deps, storage, pass } = fixture({
      invocationCapability: shortParent
    })
    const pairwise = await pairwiseSeed()
    await connect({
      directory,
      pairwise,
      grants: [
        rootGrant({ id: 'read', expires: inDays(60) }),
        rootGrant({
          id: 'inbox',
          target: INBOX_URL,
          actions: ['POST'],
          expires: inDays(30)
        })
      ]
    })
    await storeChannel({ directory, pairwiseDid: pairwise.did })

    const { entries } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'partial',
      detail: {
        reason: 'parent-too-short',
        parentTooShort: 1,
        renewedGrants: 1,
        pushed: 1
      }
    })
    expect(
      storage.addHistoryGrant.mock.calls[0]![0].grants.map(
        grant => grant.target
      )
    ).toEqual([INBOX_URL])
    expect(deps.push).toHaveBeenCalledTimes(1)
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:inbox',
        level: 'warn',
        msg: "A renewal would not outlast its source, its parent's life too short; skipped"
      })
    )
  })

  it('renews nothing on an entry a torn revoke emptied of its channel', async () => {
    const { directory, deps, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    await clearReceivedGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID
    })

    const { entries } = await pass()

    expect(entries[1].outcome).toBe('noop')
    expect(deps.push).not.toHaveBeenCalled()
  })
})

describe('the outbox', () => {
  it('keeps an item on a network failure, and sends it at the next pass', async () => {
    const { directory, deps, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    deps.push.mockRejectedValueOnce(new TypeError('Failed to fetch'))

    const first = await pass()

    expect(first.entries[1]).toMatchObject({
      outcome: 'partial',
      detail: { pushFailed: 1 }
    })
    expect(first.outcome.pushFailures).toEqual([
      { agentDid: AGENT_DID, agentName: 'News agent', reason: 'network' }
    ])
    expect((await entryOf(AGENT_DID))?.outbox).toHaveLength(1)

    const second = await pass()

    expect(second.entries[1]).toMatchObject({ detail: { pushed: 1 } })
    expect((await entryOf(AGENT_DID))?.outbox).toEqual([])
  })

  it('stops pushing on a 401 or 403 and keeps the items', async () => {
    const { directory, deps, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    deps.push.mockRejectedValue(
      Object.assign(new Error('Forbidden'), { status: 403 })
    )

    const { outcome } = await pass()

    expect(outcome.pushFailures).toEqual([
      expect.objectContaining({ reason: 'channel-refused' })
    ])
    expect((await entryOf(AGENT_DID))?.outbox).toHaveLength(1)
  })

  it('stops pushing on a 404, which a WAS host answers a denied capability with', async () => {
    const { directory, deps, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    deps.push.mockRejectedValue(
      Object.assign(new Error('Not Found'), { status: 404 })
    )

    const { entries, outcome } = await pass()

    expect(entries[1]).toMatchObject({
      outcome: 'partial',
      detail: { pushFailed: 1 }
    })
    expect(outcome.pushFailures).toEqual([
      {
        agentDid: AGENT_DID,
        agentName: 'News agent',
        reason: 'channel-refused'
      }
    ])
    expect(deps.push).toHaveBeenCalledTimes(1)
    const entry = await entryOf(AGENT_DID)
    expect(entry?.outbox).toHaveLength(1)
    // The refused channel record stays until a write that drops it exists.
    expect(entry?.grantsReceived).toHaveLength(1)
  })

  it('discards unsent an item whose capabilities have all expired', async () => {
    const { directory, deps, entryOf, pass } = fixture()
    const pairwise = await pairwiseSeed()
    await connect({ directory, pairwise })
    await storeChannel({ directory, pairwiseDid: pairwise.did })
    // A consent whose envelope was queued and never sent, now past expiry.
    const lapsed = await rootGrant({ id: 'lapsed', expires: inDays(-1) })
    await recordGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT_DID,
      kind: 'agent',
      spaceUrl: SPACE_URL,
      grants: [{ zcap: lapsed, grantKind: 'grant' }],
      message: envelope({ actor: pairwise.did, zcaps: [lapsed] })
    })
    // Nothing else is due.
    deps.readPointedDelegationId.mockResolvedValue(POINTED_DELEGATION)

    await pass()

    const sent = deps.push.mock.calls.map(
      ([options]) =>
        (options.message as { object: { zcaps: Array<{ id: string }> } }).object
          .zcaps[0]!.id
    )
    expect(sent).not.toContain('lapsed')
    expect(
      (await entryOf(AGENT_DID))?.outbox.some(item =>
        JSON.stringify(item.message).includes('"lapsed"')
      )
    ).toBe(false)
  })
})

describe('the prune', () => {
  /**
   * An agent whose grants a collected generation parented, with a live
   * channel: due by replacement, and dead-chained once superseded.
   *
   * @param fixtureOf {object}
   * @returns {Promise<void>}
   */
  async function collectedConnection(
    fixtureOf: ReturnType<typeof fixture>
  ): Promise<void> {
    const pairwise = await pairwiseSeed()
    await connect({
      directory: fixtureOf.directory,
      pairwise,
      grants: [
        annexGrant({
          id: 'collected-read',
          parentId: 'urn:uuid:collected',
          parentController: COLLECTED_ANNEX_DID
        }),
        annexGrant({
          id: 'collected-inbox',
          target: INBOX_URL,
          actions: ['POST'],
          parentId: 'urn:uuid:collected',
          parentController: COLLECTED_ANNEX_DID
        })
      ]
    })
    await storeChannel({
      directory: fixtureOf.directory,
      pairwiseDid: pairwise.did
    })
  }

  it('prunes a dead-chained predecessor once its successor is delivered', async () => {
    const delivered = fixture({
      invocationCapability: await generationDelegation()
    })
    await collectedConnection(delivered)

    await delivered.pass()

    expect(
      (await delivered.entryOf(AGENT_DID))?.grants.map(grant => grant.zcap.id)
    ).toEqual(['urn:uuid:minted-1', 'urn:uuid:minted-2'])
  })

  it('keeps a dead-chained predecessor while its successor waits on the outbox', async () => {
    const waiting = fixture({
      invocationCapability: await generationDelegation()
    })
    await collectedConnection(waiting)
    waiting.deps.push.mockRejectedValue(
      Object.assign(new Error('Bad Gateway'), { status: 502 })
    )

    await waiting.pass()

    expect(
      (await waiting.entryOf(AGENT_DID))?.grants.map(grant => grant.zcap.id)
    ).toEqual([
      'collected-read',
      'collected-inbox',
      'urn:uuid:minted-1',
      'urn:uuid:minted-2'
    ])
  })
})

describe('the proof check the renewal reads', () => {
  it('verifies a root grant by its signer and an annex grant by its parent', async () => {
    /**
     * Whether a fixture grant verifies against the fixture account.
     *
     * @param zcap {Promise<object>}
     * @returns {Promise<boolean>}
     */
    async function verified(
      zcap: Promise<Record<string, unknown>>
    ): Promise<boolean> {
      const result = await verifyRecordedGrantProof({
        zcap: (await zcap) as never,
        signerCheck: SIGNER_CHECK
      })
      return result.verified
    }

    expect(await verified(rootGrant({ id: 'a' }))).toBe(true)
    expect(await verified(rootGrant({ id: 'b', signer: 'struck' }))).toBe(false)
    expect(await verified(annexGrant({ id: 'c' }))).toBe(true)
    expect(
      await verified(annexGrant({ id: 'd', parentSigner: 'struck' }))
    ).toBe(false)
    // A parent delegated to an annex in another auxiliary Space.
    expect(
      await verified(
        annexGrant({
          id: 'e',
          parentController:
            'did:webvh:scid:was.example:space:elsewhere:gen-AAAAAAAAAAAAAAAA'
        })
      )
    ).toBe(false)
    // A listed signer whose signature does not cover the capability.
    const tampered = { ...(await rootGrant({ id: 'f' })), id: 'g' }
    expect(await verified(Promise.resolve(tampered))).toBe(false)
  })
})
