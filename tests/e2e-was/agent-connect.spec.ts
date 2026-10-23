import type { BrowserContext, Page } from '@playwright/test'
import { CapabilityAgent } from '@interop/capability-agent'
import { WasClient, type Collection } from '@interop/was-client'
import type { IZcap } from '@interop/wallet-request'
import { externalRequestPath } from '@/lib/walletRequest/externalRequestPath'
import {
  awaitLoginChain,
  signupViaWizard,
  submitTransientLogin
} from './helpers'
import {
  AgentDouble,
  outcomeOf,
  startRelay,
  WAS_SPACES_URL,
  type ConnectionResponse
} from './agentDouble'
import { listStoredResourceIds } from '../shared/storedLogs'
import { WAS_E2E_DATA_DIR } from './wasDataDir'
import { test, expect } from '../shared/consoleCapture'

/**
 * The connection request e2e (WAS mode): a scripted agent test double with
 * its own Space connects to a wallet owner over the interaction-URL entry
 * point, and the two keep the connection alive through the owner's inbox
 * and the double's.
 *
 * The owner is the default account: a credential-anchored signup on a
 * browser that remembers nothing, so every visit is a transient session and
 * every grant chains under the annex generation delegation. The owner keeps
 * an audience collection (`posts`, plaintext) holding one post.
 *
 * The run is one account and one double, in order: the whole connect
 * sequence and a forced renewal whose push first fails and is then
 * delivered from the outbox, a subscriber child of the renewed grant, the
 * inbox grant's reach, the signed request refusals, an agent revoke, and
 * the same agent returning. Each "next login" is a fresh transient login on
 * the same page, whose login tail runs the inbox pass: the drain, the
 * renewal, and the outbox push.
 *
 * The one renewal is forced through two non-production seams. The consent
 * mints its agent grants under a short share TTL
 * (`window.__E2E_SHARE_ZCAP_TTL_MS__`, 100 days: outside the 90-day renewal
 * window, and well inside the year-long generation delegation every
 * transient grant chains under, so a renewal minted under that same
 * delegation can outlast them). The renewing login then reads every
 * recorded grant as due through the renewal-window seam
 * (`window.__E2E_AGENT_GRANT_RENEWAL_WINDOW_MS__`), set on the page ahead
 * of that one submit. The recorded grants themselves are never edited: the
 * renewal verifies each grant's own signature over the capability, so an
 * edited `expires` would read as a forged leaf and renew nothing. A second
 * renewal cannot be forced, since the first already runs to the generation
 * delegation's own expiry.
 */

const APP_URL = 'http://localhost:5274'
const DAY_MS = 24 * 60 * 60 * 1000
const AGENT_NAME = 'e2e-connect-agent'
const AUDIENCE_ID = 'posts'
const POST_ID = 'post-1'
const POST = { type: 'Note', content: 'Hello, subscribers' }

/**
 * The copy the interaction-URL page shows for the two refusals asserted
 * here.
 */
const UNSIGNED_COPY =
  'This connection request is not signed by the key it names, so it was refused.'
const FOREIGN_DELIVERY_COPY =
  'This request would send your answer somewhere other than where it came from, so it was refused.'

/**
 * One `connections` entry for an agent, as the live session decrypts it,
 * with only the members the assertions read.
 */
interface AgentEntryView {
  resourceId: string
  retired?: string
  hasSeed: boolean
  grants: Array<{
    zcapId: string
    target: string
    expires: string
    renewedAt?: string
  }>
  grantsReceived: Array<{ zcapId: string; grantKind: string }>
  outbox: Array<{ createdAt: string; zcapIds: string[] }>
}

/**
 * The agent's `connections` entry, read through the live session's
 * directory store (the non-production `window.__E2E_STORAGE__` seam), or
 * undefined when the directory holds none for that DID.
 *
 * @param options {object}
 * @param options.page {Page}   a page holding a logged-in session
 * @param options.did {string}   the agent's did:key
 * @returns {Promise<AgentEntryView | undefined>}
 */
async function readAgentEntry({
  page,
  did
}: {
  page: Page
  did: string
}): Promise<AgentEntryView | undefined> {
  return await page.evaluate(async (agentDid: string) => {
    const storage = (
      window as unknown as {
        __E2E_STORAGE__?: {
          connectionsDirectory(): Promise<{
            store: {
              list(): Promise<Array<{
                resourceId: string
                body?: unknown
              }> | null>
            }
          }>
        }
      }
    ).__E2E_STORAGE__
    if (!storage) {
      throw new Error('No session published __E2E_STORAGE__ on this page.')
    }
    const { store } = await storage.connectionsDirectory()
    type Zcap = { id: string; invocationTarget: string; expires: string }
    for (const { resourceId, body } of (await store.list()) ?? []) {
      const entry = (body ?? {}) as {
        kind?: string
        id?: string
        retired?: string
        seed?: string
        grants?: Array<{ zcap: Zcap; renewedAt?: string }>
        grantsReceived?: Array<{ zcap: Zcap; grantKind: string }>
        outbox?: Array<{
          createdAt: string
          message: { object?: { zcaps?: Zcap[] } }
        }>
      }
      if (entry.kind !== 'agent' || entry.id !== agentDid) {
        continue
      }
      return {
        resourceId,
        ...(entry.retired !== undefined && { retired: entry.retired }),
        hasSeed: typeof entry.seed === 'string',
        grants: (entry.grants ?? []).map(grant => ({
          zcapId: grant.zcap.id,
          target: grant.zcap.invocationTarget,
          expires: grant.zcap.expires,
          ...(grant.renewedAt !== undefined && { renewedAt: grant.renewedAt })
        })),
        grantsReceived: (entry.grantsReceived ?? []).map(received => ({
          zcapId: received.zcap.id,
          grantKind: received.grantKind
        })),
        outbox: (entry.outbox ?? []).map(item => ({
          createdAt: item.createdAt,
          zcapIds: (item.message.object?.zcaps ?? []).map(zcap => zcap.id)
        }))
      }
    }
    return undefined
  }, did)
}

/**
 * The account Space URL and id of the live session.
 *
 * @param page {Page}
 * @returns {Promise<{ spaceUrl: string, spaceId: string }>}
 */
async function ownerSpace(
  page: Page
): Promise<{ spaceUrl: string; spaceId: string }> {
  const seam = await page.evaluate(() => {
    const storage = (
      window as unknown as {
        __E2E_STORAGE__?: { spaceUrl?: string; spaceId?: string }
      }
    ).__E2E_STORAGE__
    return { spaceUrl: storage?.spaceUrl, spaceId: storage?.spaceId }
  })
  expect(seam.spaceUrl, 'the session names an account Space').toBeTruthy()
  expect(seam.spaceId).toBeTruthy()
  return { spaceUrl: seam.spaceUrl!, spaceId: seam.spaceId! }
}

/**
 * Provisions the owner's audience collection, plaintext and not public,
 * and writes one post into it, through the live session.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function createAudience(page: Page): Promise<void> {
  await page.evaluate(
    async ({ collectionId, resourceId, post }) => {
      const storage = (
        window as unknown as {
          __E2E_STORAGE__?: {
            ensureCollection(options: {
              id: string
              name?: string
            }): Promise<void>
            remoteStore?: {
              putPlaintextResource(options: {
                collectionId: string
                resourceId: string
                data: unknown
                contentType: string
              }): Promise<{ created: boolean }>
            }
          }
        }
      ).__E2E_STORAGE__
      if (!storage?.remoteStore) {
        throw new Error('No session with a remote Space on this page.')
      }
      await storage.ensureCollection({ id: collectionId, name: 'Posts' })
      await storage.remoteStore.putPlaintextResource({
        collectionId,
        resourceId,
        data: post,
        contentType: 'application/json'
      })
    },
    { collectionId: AUDIENCE_ID, resourceId: POST_ID, post: POST }
  )
}

/**
 * Opens a request on the interaction-URL page and approves it.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.interactionUrl {string}
 * @param [options.shareTtlMs] {number}   the share TTL seam to set before
 *   approving, so the minted grants take that lifetime
 * @returns {Promise<void>}
 */
async function approveRequest({
  page,
  interactionUrl,
  shareTtlMs
}: {
  page: Page
  interactionUrl: string
  shareTtlMs?: number
}): Promise<void> {
  await page.goto('/#/dashboard')
  await page.goto(`/#${externalRequestPath({ url: interactionUrl })}`)
  await expect(page.getByRole('button', { name: 'Grant access' })).toBeVisible({
    timeout: 30_000
  })
  await expect(
    page.getByText(`An agent calling itself "${AGENT_NAME}"`)
  ).toBeVisible()
  if (shareTtlMs !== undefined) {
    // The share TTL seam, read by the mint at approval; the hash routes
    // above reload nothing, so it stands until the next reload.
    await page.evaluate((ttlMs: number) => {
      ;(
        window as unknown as { __E2E_SHARE_ZCAP_TTL_MS__?: number }
      ).__E2E_SHARE_ZCAP_TTL_MS__ = ttlMs
    }, shareTtlMs)
  }
  await page.getByRole('button', { name: 'Grant access' }).click()
  await expect(page.getByText('Access granted', { exact: false })).toBeVisible({
    timeout: 60_000
  })
}

/**
 * The response's audience grant and inbox grant.
 *
 * @param options {object}
 * @param options.presentation {ConnectionResponse}
 * @param options.audienceUrl {string}
 * @returns {{ audience: IZcap, inbox: IZcap }}
 */
function responseGrants({
  presentation,
  audienceUrl
}: {
  presentation: ConnectionResponse
  audienceUrl: string
}): { audience: IZcap; inbox: IZcap } {
  const zcaps = presentation.zcap ?? []
  expect(zcaps).toHaveLength(2)
  const audience = zcaps.find(zcap => zcap.invocationTarget === audienceUrl)
  const inbox = zcaps.find(zcap => zcap.invocationTarget.endsWith('/inbox/'))
  expect(audience, 'the response carries the audience grant').toBeDefined()
  expect(inbox, 'the response carries the inbox grant').toBeDefined()
  return { audience: audience!, inbox: inbox! }
}

/**
 * Reads the post through an audience grant, invoking it as the double's
 * connection key. Throws when the read is refused.
 *
 * @param options {object}
 * @param options.double {AgentDouble}
 * @param options.grant {IZcap}
 * @returns {Promise<unknown>}
 */
async function readPost({
  double,
  grant
}: {
  double: AgentDouble
  grant: IZcap
}): Promise<unknown> {
  const audience = double
    .agentClient()
    .fromCapability(grant as never) as Collection
  const post = await audience.get(POST_ID)
  // A refused read comes back as a missing Resource (WAS answers 404 for
  // both), which was-client reports as `null` rather than throwing.
  if (post === null) {
    throw Object.assign(new Error('The post read was refused.'), {
      status: 404
    })
  }
  return post
}

test.describe.serial('agent connection over the interaction URL', () => {
  test.describe.configure({ timeout: 300_000 })

  let context: BrowserContext
  let page: Page
  let passphrase: string
  let spaceId: string
  let audienceUrl: string
  let double: AgentDouble
  let holder: string
  let inboxGrant: IZcap
  let renewedAudience: IZcap
  let consentAudience: IZcap

  /**
   * A fresh transient login on the same page: the reload drops the
   * in-memory session, and the wait covers the login tail's inbox pass.
   * With `renewAll`, the renewal-window seam is set on the reloaded page
   * ahead of the submit, so that one login's pass finds every recorded
   * agent grant due; the next reload clears it.
   *
   * @param [options] {object}
   * @param [options.renewAll] {boolean}
   * @returns {Promise<void>}
   */
  async function nextLogin({
    renewAll = false
  }: { renewAll?: boolean } = {}): Promise<void> {
    await page.goto('/#/login')
    await page.reload()
    if (renewAll) {
      await page.evaluate(
        (windowMs: number) => {
          ;(
            window as unknown as {
              __E2E_AGENT_GRANT_RENEWAL_WINDOW_MS__?: number
            }
          ).__E2E_AGENT_GRANT_RENEWAL_WINDOW_MS__ = windowMs
        },
        10 * 365 * DAY_MS
      )
    }
    await submitTransientLogin(page, passphrase)
    await awaitLoginChain(page)
  }

  /**
   * The owner's inbox as the server stores it.
   *
   * @returns {Promise<string[]>}
   */
  async function ownerInbox(): Promise<string[]> {
    return await listStoredResourceIds({
      dataDir: WAS_E2E_DATA_DIR,
      spaceId,
      collectionId: 'inbox'
    })
  }

  /**
   * The agent's entry, which must exist.
   *
   * @returns {Promise<AgentEntryView>}
   */
  async function agentEntry(): Promise<AgentEntryView> {
    const entry = await readAgentEntry({
      page,
      did: double.connectionKey.id
    })
    expect(entry, 'the directory holds the agent entry').toBeDefined()
    return entry!
  }

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(300_000)
    context = await browser.newContext({ baseURL: APP_URL })
    page = await context.newPage()
    ;({ passphrase } = await signupViaWizard(page, testInfo, {
      rememberBrowser: false
    }))
    await awaitLoginChain(page)
    const owner = await ownerSpace(page)
    spaceId = owner.spaceId
    audienceUrl = `${owner.spaceUrl}${AUDIENCE_ID}/`
    await createAudience(page)
    double = await AgentDouble.create({ name: AGENT_NAME })
  })

  test.afterAll(async () => {
    await context?.close()
  })

  test('connects, stores the channel at the next login, and renews a due grant past a failed push', async () => {
    const challenge = crypto.randomUUID()
    const request = await double.connectionRequest({
      audienceUrls: [audienceUrl],
      challenge
    })
    expect(request.challenge).toBe(challenge)
    const { exchangeUrl, interactionUrl } = await double.storeRequest({
      request
    })
    await approveRequest({ page, interactionUrl, shareTtlMs: 100 * DAY_MS })

    // The double verifies the response before delegating anything to its
    // holder.
    const presentation = await double.awaitResponse({ exchangeUrl })
    holder = await double.verifyResponse({ presentation, challenge })
    expect(holder).not.toBe(double.connectionKey.id)
    const grants = responseGrants({ presentation, audienceUrl })
    inboxGrant = grants.inbox
    consentAudience = grants.audience
    expect(grants.audience.controller).toBe(double.connectionKey.id)
    expect(grants.inbox.controller).toBe(double.connectionKey.id)
    expect([grants.inbox.allowedAction].flat()).toEqual(['POST'])

    // The consent wrote the agent's entry with the pairwise seed and both
    // grants.
    const granted = await agentEntry()
    expect(granted.hasSeed).toBe(true)
    expect(granted.retired).toBeUndefined()
    expect(granted.grants.map(grant => grant.zcapId).sort()).toEqual(
      [grants.audience.id, grants.inbox.id].sort()
    )
    expect(granted.grantsReceived).toEqual([])

    // The audience grant reads the post.
    expect(await readPost({ double, grant: grants.audience })).toEqual(POST)

    // The invitation: the channel capability, delegated to the holder, in a
    // Grant envelope posted into the owner's inbox under the inbox grant.
    const channel = await double.issueChannel({ holder })
    await double.postToOwner({
      inboxGrant,
      body: double.grantEnvelope({ zcaps: [channel] })
    })
    expect(await ownerInbox()).toHaveLength(1)

    // The next login drains the inbox: the channel is stored on the entry,
    // and the message is deleted.
    await nextLogin()
    const connected = await agentEntry()
    expect(connected.grantsReceived).toEqual([
      { zcapId: channel.id, grantKind: 'inbox' }
    ])
    expect(await ownerInbox()).toEqual([])

    // A forced renewal: the next login renews both grants and pushes them
    // through the channel into the double's inbox. The double's server
    // answers that first push with a 503, so the renewal waits on the
    // entry's outbox.
    let refusedPushes = 0
    await page.route(
      url => url.pathname.startsWith(`/space/${double.spaceId}/inbox`),
      async route => {
        if (route.request().method() === 'POST' && refusedPushes === 0) {
          refusedPushes += 1
          await route.fulfill({
            status: 503,
            headers: { 'access-control-allow-origin': '*' },
            body: 'unavailable'
          })
          return
        }
        await route.fallback()
      }
    )
    await nextLogin({ renewAll: true })
    expect(refusedPushes).toBe(1)
    expect(await double.readOwnInbox()).toEqual([])
    const queued = await agentEntry()
    expect(queued.outbox).toHaveLength(1)
    const queuedIds = queued.outbox[0]!.zcapIds
    expect(queuedIds).toHaveLength(2)

    // The double's server recovers; the next pass delivers the queued
    // envelope, once, and mints nothing new (the renewed records are not
    // due).
    await page.unrouteAll()
    await nextLogin()
    const messages = await double.readOwnInbox()
    expect(messages).toHaveLength(1)
    const [message] = messages
    expect(message!.createdBy).toBe(holder)
    expect((message!.body as { actor?: string }).actor).toBe(holder)
    const delivered = (
      message!.body as { object?: { zcaps?: IZcap[] } }
    ).object?.zcaps?.map(zcap => zcap.id)
    expect(delivered?.sort()).toEqual([...queuedIds].sort())
    expect(double.repeatedDeliveries).toBe(0)
    const renewed = [...double.adopted.values()]
    expect(renewed).toHaveLength(2)
    const audience = renewed.find(zcap => zcap.invocationTarget === audienceUrl)
    expect(audience, 'a renewed audience grant arrived').toBeDefined()
    renewedAudience = audience!
    expect(renewedAudience.id).not.toBe(grants.audience.id)
    expect(renewedAudience.controller).toBe(double.connectionKey.id)
    const renewedInbox = renewed.find(zcap =>
      zcap.invocationTarget.endsWith('/inbox/')
    )
    expect(renewedInbox, 'a renewed inbox grant arrived').toBeDefined()
    inboxGrant = renewedInbox!

    const after = await agentEntry()
    expect(after.outbox).toEqual([])
    expect(
      after.grants.filter(grant => grant.renewedAt !== undefined).length
    ).toBe(2)

    // The double invokes the renewed grant and reads the post.
    expect(await readPost({ double, grant: renewedAudience })).toEqual(POST)
  })

  test('a subscriber child of the renewed grant reads the audience, a post, and the changes feed', async () => {
    const subscriber = await CapabilityAgent.fromSeed({
      seed: crypto.getRandomValues(new Uint8Array(32)),
      handle: 'e2e-subscriber'
    })
    const audience = double
      .agentClient()
      .fromCapability(renewedAudience as never) as Collection
    const child = (await audience.grant({
      to: subscriber.id,
      actions: ['GET'],
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000)
    })) as unknown as IZcap & {
      parentCapability?: string
      proof?: { capabilityChain?: unknown[] }
    }
    // Four links: the Space root, the generation delegation, the agent
    // grant, and the child.
    expect(child.parentCapability).toBe(renewedAudience.id)
    const agentParent = (
      renewedAudience as IZcap & { parentCapability?: string }
    ).parentCapability
    expect(agentParent).toBeDefined()
    expect(agentParent).not.toMatch(/^urn:zcap:root:/)
    expect(child.proof?.capabilityChain).toHaveLength(3)

    const reader = WasClient.fromSigner({
      serverUrl: WAS_SPACES_URL,
      signer: subscriber.getSigner()
    }).fromCapability(child as never) as Collection
    const listing = await reader.list()
    expect(listing?.items?.map(item => item.id)).toContain(POST_ID)
    expect(await reader.get(POST_ID)).toEqual(POST)
    const page1 = await reader.changes({ method: 'GET' })
    expect(
      page1.documents.some(
        doc =>
          doc.kind === 'resource' && (doc as { id?: string }).id === POST_ID
      )
    ).toBe(true)
  })

  test('the inbox grant posts on the container', async () => {
    // A fresh channel is harmless: the next drain stores it beside the
    // first.
    const channel = await double.issueChannel({ holder })
    expect(
      await outcomeOf(() =>
        double.postToOwner({
          inboxGrant,
          body: double.grantEnvelope({ zcaps: [channel] })
        })
      )
    ).toBe('ok')
  })

  // Pending the authorization profile's subtree marker: until it ships, a
  // grant whose `invocationTarget` is a bare container URL also covers that
  // container's subtree on the current server, so these reads succeed.
  test.fixme('the inbox grant reads neither the inbox query nor a message', async () => {
    const was = double.agentClient()
    const inboxUrl = inboxGrant.invocationTarget
    const queryStatus = await outcomeOf(() =>
      was.request({
        url: `${inboxUrl}query`,
        method: 'GET',
        action: 'GET',
        capability: inboxGrant as never
      })
    )
    expect(queryStatus).not.toBe('ok')
    const [messageId] = await ownerInbox()
    expect(messageId).toBeDefined()
    const getStatus = await outcomeOf(() =>
      was.request({
        url: `${inboxUrl}${messageId}`,
        method: 'GET',
        action: 'GET',
        capability: inboxGrant as never
      })
    )
    expect(getStatus).not.toBe('ok')
  })

  test('refuses an unsigned connection request, and a signed one served from another origin', async () => {
    // Unsigned: refused before consent.
    const unsigned = await double.connectionRequest({
      audienceUrls: [audienceUrl],
      challenge: crypto.randomUUID(),
      sign: false
    })
    const stored = await double.storeRequest({ request: unsigned })
    await page.goto('/#/dashboard')
    await page.goto(`/#${externalRequestPath({ url: stored.interactionUrl })}`)
    await expect(page.getByText(UNSIGNED_COPY)).toBeVisible({
      timeout: 30_000
    })
    await expect(
      page.getByRole('button', { name: 'Grant access' })
    ).toHaveCount(0)

    // A signed request naming its own presentation endpoint renders consent
    // from the agent's own exchange host.
    const endpoint = await double.storeRequest({ request: unsigned })
    const signed = await double.connectionRequest({
      audienceUrls: [audienceUrl],
      challenge: crypto.randomUUID(),
      endpoint: endpoint.exchangeUrl
    })
    const genuine = await double.storeRequest({ request: signed })
    await page.goto('/#/dashboard')
    await page.goto(`/#${externalRequestPath({ url: genuine.interactionUrl })}`)
    await expect(
      page.getByRole('button', { name: 'Grant access' })
    ).toBeVisible({ timeout: 30_000 })

    // The same signed request, verbatim, served from another origin.
    const relay = await startRelay({ request: signed })
    try {
      await page.goto('/#/dashboard')
      await page.goto(`/#${externalRequestPath({ url: relay.interactionUrl })}`)
      await expect(page.getByText(FOREIGN_DELIVERY_COPY)).toBeVisible({
        timeout: 30_000
      })
      await expect(
        page.getByRole('button', { name: 'Grant access' })
      ).toHaveCount(0)
    } finally {
      await relay.close()
    }
  })

  test('an agent revoke refuses its grants, and its next message is deleted unacted', async () => {
    // Drain what the inbox-reach test posted, so the message below is the
    // only one the next login sees.
    await nextLogin()
    expect(await ownerInbox()).toEqual([])

    // A fresh invitation posted while the agent is still connected.
    const lateChannel = await double.issueChannel({ holder })
    await double.postToOwner({
      inboxGrant,
      body: double.grantEnvelope({ zcaps: [lateChannel] })
    })
    expect(await ownerInbox()).toHaveLength(1)

    await page.goto('/#/applications')
    await expect(page.getByText(AGENT_NAME)).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: 'Revoke Agent Access' }).click()
    await expect(page.getByText('Revoke agent access?')).toBeVisible()
    await page
      .getByRole('button', { name: 'Revoke access', exact: true })
      .click()
    await expect(page.getByText('Agent access revoked.')).toBeVisible({
      timeout: 60_000
    })

    // Every audience grant the double holds is refused, the consent's and
    // each renewal, and so is the inbox grant. Soft, so the steps behind
    // still run when a refusal is missing.
    const audienceGrants = [consentAudience, ...double.adopted.values()].filter(
      zcap => zcap.invocationTarget === audienceUrl
    )
    for (const grant of audienceGrants) {
      expect
        .soft(
          await outcomeOf(() => readPost({ double, grant })),
          `audience grant ${grant.id} is refused after the revoke`
        )
        .not.toBe('ok')
    }
    expect
      .soft(
        await outcomeOf(() =>
          double.postToOwner({
            inboxGrant,
            body: double.grantEnvelope({ zcaps: [lateChannel] })
          })
        ),
        'the inbox grant is refused after the revoke'
      )
      .not.toBe('ok')

    // The next login deletes the message without storing its channel.
    await nextLogin()
    expect(await ownerInbox()).toEqual([])
    const revoked = await agentEntry()
    expect(revoked.retired).toBeDefined()
    expect(
      revoked.grantsReceived.map(received => received.zcapId)
    ).not.toContain(lateChannel.id)
  })

  test('a returning agent is un-retired under the same pairwise key, and a fresh invitation restores the channel', async () => {
    const challenge = crypto.randomUUID()
    const request = await double.connectionRequest({
      audienceUrls: [audienceUrl],
      challenge
    })
    const { exchangeUrl, interactionUrl } = await double.storeRequest({
      request
    })
    await approveRequest({ page, interactionUrl })
    const presentation = await double.awaitResponse({ exchangeUrl })
    expect(await double.verifyResponse({ presentation, challenge })).toBe(
      holder
    )
    const grants = responseGrants({ presentation, audienceUrl })
    const returned = await agentEntry()
    expect(returned.retired).toBeUndefined()
    expect(await readPost({ double, grant: grants.audience })).toEqual(POST)

    const channel = await double.issueChannel({ holder })
    await double.postToOwner({
      inboxGrant: grants.inbox,
      body: double.grantEnvelope({ zcaps: [channel] })
    })
    await nextLogin()
    expect(await ownerInbox()).toEqual([])
    const restored = await agentEntry()
    expect(restored.grantsReceived.map(received => received.zcapId)).toContain(
      channel.id
    )
    renewedAudience = grants.audience
  })

  // A lapsed connection is restored from the Notifications page, which this
  // build does not render yet.
  test.skip('a lapsed connection is restored from the Notifications page', async () => {})

  test('account deletion refuses the agent audience grant', async () => {
    await page.goto('/#/settings')
    await page
      .getByRole('button', { name: 'Delete Account', exact: true })
      .click()
    const dialog = page.getByRole('dialog')
    await expect(
      dialog.getByRole('heading', { name: 'Delete your account?' })
    ).toBeVisible()
    await dialog
      .locator('input[name="freewallet-delete-confirm"]')
      .fill(passphrase)
    await dialog
      .getByRole('button', { name: 'Delete account', exact: true })
      .click()
    await expect(page).toHaveURL(/\/#?\/?$/, { timeout: 240_000 })
    expect(
      await outcomeOf(() => readPost({ double, grant: renewedAudience }))
    ).not.toBe('ok')
  })
})
