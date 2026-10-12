/**
 * The consent rows of a connection request: every row takes the share TTL
 * and renews while the connection stands, the inbox row has its own copy and
 * no write warning, and each read row states that the agent passes read
 * access on. Also the summary above the list: the recipient, the expiry, and
 * the revoke note are stated once when the grants share them, and a card
 * keeps its own only where its value differs.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import '@/i18n'
import type { ResolvedGrant } from '@/lib/walletRequest'
import { ZcapGrantsPanel } from './ZcapGrantsPanel'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

const AGENT_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const OTHER_DID = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
const SPACE_URL = 'https://was.example/space/abc/'

const RECIPIENT_LABEL = 'Access granted to:'
const STORED_NOTE = 'This identity is stored in your wallet for this app.'
const REVOKE_NOTE = 'You can revoke access any time on the Applications page.'
const SHARE_REVOKE_NOTE =
  'You can remove this reader any time from wallet Settings.'
const READ_EXPIRY = 'Access expires in 30 days.'
const WRITE_EXPIRY = 'Access expires in 7 days.'
const SHARE_EXPIRY = 'The fetch permission expires in 365 days'

const INBOX: ResolvedGrant = {
  descriptor: {
    referenceId: 'inbox',
    controller: AGENT_DID,
    invocationTarget: { type: 'https://w3id.org/byoe#inbox' }
  },
  target: {
    targetClass: 'inbox',
    invocationTarget: `${SPACE_URL}inbox/`,
    collectionId: 'inbox',
    needsProvisioning: false,
    encrypted: false
  },
  allowedActions: ['POST'],
  write: true
}

/**
 * A read grant on one collection, delegated to `controller`.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param [options.controller] {string}
 * @param [options.write] {boolean}
 * @param [options.share] {boolean}
 * @returns {ResolvedGrant}
 */
function grantOn({
  collectionId,
  controller = AGENT_DID,
  write = false,
  share = false
}: {
  collectionId: string
  controller?: string
  write?: boolean
  share?: boolean
}): ResolvedGrant {
  const invocationTarget = `${SPACE_URL}${collectionId}/`
  return {
    descriptor: { referenceId: collectionId, controller, invocationTarget },
    target: {
      targetClass: share ? 'share' : 'collection',
      invocationTarget,
      collectionId,
      needsProvisioning: false,
      encrypted: share
    },
    allowedActions: write ? ['GET', 'HEAD', 'PUT'] : ['GET', 'HEAD'],
    write
  }
}

const AUDIENCE = grantOn({ collectionId: 'friends' })

// The roots a test mounted, released after each test.
const roots: Root[] = []

/**
 * Renders the panel and returns the summary's text and each card's text.
 *
 * @param options {object}
 * @param options.grants {ResolvedGrant[]}
 * @param [options.connectionRequest] {boolean}
 * @param [options.walletMintedRecipient] {boolean}
 * @returns {Promise<{ summary: string, rows: string[], text: string }>}
 */
async function mount({
  grants,
  connectionRequest,
  walletMintedRecipient
}: {
  grants: ResolvedGrant[]
  connectionRequest?: boolean
  walletMintedRecipient?: boolean
}) {
  const container = document.createElement('div')
  const root = createRoot(container)
  roots.push(root)
  await act(async () => {
    root.render(
      <ZcapGrantsPanel
        grants={grants}
        ttlDays={30}
        writeTtlDays={7}
        shareTtlDays={365}
        connectionRequest={connectionRequest}
        walletMintedRecipient={walletMintedRecipient}
      />
    )
  })
  const summary =
    container.querySelector('[data-testid="zcap-summary"]')?.textContent ?? ''
  const rows = [
    ...container.querySelectorAll('[data-testid="zcap-grant"]')
  ].map(row => row.textContent ?? '')
  return { summary, rows, text: container.textContent ?? '' }
}

/**
 * How many times `needle` occurs in `haystack`.
 *
 * @param haystack {string}
 * @param needle {string}
 * @returns {number}
 */
function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true
})
afterEach(async () => {
  await act(async () => {
    for (const root of roots.splice(0)) {
      root.unmount()
    }
  })
})

describe('ZcapGrantsPanel on a connection request', () => {
  it('states the share TTL and the renewal once, above the rows', async () => {
    const view = await mount({
      grants: [AUDIENCE, INBOX],
      connectionRequest: true
    })
    expect(view.rows).toHaveLength(2)
    const expiry =
      'Access expires in 365 days, and renews while this connection stands.'
    expect(view.summary).toContain(expiry)
    expect(occurrences(view.text, expiry)).toBe(1)
  })

  it('gives the inbox row its own copy and no write warning', async () => {
    const view = await mount({
      grants: [AUDIENCE, INBOX],
      connectionRequest: true
    })
    const [audience, inbox] = view.rows
    expect(inbox).toContain("Your wallet's inbox")
    expect(inbox).toContain('Can send messages to your wallet.')
    expect(inbox).not.toContain('will be able to add, change, or delete')
    expect(inbox).not.toContain('passes this read access on')
    expect(audience).toContain(
      'The agent passes this read access on to people it chooses.'
    )
  })

  it('keeps the ordinary expiry line off a connection request', async () => {
    const view = await mount({ grants: [AUDIENCE] })
    expect(view.summary).toContain(READ_EXPIRY)
    expect(view.text).not.toContain('renews while this connection stands')
    expect(view.text).not.toContain('passes this read access on')
  })
})

describe('ZcapGrantsPanel summary', () => {
  it('states a shared recipient, expiry, and revoke note once', async () => {
    const view = await mount({
      grants: ['notes', 'tasks', 'goals'].map(collectionId =>
        grantOn({ collectionId })
      ),
      walletMintedRecipient: true
    })
    expect(view.rows).toHaveLength(3)
    for (const line of [
      RECIPIENT_LABEL,
      AGENT_DID,
      STORED_NOTE,
      READ_EXPIRY,
      REVOKE_NOTE
    ]) {
      expect(view.summary).toContain(line)
      expect(occurrences(view.text, line)).toBe(1)
    }
    for (const row of view.rows) {
      expect(row).not.toContain(RECIPIENT_LABEL)
      expect(row).not.toContain('expires')
    }
  })

  it('keeps the recipient on each card when recipients differ', async () => {
    const view = await mount({
      grants: [
        grantOn({ collectionId: 'notes' }),
        grantOn({ collectionId: 'tasks', controller: OTHER_DID })
      ]
    })
    expect(view.summary).not.toContain(RECIPIENT_LABEL)
    expect(view.rows[0]).toContain(RECIPIENT_LABEL)
    expect(view.rows[0]).toContain(AGENT_DID)
    expect(view.rows[1]).toContain(RECIPIENT_LABEL)
    expect(view.rows[1]).toContain(OTHER_DID)
    // The expiry and the revoke note are still shared.
    expect(view.summary).toContain(READ_EXPIRY)
    expect(view.summary).toContain(REVOKE_NOTE)
  })

  it('states a differing expiry on its own card only', async () => {
    const view = await mount({
      grants: [
        grantOn({ collectionId: 'notes' }),
        grantOn({ collectionId: 'tasks' }),
        grantOn({ collectionId: 'drafts', write: true })
      ]
    })
    expect(view.summary).toContain(READ_EXPIRY)
    const [notes, tasks, drafts] = view.rows
    expect(notes).not.toContain('expires')
    expect(tasks).not.toContain('expires')
    expect(drafts).toContain(WRITE_EXPIRY)
    expect(occurrences(view.text, REVOKE_NOTE)).toBe(1)
  })

  it('keeps every expiry on its card when no two grants share one', async () => {
    const view = await mount({
      grants: [
        grantOn({ collectionId: 'notes' }),
        grantOn({ collectionId: 'drafts', write: true })
      ]
    })
    expect(view.summary).not.toContain('expires')
    expect(view.summary).toContain(REVOKE_NOTE)
    expect(view.rows[0]).toContain(READ_EXPIRY)
    expect(view.rows[1]).toContain(WRITE_EXPIRY)
  })

  it('keeps a share revoke note on its card beside ordinary grants', async () => {
    const view = await mount({
      grants: [
        grantOn({ collectionId: 'notes' }),
        grantOn({ collectionId: 'tasks' }),
        grantOn({ collectionId: 'journal', share: true })
      ]
    })
    expect(view.summary).toContain(REVOKE_NOTE)
    expect(view.summary).not.toContain(SHARE_REVOKE_NOTE)
    expect(view.rows[2]).toContain(SHARE_REVOKE_NOTE)
    expect(view.rows[2]).toContain(SHARE_EXPIRY)
    expect(view.rows[0]).not.toContain(SHARE_REVOKE_NOTE)
  })

  it('draws the summary expiry from the ordinary grants beside shares', async () => {
    const view = await mount({
      grants: [
        grantOn({ collectionId: 'journal', share: true }),
        grantOn({ collectionId: 'photos', share: true }),
        grantOn({ collectionId: 'notes' })
      ]
    })
    expect(view.summary).toContain(READ_EXPIRY)
    expect(view.summary).toContain(REVOKE_NOTE)
    expect(view.summary).not.toContain('The fetch permission expires')
    expect(view.rows[0]).toContain(SHARE_EXPIRY)
    expect(view.rows[0]).toContain(SHARE_REVOKE_NOTE)
    expect(view.rows[2]).not.toContain('expires')
  })

  it('keeps every expiry on its card on an even split', async () => {
    const view = await mount({
      grants: [
        grantOn({ collectionId: 'notes' }),
        grantOn({ collectionId: 'tasks' }),
        grantOn({ collectionId: 'drafts', write: true }),
        grantOn({ collectionId: 'uploads', write: true })
      ]
    })
    expect(view.summary).not.toContain('expires')
    expect(view.summary).toContain(REVOKE_NOTE)
    expect(view.rows[0]).toContain(READ_EXPIRY)
    expect(view.rows[1]).toContain(READ_EXPIRY)
    expect(view.rows[2]).toContain(WRITE_EXPIRY)
    expect(view.rows[3]).toContain(WRITE_EXPIRY)
  })

  it('states the share revoke note once when every grant is a share', async () => {
    const view = await mount({
      grants: [
        grantOn({ collectionId: 'journal', share: true }),
        grantOn({ collectionId: 'photos', share: true })
      ]
    })
    expect(view.summary).toContain(SHARE_REVOKE_NOTE)
    expect(view.summary).not.toContain(REVOKE_NOTE)
    expect(occurrences(view.text, SHARE_REVOKE_NOTE)).toBe(1)
    expect(occurrences(view.text, SHARE_EXPIRY)).toBe(1)
  })
})
