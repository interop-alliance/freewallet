/**
 * The consent rows of a connection request: every row states the share TTL
 * and that access renews while the connection stands, the inbox row has its
 * own copy and no write warning, and each read row states that the agent
 * passes read access on.
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
const SPACE_URL = 'https://was.example/space/abc/'

const AUDIENCE: ResolvedGrant = {
  descriptor: {
    referenceId: 'friends',
    controller: AGENT_DID,
    invocationTarget: `${SPACE_URL}friends/`
  },
  target: {
    targetClass: 'collection',
    invocationTarget: `${SPACE_URL}friends/`,
    collectionId: 'friends',
    needsProvisioning: false,
    encrypted: false
  },
  allowedActions: ['GET', 'HEAD'],
  write: false
}

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
 * Renders the panel and returns each row's text.
 *
 * @param options {object}
 * @param options.grants {ResolvedGrant[]}
 * @param [options.connectionRequest] {boolean}
 * @returns {Promise<{ rows: string[], unmount: () => Promise<void> }>}
 */
async function mount({
  grants,
  connectionRequest
}: {
  grants: ResolvedGrant[]
  connectionRequest?: boolean
}) {
  const container = document.createElement('div')
  const root: Root = createRoot(container)
  await act(async () => {
    root.render(
      <ZcapGrantsPanel
        grants={grants}
        ttlDays={30}
        writeTtlDays={7}
        shareTtlDays={365}
        connectionRequest={connectionRequest}
      />
    )
  })
  // The heading, then one box per grant.
  const rows = [...container.firstElementChild!.children]
    .slice(1)
    .map(row => row.textContent ?? '')
  return {
    rows,
    unmount: () =>
      act(async () => {
        root.unmount()
      })
  }
}

describe('ZcapGrantsPanel on a connection request', () => {
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
  })
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('states the share TTL and the renewal on every row', async () => {
    const view = await mount({
      grants: [AUDIENCE, INBOX],
      connectionRequest: true
    })
    expect(view.rows).toHaveLength(2)
    for (const row of view.rows) {
      expect(row).toContain(
        'Expires in 365 days, and renews while this connection stands'
      )
    }
    await view.unmount()
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
    await view.unmount()
  })

  it('keeps the ordinary expiry line off a connection request', async () => {
    const view = await mount({ grants: [AUDIENCE] })
    expect(view.rows[0]).toContain('Expires in 30 days')
    expect(view.rows[0]).not.toContain('renews while this connection stands')
    expect(view.rows[0]).not.toContain('passes this read access on')
    await view.unmount()
  })
})
