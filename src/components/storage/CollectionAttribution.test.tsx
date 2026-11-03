/**
 * The "Created for" caption for a collection stamped by an interaction-URL
 * agent: a `generator` with no `origin`. It names the agent by its stamped
 * name, else by its shortened DID, as plain text. And the wallet-collection
 * caption, which steps aside when the server-observed line beside it
 * already names the wallet.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it } from 'vitest'
import '@/i18n'
import type { StorageCollection } from '@/lib/storage'
import { CollectionAttribution } from './CollectionAttribution'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

const AGENT_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

/**
 * Renders the caption for one collection.
 *
 * @param collection {StorageCollection}
 * @param [observedByWallet] {boolean}   whether the server-observed line
 *   beside the caption already names the wallet
 * @returns {Promise<{ container: HTMLElement, unmount: () => Promise<void> }>}
 */
async function mount(
  collection: StorageCollection,
  observedByWallet?: boolean
) {
  const container = document.createElement('div')
  const root: Root = createRoot(container)
  await act(async () => {
    root.render(
      <MemoryRouter>
        <CollectionAttribution
          collection={collection}
          observedByWallet={observedByWallet}
        />
      </MemoryRouter>
    )
  })
  return {
    container,
    unmount: () =>
      act(async () => {
        root.unmount()
      })
  }
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true
})

describe("CollectionAttribution on an agent's stamp", () => {
  it('names the agent by its stamped name', async () => {
    const view = await mount({
      id: 'agent-notes',
      url: '/space/s/agent-notes/',
      generator: { id: AGENT_DID, name: 'Backup Agent' }
    })
    expect(view.container.textContent).toBe('Created for Backup Agent')
    expect(view.container.querySelector('a')).toBeNull()
    await view.unmount()
  })
})

describe('CollectionAttribution on a wallet collection', () => {
  const collection: StorageCollection = {
    id: 'private-credentials',
    url: '/space/s/private-credentials/'
  }

  it('names the wallet when no observed line stands beside it', async () => {
    const view = await mount(collection)
    expect(view.container.textContent).toBe('Created by this wallet')
    await view.unmount()
  })

  it('renders nothing when the observed line already names the wallet', async () => {
    const view = await mount(collection, true)
    expect(view.container.textContent).toBe('')
    await view.unmount()
  })
})
