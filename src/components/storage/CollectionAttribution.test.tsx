/**
 * The "Created by" caption for a collection stamped by an interaction-URL
 * agent: a `generator` with no `origin`. It names the agent by its stamped
 * name, else by its shortened DID, as plain text.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
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
 * @returns {Promise<{ container: HTMLElement, unmount: () => Promise<void> }>}
 */
async function mount(collection: StorageCollection) {
  const container = document.createElement('div')
  const root: Root = createRoot(container)
  await act(async () => {
    root.render(
      <MemoryRouter>
        <CollectionAttribution collection={collection} />
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

describe("CollectionAttribution on an agent's stamp", () => {
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
  })
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('names the agent by its stamped name', async () => {
    const view = await mount({
      id: 'agent-notes',
      url: '/space/s/agent-notes/',
      generator: { id: AGENT_DID, name: 'Backup Agent' }
    })
    expect(view.container.textContent).toBe('Created by Backup Agent')
    expect(view.container.querySelector('a')).toBeNull()
    await view.unmount()
  })
})
