/**
 * The metadata card's behavior: nothing is read until the accordion is
 * expanded, a null read and a server without metadata support both land on
 * the empty state, a failed read retries on the next expand, and the raw
 * source toggle shows the metadata document verbatim.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import '@/i18n'
import { MetadataCard } from './MetadataCard'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

const RESOURCE_FIELDS = ['contentType', 'size', 'createdAt', 'epoch']

/**
 * Mounts the card and returns its container plus an expand helper that clicks
 * the accordion's summary.
 */
async function mount({
  fetchMeta,
  encrypted = false
}: {
  fetchMeta: () => Promise<Record<string, unknown> | null>
  encrypted?: boolean
}) {
  const read = async () => ({ meta: await fetchMeta(), encrypted })
  const container = document.createElement('div')
  document.body.append(container)
  const root: Root = createRoot(container)
  await act(async () => {
    root.render(<MetadataCard fetchMeta={read} fieldOrder={RESOURCE_FIELDS} />)
  })

  async function click(element: Element | null) {
    if (!element) {
      throw new Error('Nothing to click.')
    }
    await act(async () => {
      ;(element as HTMLElement).click()
    })
    await act(async () => {
      await Promise.resolve()
    })
  }

  return {
    container,
    expand: async () =>
      await click(container.querySelector('.MuiAccordionSummary-root')),
    clickButton: async (label: string) => {
      const match = Array.from(container.querySelectorAll('button')).find(
        button => button.textContent?.includes(label)
      )
      await click(match ?? null)
    },
    unmount: () =>
      act(async () => {
        root.unmount()
        container.remove()
      })
  }
}

describe('MetadataCard', () => {
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('reads the metadata only once the card is expanded', async () => {
    const fetchMeta = vi.fn(async () => ({
      contentType: 'application/json',
      size: 2048,
      epoch: 'epoch-1'
    }))
    const card = await mount({ fetchMeta })
    expect(fetchMeta).not.toHaveBeenCalled()

    await card.expand()
    expect(fetchMeta).toHaveBeenCalledTimes(1)
    expect(card.container.textContent).toContain('application/json')
    expect(card.container.textContent).toContain('epoch-1')

    // Collapsing and expanding again does not re-read.
    await card.expand()
    await card.expand()
    expect(fetchMeta).toHaveBeenCalledTimes(1)
    await card.unmount()
  })

  it('shows the empty state on a null read', async () => {
    const card = await mount({ fetchMeta: async () => null })
    await card.expand()
    expect(card.container.textContent).toContain('No metadata available')
    await card.unmount()
  })

  it('shows the empty state on a server without metadata support', async () => {
    const card = await mount({
      fetchMeta: async () => {
        const err = new Error('Not implemented.')
        err.name = 'NotImplementedError'
        throw err
      }
    })
    await card.expand()
    expect(card.container.textContent).toContain('No metadata available')
    expect(card.container.textContent).not.toContain('Could not load')
    await card.unmount()
  })

  it('shows an inline error on any other failure, and retries', async () => {
    let attempts = 0
    const card = await mount({
      fetchMeta: async () => {
        attempts += 1
        if (attempts === 1) {
          throw new Error('network down')
        }
        return { contentType: 'text/plain', size: 3 }
      }
    })
    await card.expand()
    expect(card.container.textContent).toContain('Could not load metadata')

    // Collapse, then expand again: the failed read is retried.
    await card.expand()
    await card.expand()
    expect(attempts).toBe(2)
    expect(card.container.textContent).not.toContain('Could not load')
    expect(card.container.textContent).toContain('text/plain')
    await card.unmount()
  })

  it('toggles the raw metadata source', async () => {
    const card = await mount({
      fetchMeta: async () => ({ contentType: 'text/plain', size: 12 })
    })
    await card.expand()
    expect(card.container.textContent).not.toContain('"contentType"')

    await card.clickButton('View meta source')
    expect(card.container.textContent).toContain('"contentType"')

    await card.clickButton('Hide meta source')
    expect(card.container.textContent).not.toContain('"contentType"')
    await card.unmount()
  })

  it('labels a stored custom envelope as encrypted', async () => {
    const card = await mount({
      encrypted: true,
      fetchMeta: async () => ({
        contentType: 'application/json',
        size: 10,
        custom: { ciphertext: 'opaque' }
      })
    })
    await card.expand()
    expect(card.container.textContent).toContain('encrypted')
    expect(card.container.textContent).toContain('opaque')
    await card.unmount()
  })
})
