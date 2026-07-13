import { afterEach, describe, expect, it, vi } from 'vitest'
import { downloadBlob } from '../../src/lib/downloadBlob'

describe('downloadBlob', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('creates an object URL, clicks a download anchor, then cleans up', () => {
    const createObjectURL = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValue('blob:mock-url')
    const revokeObjectURL = vi
      .spyOn(URL, 'revokeObjectURL')
      .mockImplementation(() => {})

    // Capture the anchor by querying the document at click time; finding it
    // there also proves the click happened while the anchor was attached.
    let clickedAnchor: HTMLAnchorElement | null = null
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {
        clickedAnchor = document.body.querySelector('a[download]')
      })

    const blob = new Blob(['{"hello":"world"}'], {
      type: 'application/json'
    })
    downloadBlob({ blob, filename: 'example.json' })

    expect(createObjectURL).toHaveBeenCalledWith(blob)
    expect(clickSpy).toHaveBeenCalledTimes(1)
    expect(clickedAnchor).not.toBeNull()
    const anchor = clickedAnchor as unknown as HTMLAnchorElement
    expect(anchor.download).toBe('example.json')
    expect(anchor.getAttribute('href')).toBe('blob:mock-url')
    // The anchor is removed and the object URL revoked after the click.
    expect(document.body.contains(anchor)).toBe(false)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url')
  })
})
