/**
 * The metadata card's row derivation.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  fetchMetaWithEncryptionProbe,
  formatMetadataValue,
  metadataRows
} from './metadataRows'

describe('metadataRows', () => {
  it('orders the known members first and keeps the unknown ones', () => {
    const rows = metadataRows({
      meta: {
        epoch: 'epoch-2',
        contentType: 'application/json',
        somethingNew: 'kept'
      },
      fieldOrder: ['contentType', 'epoch'],
      locale: 'en'
    })
    expect(rows.map(row => row.key)).toEqual([
      'contentType',
      'epoch',
      'somethingNew'
    ])
  })

  it('leaves `custom` and nested objects out of the rows', () => {
    const rows = metadataRows({
      meta: {
        size: 1024,
        custom: { name: 'note' },
        encryption: { scheme: 'edv' }
      },
      fieldOrder: ['size'],
      locale: 'en'
    })
    expect(rows.map(row => row.key)).toEqual(['size'])
    expect(rows[0].value).toContain('KB')
  })

  it('renders the `generator` object one row per member', () => {
    const rows = metadataRows({
      meta: {
        name: 'docs',
        generator: {
          id: 'did:key:z6MkApp',
          origin: 'https://app.example',
          url: 'https://app.example/docs',
          name: 'Docs App'
        }
      },
      fieldOrder: ['name', 'generator'],
      locale: 'en'
    })
    expect(rows).toEqual([
      { key: 'name', value: 'docs' },
      { key: 'generator.id', value: 'did:key:z6MkApp' },
      { key: 'generator.origin', value: 'https://app.example' },
      { key: 'generator.url', value: 'https://app.example/docs' },
      { key: 'generator.name', value: 'Docs App' }
    ])
  })

  it("renders an agent's `generator` stamp, which carries no origin or url", () => {
    const rows = metadataRows({
      meta: {
        generator: { id: 'did:key:z6MkAgent', name: 'Backup Agent' }
      },
      fieldOrder: ['name', 'generator'],
      locale: 'en'
    })
    expect(rows).toEqual([
      { key: 'generator.id', value: 'did:key:z6MkAgent' },
      { key: 'generator.name', value: 'Backup Agent' }
    ])
  })

  it('formats timestamps, scalars and scalar arrays', () => {
    expect(
      formatMetadataValue({
        key: 'createdAt',
        value: '2026-09-14T10:00:00Z',
        locale: 'en'
      })
    ).toMatch(/2026/)
    expect(
      formatMetadataValue({ key: 'type', value: ['Collection'], locale: 'en' })
    ).toBe('Collection')
    expect(
      formatMetadataValue({ key: 'name', value: 'notes', locale: 'en' })
    ).toBe('notes')
    expect(
      formatMetadataValue({ key: 'backend', value: { id: 'x' }, locale: 'en' })
    ).toBeNull()
  })
})

describe('fetchMetaWithEncryptionProbe', () => {
  it('reports encrypted from the probe when it resolves', async () => {
    const result = await fetchMetaWithEncryptionProbe({
      fetchMeta: async () => ({ contentType: 'application/json' }),
      probeEncrypted: async () => true
    })
    expect(result).toEqual({
      meta: { contentType: 'application/json' },
      encrypted: true
    })
  })

  it('still returns the meta document when the probe rejects', async () => {
    const onProbeError = vi.fn()
    const result = await fetchMetaWithEncryptionProbe({
      fetchMeta: async () => ({ contentType: 'application/json' }),
      probeEncrypted: async () => {
        throw new Error('continuity refusal')
      },
      onProbeError
    })
    expect(result.meta).toEqual({ contentType: 'application/json' })
    expect(onProbeError).toHaveBeenCalledTimes(1)
  })

  it('falls back to the document own `encryption` member on a rejected probe', async () => {
    const result = await fetchMetaWithEncryptionProbe({
      fetchMeta: async () => ({ encryption: { scheme: 'edv' } }),
      probeEncrypted: async () => {
        throw new Error('unreachable host')
      }
    })
    expect(result.encrypted).toBe(true)
  })

  it('falls back to false on a rejected probe when the document carries no `encryption` member', async () => {
    const result = await fetchMetaWithEncryptionProbe({
      fetchMeta: async () => ({ contentType: 'application/json' }),
      probeEncrypted: async () => {
        throw new Error('unreachable host')
      }
    })
    expect(result.encrypted).toBe(false)
  })

  it('keeps the two reads concurrent rather than serialized', async () => {
    const order: string[] = []
    const result = await fetchMetaWithEncryptionProbe({
      fetchMeta: async () => {
        order.push('meta-start')
        await Promise.resolve()
        order.push('meta-end')
        return { contentType: 'application/json' }
      },
      probeEncrypted: async () => {
        order.push('probe-start')
        await Promise.resolve()
        order.push('probe-end')
        return false
      }
    })
    expect(order).toEqual([
      'meta-start',
      'probe-start',
      'meta-end',
      'probe-end'
    ])
    expect(result.meta).toEqual({ contentType: 'application/json' })
  })
})
