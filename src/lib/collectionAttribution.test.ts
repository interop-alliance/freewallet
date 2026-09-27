import { describe, it, expect } from 'vitest'
import {
  attributeCollectionsToApps,
  collectionCreatorLabel
} from './collectionAttribution'
import type { CollectionCreator } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'

/**
 * A listing entry, in the server-relative URL form the Space listing reports.
 *
 * @param options {object}
 * @param options.id {string}
 * @param [options.generator] {string}   the stamped `generator.id`
 * @returns {StorageCollection}
 */
function collectionEntry({
  id,
  generator
}: {
  id: string
  generator?: `did:${string}`
}): StorageCollection {
  return {
    id,
    url: `/space/abc/${id}`,
    ...(generator && { generator: { id: generator } })
  }
}

const CONNECTED: CollectionCreator = {
  name: 'Editor',
  appUrl: 'https://app.example/editor',
  cid: 'cid-1'
}

describe('attributeCollectionsToApps', () => {
  it('matches a collection on its stamped generator', () => {
    const attribution = attributeCollectionsToApps({
      collections: [collectionEntry({ id: 'docs', generator: 'did:key:zApp' })],
      creators: new Map([['did:key:zApp', CONNECTED]])
    })
    expect(attribution.get('docs')).toBe(CONNECTED)
  })

  it('leaves a collection with no generator unattributed', () => {
    const attribution = attributeCollectionsToApps({
      collections: [collectionEntry({ id: 'docs' })],
      creators: new Map([['did:key:zApp', CONNECTED]])
    })
    expect(attribution.size).toBe(0)
  })

  it('leaves a collection naming an app no record knows unattributed', () => {
    const attribution = attributeCollectionsToApps({
      collections: [
        collectionEntry({ id: 'docs', generator: 'did:key:zGone' })
      ],
      creators: new Map([['did:key:zApp', CONNECTED]])
    })
    expect(attribution.size).toBe(0)
  })

  it('attributes a disconnected creator by its recorded name', () => {
    const disconnected: CollectionCreator = {
      name: 'Notes',
      appUrl: 'https://app.example/notes'
    }
    const attribution = attributeCollectionsToApps({
      collections: [
        collectionEntry({ id: 'notes', generator: 'did:key:zNotes' })
      ],
      creators: new Map([['did:key:zNotes', disconnected]])
    })
    expect(attribution.get('notes')).toBe(disconnected)
  })
})

describe('collectionCreatorLabel', () => {
  const STAMPED: StorageCollection = {
    id: 'docs',
    url: '/space/abc/docs',
    generator: {
      id: 'did:key:zApp',
      origin: 'https://app.example',
      url: 'https://app.example/editor',
      name: 'Stamped Editor'
    }
  }

  it('prefers the stamped generator.name', () => {
    expect(
      collectionCreatorLabel({
        generator: STAMPED.generator,
        recordName: CONNECTED.name
      })
    ).toBe('Stamped Editor')
  })

  it("falls back to the wallet records' name when generator.name is absent", () => {
    const generator = { ...STAMPED.generator!, name: undefined }
    expect(
      collectionCreatorLabel({ generator, recordName: CONNECTED.name })
    ).toBe('Editor')
  })

  it('falls back to the stamped origin when nothing names the app', () => {
    const generator = {
      id: 'did:key:zApp' as const,
      origin: 'https://app.example'
    }
    expect(collectionCreatorLabel({ generator })).toBe('https://app.example')
  })

  it('names nothing for an unattributed collection', () => {
    expect(
      collectionCreatorLabel({
        generator: collectionEntry({ id: 'docs' }).generator
      })
    ).toBeUndefined()
  })
})
