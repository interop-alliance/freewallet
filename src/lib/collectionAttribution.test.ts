import { describe, it, expect } from 'vitest'
import { attributeCollectionsToApps } from './collectionAttribution'
import type { ConnectedApp } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'

/**
 * A listing entry, in the server-relative URL form the Space listing reports.
 *
 * @param options {object}
 * @param options.id {string}
 * @param [options.generator] {string}
 * @returns {StorageCollection}
 */
function collectionEntry({
  id,
  generator
}: {
  id: string
  generator?: string
}): StorageCollection {
  return { id, url: `/space/abc/${id}`, generator }
}

/**
 * A connected app with the given subject DID.
 *
 * @param options {object}
 * @param options.cid {string}
 * @param options.subjectDid {string}
 * @returns {ConnectedApp}
 */
function connectedApp({
  cid,
  subjectDid
}: {
  cid: string
  subjectDid: string
}): ConnectedApp {
  return {
    cid,
    name: `App ${cid}`,
    origin: 'https://app.example',
    appUrl: 'https://app.example/',
    subjectDid,
    grants: []
  }
}

describe('attributeCollectionsToApps', () => {
  it('matches a collection on its stamped generator', () => {
    const app = connectedApp({ cid: 'cid-1', subjectDid: 'did:key:zApp' })
    const attribution = attributeCollectionsToApps({
      collections: [collectionEntry({ id: 'docs', generator: 'did:key:zApp' })],
      apps: [app]
    })
    expect(attribution.get('docs')).toBe(app)
  })

  it('leaves a collection with no generator unattributed', () => {
    const attribution = attributeCollectionsToApps({
      collections: [collectionEntry({ id: 'docs' })],
      apps: [connectedApp({ cid: 'cid-1', subjectDid: 'did:key:zApp' })]
    })
    expect(attribution.size).toBe(0)
  })

  it('leaves a collection naming an app the wallet holds no key for unattributed', () => {
    const attribution = attributeCollectionsToApps({
      collections: [
        collectionEntry({ id: 'docs', generator: 'did:key:zGone' })
      ],
      apps: [connectedApp({ cid: 'cid-1', subjectDid: 'did:key:zApp' })]
    })
    expect(attribution.size).toBe(0)
  })

  it('takes the newest connect when several app keys share a subject DID', () => {
    const newest = connectedApp({ cid: 'cid-new', subjectDid: 'did:key:zApp' })
    const older = connectedApp({ cid: 'cid-old', subjectDid: 'did:key:zApp' })
    const attribution = attributeCollectionsToApps({
      collections: [collectionEntry({ id: 'docs', generator: 'did:key:zApp' })],
      apps: [newest, older]
    })
    expect(attribution.get('docs')).toBe(newest)
  })
})
