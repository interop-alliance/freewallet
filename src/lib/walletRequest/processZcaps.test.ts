// @vitest-environment node
import { describe, it, expect } from 'vitest'
import {
  existingCollectionsFrom,
  isSatisfiable,
  resolveGrant,
  resolveInvocationTarget
} from './processZcaps'
import type { ICapabilityQueryDetail } from './types'

const SPACE = { serverUrl: 'https://was.example/', spaceId: 'abc' }
const DESCRIPTOR: ICapabilityQueryDetail = {
  referenceId: 'docs',
  allowedAction: ['GET'],
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'docs'
  },
  controller: 'did:key:z6MkTest'
}

describe('resolveGrant recipient presence', () => {
  it('resolves satisfiable with a controller present', () => {
    const { target } = resolveGrant({
      descriptor: DESCRIPTOR,
      space: SPACE,
      collections: existingCollectionsFrom([])
    })
    expect(isSatisfiable(target)).toBe(true)
  })

  it('refuses a descriptor that names no controller as unsatisfiable', () => {
    // The wire type requires a `controller`, but an actual request body can
    // omit it; a grant with no recipient must render "cannot fulfill" rather
    // than a recipient-less consent row that delegates to nobody.
    const { controller: _controller, ...omitted } = DESCRIPTOR
    const { target } = resolveGrant({
      descriptor: omitted as ICapabilityQueryDetail,
      space: SPACE,
      collections: existingCollectionsFrom([])
    })
    expect(target.targetClass).toBeUndefined()
  })

  it('allows an empty controller for the App Connect consent preview', () => {
    // On first run the app-key DID does not exist yet; the preview resolves
    // with an empty controller and the approved path fills the real subject
    // DID before resolving again (without the opt-out).
    const { target } = resolveGrant({
      descriptor: { ...DESCRIPTOR, controller: '' },
      space: SPACE,
      collections: existingCollectionsFrom([]),
      allowMissingController: true
    })
    expect(isSatisfiable(target)).toBe(true)
  })
})

describe('resolveInvocationTarget existing-collection reading', () => {
  const APP_DID = 'did:key:z6MkAppOne'
  const APP_ORIGIN = 'https://app.example'
  const APP_URL = 'https://app.example/editor'
  const OTHER_DID = 'did:key:z6MkAppTwo'
  const OTHER_ORIGIN = 'https://other.example'
  const DOCS = {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'docs'
  }
  // The attribution as the resolver sees it: the two stamped members off the
  // collection, plus the creating app as the wallet's own records know it.
  const createdByApp = existingCollectionsFrom([
    {
      id: 'docs',
      attribution: {
        generator: APP_DID,
        generatorOrigin: APP_ORIGIN,
        creatorApp: { name: 'Editor', appUrl: APP_URL }
      }
    }
  ])

  it('reports nothing for a collection that does not exist yet', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([]),
      requester: { controller: APP_DID, origin: APP_ORIGIN }
    })
    expect(target.existing).toBeUndefined()
    expect(target.needsProvisioning).toBe(true)
  })

  it('reports nothing for a collection whose attribution is unread', () => {
    // The first pass resolves over the lean listing alone; the row shows no
    // note until the second pass has read the collection's metadata.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'docs' }]),
      requester: { controller: OTHER_DID, origin: OTHER_ORIGIN }
    })
    expect(target.existing).toBeUndefined()
    expect(target.needsProvisioning).toBe(true)
  })

  it("reads the requester's own collection as this-app", () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: APP_DID, origin: APP_ORIGIN }
    })
    expect(target.existing).toEqual({
      creator: 'this-app',
      generator: APP_DID,
      generatorOrigin: APP_ORIGIN
    })
  })

  it('reads a collection an earlier key of the same app created as this-application', () => {
    // The site was disconnected (its app key deleted) and reconnects: a new
    // did:key, the same attested origin, the same canonical app URL.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID, origin: APP_ORIGIN, appUrl: APP_URL }
    })
    expect(target.existing?.creator).toBe('this-application')
  })

  it("reads a different app on the same origin's collection as other", () => {
    // Two apps hosted at different paths of one origin are two apps: the
    // wallet tells them apart by appUrl, and so does the reading.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: {
        controller: OTHER_DID,
        origin: APP_ORIGIN,
        appUrl: 'https://app.example/notes'
      }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it("reads other when the creator's app URL is unknown to an App Connect requester", () => {
    // The wallet holds no record naming the creator (no app key, no Login
    // activity), so an origin match alone does not vouch for the same app.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([
        {
          id: 'docs',
          attribution: { generator: APP_DID, generatorOrigin: APP_ORIGIN }
        }
      ]),
      requester: { controller: OTHER_DID, origin: APP_ORIGIN, appUrl: APP_URL }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('falls back to the origin comparison for a requester with no app URL', () => {
    // A plain zcap request carries an attested origin and nothing finer.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID, origin: APP_ORIGIN }
    })
    expect(target.existing?.creator).toBe('this-application')
  })

  it("reads another application's collection as other, and still admits the requester", () => {
    // The decided collision policy: the second application is admitted into
    // the collection's every key epoch, exactly as a reconnect is, and the
    // consent row states the creator before approval. The reading is what
    // keeps that admission from being silent.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID, origin: OTHER_ORIGIN }
    })
    expect(target.existing).toEqual({
      creator: 'other',
      generator: APP_DID,
      generatorOrigin: APP_ORIGIN,
      creatorName: 'Editor'
    })
    expect(isSatisfiable(target)).toBe(true)
    expect(target.needsProvisioning).toBe(true)
  })

  it('reads other on a first-run preview, where no requester DID exists yet', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: '', origin: OTHER_ORIGIN }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('reads a collection with no attribution as unattributed', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'docs', attribution: {} }]),
      requester: { controller: OTHER_DID, origin: OTHER_ORIGIN }
    })
    expect(target.existing).toEqual({ creator: 'unattributed' })
  })

  it('reports nothing for a public or a protected collection', () => {
    const collections = existingCollectionsFrom([
      { id: 'docs', isPublic: true, attribution: { generator: APP_DID } },
      { id: 'private-credentials', attribution: { generator: APP_DID } }
    ])
    const requester = { controller: OTHER_DID, origin: OTHER_ORIGIN }
    expect(
      resolveInvocationTarget({
        descriptor: DOCS,
        space: SPACE,
        collections,
        requester
      }).existing
    ).toBeUndefined()
    expect(
      resolveInvocationTarget({
        descriptor: { ...DOCS, name: 'private-credentials' },
        space: SPACE,
        collections,
        requester
      }).existing
    ).toBeUndefined()
  })

  it('reads the same collection named as a plain URL the same way', () => {
    const target = resolveInvocationTarget({
      descriptor: `${SPACE.serverUrl}space/${SPACE.spaceId}/docs/`,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID, origin: OTHER_ORIGIN }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('carries the reading through resolveGrant with the descriptor controller and the origin', () => {
    const { target } = resolveGrant({
      descriptor: { ...DESCRIPTOR, controller: OTHER_DID },
      space: SPACE,
      collections: createdByApp,
      requester: { origin: OTHER_ORIGIN }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('carries the app URL through resolveGrant', () => {
    const { target } = resolveGrant({
      descriptor: { ...DESCRIPTOR, controller: OTHER_DID },
      space: SPACE,
      collections: createdByApp,
      requester: { origin: APP_ORIGIN, appUrl: APP_URL }
    })
    expect(target.existing?.creator).toBe('this-application')
  })
})
