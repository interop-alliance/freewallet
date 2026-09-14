// @vitest-environment node
import { describe, it, expect } from 'vitest'
import {
  existingCollectionsFrom,
  isSatisfiable,
  resolveGrant
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
