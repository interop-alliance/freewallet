/**
 * The revoke-before-delete half of the login-time app-key sweep: deleting a
 * stranded row removes the app's only listing on the Applications page, so its
 * authority must be retired first, and a revocation that does not fully land
 * leaves the row in place to be retried at the next login. The second half is
 * the orphan pass: a public copy with no private row behind it (a pre-upgrade
 * app key kept through the delete dialog's "keep public copy" choice) is
 * retracted on its own, while a copy that still has a private row is left to
 * that row's delete. The sweep's detection rules have their own suite
 * (`tests/unit/appKeySweep.test.ts`).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { sweepStrandedAppKeys } from '@/session/appKeySweep'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { StorageManager } from '@/stores/storageManager'

const calls: string[] = []

/**
 * A marker-typed app-key credential, the shape the sweep recognizes without
 * any seed binding.
 *
 * @param options {object}
 * @param options.subject {string | undefined}   the subject DID
 * @param options.origin {string | undefined}   the claimed origin
 * @returns {IVerifiableCredential}
 */
function appKeyFixture({
  subject = 'did:key:z6MkfakeAppSubject',
  origin = 'https://app.example'
}: {
  subject?: string
  origin?: string
} = {}): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'AppKeyCredential'],
    issuer: subject,
    credentialSubject: {
      ...(subject !== undefined && { id: subject }),
      ...(origin !== undefined && { origin })
    }
  } as unknown as IVerifiableCredential
}

/**
 * An ordinary (non-app-key) stored credential.
 *
 * @returns {IVerifiableCredential}
 */
function plainCredential(): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: 'did:key:z6MkfakeIssuer',
    credentialSubject: { id: 'did:key:z6MkfakeHolder', name: 'Alice' }
  } as unknown as IVerifiableCredential
}

/**
 * A storage double whose methods record their call order.
 *
 * @param options {object}
 * @param options.credentials {Array<{ cid: string; vc: IVerifiableCredential }>}
 * @param [options.publicCopies] {Array<{ cid: string; vc: IVerifiableCredential }>}
 *   the world-readable public copies, private row or not
 * @returns {StorageManager}
 */
function storageDouble({
  credentials,
  publicCopies = []
}: {
  credentials: Array<{ cid: string; vc: IVerifiableCredential }>
  publicCopies?: Array<{ cid: string; vc: IVerifiableCredential }>
}) {
  const storage = {
    listCredentials: vi.fn(async () => credentials),
    listHistoryItems: vi.fn(async () => {
      calls.push('listHistoryItems')
      return []
    }),
    revokeAppCollectionRecipients: vi.fn(
      async ({ subjectDid }: { subjectDid: string }) => {
        calls.push(`rotate:${subjectDid}`)
        return { collections: 0, rotated: 0, failed: 0 }
      }
    ),
    revokeAppGrants: vi.fn(async ({ subjectDid }: { subjectDid: string }) => {
      calls.push(`revoke:${subjectDid}`)
      return { revoked: 0, skipped: 0 }
    }),
    deleteCredential: vi.fn(async ({ cid }: { cid: string }) => {
      calls.push(`delete:${cid}`)
    }),
    listPublicCredentials: vi.fn(
      async ({ skipCids }: { skipCids?: Set<string> } = {}) =>
        publicCopies.filter(({ cid }) => !skipCids?.has(cid))
    ),
    retractPublicCopy: vi.fn(async ({ cid }: { cid: string }) => {
      calls.push(`retract:${cid}`)
    })
  }
  return storage
}

describe('sweepStrandedAppKeys', () => {
  beforeEach(() => {
    calls.length = 0
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  it('revokes the app authority before deleting its row', async () => {
    const storage = storageDouble({
      credentials: [{ cid: 'cid-1', vc: appKeyFixture() }]
    })

    const { deleted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(1)
    expect(calls).toEqual([
      'listHistoryItems',
      'rotate:did:key:z6MkfakeAppSubject',
      'revoke:did:key:z6MkfakeAppSubject',
      'delete:cid-1'
    ])
    expect(storage.revokeAppCollectionRecipients).toHaveBeenCalledWith({
      origin: 'https://app.example',
      subjectDid: 'did:key:z6MkfakeAppSubject',
      items: []
    })
    expect(storage.revokeAppGrants).toHaveBeenCalledWith({
      origin: 'https://app.example',
      subjectDid: 'did:key:z6MkfakeAppSubject',
      items: []
    })
  })

  it('fetches the activity history once for the whole sweep', async () => {
    const storage = storageDouble({
      credentials: [
        { cid: 'cid-1', vc: appKeyFixture({ subject: 'did:key:zFirst' }) },
        { cid: 'cid-2', vc: appKeyFixture({ subject: 'did:key:zSecond' }) }
      ]
    })

    const { deleted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(2)
    expect(storage.listHistoryItems).toHaveBeenCalledTimes(1)
    expect(calls.filter(entry => entry === 'listHistoryItems')).toHaveLength(1)
  })

  it('skips the delete when the grant revocation throws', async () => {
    const storage = storageDouble({
      credentials: [
        { cid: 'cid-1', vc: appKeyFixture({ subject: 'did:key:zFirst' }) },
        { cid: 'cid-2', vc: appKeyFixture({ subject: 'did:key:zSecond' }) }
      ]
    })
    storage.revokeAppGrants.mockImplementationOnce(async () => {
      throw new Error('server unreachable')
    })

    const { deleted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(1)
    expect(calls).not.toContain('delete:cid-1')
    expect(calls).toContain('delete:cid-2')
  })

  it('skips the delete when a collection rotation failed', async () => {
    const storage = storageDouble({
      credentials: [
        { cid: 'cid-1', vc: appKeyFixture({ subject: 'did:key:zFirst' }) },
        { cid: 'cid-2', vc: appKeyFixture({ subject: 'did:key:zSecond' }) }
      ]
    })
    storage.revokeAppCollectionRecipients.mockImplementationOnce(async () => {
      calls.push('rotate:did:key:zFirst')
      return { collections: 2, rotated: 1, failed: 1 }
    })

    const { deleted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(1)
    expect(storage.revokeAppGrants).toHaveBeenCalledTimes(1)
    expect(calls).not.toContain('delete:cid-1')
    expect(calls).toContain('delete:cid-2')
  })

  it('deletes a row with no revocable identity directly', async () => {
    const originless = appKeyFixture()
    delete (originless.credentialSubject as { origin?: string }).origin
    const storage = storageDouble({
      credentials: [{ cid: 'cid-1', vc: originless }]
    })

    const { deleted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(1)
    expect(storage.listHistoryItems).not.toHaveBeenCalled()
    expect(storage.revokeAppCollectionRecipients).not.toHaveBeenCalled()
    expect(storage.revokeAppGrants).not.toHaveBeenCalled()
    expect(calls).toEqual(['delete:cid-1'])
  })

  it('leaves an ordinary credential untouched', async () => {
    const storage = storageDouble({
      credentials: [{ cid: 'cid-1', vc: plainCredential() }]
    })

    const { deleted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(0)
    expect(calls).toEqual([])
    expect(storage.deleteCredential).not.toHaveBeenCalled()
  })
  it('retracts an orphaned public app-key copy with no private row', async () => {
    const storage = storageDouble({
      credentials: [],
      publicCopies: [{ cid: 'pub-1', vc: appKeyFixture() }]
    })

    const { deleted, retracted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(0)
    expect(retracted).toBe(1)
    expect(calls).toEqual([
      'listHistoryItems',
      'rotate:did:key:z6MkfakeAppSubject',
      'revoke:did:key:z6MkfakeAppSubject',
      'retract:pub-1'
    ])
  })

  it('leaves a public copy that has a private row to the row delete', async () => {
    const appKey = appKeyFixture()
    const storage = storageDouble({
      credentials: [{ cid: 'cid-1', vc: appKey }],
      publicCopies: [{ cid: 'cid-1', vc: appKey }]
    })

    const { deleted, retracted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(1)
    expect(retracted).toBe(0)
    expect(calls).toContain('delete:cid-1')
    expect(calls).not.toContain('retract:cid-1')
    expect(storage.listPublicCredentials).toHaveBeenCalledWith({
      skipCids: new Set(['cid-1'])
    })
  })

  it('leaves an ordinary public credential alone', async () => {
    const storage = storageDouble({
      credentials: [],
      publicCopies: [{ cid: 'pub-1', vc: plainCredential() }]
    })

    const { retracted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(retracted).toBe(0)
    expect(storage.retractPublicCopy).not.toHaveBeenCalled()
  })

  it('completes the private pass when the public listing fails', async () => {
    const storage = storageDouble({
      credentials: [{ cid: 'cid-1', vc: appKeyFixture() }]
    })
    storage.listPublicCredentials.mockImplementationOnce(async () => {
      throw new Error('collection unreachable')
    })

    const { deleted, retracted } = await sweepStrandedAppKeys({
      storage: storage as unknown as StorageManager
    })

    expect(deleted).toBe(1)
    expect(retracted).toBe(0)
    expect(calls).toContain('delete:cid-1')
    expect(console.warn).toHaveBeenCalled()
  })
})
