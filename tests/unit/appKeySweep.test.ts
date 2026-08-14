// @vitest-environment node
/**
 * Unit tests for the login-time app-key sweep (`src/session/appKeySweep.ts`):
 * app keys now live in their own `app-connections` collection, so any left in
 * `private-credentials` by an earlier version are deleted -- never moved,
 * since a row there stays reachable from the credential-wide surfaces (a
 * world-readable public link, a share of the credentials collection). Two
 * detection rules, deliberately both: the `AppKeyCredential` marker every
 * minted key carries, and the pre-marker shape (self-issued, claiming an
 * origin, and carrying a seed that re-derives its own subject DID). Ordinary
 * credentials are left alone -- including a self-issued one that merely
 * claims an origin -- a clean store is read-only, a failing delete does not
 * strand the rest, and a second run finds nothing.
 */
import { describe, expect, it, vi } from 'vitest'
import { mintAppKeyCredential } from '@interop/wallet-core/request'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { StoredCredential } from '@/types/credential'
import type { StorageManager } from '@/stores/storageManager'
import { sweepStrandedAppKeys } from '@/session/appKeySweep'

const APP_DID = 'did:key:z6MkTestApp'

/**
 * A credential body, with the members the sweep's two rules read.
 */
function credential({
  types = ['VerifiableCredential'],
  issuer = 'did:key:z6MkTestIssuer',
  subject = 'did:key:z6MkTestSubject',
  origin
}: {
  types?: string[]
  issuer?: string
  subject?: string
  origin?: string
} = {}): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: types,
    issuer,
    credentialSubject: {
      id: subject,
      ...(origin !== undefined && { origin })
    }
  } as unknown as IVerifiableCredential
}

/**
 * A marker-typed app key, as every minted one is stored.
 */
function markedAppKey(): IVerifiableCredential {
  return credential({
    types: ['VerifiableCredential', 'AppKeyCredential'],
    issuer: APP_DID,
    subject: APP_DID,
    origin: 'https://app.example'
  })
}

/**
 * A genuine app key from before the marker existed: a real minted key (its
 * `credentialSubject.seed` re-derives its subject DID) with the marker type
 * and the `appUrl` claim stripped -- the shape the old match path accepted.
 */
async function legacyAppKey(): Promise<IVerifiableCredential> {
  const { credential: minted } = await mintAppKeyCredential({
    app: { name: 'Legacy App', appUrl: 'https://legacy-app.example/' },
    origin: 'https://legacy-app.example'
  })
  const subject = { ...(minted.credentialSubject as Record<string, unknown>) }
  delete subject.appUrl
  return {
    ...minted,
    type: ['VerifiableCredential'],
    credentialSubject: subject
  } as unknown as IVerifiableCredential
}

/**
 * A self-issued credential claiming an origin but carrying no seed: the shape
 * the legacy rule must NOT delete, since it was never an app key.
 */
function selfIssuedWithOrigin(): IVerifiableCredential {
  return credential({
    issuer: APP_DID,
    subject: APP_DID,
    origin: 'https://not-an-app-key.example'
  })
}

/**
 * A storage stub over `private-credentials` whose deletes really remove the
 * row, so a second sweep sees the post-sweep state.
 */
function fakeStorage(stored: StoredCredential[]) {
  const rows = [...stored]
  const storage = {
    listCredentials: vi.fn(async () => [...rows]),
    // The sweep retires a stranded key's live authority before deleting its
    // row; the revoke-before-delete ordering has its own suite
    // (`src/session/appKeySweep.test.ts`), so here they just succeed.
    listHistoryItems: vi.fn(async () => []),
    revokeAppCollectionRecipients: vi.fn(async () => ({
      collections: 0,
      rotated: 0,
      failed: 0
    })),
    revokeAppGrants: vi.fn(async () => ({ revoked: 0, skipped: 0 })),
    deleteCredential: vi.fn(async ({ cid }: { cid: string }) => {
      const index = rows.findIndex(row => row.cid === cid)
      if (index >= 0) {
        rows.splice(index, 1)
      }
    })
  }
  return { storage: storage as unknown as StorageManager, rows, calls: storage }
}

describe('sweepStrandedAppKeys', () => {
  it('deletes a marker-typed and a legacy-shaped app key, keeping the rest', async () => {
    const { storage, rows, calls } = fakeStorage([
      { cid: 'c-marked', vc: markedAppKey() },
      { cid: 'c-legacy', vc: await legacyAppKey() },
      { cid: 'c-diploma', vc: credential() }
    ])

    expect(await sweepStrandedAppKeys({ storage })).toBe(2)

    // Through the ordinary delete path, so a stranded key ever published as a
    // public link has that world-readable copy retracted first.
    expect(calls.deleteCredential).toHaveBeenCalledWith({ cid: 'c-marked' })
    expect(calls.deleteCredential).toHaveBeenCalledWith({ cid: 'c-legacy' })
    expect(rows.map(({ cid }) => cid)).toEqual(['c-diploma'])
  })

  it('leaves an ordinary credential that merely claims an origin', async () => {
    // The legacy rule needs self-issuance too: a credential someone else
    // issued is not an app key however it is shaped.
    const { storage, calls } = fakeStorage([
      {
        cid: 'c-ticket',
        vc: credential({ origin: 'https://issuer.example' })
      }
    ])

    expect(await sweepStrandedAppKeys({ storage })).toBe(0)
    expect(calls.deleteCredential).not.toHaveBeenCalled()
  })

  it('keeps a self-issued credential with an origin but no binding seed', async () => {
    // The legacy rule needs the seed-to-subject binding too: without it an
    // ordinary self-issued credential that happens to claim an origin would
    // be deleted permanently, and it was never an app key.
    const { storage, rows, calls } = fakeStorage([
      { cid: 'c-membership', vc: selfIssuedWithOrigin() }
    ])

    expect(await sweepStrandedAppKeys({ storage })).toBe(0)
    expect(calls.deleteCredential).not.toHaveBeenCalled()
    expect(rows.map(({ cid }) => cid)).toEqual(['c-membership'])
  })

  it('deletes a genuine legacy app key whose seed derives its subject', async () => {
    const { storage, rows } = fakeStorage([
      { cid: 'c-legacy', vc: await legacyAppKey() }
    ])

    expect(await sweepStrandedAppKeys({ storage })).toBe(1)
    expect(rows).toEqual([])
  })

  it('keeps sweeping after a delete fails, reporting only what was deleted', async () => {
    // One unretractable public copy (or a network failure) must not strand
    // every later seed until some future login.
    const { storage, rows, calls } = fakeStorage([
      { cid: 'c-stuck', vc: markedAppKey() },
      { cid: 'c-marked', vc: markedAppKey() }
    ])
    const realDelete = calls.deleteCredential.getMockImplementation()!
    calls.deleteCredential.mockImplementation(async ({ cid }) => {
      if (cid === 'c-stuck') {
        throw new Error('public copy could not be retracted')
      }
      await realDelete({ cid })
    })

    expect(await sweepStrandedAppKeys({ storage })).toBe(1)
    expect(calls.deleteCredential).toHaveBeenCalledTimes(2)
    expect(rows.map(({ cid }) => cid)).toEqual(['c-stuck'])
  })

  it('writes nothing on a clean store', async () => {
    const { storage, calls } = fakeStorage([
      { cid: 'c-diploma', vc: credential() }
    ])

    expect(await sweepStrandedAppKeys({ storage })).toBe(0)
    expect(calls.listCredentials).toHaveBeenCalledOnce()
    expect(calls.deleteCredential).not.toHaveBeenCalled()
  })

  it('is idempotent: a second run finds nothing left to delete', async () => {
    const { storage, calls } = fakeStorage([
      { cid: 'c-marked', vc: markedAppKey() }
    ])

    expect(await sweepStrandedAppKeys({ storage })).toBe(1)
    expect(await sweepStrandedAppKeys({ storage })).toBe(0)
    expect(calls.deleteCredential).toHaveBeenCalledOnce()
  })
})
