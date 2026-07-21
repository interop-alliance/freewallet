/**
 * Tests for the connected-applications model: `listConnectedApps` joins
 * self-issued app-key credentials with the latest matching App Connect Login
 * activity (name, grants, last-connected timestamp), skipping ordinary
 * credentials; `revokeAppAccess` deletes the app key and records the
 * revocation.
 */
import { describe, expect, it, vi } from 'vitest'
import type { StorageManager } from '@/stores/storageManager'
import type { StoredCredential } from '@/types/credential'
import type { User } from '@/types/auth'
import {
  listConnectedApps,
  revokeAppAccess,
  type ConnectedApp
} from '@/lib/connectedApps'

const APP_DID = 'did:key:zApp'

/**
 * A self-issued app-key StoredCredential bound to an origin.
 */
function appKeyCredential({
  cid,
  did = APP_DID,
  origin,
  name = 'Example app key',
  issuanceDate = '2026-07-01T00:00:00Z'
}: {
  cid: string
  did?: string
  origin: string
  name?: string
  issuanceDate?: string
}): StoredCredential {
  return {
    cid,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'ExampleAppKey'],
      name,
      issuer: did,
      issuanceDate,
      credentialSubject: { id: did, origin, seed: 'c2VlZA' }
    } as unknown as StoredCredential['vc']
  }
}

/**
 * A plain (non-self-issued) stored credential that must be ignored.
 */
function ordinaryCredential(cid: string): StoredCredential {
  return {
    cid,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: 'did:key:zIssuer',
      credentialSubject: { id: 'did:key:zSubject' }
    } as unknown as StoredCredential['vc']
  }
}

function loginActivity({
  origin,
  name,
  created,
  grants = []
}: {
  origin: string
  name: string
  created: string
  grants?: Array<{
    id: string
    target: string
    allowedActions: string[]
    expires: string
  }>
}) {
  return {
    id: `login-${created}`,
    doc: {
      type: ['Login'],
      summary: `Connected ${name} (${origin}) to wallet.`,
      object: { origin, zcaps: grants, appConnect: { name, firstRun: false } },
      created
    }
  }
}

function fakeStorage({
  credentials,
  history
}: {
  credentials: StoredCredential[]
  history: Array<{ id: string; doc: unknown }>
}) {
  return {
    listCredentials: vi.fn(async () => credentials),
    listHistoryItems: vi.fn(async () => history),
    deleteCredential: vi.fn(async () => {}),
    addHistoryAppRevoke: vi.fn(async () => {}),
    revokeAppGrants: vi.fn(async () => ({ revoked: 1, skipped: 0 }))
  } as unknown as StorageManager
}

describe('listConnectedApps', () => {
  it('joins an app-key credential with its latest Login activity', async () => {
    const origin = 'https://app.example'
    const storage = fakeStorage({
      credentials: [
        ordinaryCredential('c-plain'),
        appKeyCredential({ cid: 'c-app', origin })
      ],
      history: [
        loginActivity({
          origin,
          name: 'Old Name',
          created: '2026-07-01T00:00:00Z'
        }),
        loginActivity({
          origin,
          name: 'Example App',
          created: '2026-07-05T00:00:00Z',
          grants: [
            {
              id: 'urn:zcap:1',
              target: 'https://was.example/space/x/private-credentials',
              allowedActions: ['GET', 'PUT'],
              expires: '2026-08-01T00:00:00Z'
            }
          ]
        })
      ]
    })

    const apps = await listConnectedApps({ storage })

    expect(apps).toHaveLength(1)
    const [app] = apps
    expect(app.cid).toBe('c-app')
    expect(app.origin).toBe(origin)
    expect(app.subjectDid).toBe(APP_DID)
    // The latest Login supplies the display name and grants.
    expect(app.name).toBe('Example App')
    expect(app.lastConnectedAt).toBe('2026-07-05T00:00:00Z')
    expect(app.connectedAt).toBe('2026-07-01T00:00:00Z')
    expect(app.grants).toHaveLength(1)
    expect(app.grants[0].allowedActions).toEqual(['GET', 'PUT'])
  })

  it('falls back to the stripped credential name when no Login matches', async () => {
    const storage = fakeStorage({
      credentials: [
        appKeyCredential({
          cid: 'c-app',
          origin: 'https://app.example',
          name: 'Solo App app key'
        })
      ],
      history: []
    })

    const apps = await listConnectedApps({ storage })

    expect(apps).toHaveLength(1)
    expect(apps[0].name).toBe('Solo App')
    expect(apps[0].grants).toEqual([])
    expect(apps[0].lastConnectedAt).toBeUndefined()
  })

  it('ignores credentials that are not self-issued or lack an origin', async () => {
    const storage = fakeStorage({
      credentials: [ordinaryCredential('c-plain')],
      history: []
    })

    expect(await listConnectedApps({ storage })).toEqual([])
  })
})

describe('revokeAppAccess', () => {
  const user: User = { id: 'did:key:zUser', email: 'user@example.com' }
  const app: ConnectedApp = {
    cid: 'c-app',
    name: 'Example App',
    origin: 'https://app.example',
    subjectDid: APP_DID,
    grants: []
  }

  it('revokes grants, deletes the app key, and records the revocation', async () => {
    const storage = fakeStorage({ credentials: [], history: [] })

    const outcome = await revokeAppAccess({ storage, user, app })

    expect(outcome).toEqual({ revoked: 1, skipped: 0 })
    expect(storage.revokeAppGrants).toHaveBeenCalledWith({
      origin: 'https://app.example',
      subjectDid: APP_DID
    })
    expect(storage.deleteCredential).toHaveBeenCalledWith({ cid: 'c-app' })
    expect(storage.addHistoryAppRevoke).toHaveBeenCalledWith({
      user,
      origin: 'https://app.example',
      name: 'Example App',
      cid: 'c-app',
      revoked: 1,
      skipped: 0
    })
  })

  it('does not delete the credential when grant revocation fails', async () => {
    const storage = fakeStorage({ credentials: [], history: [] })
    ;(storage.revokeAppGrants as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('network down')
    )

    await expect(revokeAppAccess({ storage, user, app })).rejects.toThrow(
      'network down'
    )
    expect(storage.deleteCredential).not.toHaveBeenCalled()
    expect(storage.addHistoryAppRevoke).not.toHaveBeenCalled()
  })
})
