/**
 * Tests for the connected-applications model: `listConnectedApps` joins the
 * app-key credentials of the dedicated `app-connections` collection with the
 * latest matching App Connect Login activity (name, grants, last-connected
 * timestamp), skipping rows that do not carry the `AppKeyCredential` marker;
 * `deriveGrantsState` reads the recorded delegation signers against the
 * account's current key set (the current-key-set rule), deriving a
 * client-annex signer as unknown rather than orphaned; `revokeAppAccess`
 * deletes the app key from that collection and records the revocation,
 * POSTing every recorded grant's revocation whatever the row derived as.
 */
import { describe, expect, it, vi } from 'vitest'
import type { StorageManager } from '@/stores/storageManager'
import type { StoredCredential } from '@/types/credential'
import type { User } from '@/types/auth'
import {
  deriveGrantsState,
  listConnectedApps,
  revokeAppAccess,
  type AppGrant,
  type ConnectedApp
} from '@/lib/connectedApps'

const APP_DID = 'did:key:zApp'
const APP_URL = 'https://app.example/editor'

/**
 * A self-issued app-key StoredCredential carrying the `AppKeyCredential`
 * marker type, bound to an origin and to an `appUrl` within it. Omitting the
 * `appUrl` produces a row the listing cannot attribute to an app.
 */
function appKeyCredential({
  cid,
  did = APP_DID,
  origin,
  appUrl,
  name = 'Example app key',
  issuanceDate = '2026-07-01T00:00:00Z'
}: {
  cid: string
  did?: string
  origin: string
  appUrl?: string
  name?: string
  issuanceDate?: string
}): StoredCredential {
  return {
    cid,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'AppKeyCredential'],
      name,
      issuer: did,
      issuanceDate,
      credentialSubject: {
        id: did,
        origin,
        ...(appUrl !== undefined && { appUrl }),
        seed: 'c2VlZA'
      }
    } as unknown as StoredCredential['vc']
  }
}

/**
 * A row in the collection that carries no `AppKeyCredential` marker -- what an
 * opaque resource planted server-side (through a space import, say) looks like
 * to the listing. It must be ignored: the page can neither render nor revoke
 * it.
 */
function unmarkedRow(cid: string): StoredCredential {
  return {
    cid,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: 'did:key:zIssuer',
      credentialSubject: {
        id: 'did:key:zSubject',
        origin: 'https://app.example'
      }
    } as unknown as StoredCredential['vc']
  }
}

/**
 * An App Connect Login activity row. Omitting `appUrl` produces a row the
 * listing cannot join to any app key.
 */
function loginActivity({
  origin,
  appUrl,
  name,
  created,
  grants = []
}: {
  origin: string
  appUrl?: string
  name: string
  created: string
  grants?: Array<{
    id: string
    target: string
    allowedActions: string[]
    expires: string
    zcap?: unknown
  }>
}) {
  return {
    id: `login-${created}-${name}`,
    doc: {
      type: ['Login'],
      summary: `Connected ${name} (${origin}) to wallet.`,
      object: {
        origin,
        zcaps: grants,
        appConnect: {
          name,
          firstRun: false,
          ...(appUrl !== undefined && { appUrl })
        }
      },
      created
    }
  }
}

/**
 * A storage stub over the two collections the listing joins: the app keys of
 * `app-connections` and the wallet activity log. `listCredentials` is
 * deliberately absent -- the connected-apps surface must never reach for the
 * user's own credentials.
 */
function fakeStorage({
  appKeys,
  history
}: {
  appKeys: StoredCredential[]
  history: Array<{ id: string; doc: unknown }>
}) {
  return {
    listAppKeys: vi.fn(async () => ({
      appKeys,
      skipped: { unknownEpoch: 0, noEpochKey: 0, undecryptable: 0 }
    })),
    listHistoryItems: vi.fn(async () => history),
    deleteAppKey: vi.fn(async () => {}),
    addHistoryAppRevoke: vi.fn(async () => {}),
    revokeAppCollectionRecipients: vi.fn(async () => ({
      collections: 0,
      rotated: 0,
      failed: 0
    })),
    revokeAppGrants: vi.fn(async () => ({ revoked: 1, skipped: 0 }))
  } as unknown as StorageManager
}

describe('listConnectedApps', () => {
  it('joins an app-key credential with its latest Login activity', async () => {
    const origin = 'https://app.example'
    const storage = fakeStorage({
      appKeys: [
        unmarkedRow('c-plain'),
        appKeyCredential({ cid: 'c-app', origin, appUrl: APP_URL })
      ],
      history: [
        loginActivity({
          origin,
          appUrl: APP_URL,
          name: 'Old Name',
          created: '2026-07-01T00:00:00Z'
        }),
        loginActivity({
          origin,
          appUrl: APP_URL,
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

  it('tells two apps sharing an origin apart by their appUrl', async () => {
    const origin = 'https://app.example'
    const editorUrl = 'https://app.example/editor'
    const readerUrl = 'https://app.example/reader'
    const storage = fakeStorage({
      appKeys: [
        appKeyCredential({ cid: 'c-editor', origin, appUrl: editorUrl }),
        appKeyCredential({
          cid: 'c-reader',
          did: 'did:key:zReader',
          origin,
          appUrl: readerUrl
        })
      ],
      history: [
        loginActivity({
          origin,
          appUrl: editorUrl,
          name: 'Editor',
          created: '2026-07-05T00:00:00Z',
          grants: [
            {
              id: 'urn:zcap:editor',
              target: 'https://was.example/space/x/editor-data',
              allowedActions: ['GET'],
              expires: '2027-08-01T00:00:00Z'
            }
          ]
        }),
        loginActivity({
          origin,
          appUrl: readerUrl,
          name: 'Reader',
          created: '2026-07-09T00:00:00Z',
          grants: [
            {
              id: 'urn:zcap:reader',
              target: 'https://was.example/space/x/reader-data',
              allowedActions: ['GET'],
              expires: '2027-08-01T00:00:00Z'
            }
          ]
        })
      ]
    })

    const apps = await listConnectedApps({ storage })

    const editor = apps.find(app => app.cid === 'c-editor')
    const reader = apps.find(app => app.cid === 'c-reader')
    expect(editor).toMatchObject({
      name: 'Editor',
      appUrl: editorUrl,
      lastConnectedAt: '2026-07-05T00:00:00Z'
    })
    expect(editor?.grants.map(grant => grant.id)).toEqual(['urn:zcap:editor'])
    expect(reader).toMatchObject({
      name: 'Reader',
      appUrl: readerUrl,
      lastConnectedAt: '2026-07-09T00:00:00Z'
    })
    expect(reader?.grants.map(grant => grant.id)).toEqual(['urn:zcap:reader'])
  })

  it('never joins a Login activity that recorded no appUrl', async () => {
    // The `appUrl` is the whole join. A Login row carrying none names no
    // application, so it cannot lend its grants to a key that shares only the
    // origin.
    const origin = 'https://app.example'
    const storage = fakeStorage({
      appKeys: [
        appKeyCredential({
          cid: 'c-app',
          origin,
          appUrl: APP_URL,
          name: 'Example App app key'
        })
      ],
      history: [
        loginActivity({
          origin,
          name: 'Example App',
          created: '2026-07-05T00:00:00Z',
          grants: [
            {
              id: 'urn:zcap:unscoped',
              target: 'https://was.example/space/x/private-credentials',
              allowedActions: ['GET'],
              expires: '2027-08-01T00:00:00Z'
            }
          ]
        })
      ]
    })

    const [app] = await listConnectedApps({ storage })

    expect(app.name).toBe('Example App')
    expect(app.grants).toEqual([])
    expect(app.lastConnectedAt).toBeUndefined()
  })

  it("never lends another app's appUrl-scoped row to a sibling app", async () => {
    const origin = 'https://app.example'
    const storage = fakeStorage({
      appKeys: [
        appKeyCredential({
          cid: 'c-editor',
          origin,
          appUrl: 'https://app.example/editor',
          name: 'Editor app key'
        })
      ],
      history: [
        loginActivity({
          origin,
          appUrl: 'https://app.example/reader',
          name: 'Reader',
          created: '2026-07-09T00:00:00Z',
          grants: [
            {
              id: 'urn:zcap:reader',
              target: 'https://was.example/space/x/reader-data',
              allowedActions: ['GET'],
              expires: '2027-08-01T00:00:00Z'
            }
          ]
        })
      ]
    })

    const [app] = await listConnectedApps({ storage })

    expect(app.name).toBe('Editor')
    expect(app.grants).toEqual([])
    expect(app.lastConnectedAt).toBeUndefined()
  })

  it('falls back to the stripped credential name when no Login matches', async () => {
    const storage = fakeStorage({
      appKeys: [
        appKeyCredential({
          cid: 'c-app',
          origin: 'https://app.example',
          appUrl: APP_URL,
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

  it('ignores rows without the marker, an origin, or an appUrl', async () => {
    // The collection holds app keys only, so the row check is the marker type
    // plus the three members the listing reads (subject DID, origin, appUrl).
    const originless = appKeyCredential({
      cid: 'c-originless',
      origin: 'https://app.example',
      appUrl: APP_URL
    })
    delete (originless.vc.credentialSubject as { origin?: unknown }).origin
    const urlless = appKeyCredential({
      cid: 'c-urlless',
      origin: 'https://app.example'
    })
    const storage = fakeStorage({
      appKeys: [unmarkedRow('c-plain'), originless, urlless],
      history: []
    })

    expect(await listConnectedApps({ storage })).toEqual([])
  })

  it('extracts the delegation signer from a recorded full zcap', async () => {
    const origin = 'https://app.example'
    const storage = fakeStorage({
      appKeys: [appKeyCredential({ cid: 'c-app', origin, appUrl: APP_URL })],
      history: [
        loginActivity({
          origin,
          appUrl: APP_URL,
          name: 'Example App',
          created: '2026-07-05T00:00:00Z',
          grants: [
            {
              id: 'urn:zcap:1',
              target: 'https://was.example/space/x/app-data',
              allowedActions: ['GET'],
              expires: '2027-08-01T00:00:00Z',
              zcap: {
                id: 'urn:zcap:1',
                parentCapability: 'urn:zcap:root:x',
                proof: {
                  proofPurpose: 'capabilityDelegation',
                  verificationMethod: 'did:webvh:s:h:x#zClientKey'
                }
              }
            },
            {
              id: 'urn:zcap:legacy',
              target: 'https://was.example/space/x/other',
              allowedActions: ['GET'],
              expires: '2027-08-01T00:00:00Z'
            }
          ]
        })
      ]
    })

    const [app] = await listConnectedApps({ storage })

    expect(app.grants[0].signerKeyId).toBe('did:webvh:s:h:x#zClientKey')
    expect(app.grants[1].signerKeyId).toBeUndefined()
  })
})

describe('deriveGrantsState', () => {
  function grantsSignedBy(signers: Array<string | undefined>): AppGrant[] {
    return signers.map((signerKeyId, index) => ({
      id: `urn:zcap:${index}`,
      target: 'https://was.example/space/x/app-data',
      allowedActions: ['GET'],
      expires: '2027-08-01T00:00:00Z',
      signerKeyId
    }))
  }

  const ACCOUNT_DID = 'did:webvh:s:h:x'
  const ANNEX_DID = 'did:webvh:a:h:gen-1'
  const check = {
    accountDid: ACCOUNT_DID,
    currentSigningKeys: new Set(['zKey'])
  }

  it('is unknown without a verified key set to check against', () => {
    expect(
      deriveGrantsState({ grants: grantsSignedBy([`${ACCOUNT_DID}#zKey`]) })
    ).toBe('unknown')
  })

  it('is unknown when no grant recorded a signer (legacy records)', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([undefined]),
        signerCheck: check
      })
    ).toBe('unknown')
  })

  it('is active when a signer is in the current key set', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([`${ACCOUNT_DID}#zGone`, `${ACCOUNT_DID}#zKey`]),
        signerCheck: check
      })
    ).toBe('active')
  })

  it('matches the did:key form of a still-enrolled key', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy(['did:key:zKey#zKey']),
        signerCheck: check
      })
    ).toBe('active')
  })

  it('is orphaned when no recorded signer is in the current key set', () => {
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([`${ACCOUNT_DID}#zGone`]),
        signerCheck: check
      })
    ).toBe('orphaned')
  })

  it('is unknown for a grant a transient session minted (annex signer)', () => {
    // The annex VM is never in the account document, so its absence is not
    // evidence of a disconnect; only the revocation can say whether the
    // chain under the generation delegation is still alive.
    expect(
      deriveGrantsState({
        grants: grantsSignedBy([`${ANNEX_DID}#zVisit`]),
        signerCheck: check
      })
    ).toBe('unknown')
  })
})

describe('revokeAppAccess', () => {
  const user: User = { id: 'did:key:zUser', email: 'user@example.com' }
  const app: ConnectedApp = {
    cid: 'c-app',
    name: 'Example App',
    origin: 'https://app.example',
    appUrl: 'https://app.example/editor',
    subjectDid: APP_DID,
    grants: []
  }

  it('revokes grants, deletes the app key, and records the revocation', async () => {
    const storage = fakeStorage({ appKeys: [], history: [] })

    const outcome = await revokeAppAccess({ storage, user, app })

    expect(outcome).toEqual({ revoked: 1, skipped: 0, rotated: 0 })
    // The epoch rotation runs first, so a revoked app cannot decrypt future
    // writes before its grants are even withdrawn.
    expect(storage.revokeAppCollectionRecipients).toHaveBeenCalledWith({
      origin: 'https://app.example',
      subjectDid: APP_DID,
      items: []
    })
    expect(storage.revokeAppGrants).toHaveBeenCalledWith({
      origin: 'https://app.example',
      subjectDid: APP_DID,
      items: []
    })
    expect(storage.deleteAppKey).toHaveBeenCalledWith({ cid: 'c-app' })
    expect(storage.addHistoryAppRevoke).toHaveBeenCalledWith({
      user,
      origin: 'https://app.example',
      name: 'Example App',
      cid: 'c-app',
      revoked: 1,
      skipped: 0
    })
  })

  it('posts the grant revocations whatever the row derived as', async () => {
    const storage = fakeStorage({ appKeys: [], history: [] })

    const outcome = await revokeAppAccess({ storage, user, app })

    // A grant minted in a transient session is signed by an annex key the
    // account document never lists, so its row derives as unknown while its
    // chain may still be alive under the generation delegation. The
    // revocations are POSTed whatever the marker says.
    expect(outcome).toEqual({ revoked: 1, skipped: 0, rotated: 0 })
    expect(storage.revokeAppGrants).toHaveBeenCalledWith({
      origin: 'https://app.example',
      subjectDid: APP_DID,
      items: []
    })
    expect(storage.deleteAppKey).toHaveBeenCalledWith({ cid: 'c-app' })
  })

  it('does not delete the credential when grant revocation fails', async () => {
    const storage = fakeStorage({ appKeys: [], history: [] })
    ;(storage.revokeAppGrants as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('network down')
    )

    await expect(revokeAppAccess({ storage, user, app })).rejects.toThrow(
      'network down'
    )
    expect(storage.deleteAppKey).not.toHaveBeenCalled()
    expect(storage.addHistoryAppRevoke).not.toHaveBeenCalled()
  })
})
