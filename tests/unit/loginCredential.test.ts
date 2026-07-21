// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import * as vc from '@interop/vc'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { securityLoader } from '@interop/security-document-loader'
import type { Session } from '@/types/auth'
import type { StoredCredential } from '@/types/credential'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  issueLoginCredential,
  findLoginCredential,
  loginHandleOf,
  setLoginHandle,
  LOGIN_CREDENTIAL_TYPE
} from '@/lib/loginCredential'

const documentLoader = securityLoader({ fetchRemoteContexts: true }).build()

/**
 * An in-memory stand-in for `session.storage`: only the three methods
 * `setLoginHandle` touches (`listCredentials`, `addCredential`,
 * `deleteCredential`), keyed by a monotonically increasing pseudo-cid.
 */
class FakeStorage {
  private _items: StoredCredential[] = []
  private _next = 0

  async listCredentials(): Promise<StoredCredential[]> {
    return [...this._items]
  }

  async addCredential({ credential }: { credential: IVerifiableCredential }) {
    this._items.push({ cid: `cid-${this._next++}`, vc: credential })
  }

  async deleteCredential({ cid }: { cid: string }) {
    this._items = this._items.filter(item => item.cid !== cid)
  }
}

let session: Session
let storage: FakeStorage

beforeAll(async () => {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: 'correct horse battery staple',
    handle: 'test',
    keyName: 'test-key'
  })
  storage = new FakeStorage()
  session = {
    user: { id: keyAgent.id },
    profile: { keyAgent },
    storage
  } as unknown as Session
})

describe('issueLoginCredential', () => {
  it('produces a self-issued LoginCredential with the expected shape', async () => {
    const credential = await issueLoginCredential({
      session,
      username: 'alice'
    })

    // The VC 1.0 context first, then the inline Login Credential context
    // object. (vc.issue also appends the signing suite's context.)
    const context = credential['@context'] as Array<string | object>
    expect(context[0]).toBe('https://www.w3.org/2018/credentials/v1')
    expect(context[1]).toEqual(
      expect.objectContaining({
        LoginCredential: 'urn:freewallet:vocab#LoginCredential',
        preferredUsername:
          'https://www.w3.org/ns/activitystreams#preferredUsername'
      })
    )
    expect(credential.type).toEqual([
      'VerifiableCredential',
      LOGIN_CREDENTIAL_TYPE
    ])
    expect(credential.issuer).toBe(session.user.id)
    const subject = credential.credentialSubject as {
      id: string
      preferredUsername: string
    }
    expect(subject.id).toBe(session.user.id)
    expect(subject.preferredUsername).toBe('alice')
    // vc.issue auto-fills issuanceDate.
    expect(typeof credential.issuanceDate).toBe('string')
    const proof = credential.proof as Record<string, unknown>
    expect(proof.proofPurpose).toBe('assertionMethod')
  })

  it('signs a credential that verifies', async () => {
    const credential = await issueLoginCredential({
      session,
      username: 'alice'
    })
    const result = await vc.verifyCredential({
      credential: credential as never,
      suite: new Ed25519Signature2020(),
      documentLoader
    })
    expect(result.verified).toBe(true)
  })

  it('throws without a passphrase (root key) session', async () => {
    const noKeyAgent = {
      user: { id: session.user.id },
      profile: {}
    } as unknown as Session
    await expect(
      issueLoginCredential({ session: noKeyAgent, username: 'alice' })
    ).rejects.toThrow(/full \(passphrase\) session/)
  })
})

describe('findLoginCredential / setLoginHandle', () => {
  it('sets, reads, and re-issues (replacing rather than accumulating)', async () => {
    await setLoginHandle({ session, username: 'alice' })
    let stored = await storage.listCredentials()
    let found = findLoginCredential({ credentials: stored })
    expect(found).toBeDefined()
    expect(loginHandleOf(found!.vc)).toBe('alice')

    // Re-issue with a new handle: still exactly one LoginCredential.
    await setLoginHandle({ session, username: 'bob' })
    stored = await storage.listCredentials()
    const logins = stored.filter(({ vc: credential }) =>
      (credential.type as string[]).includes(LOGIN_CREDENTIAL_TYPE)
    )
    expect(logins).toHaveLength(1)
    found = findLoginCredential({ credentials: stored })
    expect(loginHandleOf(found!.vc)).toBe('bob')
  })

  it('an empty username clears the handle (delete only)', async () => {
    await setLoginHandle({ session, username: 'carol' })
    await setLoginHandle({ session, username: '' })
    const stored = await storage.listCredentials()
    expect(findLoginCredential({ credentials: stored })).toBeUndefined()
  })

  it('ignores VCs of the right type that are not self-issued', () => {
    const foreign: StoredCredential = {
      cid: 'foreign',
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', LOGIN_CREDENTIAL_TYPE],
        issuer: 'did:key:someoneElse',
        credentialSubject: { id: 'did:key:me', preferredUsername: 'x' }
      } as unknown as IVerifiableCredential
    }
    expect(findLoginCredential({ credentials: [foreign] })).toBeUndefined()
  })
})
