// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { CapabilityAgent } from '@interop/webkms-client'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { StoredCredential } from '@/types/credential'
import {
  APP_KEY_KEY_NAME,
  appKeyCredentialsIn,
  appKeySubjectDid,
  findAppKeyCredential,
  mintAppKeyCredential,
  type AppConnectApp
} from '@/lib/appKey'

const app: AppConnectApp = {
  name: 'Text Editor',
  credentialType: 'TextEditorAppKey',
  vocabBase: 'urn:text-editor:vocab#'
}
const origin = 'https://app.example'

/**
 * Wraps a raw VC as a StoredCredential fixture with an arbitrary cid.
 */
function stored(vc: IVerifiableCredential, cid = 'cid'): StoredCredential {
  return { cid, vc }
}

describe('mintAppKeyCredential', () => {
  it('self-issues: issuer === credentialSubject.id', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app,
      origin
    })
    const subject = credential.credentialSubject as { id: string }
    expect(credential.issuer).toBe(subject.id)
    expect(subjectDid).toBe(subject.id)
    expect(appKeySubjectDid(credential)).toBe(subject.id)
  })

  it('encodes the seed as base64url-no-pad 32 bytes', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    const subject = credential.credentialSubject as { seed: string }
    const decoded = base64urlnopad.decode(subject.seed)
    expect(decoded).toHaveLength(32)
  })

  it('re-derives the subject DID from the seed via fromSeed', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app,
      origin
    })
    const subject = credential.credentialSubject as { seed: string }
    const seed = base64urlnopad.decode(subject.seed)
    const agent = await CapabilityAgent.fromSeed({
      seed,
      handle: 'any-handle',
      keyName: APP_KEY_KEY_NAME
    })
    expect(agent.id).toBe(subjectDid)
  })

  it('opens with the VC 1.0 context then the interpolated inline context', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    const context = credential['@context'] as unknown[]
    // The two-element pre-signing shape; the Ed25519Signature2020 suite
    // appends its own context URL as a third element at issue time.
    expect(context.slice(0, 2)).toEqual([
      'https://www.w3.org/2018/credentials/v1',
      {
        '@protected': true,
        TextEditorAppKey: 'urn:text-editor:vocab#TextEditorAppKey',
        seed: 'urn:text-editor:vocab#seed',
        origin: 'urn:text-editor:vocab#origin',
        name: 'https://schema.org/name',
        description: 'https://schema.org/description'
      }
    ])
    expect(context[2]).toBe('https://w3id.org/security/suites/ed25519-2020/v1')
  })

  it('carries the exact name and description strings', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    expect((credential as { name: string }).name).toBe('Text Editor app key')
    expect((credential as { description: string }).description).toBe(
      'The Text Editor app keeps this key in your wallet so it can open ' +
        'your encrypted data on this and other devices.'
    )
  })

  it('binds the origin and the credential type', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    const subject = credential.credentialSubject as { origin: string }
    expect(subject.origin).toBe(origin)
    expect(credential.type).toEqual([
      'VerifiableCredential',
      'TextEditorAppKey'
    ])
  })

  it('carries an Ed25519Signature2020 proof', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    const proof = (credential as { proof: { type: string } }).proof
    expect(proof.type).toBe('Ed25519Signature2020')
  })
})

describe('appKeyCredentialsIn / findAppKeyCredential', () => {
  it('matches by type + origin + self-issue, latest-first', async () => {
    const older = await mintAppKeyCredential({ app, origin })
    const newer = await mintAppKeyCredential({ app, origin })
    // Force distinct, ordered issuance dates.
    ;(older.credential as { issuanceDate: string }).issuanceDate =
      '2024-01-01T00:00:00Z'
    ;(newer.credential as { issuanceDate: string }).issuanceDate =
      '2024-06-01T00:00:00Z'

    const credentials = [
      stored(older.credential, 'older'),
      stored(newer.credential, 'newer')
    ]
    const matched = appKeyCredentialsIn({
      credentials,
      credentialType: app.credentialType,
      origin
    })
    expect(matched.map(({ cid }) => cid)).toEqual(['newer', 'older'])
    expect(
      findAppKeyCredential({
        credentials,
        credentialType: app.credentialType,
        origin
      })?.cid
    ).toBe('newer')
  })

  it('returns undefined for a wrong origin', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    expect(
      findAppKeyCredential({
        credentials: [stored(credential)],
        credentialType: app.credentialType,
        origin: 'https://evil.example'
      })
    ).toBeUndefined()
  })

  it('returns undefined for a wrong credential type', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    expect(
      findAppKeyCredential({
        credentials: [stored(credential)],
        credentialType: 'OtherAppKey',
        origin
      })
    ).toBeUndefined()
  })

  it('excludes a credential that is not self-issued', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    ;(credential as { issuer: string }).issuer = 'did:key:zSomeoneElse'
    expect(
      findAppKeyCredential({
        credentials: [stored(credential)],
        credentialType: app.credentialType,
        origin
      })
    ).toBeUndefined()
  })
})
