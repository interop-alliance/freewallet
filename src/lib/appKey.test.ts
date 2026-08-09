// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { CapabilityAgent } from '@interop/webkms-client'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { StoredCredential } from '@/types/credential'
import { typeArray } from '@/lib/vcShape'
import {
  APP_KEY_CREDENTIAL_TYPE,
  APP_KEY_KEY_NAME,
  AppKeyRefusedError,
  appKeyCredentialsIn,
  assertStorableAppKey,
  presentsAsAppKey,
  appKeySeedBindsSubject,
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

/**
 * A credential whose subject/issuer DID is an attacker's rather than the one
 * its own seed derives -- otherwise a perfect match (right marker + app type,
 * self-issued, right origin, newest issuance date).
 */
async function plantedCredential(): Promise<IVerifiableCredential> {
  const attacker = await CapabilityAgent.fromSecret({
    secret: 'attacker-secret',
    handle: 'attacker'
  })
  const { credential } = await mintAppKeyCredential({ app, origin })
  ;(credential as { issuer: string }).issuer = attacker.id
  ;(credential.credentialSubject as { id: string }).id = attacker.id
  ;(credential as { issuanceDate: string }).issuanceDate =
    '2099-01-01T00:00:00Z'
  return credential
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
        AppKeyCredential: 'https://w3id.org/byoe#AppKeyCredential',
        TextEditorAppKey: 'urn:text-editor:vocab#TextEditorAppKey',
        seed: 'https://w3id.org/byoe#seed',
        origin: 'https://w3id.org/byoe#origin',
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
      'AppKeyCredential',
      'TextEditorAppKey'
    ])
  })

  it('carries the shared marker type for every app', async () => {
    const other = await mintAppKeyCredential({
      app: {
        name: 'Notes',
        credentialType: 'NotesAppKey',
        vocabBase: 'urn:notes:vocab#'
      },
      origin: 'https://notes.example'
    })
    expect(typeArray(other.credential.type)).toContain(APP_KEY_CREDENTIAL_TYPE)
    expect(presentsAsAppKey(other.credential)).toBe(true)
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
    const matched = await appKeyCredentialsIn({
      credentials,
      credentialType: app.credentialType,
      origin
    })
    expect(matched.map(({ cid }) => cid)).toEqual(['newer', 'older'])
    expect(
      (
        await findAppKeyCredential({
          credentials,
          credentialType: app.credentialType,
          origin
        })
      )?.cid
    ).toBe('newer')
  })

  it('returns undefined for a wrong origin', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    expect(
      await findAppKeyCredential({
        credentials: [stored(credential)],
        credentialType: app.credentialType,
        origin: 'https://evil.example'
      })
    ).toBeUndefined()
  })

  it('returns undefined for a wrong credential type', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    expect(
      await findAppKeyCredential({
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
      await findAppKeyCredential({
        credentials: [stored(credential)],
        credentialType: app.credentialType,
        origin
      })
    ).toBeUndefined()
  })
})

describe('app-key seed binding', () => {
  it('accepts a wallet-minted credential', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    expect(await appKeySeedBindsSubject(credential)).toBe(true)
  })

  it('rejects a subject DID that does not derive from the seed', async () => {
    expect(await appKeySeedBindsSubject(await plantedCredential())).toBe(false)
  })

  it('does not match a planted credential, even as the newest candidate', async () => {
    const mine = await mintAppKeyCredential({ app, origin })
    ;(mine.credential as { issuanceDate: string }).issuanceDate =
      '2024-01-01T00:00:00Z'
    const credentials = [
      stored(await plantedCredential(), 'planted'),
      stored(mine.credential, 'mine')
    ]
    const matched = await appKeyCredentialsIn({
      credentials,
      credentialType: app.credentialType,
      origin
    })
    expect(matched.map(({ cid }) => cid)).toEqual(['mine'])
    expect(
      (
        await findAppKeyCredential({
          credentials,
          credentialType: app.credentialType,
          origin
        })
      )?.cid
    ).toBe('mine')
  })

  it('fails closed on an absent, malformed, or wrong-length seed', async () => {
    for (const seed of [
      undefined,
      42,
      'not base64url!!',
      base64urlnopad.encode(new Uint8Array(16))
    ]) {
      const { credential } = await mintAppKeyCredential({ app, origin })
      const subject = credential.credentialSubject as { seed?: unknown }
      if (seed === undefined) {
        delete subject.seed
      } else {
        subject.seed = seed
      }
      await expect(appKeySeedBindsSubject(credential)).resolves.toBe(false)
      expect(
        await findAppKeyCredential({
          credentials: [stored(credential)],
          credentialType: app.credentialType,
          origin
        })
      ).toBeUndefined()
    }
  })
})

describe('the AppKeyCredential marker', () => {
  it('is required at match time', async () => {
    const { credential } = await mintAppKeyCredential({ app, origin })
    // Otherwise a perfect match: strip only the marker.
    ;(credential as { type: string[] }).type = (
      credential.type as string[]
    ).filter(term => term !== APP_KEY_CREDENTIAL_TYPE)
    expect(
      await findAppKeyCredential({
        credentials: [stored(credential)],
        credentialType: app.credentialType,
        origin
      })
    ).toBeUndefined()
  })

  it('is not claimed by an ordinary credential', () => {
    const ordinary = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'SomeOtherCredential'],
      issuer: 'did:key:zIssuer',
      credentialSubject: { id: 'did:key:zSubject', seed: 'abc', origin }
    } as unknown as IVerifiableCredential
    expect(presentsAsAppKey(ordinary)).toBe(false)
    expect(() => assertStorableAppKey(ordinary)).not.toThrow()
  })
})

describe('assertStorableAppKey', () => {
  it('refuses every marker credential, even one that binds perfectly', async () => {
    // A fully attacker-generated credential binds (its subject DID derives
    // from its own fresh seed), so binding proves nothing about provenance:
    // external ingest refuses on the marker alone.
    const { credential } = await mintAppKeyCredential({ app, origin })
    expect(() => assertStorableAppKey(credential)).toThrow(AppKeyRefusedError)
  })

  it('refuses a planted app key', async () => {
    const planted = await plantedCredential()
    expect(() => assertStorableAppKey(planted)).toThrow(AppKeyRefusedError)
  })

  it('refuses one with an absent, malformed, or wrong-length seed', async () => {
    for (const seed of [
      undefined,
      42,
      'not base64url!!',
      base64urlnopad.encode(new Uint8Array(16))
    ]) {
      const { credential } = await mintAppKeyCredential({ app, origin })
      const subject = credential.credentialSubject as { seed?: unknown }
      if (seed === undefined) {
        delete subject.seed
      } else {
        subject.seed = seed
      }
      expect(() => assertStorableAppKey(credential)).toThrow(AppKeyRefusedError)
    }
  })
})

describe('the far-future issuanceDate cutoff', () => {
  /**
   * The fully attacker-generated planted credential: the attacker's OWN
   * fresh seed (so it binds perfectly), the victim app's origin and
   * credentialType, self-issued, and a far-future `issuanceDate` picked to
   * win the latest-first ranking durably.
   */
  async function boundPlantedCredential(): Promise<IVerifiableCredential> {
    const { credential } = await mintAppKeyCredential({ app, origin })
    ;(credential as { issuanceDate: string }).issuanceDate =
      '2099-01-01T00:00:00Z'
    return credential
  }

  it('a far-future planted credential never outranks a wallet-minted key', async () => {
    const mine = await mintAppKeyCredential({ app, origin })
    ;(mine.credential as { issuanceDate: string }).issuanceDate =
      '2024-01-01T00:00:00Z'
    const credentials = [
      stored(await boundPlantedCredential(), 'planted'),
      stored(mine.credential, 'mine')
    ]
    expect(
      (
        await findAppKeyCredential({
          credentials,
          credentialType: app.credentialType,
          origin
        })
      )?.cid
    ).toBe('mine')
    const matched = await appKeyCredentialsIn({
      credentials,
      credentialType: app.credentialType,
      origin
    })
    expect(matched.map(({ cid }) => cid)).toEqual(['mine'])
  })

  it('a far-future planted credential alone matches nothing', async () => {
    expect(
      await findAppKeyCredential({
        credentials: [stored(await boundPlantedCredential(), 'planted')],
        credentialType: app.credentialType,
        origin
      })
    ).toBeUndefined()
  })

  it('drops a candidate whose issuanceDate does not parse', async () => {
    // `Date.parse` fails on these, but the ranking compares raw strings,
    // where '9999-99-99...' and 'z2099' sort ahead of every real ISO date --
    // so the cutoff must fail closed, not keep what it cannot parse.
    for (const issuanceDate of ['9999-99-99T00:00:00Z', 'z2099']) {
      const mine = await mintAppKeyCredential({ app, origin })
      ;(mine.credential as { issuanceDate: string }).issuanceDate =
        '2024-01-01T00:00:00Z'
      const planted = await mintAppKeyCredential({ app, origin })
      ;(planted.credential as { issuanceDate: string }).issuanceDate =
        issuanceDate
      const credentials = [
        stored(planted.credential, 'planted'),
        stored(mine.credential, 'mine')
      ]
      expect(
        (
          await findAppKeyCredential({
            credentials,
            credentialType: app.credentialType,
            origin
          })
        )?.cid
      ).toBe('mine')
      expect(
        await findAppKeyCredential({
          credentials: [stored(planted.credential, 'planted')],
          credentialType: app.credentialType,
          origin
        })
      ).toBeUndefined()
    }
  })

  it('drops a non-string issuanceDate without breaking the match', async () => {
    // A number or an array would throw inside the raw-string sort
    // (`localeCompare` on a non-string); the cutoff drops the candidate
    // instead, so the genuine key still matches.
    for (const issuanceDate of [1893456000, ['2024-01-01T00:00:00Z'], null]) {
      const mine = await mintAppKeyCredential({ app, origin })
      const planted = await mintAppKeyCredential({ app, origin })
      ;(planted.credential as { issuanceDate?: unknown }).issuanceDate =
        issuanceDate
      const credentials = [
        stored(planted.credential, 'planted'),
        stored(mine.credential, 'mine')
      ]
      expect(
        (
          await findAppKeyCredential({
            credentials,
            credentialType: app.credentialType,
            origin
          })
        )?.cid
      ).toBe('mine')
    }
  })

  it("tolerates ordinary clock skew between the account's own clients", async () => {
    // A key minted on a client whose clock runs a few minutes ahead must not
    // be dropped -- excluding it would mint a duplicate key whose seed cannot
    // open the app's existing data.
    const { credential } = await mintAppKeyCredential({ app, origin })
    ;(credential as { issuanceDate: string }).issuanceDate = new Date(
      Date.now() + 5 * 60 * 1000
    ).toISOString()
    expect(
      (
        await findAppKeyCredential({
          credentials: [stored(credential, 'skewed')],
          credentialType: app.credentialType,
          origin
        })
      )?.cid
    ).toBe('skewed')
  })
})
