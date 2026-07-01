/**
 * Unit tests for the local EDV document cipher seam: real X25519 keys drive
 * the was-client EDV codec end to end (encrypt to a content-derived-id
 * envelope, decrypt back), plus the envelope structural guard.
 *
 * @vitest-environment node
 */
import { describe, expect, it } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  createEdvDocCipher,
  isEncryptedEnvelope,
  type DocCipher
} from './edvDocCipher'

/**
 * Builds a cipher over a freshly generated X25519 key pair, mirroring how the
 * session profile supplies keys (a key agreement key plus a resolver that
 * returns its public form).
 */
async function makeCipher(): Promise<DocCipher> {
  const keyAgreementKey = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkTestController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: keyAgreementKey.id!,
    type: keyAgreementKey.type,
    publicKeyMultibase: keyAgreementKey.publicKeyMultibase
  })
  return await createEdvDocCipher({
    keyAgreementKey: keyAgreementKey as IKeyAgreementKey,
    keyResolver,
    collectionId: 'private-credentials'
  })
}

describe('createEdvDocCipher', () => {
  it('round-trips a JSON document through an EDV envelope', async () => {
    const cipher = await makeCipher()
    const data = { hello: 'world', nested: { count: 3 } }

    const { id, envelope } = await cipher.encrypt({ data })

    // The stored body is an opaque envelope: EDV id + JWE, no plaintext.
    expect(isEncryptedEnvelope(envelope)).toBe(true)
    expect((envelope as { id?: string }).id).toBe(id)
    expect(id).toMatch(/^z[1-9A-HJ-NP-Za-km-z]{21,}$/)
    expect(JSON.stringify(envelope)).not.toContain('world')

    await expect(cipher.decrypt({ envelope })).resolves.toEqual(data)
  })

  it('mints a fresh id per encryption (nondeterministic JWE)', async () => {
    const cipher = await makeCipher()
    const data = { same: 'content' }

    const first = await cipher.encrypt({ data })
    const second = await cipher.encrypt({ data })

    expect(first.id).not.toBe(second.id)
  })
})

describe('isEncryptedEnvelope', () => {
  it('accepts only an object carrying an object jwe', () => {
    expect(isEncryptedEnvelope({ id: 'z123', jwe: { ciphertext: 'x' } })).toBe(
      true
    )
    expect(isEncryptedEnvelope({ jwe: 'not-an-object' })).toBe(false)
    expect(isEncryptedEnvelope({ name: 'plaintext doc' })).toBe(false)
    expect(isEncryptedEnvelope(undefined)).toBe(false)
    expect(isEncryptedEnvelope(null)).toBe(false)
    expect(isEncryptedEnvelope('jwe')).toBe(false)
  })
})
