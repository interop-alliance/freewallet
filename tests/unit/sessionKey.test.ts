// @vitest-environment node
/**
 * Unit tests for the browser session key module (`src/lib/sessionKey.ts`):
 * did:key derivation from a
 * WebCrypto Ed25519 public key and the pluggable signer wrapper. The
 * IndexedDB persistence paths are exercised by the e2e-was suite (node has
 * no IndexedDB).
 */
import { describe, expect, it } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { sessionKeyDid, sessionKeySigner } from '@/lib/sessionKey'

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey('Ed25519', false, [
    'sign',
    'verify'
  ])) as CryptoKeyPair
}

describe('sessionKeyDid', () => {
  it('derives a did:key with the Ed25519 multicodec fingerprint', async () => {
    const { publicKey } = await generateKeyPair()
    const { did, verificationMethodId } = await sessionKeyDid({ publicKey })
    expect(did).toMatch(/^did:key:z6Mk/)
    const fingerprint = did.slice('did:key:'.length)
    expect(verificationMethodId).toBe(`${did}#${fingerprint}`)
  })

  it('is deterministic for the same public key', async () => {
    const { publicKey } = await generateKeyPair()
    const first = await sessionKeyDid({ publicKey })
    const second = await sessionKeyDid({ publicKey })
    expect(second).toEqual(first)
  })
})

describe('sessionKeySigner', () => {
  it('signs payloads verifiable against the exported public key', async () => {
    const keyPair = await generateKeyPair()
    const { signer, did } = await sessionKeySigner({ keyPair })
    expect(signer.id).toBe(`${did}#${did.slice('did:key:'.length)}`)

    const data = new TextEncoder().encode('capability invocation bytes')
    const signature = await signer.sign({ data })

    const publicKeyJwk = (await crypto.subtle.exportKey(
      'jwk',
      keyPair.publicKey
    )) as { kty: 'OKP'; crv: 'Ed25519'; x: string }
    const verificationKey = await Ed25519VerificationKey.fromJsonWebKey({
      type: 'JsonWebKey',
      publicKeyJwk
    })
    const verifier = verificationKey.verifier()
    expect(await verifier.verify({ data, signature })).toBe(true)
  })
})
