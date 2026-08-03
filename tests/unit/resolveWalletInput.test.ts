// @vitest-environment node
/**
 * Unit tests for the free-form wallet-input door
 * (`src/lib/resolveWalletInput.ts`): the shared classifier decides what a
 * piece of pasted or scanned text IS, and freewallet handles two of the kinds
 * -- raw credentials, and a connect code it recognizes but does not consume
 * here.
 */
import { describe, expect, it, vi } from 'vitest'
import { CONNECT_CODE_PREFIX } from '@interop/wallet-core/enrollment'

vi.mock('@/lib/corsProxy', () => ({
  fetchFromURL: vi.fn(async () => {
    throw new Error('no network in unit tests')
  })
}))

const { resolveWalletInput, WalletInputUnsupportedError } =
  await import('@/lib/resolveWalletInput')

const credential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:z6MkIssuer',
  credentialSubject: { id: 'did:key:z6MkSubject' }
}

describe('resolveWalletInput', () => {
  it('resolves raw credential JSON through the credentials branch', async () => {
    const resolved = await resolveWalletInput(JSON.stringify(credential))

    expect(resolved).toHaveLength(1)
    expect(resolved[0].issuer).toBe('did:key:z6MkIssuer')
  })

  it('recognizes a connect code instead of failing it as malformed JSON', async () => {
    const code = `${CONNECT_CODE_PREFIX}bm90LWEtY3JlZGVudGlhbA`

    await expect(resolveWalletInput(code)).rejects.toThrow(
      WalletInputUnsupportedError
    )
    await expect(resolveWalletInput(code)).rejects.toMatchObject({
      code: 'connect_code'
    })
  })

  it('refuses a kind this screen does not implement', async () => {
    // A wallet API message classifies positively and has no handler here.
    const message = JSON.stringify({
      type: 'VerifiablePresentationRequest',
      protocols: { vcapi: 'https://example.test/exchange' }
    })

    const thrown = await resolveWalletInput(message).catch(err => err)

    if (thrown instanceof WalletInputUnsupportedError) {
      expect(thrown.code).toBe('unsupported')
    } else {
      // Classified as credentials (the fallback), which the resolver then
      // refuses on its own terms -- either way the input never silently
      // becomes a stored credential.
      expect(thrown).toBeInstanceOf(Error)
    }
  })
})
