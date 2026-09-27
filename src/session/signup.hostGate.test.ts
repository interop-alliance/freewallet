// @vitest-environment node
/**
 * The signup's host gate: a WAS signup publishes a ladder verification method,
 * so it refuses a storage server whose service description does not claim the
 * client annex profile, before the key derivation and before any passkey is
 * registered.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ServiceDescription } from '@interop/was-client'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example',
  WAS_SPACES_URL: 'https://was.example/spaces/'
}))

const serviceDescription = vi.fn<() => Promise<ServiceDescription>>()
vi.mock('@/lib/wasService', () => ({
  wasServiceDescription: () => serviceDescription()
}))

const deriveUnlockCredential = vi.fn()
vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  deriveUnlockCredential: (...args: unknown[]) =>
    deriveUnlockCredential(...args)
}))

const registerPasskey = vi.fn()
vi.mock('@/lib/passkey', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  registerPasskey: (...args: unknown[]) => registerPasskey(...args)
}))

const { signUpWithPasskey, signUpWithPassphrase } =
  await import('@/session/signup')

const NO_ANNEX_CLAIM = {
  url: 'https://was.example/service',
  specs: { 'https://w3id.org/pws': [{ version: '0.5' }] }
} as unknown as ServiceDescription

describe('the signup host gate', () => {
  beforeEach(() => {
    serviceDescription.mockReset()
    deriveUnlockCredential.mockReset()
    registerPasskey.mockReset()
    serviceDescription.mockResolvedValue(NO_ANNEX_CLAIM)
  })

  it('refuses a passphrase signup before the key derivation', async () => {
    const outcome = signUpWithPassphrase({ passphrase: 'correct horse' })
    await expect(outcome).rejects.toMatchObject({
      name: 'IncompatibleServerError'
    })
    expect(deriveUnlockCredential).not.toHaveBeenCalled()
  })

  it('refuses a remembered passphrase signup the same way', async () => {
    const outcome = signUpWithPassphrase({
      passphrase: 'correct horse',
      rememberBrowser: true
    })
    await expect(outcome).rejects.toMatchObject({
      name: 'IncompatibleServerError'
    })
    expect(deriveUnlockCredential).not.toHaveBeenCalled()
  })

  it('refuses a passkey signup before the WebAuthn ceremony', async () => {
    const outcome = signUpWithPasskey({
      locale: 'en',
      userName: 'alice',
      promptForPrfRetry: async () => false
    })
    await expect(outcome).rejects.toMatchObject({
      name: 'IncompatibleServerError'
    })
    expect(registerPasskey).not.toHaveBeenCalled()
  })
})
