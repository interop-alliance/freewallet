/**
 * The passkey ceremonies over a fake `navigator.credentials`: the PRF result
 * shapes real authenticators return, which the CDP virtual authenticator
 * cannot produce, and the reason code and log line each refusal carries.
 */
import { addSink, captureSink } from '@interop/logger'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  assertPasskeyPrf,
  PasskeyCancelledError,
  PasskeyDuplicateError,
  PasskeyPrfUnsupportedError,
  registerPasskey
} from './passkey'

const PRF_OUTPUT = new Uint8Array(32).fill(7)

/**
 * Builds a fake `PublicKeyCredential` carrying the given PRF client-extension
 * result. `create()` responses get `getTransports` and
 * `getAuthenticatorData`; `get()` responses get a `userHandle`.
 *
 * @param options {object}
 * @param options.prf {object | undefined}   the `prf` client-extension result
 * @param [options.kind] {'create' | 'get'}
 * @returns {PublicKeyCredential}
 */
function fakeCredential({
  prf,
  kind = 'create'
}: {
  prf: { enabled?: boolean; results?: { first: ArrayBuffer } } | undefined
  kind?: 'create' | 'get'
}): PublicKeyCredential {
  const rawId = new Uint8Array(16).fill(1).buffer
  const response =
    kind === 'create'
      ? {
          getTransports: () => ['internal'],
          // 37 bytes: rpIdHash (32), flags (1), signCount (4). Flags set
          // BE and BS (bits 3 and 4).
          getAuthenticatorData: () => {
            const data = new Uint8Array(37)
            data[32] = 0b0001_1000
            return data.buffer
          }
        }
      : { userHandle: new Uint8Array(8).fill(2).buffer }
  return {
    rawId,
    authenticatorAttachment: 'platform',
    response,
    getClientExtensionResults: () => (prf ? { prf } : {})
  } as unknown as PublicKeyCredential
}

/**
 * Installs a fake `navigator.credentials` and returns its `create` and
 * `get` mocks.
 *
 * @returns {{ create: ReturnType<typeof vi.fn>, get: ReturnType<typeof vi.fn> }}
 */
function installCredentials(): {
  create: ReturnType<typeof vi.fn>
  get: ReturnType<typeof vi.fn>
} {
  const create = vi.fn()
  const get = vi.fn()
  Object.defineProperty(navigator, 'credentials', {
    value: { create, get },
    configurable: true
  })
  return { create, get }
}

describe('registerPasskey', () => {
  let credentials: ReturnType<typeof installCredentials>
  let capture: ReturnType<typeof captureSink>
  let removeSink: () => void

  beforeEach(() => {
    credentials = installCredentials()
    capture = captureSink()
    removeSink = addSink(capture.sink)
  })

  afterEach(() => {
    removeSink()
  })

  const userHandle = new Uint8Array(16).fill(3)

  it('takes the PRF output from create() and runs no retry', async () => {
    credentials.create.mockResolvedValue(
      fakeCredential({
        prf: { enabled: true, results: { first: PRF_OUTPUT.buffer } }
      })
    )
    const promptForPrfRetry = vi.fn(() => true)

    const registration = await registerPasskey({
      userHandle,
      userName: 'probe',
      promptForPrfRetry
    })

    expect(registration.prfOutput).toEqual(PRF_OUTPUT)
    expect(registration.backupEligibility).toBe(true)
    expect(registration.backupState).toBe(true)
    expect(registration.transports).toEqual(['internal'])
    expect(promptForPrfRetry).not.toHaveBeenCalled()
    expect(credentials.get).not.toHaveBeenCalled()
    const created = capture.events.find(
      event => event.msg === 'Passkey created'
    )
    expect(created?.data).toMatchObject({
      prfPresent: true,
      prfEnabled: true,
      prfResultBytes: 32,
      transports: ['internal'],
      credentialIdBytes: 16
    })
  })

  it('refuses at once, with no retry prompt, when create() declares PRF unsupported', async () => {
    credentials.create.mockResolvedValue(
      fakeCredential({ prf: { enabled: false } })
    )
    const promptForPrfRetry = vi.fn(() => true)

    const failure = await registerPasskey({
      userHandle,
      userName: 'probe',
      promptForPrfRetry
    }).catch(err => err)

    expect(failure).toBeInstanceOf(PasskeyPrfUnsupportedError)
    expect(failure.reason).toBe('create-enabled-false')
    expect(promptForPrfRetry).not.toHaveBeenCalled()
    expect(JSON.stringify(capture.events)).toContain('create-enabled-false')
  })

  it('evaluates PRF through the consented retry assertion when create() returns none', async () => {
    credentials.create.mockResolvedValue(
      fakeCredential({ prf: { enabled: true } })
    )
    credentials.get.mockResolvedValue(
      fakeCredential({
        prf: { results: { first: PRF_OUTPUT.buffer } },
        kind: 'get'
      })
    )

    const registration = await registerPasskey({
      userHandle,
      userName: 'probe',
      promptForPrfRetry: () => true
    })

    expect(registration.prfOutput).toEqual(PRF_OUTPUT)
    const getOptions = credentials.get.mock.calls[0][0].publicKey
    expect(getOptions.allowCredentials).toHaveLength(1)
    expect(getOptions.allowCredentials[0].transports).toEqual(['internal'])
    expect(
      capture.events.find(event => event.msg === 'PRF retry assertion returned')
        ?.data
    ).toMatchObject({ prfPresent: true, prfResultBytes: 32 })
  })

  it('refuses with retry-no-result when the retry assertion returns none either', async () => {
    credentials.create.mockResolvedValue(fakeCredential({ prf: undefined }))
    credentials.get.mockResolvedValue(
      fakeCredential({ prf: { enabled: true }, kind: 'get' })
    )

    const failure = await registerPasskey({
      userHandle,
      userName: 'probe',
      promptForPrfRetry: () => true
    }).catch(err => err)

    expect(failure).toBeInstanceOf(PasskeyPrfUnsupportedError)
    expect(failure.reason).toBe('retry-no-result')
    expect(JSON.stringify(capture.events)).toContain('retry-no-result')
  })

  it('cancels when the retry prompt is declined', async () => {
    credentials.create.mockResolvedValue(
      fakeCredential({ prf: { enabled: true } })
    )

    await expect(
      registerPasskey({
        userHandle,
        userName: 'probe',
        promptForPrfRetry: () => false
      })
    ).rejects.toBeInstanceOf(PasskeyCancelledError)
    expect(credentials.get).not.toHaveBeenCalled()
  })

  it('maps a dismissed create() to the cancel error and an excluded one to the duplicate error', async () => {
    credentials.create.mockRejectedValueOnce(
      new DOMException('dismissed', 'NotAllowedError')
    )
    await expect(
      registerPasskey({
        userHandle,
        userName: 'probe',
        promptForPrfRetry: () => true
      })
    ).rejects.toBeInstanceOf(PasskeyCancelledError)

    credentials.create.mockRejectedValueOnce(
      new DOMException('exists', 'InvalidStateError')
    )
    await expect(
      registerPasskey({
        userHandle,
        userName: 'probe',
        promptForPrfRetry: () => true
      })
    ).rejects.toBeInstanceOf(PasskeyDuplicateError)
  })
})

describe('assertPasskeyPrf', () => {
  let credentials: ReturnType<typeof installCredentials>
  let capture: ReturnType<typeof captureSink>
  let removeSink: () => void

  beforeEach(() => {
    credentials = installCredentials()
    capture = captureSink()
    removeSink = addSink(capture.sink)
  })

  afterEach(() => {
    removeSink()
  })

  it('returns the PRF output, credential id, and user handle', async () => {
    credentials.get.mockResolvedValue(
      fakeCredential({
        prf: { results: { first: PRF_OUTPUT.buffer } },
        kind: 'get'
      })
    )

    const result = await assertPasskeyPrf({})

    expect(result.prfOutput).toEqual(PRF_OUTPUT)
    expect(result.credentialId.byteLength).toBe(16)
    expect(result.userHandle?.byteLength).toBe(8)
    expect(
      capture.events.find(event => event.msg === 'Passkey assertion returned')
        ?.data
    ).toMatchObject({ prfPresent: true, prfResultBytes: 32 })
  })

  it('refuses with assertion-no-result when the assertion carries no PRF output', async () => {
    credentials.get.mockResolvedValue(
      fakeCredential({ prf: { enabled: true }, kind: 'get' })
    )

    const failure = await assertPasskeyPrf({}).catch(err => err)

    expect(failure).toBeInstanceOf(PasskeyPrfUnsupportedError)
    expect(failure.reason).toBe('assertion-no-result')
    expect(JSON.stringify(capture.events)).toContain('assertion-no-result')
  })
})
