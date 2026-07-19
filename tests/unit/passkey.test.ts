/**
 * Unit tests for the passkey ceremony module (`src/lib/passkey.ts`): the pure
 * options builders, the BE / BS flag parser, DOMException-to-typed-error
 * mapping, and the PRF resolution dance. The WebAuthn API is faked (a stubbed
 * `navigator.credentials`); the real ceremonies are exercised by the e2e
 * suite. Default (jsdom) environment.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { PASSKEY_PRF_INPUT } from '@/app.config'
import {
  assertPasskeyPrf,
  buildAssertionOptions,
  buildRegistrationOptions,
  parseBackupFlags,
  passkeySupported,
  PasskeyCancelledError,
  PasskeyDuplicateError,
  PasskeyPrfUnsupportedError,
  registerPasskey
} from '@/lib/passkey'

/**
 * Installs a fake `navigator.credentials` with the given `create` / `get`
 * mocks, returning them for assertions.
 *
 * @param options {object}
 * @param [options.create] {ReturnType<typeof vi.fn>}
 * @param [options.get] {ReturnType<typeof vi.fn>}
 * @returns {{ create: ReturnType<typeof vi.fn>, get: ReturnType<typeof vi.fn> }}
 */
function stubCredentials({
  create = vi.fn(),
  get = vi.fn()
}: {
  create?: ReturnType<typeof vi.fn>
  get?: ReturnType<typeof vi.fn>
} = {}) {
  Object.defineProperty(navigator, 'credentials', {
    value: { create, get },
    configurable: true,
    writable: true
  })
  return { create, get }
}

/**
 * Builds a fake PublicKeyCredential-shaped object for a registration ceremony.
 *
 * @param options {object}
 * @param options.rawId {ArrayBuffer}
 * @param [options.prf] {unknown}   the prf client-extension output
 * @param [options.transports] {string[] | undefined}
 * @param [options.authenticatorData] {Uint8Array | undefined}
 * @returns {unknown}
 */
function fakeRegistrationCredential({
  rawId,
  prf,
  transports,
  authenticatorData
}: {
  rawId: ArrayBuffer
  prf?: unknown
  transports?: string[]
  authenticatorData?: Uint8Array
}) {
  return {
    rawId,
    response: {
      getTransports: transports ? () => transports : undefined,
      getAuthenticatorData: authenticatorData
        ? () => authenticatorData
        : undefined
    },
    getClientExtensionResults: () => ({ prf })
  }
}

/**
 * Builds a fake PublicKeyCredential-shaped object for an assertion ceremony.
 *
 * @param options {object}
 * @param options.rawId {ArrayBuffer}
 * @param [options.prf] {unknown}
 * @param [options.userHandle] {ArrayBuffer | null}
 * @returns {unknown}
 */
function fakeAssertionCredential({
  rawId,
  prf,
  userHandle = null
}: {
  rawId: ArrayBuffer
  prf?: unknown
  userHandle?: ArrayBuffer | null
}) {
  return {
    rawId,
    response: { userHandle },
    getClientExtensionResults: () => ({ prf })
  }
}

const prfResults = (bytes: Uint8Array) => ({ results: { first: bytes } })

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('parseBackupFlags', () => {
  function authData(flagByte: number): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(37)
    bytes[32] = flagByte
    return bytes
  }

  it('reports both flags false when neither bit is set', () => {
    expect(parseBackupFlags(authData(0x00))).toEqual({
      backupEligibility: false,
      backupState: false
    })
  })

  it('reports BE only when 0x08 is set', () => {
    expect(parseBackupFlags(authData(0x08))).toEqual({
      backupEligibility: true,
      backupState: false
    })
  })

  it('reports BS only when 0x10 is set', () => {
    expect(parseBackupFlags(authData(0x10))).toEqual({
      backupEligibility: false,
      backupState: true
    })
  })

  it('reports both flags when 0x18 is set', () => {
    expect(parseBackupFlags(authData(0x18))).toEqual({
      backupEligibility: true,
      backupState: true
    })
  })

  it('ignores unrelated flag bits', () => {
    // UP (0x01) + UV (0x04) set, but neither BE nor BS.
    expect(parseBackupFlags(authData(0x05))).toEqual({
      backupEligibility: false,
      backupState: false
    })
  })

  it('defaults both flags to false for a buffer too short to hold the flags', () => {
    expect(parseBackupFlags(new Uint8Array(4))).toEqual({
      backupEligibility: false,
      backupState: false
    })
    expect(parseBackupFlags(new Uint8Array(0))).toEqual({
      backupEligibility: false,
      backupState: false
    })
  })

  it('accepts an ArrayBuffer as well as a Uint8Array', () => {
    expect(parseBackupFlags(authData(0x18).buffer)).toEqual({
      backupEligibility: true,
      backupState: true
    })
  })
})

describe('buildRegistrationOptions', () => {
  const userHandle = new Uint8Array([9, 9, 9, 9])

  it('maps excludeCredentials, threading ids under type public-key', () => {
    const idA = new Uint8Array([1, 2])
    const idB = new Uint8Array([3, 4])
    const options = buildRegistrationOptions({
      userHandle,
      userName: 'user@example.com',
      excludeCredentialIds: [idA, idB]
    })
    expect(options.excludeCredentials).toHaveLength(2)
    expect(options.excludeCredentials?.[0]).toEqual({
      type: 'public-key',
      id: idA
    })
    expect(options.excludeCredentials?.[0]?.id).toBe(idA)
    expect(options.excludeCredentials?.[1]?.id).toBe(idB)
  })

  it('defaults excludeCredentials to an empty array', () => {
    const options = buildRegistrationOptions({ userHandle, userName: 'x' })
    expect(options.excludeCredentials).toEqual([])
  })

  it('leaves the RP id undefined by default and names the RP Freewallet', () => {
    const options = buildRegistrationOptions({ userHandle, userName: 'x' })
    expect(options.rp.id).toBeUndefined()
    expect(options.rp.name).toBe('Freewallet')
  })

  it('threads the user handle and name', () => {
    const options = buildRegistrationOptions({
      userHandle,
      userName: 'user@example.com'
    })
    expect(options.user.id).toBe(userHandle)
    expect(options.user.name).toBe('user@example.com')
    expect(options.user.displayName).toBe('user@example.com')
  })

  it('requires a discoverable credential with user verification', () => {
    const options = buildRegistrationOptions({ userHandle, userName: 'x' })
    expect(options.authenticatorSelection?.residentKey).toBe('required')
    expect(options.authenticatorSelection?.requireResidentKey).toBe(true)
    expect(options.authenticatorSelection?.userVerification).toBe('required')
  })

  it('lists pubKeyCredParams as EdDSA, ES256, RS256 in order', () => {
    const options = buildRegistrationOptions({ userHandle, userName: 'x' })
    expect(options.pubKeyCredParams.map(param => param.alg)).toEqual([
      -8, -7, -257
    ])
    expect(
      options.pubKeyCredParams.every(param => param.type === 'public-key')
    ).toBe(true)
  })

  it('requests no attestation and the fixed PRF eval input', () => {
    const options = buildRegistrationOptions({ userHandle, userName: 'x' })
    expect(options.attestation).toBe('none')
    expect(options.extensions?.prf?.eval?.first).toBe(PASSKEY_PRF_INPUT)
  })

  it('uses a fresh 32-byte challenge', () => {
    const first = buildRegistrationOptions({ userHandle, userName: 'x' })
    const second = buildRegistrationOptions({ userHandle, userName: 'x' })
    expect(first.challenge).toBeInstanceOf(Uint8Array)
    expect((first.challenge as Uint8Array).byteLength).toBe(32)
    expect(first.challenge).not.toEqual(second.challenge)
  })
})

describe('buildAssertionOptions', () => {
  it('maps allowCredentials, threading ids under type public-key', () => {
    const idA = new Uint8Array([5, 6])
    const idB = new Uint8Array([7, 8])
    const options = buildAssertionOptions({ credentialIds: [idA, idB] })
    expect(options.allowCredentials).toHaveLength(2)
    expect(options.allowCredentials?.[0]).toEqual({
      type: 'public-key',
      id: idA
    })
    expect(options.allowCredentials?.[0]?.id).toBe(idA)
    expect(options.allowCredentials?.[1]?.id).toBe(idB)
  })

  it('yields an empty allowCredentials for the discoverable flow', () => {
    const options = buildAssertionOptions({})
    expect(options.allowCredentials).toEqual([])
  })

  it('leaves the RP id undefined, requires UV, and requests the PRF input', () => {
    const options = buildAssertionOptions({})
    expect(options.rpId).toBeUndefined()
    expect(options.userVerification).toBe('required')
    expect(options.extensions?.prf?.eval?.first).toBe(PASSKEY_PRF_INPUT)
  })

  it('uses a fresh 32-byte challenge', () => {
    const options = buildAssertionOptions({})
    expect(options.challenge).toBeInstanceOf(Uint8Array)
    expect((options.challenge as Uint8Array).byteLength).toBe(32)
  })
})

describe('passkeySupported', () => {
  it('is true when PublicKeyCredential is defined', () => {
    vi.stubGlobal('PublicKeyCredential', class {})
    expect(passkeySupported()).toBe(true)
  })

  it('is false when PublicKeyCredential is absent', () => {
    vi.stubGlobal('PublicKeyCredential', undefined)
    expect(passkeySupported()).toBe(false)
  })
})

describe('registerPasskey PRF resolution', () => {
  const userHandle = new Uint8Array([1, 1, 1, 1])
  const rawId = new Uint8Array([10, 20, 30, 40]).buffer

  it('uses the create() PRF result directly and never runs get()', async () => {
    const prfBytes = new Uint8Array(32).fill(7)
    const authenticatorData = new Uint8Array(37)
    authenticatorData[32] = 0x18
    const { get } = stubCredentials({
      create: vi.fn().mockResolvedValue(
        fakeRegistrationCredential({
          rawId,
          prf: prfResults(prfBytes),
          transports: ['internal', 'hybrid'],
          authenticatorData
        })
      )
    })
    const promptForPrfRetry = vi.fn()

    const registration = await registerPasskey({
      userHandle,
      userName: 'x',
      promptForPrfRetry
    })

    expect(get).not.toHaveBeenCalled()
    expect(promptForPrfRetry).not.toHaveBeenCalled()
    expect(registration.prfOutput).toEqual(prfBytes)
    expect(registration.credentialId).toEqual(new Uint8Array([10, 20, 30, 40]))
    expect(registration.transports).toEqual(['internal', 'hybrid'])
    expect(registration.backupEligibility).toBe(true)
    expect(registration.backupState).toBe(true)
  })

  it('defaults transports and flags when the getters are absent', async () => {
    const prfBytes = new Uint8Array(32).fill(3)
    stubCredentials({
      create: vi
        .fn()
        .mockResolvedValue(
          fakeRegistrationCredential({ rawId, prf: prfResults(prfBytes) })
        )
    })

    const registration = await registerPasskey({
      userHandle,
      userName: 'x',
      promptForPrfRetry: vi.fn()
    })

    expect(registration.transports).toEqual([])
    expect(registration.backupEligibility).toBe(false)
    expect(registration.backupState).toBe(false)
  })

  it('runs the follow-up get() restricted to the new credential when create() yields no PRF', async () => {
    const prfBytes = new Uint8Array(32).fill(9)
    const create = vi.fn().mockResolvedValue(
      fakeRegistrationCredential({
        rawId,
        prf: { enabled: true },
        transports: ['internal']
      })
    )
    const get = vi
      .fn()
      .mockResolvedValue(
        fakeAssertionCredential({ rawId, prf: prfResults(prfBytes) })
      )
    stubCredentials({ create, get })
    const promptForPrfRetry = vi.fn().mockResolvedValue(true)

    const registration = await registerPasskey({
      userHandle,
      userName: 'x',
      promptForPrfRetry
    })

    expect(promptForPrfRetry).toHaveBeenCalledOnce()
    expect(get).toHaveBeenCalledOnce()
    const getOptions = get.mock.calls[0][0].publicKey
    expect(getOptions.allowCredentials).toHaveLength(1)
    expect(getOptions.allowCredentials[0].id).toBe(rawId)
    expect(getOptions.allowCredentials[0].transports).toEqual(['internal'])
    expect(getOptions.userVerification).toBe('required')
    expect(registration.prfOutput).toEqual(prfBytes)
  })

  it('cancels without calling get() when the retry prompt is declined', async () => {
    const create = vi
      .fn()
      .mockResolvedValue(
        fakeRegistrationCredential({ rawId, prf: { enabled: true } })
      )
    const get = vi.fn()
    stubCredentials({ create, get })
    const promptForPrfRetry = vi.fn().mockResolvedValue(false)

    await expect(
      registerPasskey({ userHandle, userName: 'x', promptForPrfRetry })
    ).rejects.toBeInstanceOf(PasskeyCancelledError)
    expect(get).not.toHaveBeenCalled()
  })

  it('throws PasskeyPrfUnsupportedError without prompting when prf.enabled is false', async () => {
    const create = vi
      .fn()
      .mockResolvedValue(
        fakeRegistrationCredential({ rawId, prf: { enabled: false } })
      )
    const promptForPrfRetry = vi.fn()
    stubCredentials({ create })

    await expect(
      registerPasskey({ userHandle, userName: 'x', promptForPrfRetry })
    ).rejects.toBeInstanceOf(PasskeyPrfUnsupportedError)
    expect(promptForPrfRetry).not.toHaveBeenCalled()
  })

  it('throws PasskeyPrfUnsupportedError when the retry get() still has no PRF result', async () => {
    const create = vi
      .fn()
      .mockResolvedValue(
        fakeRegistrationCredential({ rawId, prf: { enabled: true } })
      )
    const get = vi
      .fn()
      .mockResolvedValue(fakeAssertionCredential({ rawId, prf: {} }))
    stubCredentials({ create, get })

    await expect(
      registerPasskey({
        userHandle,
        userName: 'x',
        promptForPrfRetry: vi.fn().mockResolvedValue(true)
      })
    ).rejects.toBeInstanceOf(PasskeyPrfUnsupportedError)
    expect(get).toHaveBeenCalledOnce()
  })
})

describe('registerPasskey error mapping', () => {
  const base = { userHandle: new Uint8Array([1]), userName: 'x' }

  it('maps a NotAllowedError from create() to PasskeyCancelledError', async () => {
    stubCredentials({
      create: vi
        .fn()
        .mockRejectedValue(new DOMException('denied', 'NotAllowedError'))
    })
    await expect(
      registerPasskey({ ...base, promptForPrfRetry: vi.fn() })
    ).rejects.toBeInstanceOf(PasskeyCancelledError)
  })

  it('maps an InvalidStateError from create() to PasskeyDuplicateError', async () => {
    stubCredentials({
      create: vi
        .fn()
        .mockRejectedValue(new DOMException('exists', 'InvalidStateError'))
    })
    await expect(
      registerPasskey({ ...base, promptForPrfRetry: vi.fn() })
    ).rejects.toBeInstanceOf(PasskeyDuplicateError)
  })

  it('rethrows an unknown error unchanged', async () => {
    const boom = new Error('boom')
    stubCredentials({ create: vi.fn().mockRejectedValue(boom) })
    await expect(
      registerPasskey({ ...base, promptForPrfRetry: vi.fn() })
    ).rejects.toBe(boom)
  })
})

describe('assertPasskeyPrf', () => {
  const rawId = new Uint8Array([2, 4, 6, 8]).buffer

  it('returns the credential id, user handle, and PRF output', async () => {
    const prfBytes = new Uint8Array(32).fill(5)
    const userHandle = new Uint8Array([100, 101]).buffer
    stubCredentials({
      get: vi.fn().mockResolvedValue(
        fakeAssertionCredential({
          rawId,
          prf: prfResults(prfBytes),
          userHandle
        })
      )
    })

    const assertion = await assertPasskeyPrf({})

    expect(assertion.credentialId).toEqual(new Uint8Array([2, 4, 6, 8]))
    expect(assertion.userHandle).toEqual(new Uint8Array([100, 101]))
    expect(assertion.prfOutput).toEqual(prfBytes)
  })

  it('returns a null user handle when the authenticator omits one', async () => {
    const prfBytes = new Uint8Array(32).fill(1)
    stubCredentials({
      get: vi
        .fn()
        .mockResolvedValue(
          fakeAssertionCredential({ rawId, prf: prfResults(prfBytes) })
        )
    })

    const assertion = await assertPasskeyPrf({})
    expect(assertion.userHandle).toBeNull()
  })

  it('throws PasskeyPrfUnsupportedError when the assertion has no PRF result', async () => {
    stubCredentials({
      get: vi
        .fn()
        .mockResolvedValue(fakeAssertionCredential({ rawId, prf: {} }))
    })
    await expect(assertPasskeyPrf({})).rejects.toBeInstanceOf(
      PasskeyPrfUnsupportedError
    )
  })

  it('maps a NotAllowedError from get() to PasskeyCancelledError', async () => {
    stubCredentials({
      get: vi
        .fn()
        .mockRejectedValue(new DOMException('denied', 'NotAllowedError'))
    })
    await expect(assertPasskeyPrf({})).rejects.toBeInstanceOf(
      PasskeyCancelledError
    )
  })

  it('does not map an InvalidStateError from get() to a duplicate error', async () => {
    const invalidState = new DOMException('bad state', 'InvalidStateError')
    stubCredentials({ get: vi.fn().mockRejectedValue(invalidState) })
    await expect(assertPasskeyPrf({})).rejects.toBe(invalidState)
  })
})
