// @vitest-environment node
/**
 * Unit tests for the shared CHAPI popup login sequence
 * (`src/session/completePopupLogin.ts`): the popup keyring resolve, the
 * account-not-found guard, and the error mapping both popup pages apply --
 * including the transient refusals a record-less popup now reaches (FW-203).
 * `loginWithPassphrase` (network + IndexedDB) and the storage-error
 * classifier are stubbed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'

vi.mock('@/session/initSession', () => ({ loginWithPassphrase: vi.fn() }))
vi.mock('@/lib/storageErrors', () => ({ isStorageUnreachable: vi.fn() }))
vi.mock('@/lib/storageAccess', () => ({
  requestUnpartitionedIdb: vi.fn(async () => undefined)
}))

import { loginWithPassphrase } from '@/session/initSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { requestUnpartitionedIdb } from '@/lib/storageAccess'
import {
  completePopupLogin,
  mapPopupLoginError
} from '@/session/completePopupLogin'
import {
  TransientLoginUnavailableError,
  type TransientLoginUnavailableReason
} from '@/session/transientLogin'

const PASSPHRASE = 'correct horse battery staple'
const fakeSession = { user: { id: 'did:key:z6MkUser' } } as unknown as Session

beforeEach(() => {
  vi.mocked(isStorageUnreachable).mockReturnValue(false)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('completePopupLogin', () => {
  it('returns the session and logs in as a popup session', async () => {
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: fakeSession,
      userExists: true
    })

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ session: fakeSession })
    expect(loginWithPassphrase).toHaveBeenCalledWith({
      passphrase: PASSPHRASE,
      popup: true,
      idb: undefined
    })
  })

  it('threads the unpartitioned IndexedDB handle when the browser grants one', async () => {
    const unpartitioned = { isUnpartitionedIdb: true } as unknown as IDBFactory
    vi.mocked(requestUnpartitionedIdb).mockResolvedValue(unpartitioned)
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: fakeSession,
      userExists: true
    })

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ session: fakeSession })
    expect(loginWithPassphrase).toHaveBeenCalledWith({
      passphrase: PASSPHRASE,
      popup: true,
      idb: unpartitioned
    })
  })

  it('maps a keyring miss to the account-not-found key', async () => {
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: null,
      userExists: false
    })

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ errorKey: 'chapi.accountNotFound' })
  })

  it('maps a half-finished signup (userExists false) to account-not-found', async () => {
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: fakeSession,
      userExists: false
    })

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ errorKey: 'chapi.accountNotFound' })
  })

  it('maps a storage-unreachable failure to the storage-unreachable key', async () => {
    const err = new Error('network down')
    vi.mocked(loginWithPassphrase).mockRejectedValue(err)
    vi.mocked(isStorageUnreachable).mockReturnValue(true)

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ errorKey: 'chapi.storageUnreachable' })
  })

  it('maps a transient refusal to the shared per-reason copy', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.mocked(loginWithPassphrase).mockRejectedValue(
      new TransientLoginUnavailableError({ reason: 'no-user-key-wrap' })
    )

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ errorKey: 'auth.errors.transientNoUserKeyWrap' })
  })

  it('maps any other failure to the generic login-failed key', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.mocked(loginWithPassphrase).mockRejectedValue(new Error('boom'))
    vi.mocked(isStorageUnreachable).mockReturnValue(false)

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ errorKey: 'chapi.loginFailed' })
  })
})

describe('mapPopupLoginError', () => {
  it('returns the storage-unreachable key for an unreachable-server error', () => {
    vi.mocked(isStorageUnreachable).mockReturnValue(true)
    expect(mapPopupLoginError(new Error('x'))).toBe('chapi.storageUnreachable')
  })

  it('never maps a transient refusal onto the not-enrolled guidance', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const reasons: TransientLoginUnavailableReason[] = [
      'no-was-server',
      'no-delegated-clients',
      'unpromoted-account',
      'no-clientAnnex-generation',
      'no-generation-delegation',
      'no-user-key-roster',
      'no-user-key-wrap',
      'roster-mint-refused'
    ]
    for (const reason of reasons) {
      const key = mapPopupLoginError(
        new TransientLoginUnavailableError({ reason })
      )
      expect(key).not.toBe('chapi.clientNotEnrolled')
      expect(key).not.toBe('chapi.loginFailed')
    }
  })

  it('returns the generic key for anything else', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.mocked(isStorageUnreachable).mockReturnValue(false)
    expect(mapPopupLoginError(new Error('x'))).toBe('chapi.loginFailed')
  })
})
