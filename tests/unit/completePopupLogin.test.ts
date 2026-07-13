// @vitest-environment node
/**
 * Unit tests for the shared CHAPI popup login sequence
 * (`src/session/completePopupLogin.ts`): remote-direct keyring resolve, the
 * account-not-found guard, fire-and-forget delegated-session persistence
 * through the first-party handle, and the error mapping both popup pages
 * apply. `loginWithPassphrase` / `persistDelegatedSession` (network + IndexedDB)
 * and the storage-error classifier are stubbed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'

vi.mock('@/session/initSession', () => ({ loginWithPassphrase: vi.fn() }))
vi.mock('@/session/delegatedSession', () => ({
  persistDelegatedSession: vi.fn()
}))
vi.mock('@/lib/storageErrors', () => ({ isStorageUnreachable: vi.fn() }))

import { loginWithPassphrase } from '@/session/initSession'
import { persistDelegatedSession } from '@/session/delegatedSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
import {
  completePopupLogin,
  mapPopupLoginError
} from '@/session/completePopupLogin'

const PASSPHRASE = 'correct horse battery staple'
const fakeSession = { user: { id: 'did:key:z6MkUser' } } as unknown as Session

beforeEach(() => {
  vi.mocked(persistDelegatedSession).mockResolvedValue(undefined)
  vi.mocked(isStorageUnreachable).mockReturnValue(false)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('completePopupLogin', () => {
  it('returns the session and logs in remote-direct via the first-party handle', async () => {
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: fakeSession,
      userExists: true
    })
    const firstPartyIdb = {} as IDBFactory

    const result = await completePopupLogin({
      passphrase: PASSPHRASE,
      firstPartyIdb
    })

    expect(result).toEqual({ session: fakeSession })
    expect(loginWithPassphrase).toHaveBeenCalledWith({
      passphrase: PASSPHRASE,
      idb: firstPartyIdb,
      remoteDirectStorage: true
    })
    expect(persistDelegatedSession).toHaveBeenCalledWith({
      session: fakeSession,
      idb: firstPartyIdb
    })
  })

  it('does not persist a delegated session without a first-party handle', async () => {
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: fakeSession,
      userExists: true
    })

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ session: fakeSession })
    expect(loginWithPassphrase).toHaveBeenCalledWith({
      passphrase: PASSPHRASE,
      idb: undefined,
      remoteDirectStorage: true
    })
    expect(persistDelegatedSession).not.toHaveBeenCalled()
  })

  it('maps a keyring miss to the account-not-found key', async () => {
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: null,
      userExists: false
    })

    const result = await completePopupLogin({ passphrase: PASSPHRASE })

    expect(result).toEqual({ errorKey: 'chapi.accountNotFound' })
    expect(persistDelegatedSession).not.toHaveBeenCalled()
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

  it('returns the generic key for anything else', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.mocked(isStorageUnreachable).mockReturnValue(false)
    expect(mapPopupLoginError(new Error('x'))).toBe('chapi.loginFailed')
  })
})
