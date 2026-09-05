/**
 * Unit tests for the shared post-login step sequence: every page-level login
 * site runs the same five steps once, in order, and only the navigation
 * varies by caller.
 *
 * @vitest-environment node
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'

vi.mock('@/lib/registerWallet', () => ({
  registerWallet: vi.fn(async () => {})
}))
vi.mock('@/session/recovery', () => ({
  checkRecoveryHealth: vi.fn(async () => [])
}))
vi.mock('@/session/walletLoginActivity', () => ({
  recordWalletLogin: vi.fn()
}))
vi.mock('@/stores/toastStore', () => ({
  showToast: vi.fn()
}))
const loginIntoStore = vi.fn()
vi.mock('@/stores/authStore', () => ({
  useAuthStore: { getState: () => ({ login: loginIntoStore }) }
}))

const { registerWallet } = await import('@/lib/registerWallet')
const { checkRecoveryHealth } = await import('@/session/recovery')
const { recordWalletLogin } = await import('@/session/walletLoginActivity')
const { showToast } = await import('@/stores/toastStore')
const { completeAppLogin } = await import('@/session/completeAppLogin')

const t = ((key: string) => key) as unknown as Parameters<
  typeof completeAppLogin
>[0]['t']

/**
 * A session stub carrying only what the sequence reads: the storage-ready
 * gate and the could-not-remember flag.
 *
 * @param [options] {object}
 * @param [options.userKeyPersistFailed] {boolean}
 * @returns {Session}
 */
function makeSession({
  userKeyPersistFailed = false
}: { userKeyPersistFailed?: boolean } = {}): Session {
  return {
    storageReady: Promise.resolve(),
    userKeyPersistFailed
  } as unknown as Session
}

describe('completeAppLogin', () => {
  it('adopts, records, registers, then navigates', async () => {
    vi.clearAllMocks()
    const session = makeSession()
    const navigate = vi.fn()
    await completeAppLogin({ session, t, navigate })
    expect(loginIntoStore).toHaveBeenCalledWith(session)
    expect(recordWalletLogin).toHaveBeenCalledWith({ session })
    expect(registerWallet).toHaveBeenCalledTimes(1)
    expect(checkRecoveryHealth).toHaveBeenCalledWith({ session })
    expect(navigate).toHaveBeenCalledWith('/dashboard', { replace: true })
    expect(showToast).not.toHaveBeenCalled()
  })

  it('waits for storage provisioning before adopting the session', async () => {
    vi.clearAllMocks()
    let release!: () => void
    const session = {
      storageReady: new Promise<void>(resolve => {
        release = resolve
      })
    } as unknown as Session
    const run = completeAppLogin({ session, t })
    await Promise.resolve()
    expect(loginIntoStore).not.toHaveBeenCalled()
    release()
    await run
    expect(loginIntoStore).toHaveBeenCalledWith(session)
  })

  it('stays put when no navigate is given', async () => {
    vi.clearAllMocks()
    await completeAppLogin({ session: makeSession(), t })
    expect(loginIntoStore).toHaveBeenCalledTimes(1)
  })

  it('warns when the rotated user key could not be persisted', async () => {
    vi.clearAllMocks()
    await completeAppLogin({
      session: makeSession({ userKeyPersistFailed: true }),
      t
    })
    expect(showToast).toHaveBeenCalledWith({
      message: 'auth.login.rememberBrowserWarning',
      severity: 'warning'
    })
  })

  it('nudges when the recovery health check flags something', async () => {
    vi.clearAllMocks()
    vi.mocked(checkRecoveryHealth).mockResolvedValueOnce([
      { kind: 'delegation-rot' }
    ] as never)
    await completeAppLogin({ session: makeSession(), t })
    // The check is fire-and-forget; let its continuation run.
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(showToast).toHaveBeenCalledWith({
      message: 'auth.login.recoveryHealthWarning',
      severity: 'warning'
    })
  })

  it('swallows a failed health check', async () => {
    vi.clearAllMocks()
    vi.mocked(checkRecoveryHealth).mockRejectedValueOnce(new Error('down'))
    const navigate = vi.fn()
    await completeAppLogin({ session: makeSession(), t, navigate })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(navigate).toHaveBeenCalledTimes(1)
    expect(showToast).not.toHaveBeenCalled()
  })
})
