// @vitest-environment node
/**
 * Unit tests for the dead account pointer
 * (`src/session/deadAccountPointer.ts`): the one signal (the account log
 * answering 404) is refused as `DeadAccountPointerError` carrying the
 * removal closure, a transport failure and a continuity refusal rethrow
 * unchanged so neither reaches the deleter, a read with no unlock identity
 * in hand rethrows the 404 as before, and the closure retires the
 * credential's unlock identity and reports the mend.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { captureCeremonyEvents } from './ceremonyEventCapture'

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn()
}))

vi.mock('@/session/retireUnlockIdentity', () => ({
  retireUnlockIdentity: vi.fn()
}))

import {
  AccountLogMissingError,
  verifyAccountLog
} from '@interop/wallet-core/webvh'
import { retireUnlockIdentity } from '@/session/retireUnlockIdentity'
import {
  DeadAccountPointerError,
  removeDeadPointerSignInData,
  verifyPointedAccountLog
} from '@/session/deadAccountPointer'

const UNLOCK = { spaceId: 'unlock-space-1' } as never
const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id'
}

let capture: ReturnType<typeof captureCeremonyEvents>

beforeEach(() => {
  vi.clearAllMocks()
  capture = captureCeremonyEvents()
})

afterEach(() => {
  capture.stop()
})

async function refusalFor(options: { unlock?: unknown } = {}) {
  try {
    await verifyPointedAccountLog({
      ...POINTER,
      ...(options.unlock !== undefined
        ? { unlock: options.unlock as never }
        : {})
    })
  } catch (err) {
    return err
  }
  throw new Error('expected a refusal')
}

describe('verifyPointedAccountLog', () => {
  it('passes a verified log through untouched', async () => {
    const verified = { doc: { id: POINTER.did }, log: [] }
    vi.mocked(verifyAccountLog).mockResolvedValue(verified as never)
    await expect(
      verifyPointedAccountLog({ ...POINTER, unlock: UNLOCK })
    ).resolves.toBe(verified)
  })

  it('refuses a 404 as the dead pointer, carrying the removal closure', async () => {
    const missing = new AccountLogMissingError()
    vi.mocked(verifyAccountLog).mockRejectedValue(missing)
    const err = (await refusalFor({
      unlock: UNLOCK
    })) as DeadAccountPointerError
    expect(err).toBeInstanceOf(DeadAccountPointerError)
    expect(err.name).toBe('DeadAccountPointerError')
    expect(err.unlockSpaceId).toBe('unlock-space-1')
    expect(err.accountDid).toBe(POINTER.did)
    expect(err.cause).toBe(missing)
    expect(typeof err.removeSignInData).toBe('function')
    // The refusal alone deletes nothing: the user's accept does.
    expect(retireUnlockIdentity).not.toHaveBeenCalled()
  })

  it('matches the 404 on its name, across a duplicated wallet-core', async () => {
    const foreign = Object.assign(new Error('gone'), {
      name: 'AccountLogMissingError'
    })
    vi.mocked(verifyAccountLog).mockRejectedValue(foreign)
    const err = await refusalFor({ unlock: UNLOCK })
    expect(err).toBeInstanceOf(DeadAccountPointerError)
  })

  it('rethrows a transport failure unchanged, so it never reaches the deleter', async () => {
    const flap = new TypeError('Failed to fetch')
    vi.mocked(verifyAccountLog).mockRejectedValue(flap)
    expect(await refusalFor({ unlock: UNLOCK })).toBe(flap)
  })

  it('rethrows a continuity refusal unchanged, a rollback included', async () => {
    const rollback = Object.assign(new Error('rollback'), {
      name: 'ResourceLogContinuityError',
      reason: 'rollback'
    })
    vi.mocked(verifyAccountLog).mockRejectedValue(rollback)
    expect(await refusalFor({ unlock: UNLOCK })).toBe(rollback)
  })

  it('rethrows the 404 as before when no unlock identity is in hand', async () => {
    const missing = new AccountLogMissingError()
    vi.mocked(verifyAccountLog).mockRejectedValue(missing)
    expect(await refusalFor()).toBe(missing)
  })
})

describe('removeDeadPointerSignInData', () => {
  it('retires the unlock identity and reports a clean mend', async () => {
    vi.mocked(retireUnlockIdentity).mockResolvedValue(true)
    const idb = {} as IDBFactory
    await expect(
      removeDeadPointerSignInData({ unlock: UNLOCK, idb })
    ).resolves.toEqual({ unlockSpaceDeleted: true })
    expect(retireUnlockIdentity).toHaveBeenCalledWith(
      expect.objectContaining({ unlock: UNLOCK, idb })
    )
    const [event] = capture.menders('no-unlock-space-outlives-its-credential')
    expect(event).toBeDefined()
    expect((event!.data as { outcome: string }).outcome).toBe('clean')
  })

  it('reports partial when the unlock Space could not be deleted', async () => {
    vi.mocked(retireUnlockIdentity).mockResolvedValue(false)
    await expect(
      removeDeadPointerSignInData({ unlock: UNLOCK })
    ).resolves.toEqual({ unlockSpaceDeleted: false })
    const [event] = capture.menders('no-unlock-space-outlives-its-credential')
    expect((event!.data as { outcome: string }).outcome).toBe('partial')
  })

  it('runs through the refusal closure with the same identity', async () => {
    const missing = new AccountLogMissingError()
    vi.mocked(verifyAccountLog).mockRejectedValue(missing)
    vi.mocked(retireUnlockIdentity).mockResolvedValue(true)
    const err = (await refusalFor({
      unlock: UNLOCK
    })) as DeadAccountPointerError
    await expect(err.removeSignInData()).resolves.toEqual({
      unlockSpaceDeleted: true
    })
    expect(retireUnlockIdentity).toHaveBeenCalledWith(
      expect.objectContaining({ unlock: UNLOCK })
    )
  })
})
