/**
 * The PRF-retry prompt store: the pending WebAuthn retry question and the
 * resolver waiting on it. No prompt may be left unsettled -- a dead resolver
 * hangs the ceremony that awaited it, and a stale `open` pops a spurious
 * dialog on the next page that renders one.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import {
  promptForPrfRetry,
  resetPrfRetryPrompt,
  usePrfRetryStore
} from '@/stores/prfRetryStore'

describe('prfRetryStore', () => {
  beforeEach(() => {
    resetPrfRetryPrompt()
  })

  it('resolves the user choice for the ceremony that asked', async () => {
    const consented = promptForPrfRetry()
    expect(usePrfRetryStore.getState().open).toBe(true)
    usePrfRetryStore.getState().answer(true)
    await expect(consented).resolves.toBe(true)
    expect(usePrfRetryStore.getState().open).toBe(false)
    expect(usePrfRetryStore.getState().resolve).toBeNull()
  })

  it('settles the pending question before a second one takes its place', async () => {
    const abandoned = promptForPrfRetry()
    const current = promptForPrfRetry()
    // The first ceremony's await is resolved rather than left hanging.
    await expect(abandoned).resolves.toBe(false)
    expect(usePrfRetryStore.getState().open).toBe(true)
    usePrfRetryStore.getState().answer(true)
    await expect(current).resolves.toBe(true)
  })

  it('resets a prompt nobody is left to answer', async () => {
    const consented = promptForPrfRetry()
    resetPrfRetryPrompt()
    await expect(consented).resolves.toBe(false)
    expect(usePrfRetryStore.getState().open).toBe(false)
    expect(usePrfRetryStore.getState().resolve).toBeNull()
  })

  it('is a no-op with nothing pending', () => {
    resetPrfRetryPrompt()
    expect(usePrfRetryStore.getState().open).toBe(false)
  })
})
