/**
 * Unit tests for the module-level zxcvbn loader behind PasswordStrengthMeter.
 *
 * These exercise the caching layer only, via the injectable importer, so the
 * real (heavy, CJS-interop-broken under jsdom) dictionary chunks are never
 * imported -- see the file-header note in passwordScorer.ts.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { loadScorer, __resetScorerCacheForTests } from '@/lib/passwordScorer'

describe('loadScorer', () => {
  beforeEach(() => {
    __resetScorerCacheForTests()
  })

  it('retries the import after a rejected load instead of caching the failure', async () => {
    const passingScorer = () => 4
    const importScorer = vi
      .fn<() => Promise<() => number>>()
      .mockRejectedValueOnce(new Error('chunk load failed'))
      .mockResolvedValueOnce(passingScorer)

    // First attempt fails (flaky chunk fetch).
    await expect(loadScorer({ language: 'en', importScorer })).rejects.toThrow(
      'chunk load failed'
    )

    // A later attempt must retry the import and succeed, rather than returning
    // the same poisoned rejected promise.
    const scorer = await loadScorer({ language: 'en', importScorer })
    expect(scorer).toBe(passingScorer)
    expect(importScorer).toHaveBeenCalledTimes(2)
  })

  it('reuses the cached scorer across calls for the same locale', async () => {
    const passingScorer = () => 3
    const importScorer = vi
      .fn<() => Promise<() => number>>()
      .mockResolvedValue(passingScorer)

    const first = await loadScorer({ language: 'en', importScorer })
    const second = await loadScorer({ language: 'en', importScorer })

    expect(first).toBe(passingScorer)
    expect(second).toBe(passingScorer)
    expect(importScorer).toHaveBeenCalledTimes(1)
  })

  it('shares the in-flight load promise between concurrent callers', async () => {
    const passingScorer = () => 2
    const importScorer = vi
      .fn<() => Promise<() => number>>()
      .mockResolvedValue(passingScorer)

    const [first, second] = await Promise.all([
      loadScorer({ language: 'en', importScorer }),
      loadScorer({ language: 'en', importScorer })
    ])

    expect(first).toBe(passingScorer)
    expect(second).toBe(passingScorer)
    expect(importScorer).toHaveBeenCalledTimes(1)
  })
})
