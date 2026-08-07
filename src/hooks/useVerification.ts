import { useCallback, useEffect, useState } from 'react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { canonicalize as jcsCanonicalize } from 'json-canonicalize'
import { verifyResultToChecklist } from '@/lib/viewMappers/mapVerificationToUi'
import {
  issuerRegistryInfoFromVerifyPayload,
  type IssuerRegistryInfo
} from '@/lib/viewMappers/issuerRegistryInfo'
import { verifyCredential } from '@/lib/verify'
import type { VerificationResult } from '@/types/credential'
import type { IVerifiableCredential } from '@interop/data-integrity-core'

export interface UseVerificationReturn {
  result: VerificationResult | null
  loading: boolean
  error: Error | null
  verify: () => Promise<void>
  lastCheckedAt: Date | null
  issuerRegistry: IssuerRegistryInfo | null
}

/**
 * How long a verification result stays reusable. Verifying a credential does
 * full JSON-LD canonicalization, a signature check, and status-list plus
 * registry network fetches, so remounts (e.g. a dashboard sync tick) and
 * revisits within this window reuse the cached result instead of redoing all
 * of that work. The window is short enough that a freshly revoked or expired
 * credential is re-checked soon after.
 */
const VERIFICATION_CACHE_TTL_MS = 5 * 60 * 1000

interface VerificationCacheEntry {
  checkedAt: number
  result: VerificationResult
  issuerRegistry: IssuerRegistryInfo | null
}

/**
 * Module-level, process-lifetime cache of verification results. Keyed by the
 * canonicalized credential plus the active language (checklist messages are
 * localized), so distinct credentials and languages never collide. Only
 * successful mappings are stored -- transient failures fall through and are
 * retried on the next mount.
 */
const verificationCache = new Map<string, VerificationCacheEntry>()

function verificationCacheKey(
  credential: IVerifiableCredential,
  language: string
): string {
  return `${language}::${jcsCanonicalize(credential as object)}`
}

/**
 * Synchronously read a still-fresh cache entry, or `null` on miss/expiry.
 */
function readVerificationCache(
  credential: IVerifiableCredential,
  language: string
): VerificationCacheEntry | null {
  const cached = verificationCache.get(
    verificationCacheKey(credential, language)
  )
  if (cached && Date.now() - cached.checkedAt < VERIFICATION_CACHE_TTL_MS) {
    return cached
  }
  return null
}

async function verifyAndMap(
  credential: IVerifiableCredential,
  t: TFunction
): Promise<{
  result: VerificationResult
  issuerRegistry: IssuerRegistryInfo | null
}> {
  const verifyPayload = await verifyCredential(credential)
  const raw = verifyPayload as Record<string, unknown>
  return {
    result: verifyResultToChecklist(raw, credential, t),
    issuerRegistry: issuerRegistryInfoFromVerifyPayload(raw)
  }
}

/**
 * Verify a credential and store the freshly mapped result in the cache,
 * overwriting any prior entry for the same credential/language. Used both on a
 * cache miss and by the imperative `verify()` re-check, which always bypasses
 * the cache.
 */
async function verifyAndStore(
  credential: IVerifiableCredential,
  t: TFunction,
  language: string
): Promise<VerificationCacheEntry> {
  const mapped = await verifyAndMap(credential, t)
  const entry: VerificationCacheEntry = {
    checkedAt: Date.now(),
    result: mapped.result,
    issuerRegistry: mapped.issuerRegistry
  }
  verificationCache.set(verificationCacheKey(credential, language), entry)
  return entry
}

export function useVerification(
  credential: IVerifiableCredential | null | undefined,
  options: { runOnMount?: boolean } = { runOnMount: true }
): UseVerificationReturn {
  const { runOnMount = true } = options
  const { t, i18n } = useTranslation()
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const [lastCheckedAt, setLastCheckedAt] = useState<Date | null>(null)
  const [issuerRegistry, setIssuerRegistry] =
    useState<IssuerRegistryInfo | null>(null)

  const [previousCredential, setPreviousCredential] = useState(credential)
  if (previousCredential !== credential) {
    setPreviousCredential(credential)
    setLastCheckedAt(null)
  }

  // Runs one verification pass and applies its outcome. `isStale` lets the
  // mount effect drop a result whose run was superseded (a cancelled effect);
  // the imperative `verify` never cancels and passes nothing.
  const runVerification = useCallback(
    async (
      subject: IVerifiableCredential,
      language: string,
      isStale?: () => boolean
    ) => {
      setLoading(true)
      setError(null)
      try {
        const entry = await verifyAndStore(subject, t, language)
        if (isStale?.()) {
          return
        }
        setResult(entry.result)
        setIssuerRegistry(entry.issuerRegistry)
        setLastCheckedAt(new Date(entry.checkedAt))
      } catch (err) {
        if (isStale?.()) {
          return
        }
        const error = err instanceof Error ? err : new Error(String(err))
        setError(error)
        setResult(null)
        setIssuerRegistry(null)
        setLastCheckedAt(new Date())
      } finally {
        if (!isStale?.()) {
          setLoading(false)
        }
      }
    },
    [t]
  )

  const verify = useCallback(async () => {
    if (!credential) {
      setResult(null)
      setError(null)
      setIssuerRegistry(null)
      return
    }
    // The imperative re-check always bypasses the cache and refreshes it.
    await runVerification(credential, i18n.language)
  }, [credential, i18n.language, runVerification])

  useEffect(() => {
    if (!runOnMount || !credential) {
      return
    }
    const language = i18n.language
    let cancelled = false
    async function run() {
      // A fresh cached result skips the whole verification pass. It is applied
      // before the first await (so before paint), avoiding the "verifying"
      // flicker on remount.
      const cached = readVerificationCache(credential!, language)
      if (cached) {
        setResult(cached.result)
        setIssuerRegistry(cached.issuerRegistry)
        setLastCheckedAt(new Date(cached.checkedAt))
        setError(null)
        setLoading(false)
        return
      }
      await runVerification(credential!, language, () => cancelled)
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [runOnMount, credential, i18n.language, runVerification])

  return { result, loading, error, verify, lastCheckedAt, issuerRegistry }
}
