import { useCallback, useEffect, useState } from 'react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
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

async function verifyAndMap(
  credential: IVerifiableCredential,
  t: TFunction
): Promise<{ result: VerificationResult; issuerRegistry: IssuerRegistryInfo | null }> {
  const verifyPayload = await verifyCredential(credential)
  const raw = verifyPayload as Record<string, unknown>
  return {
    result: verifyResultToChecklist(raw, credential, t),
    issuerRegistry: issuerRegistryInfoFromVerifyPayload(raw)
  }
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

  const verify = useCallback(async () => {
    if (!credential) {
      setResult(null)
      setError(null)
      setIssuerRegistry(null)
      return
    }
    setLoading(true)
    setError(null)
    try {
      const mapped = await verifyAndMap(credential, t)
      setResult(mapped.result)
      setIssuerRegistry(mapped.issuerRegistry)
      setLastCheckedAt(new Date())
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e))
      setError(err)
      setResult(null)
      setIssuerRegistry(null)
      setLastCheckedAt(new Date())
    } finally {
      setLoading(false)
    }
  }, [credential, t])

  useEffect(() => {
    if (!runOnMount || !credential) {
      return
    }
    let cancelled = false
    async function run() {
      setLoading(true)
      setError(null)
      try {
        const mapped = await verifyAndMap(credential!, t)
        if (cancelled) {
          return
        }
        setResult(mapped.result)
        setIssuerRegistry(mapped.issuerRegistry)
        setLastCheckedAt(new Date())
      } catch (e) {
        if (cancelled) {
          return
        }
        const err = e instanceof Error ? e : new Error(String(e))
        setError(err)
        setResult(null)
        setIssuerRegistry(null)
        setLastCheckedAt(new Date())
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [runOnMount, credential, i18n.language, t])

  return { result, loading, error, verify, lastCheckedAt, issuerRegistry }
}
