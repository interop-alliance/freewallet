import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { verifyResultToChecklist } from '@/lib/viewMappers/mapVerificationToUi'
import {
  issuerRegistryInfoFromVerifyPayload,
  type IssuerRegistryInfo
} from '@/lib/viewMappers/issuerRegistryInfo'
import { verifyCredential } from '@/lib/verify'
import type { VerificationResult } from '@/types/credential'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export interface UseVerificationReturn {
  result: VerificationResult | null
  loading: boolean
  error: Error | null
  verify: () => Promise<void>
  /**
   * Set when a verification attempt completes (success or structured failure).
   */
  lastCheckedAt: Date | null
  issuerRegistry: IssuerRegistryInfo | null
}

export function useVerification(
  credential: IVerifiableCredential | null | undefined,
  options: { runOnMount?: boolean } = { runOnMount: true }
): UseVerificationReturn {
  const { runOnMount = true } = options
  const { i18n } = useTranslation()
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const [lastCheckedAt, setLastCheckedAt] = useState<Date | null>(null)
  const [issuerRegistry, setIssuerRegistry] = useState<IssuerRegistryInfo | null>(
    null
  )

  useEffect(() => {
    setLastCheckedAt(null)
    setIssuerRegistry(null)
  }, [credential])

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
      const verifyPayload = await verifyCredential(credential)
      setResult(
        verifyResultToChecklist(
          verifyPayload as Record<string, unknown>,
          credential
        )
      )
      setIssuerRegistry(
        issuerRegistryInfoFromVerifyPayload(verifyPayload as Record<string, unknown>)
      )
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
  }, [credential])

  useEffect(() => {
    if (!runOnMount || !credential) {
      return
    }
    void verify()
  }, [runOnMount, credential, verify, i18n.language])

  return { result, loading, error, verify, lastCheckedAt, issuerRegistry }
}
