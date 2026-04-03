import { useCallback, useEffect, useState } from 'react'

import { verifyCredential } from '@/lib/verifyCredential'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'

import type { VerificationResult } from '@/types/verification'

export interface UseVerificationOptions {
  runOnMount?: boolean
}

export interface UseVerificationReturn {
  result: VerificationResult | null
  loading: boolean
  error: Error | null
  verify: () => Promise<void>
  /** Set when a verification attempt completes (success or structured failure). */
  lastCheckedAt: Date | null
}

export function useVerification(
  credential: IVerifiableCredential | null | undefined,
  options: UseVerificationOptions = {}
): UseVerificationReturn {
  const { runOnMount = true } = options
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const [lastCheckedAt, setLastCheckedAt] = useState<Date | null>(null)

  useEffect(() => {
    setLastCheckedAt(null)
  }, [credential])

  const verify = useCallback(async () => {
    if (!credential) {
      setResult(null)
      setError(null)
      return
    }
    setLoading(true)
    setError(null)
    try {
      setResult(await verifyCredential(credential))
      setLastCheckedAt(new Date())
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e))
      setError(err)
      setResult(null)
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
  }, [runOnMount, credential, verify])

  return { result, loading, error, verify, lastCheckedAt }
}
