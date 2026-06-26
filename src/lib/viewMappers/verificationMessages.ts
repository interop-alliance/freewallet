import type {
  VerificationAggregateStatus,
  VerificationResult
} from '@/types/credential'

/** Hard failures: bad signature, format, or revocation. Warnings: unknown issuer or expired. */
export function getVerificationAggregateStatus(
  result: VerificationResult | null
): VerificationAggregateStatus | null {
  if (!result) {
    return null
  }

  const hasFailure =
    !result.signature.valid ||
    !result.supportedFormat.valid ||
    !result.revocation.valid

  const hasWarning = !result.issuer.valid || !result.expiration.valid

  if (hasFailure) {
    return 'not_verified'
  }
  if (hasWarning) {
    return 'warning'
  }
  return 'verified'
}

export function isFullyVerified(result: VerificationResult | null): boolean {
  return getVerificationAggregateStatus(result) === 'verified'
}

export function isExpiredOnly(result: VerificationResult | null): boolean {
  if (!result) {
    return false
  }
  return (
    result.signature.valid &&
    result.supportedFormat.valid &&
    result.issuer.valid &&
    result.revocation.valid &&
    !result.expiration.valid
  )
}

export function hasVerificationWarning(result: VerificationResult | null): boolean {
  return getVerificationAggregateStatus(result) === 'warning'
}
