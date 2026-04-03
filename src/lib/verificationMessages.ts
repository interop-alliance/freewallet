import type { VerificationResult, VerificationStep } from '@/types/verification'

export function isFullyVerified(result: VerificationResult | null): boolean {
  if (!result) {
    return false
  }
  return result.signature.valid && result.expiry.valid && result.status.valid
}

export function isFailed(result: VerificationResult): VerificationStep | null {
  if (!result.signature.valid) {
    return result.signature
  }
  if (!result.expiry.valid) {
    return result.expiry
  }
  if (!result.status.valid) {
    return result.status
  }
  return null
}

/** User-facing headline + body for the verification panel (not crypto data). */
export function getVerificationNarrative(
  result: VerificationResult | null,
  hookError: Error | null
): { headline: string; body: string } {
  if (hookError) {
    return {
      headline: 'There was an error verifying this credential.',
      body: hookError.message
    }
  }
  if (result && isFullyVerified(result)) {
    return {
      headline: 'This credential was verified successfully.',
      body: 'Cryptographic proof, validity period, and revocation status (if present) were checked successfully.'
    }
  }
  if (result) {
    const failed = isFailed(result)
    const detail =
      failed?.error ??
      failed?.message ??
      'The credential could not be fully verified. Contact the issuer if this problem continues.'
    return {
      headline: 'There was an error verifying this credential.',
      body: detail
    }
  }
  return {
    headline: 'Verification has not completed yet.',
    body: ''
  }
}
