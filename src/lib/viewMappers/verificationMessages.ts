import type { TFunction } from 'i18next'
import type { VerificationResult } from '@/types/credential'

export function isFullyVerified(result: VerificationResult | null): boolean {
  if (!result) {
    return false
  }
  return result.signature.valid && result.expiry.valid && result.status.valid
}

export function isExpiredOnly(result: VerificationResult | null): boolean {
  if (!result) {
    return false
  }
  return result.signature.valid && !result.expiry.valid && result.status.valid
}

/** User-facing headline + body for the verification panel (not crypto data). */
export function getVerificationNarrative(
  result: VerificationResult | null,
  hookError: Error | null,
  t: TFunction
): { headline: string; body: string } {
  if (hookError) {
    return {
      headline: t('verification.narrative.hookErrorHeadline'),
      body: hookError.message
    }
  }
  if (result && isFullyVerified(result)) {
    return {
      headline: t('verification.narrative.verifiedHeadline'),
      body: t('verification.narrative.verifiedBody')
    }
  }
  if (result && isExpiredOnly(result)) {
    return {
      headline: t('verification.narrative.expiredHeadline'),
      body: ''
    }
  }
  if (result) {
    const failed = [result.signature, result.expiry, result.status].find(
      step => !step.valid
    )
    const detail =
      failed?.error ??
      failed?.message ??
      t('verification.narrative.failedBodyFallback')
    return {
      headline: t('verification.narrative.failedHeadline'),
      body: detail
    }
  }
  return {
    headline: t('verification.narrative.pendingHeadline'),
    body: ''
  }
}
