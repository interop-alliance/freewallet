/**
 * Verification aggregate-status helpers moved to
 * `@interop/vc-display`; re-exported here so existing importers are
 * unaffected. They read the five-step checklist and roll it up (hard failures:
 * bad signature / format / revocation; warnings: unknown issuer or expired).
 */
export {
  getVerificationAggregateStatus,
  isFullyVerified,
  isExpiredOnly,
  hasVerificationWarning
} from '@interop/vc-display'
