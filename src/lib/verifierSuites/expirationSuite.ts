/**
 * Custom verification suite that re-adds the credential expiration check the
 * un-bundled @interop/verifier-core removed ("to be added in future"). It is
 * appended to the pipeline via `additionalSuites` and reads the credential's
 * expiry off the verification subject, comparing it against the injected
 * `timeService`. Kept deliberately small so it can be deleted in favor of the
 * built-in check once expiration returns upstream.
 *
 * Severity: non-fatal (a warning), matching freewallet's existing model where
 * expiration is a soft check rather than a hard failure.
 */
import type {
  CheckOutcome,
  VerificationCheck,
  VerificationContext,
  VerificationSubject,
  VerificationSuite
} from '@interop/verifier-core'

/**
 * Own problem `type` URI for an expired credential. The fork has no built-in
 * EXPIRED problem type, so we mint one in the freewallet namespace.
 */
export const EXPIRED_PROBLEM_TYPE = 'urn:freewallet:problem:EXPIRED'

/**
 * Reads the credential's expiry instant, preferring the VC 2.0 `validUntil`
 * property and falling back to the VC 1.x `expirationDate`.
 *
 * @param credential {Record<string, unknown>}
 * @returns {string | undefined}   The ISO date string, or undefined when none.
 */
function getExpirationIso(
  credential: Record<string, unknown>
): string | undefined {
  const validUntil = credential.validUntil
  if (typeof validUntil === 'string' && validUntil) {
    return validUntil
  }
  const expirationDate = credential.expirationDate
  if (typeof expirationDate === 'string' && expirationDate) {
    return expirationDate
  }
  return undefined
}

const expirationCheck: VerificationCheck = {
  id: 'validity.expiration',
  name: 'Credential Expiration Check',
  description:
    'Verifies the credential is within its validity period (validUntil / expirationDate).',
  fatal: false,
  appliesTo: ['verifiableCredential'],
  execute: async (
    subject: VerificationSubject,
    context: VerificationContext
  ): Promise<CheckOutcome> => {
    const credential = subject.verifiableCredential as
      | Record<string, unknown>
      | undefined

    if (!credential) {
      return {
        status: 'skipped',
        reason: 'No verifiable credential found in subject.'
      }
    }

    const expirationIso = getExpirationIso(credential)
    if (!expirationIso) {
      return {
        status: 'skipped',
        reason: 'Credential has no expiration date.'
      }
    }

    const expiresMs = new Date(expirationIso).getTime()
    if (Number.isNaN(expiresMs)) {
      return {
        status: 'skipped',
        reason: 'Credential expiration date is not a valid date.'
      }
    }

    const nowMs = context.timeService
      ? context.timeService.dateNowMs()
      : Date.now()

    if (expiresMs >= nowMs) {
      return {
        status: 'success',
        message: `Credential is within its validity period (expires ${expirationIso}).`
      }
    }

    return {
      status: 'failure',
      problems: [
        {
          type: EXPIRED_PROBLEM_TYPE,
          title: 'Credential Expired',
          detail: `Credential expired on ${expirationIso}.`
        }
      ]
    }
  }
}

/**
 * The expiration suite, appended to the verifier pipeline via
 * `additionalSuites`.
 */
export const expirationSuite: VerificationSuite = {
  id: 'validity',
  name: 'Validity Period',
  description: 'Checks the credential expiration / validity period.',
  phase: 'cryptographic',
  checks: [expirationCheck]
}
