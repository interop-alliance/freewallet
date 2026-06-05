/**
 * Custom verification suite that surfaces rich issuer registry metadata.
 *
 * The un-bundled @interop/verifier-core gutted the registry check down to a
 * boolean `{ found, matchingRegistries }` and discards the rich issuer
 * payload (logo, legal name, homepage, registry org). This suite restores it:
 * it calls @digitalcredentials/issuer-registry-client's `lookupIssuersFor`
 * via the shared singleton client and returns the full `matchingIssuers`
 * entries on the check `outcome.payload` -- the same channel the verifier's
 * own `recognition.profile` uses. `verify.ts` reads this payload back into the
 * legacy `registered_issuer` log entry the view layer consumes.
 *
 * Severity: non-fatal (a warning) -- an unrecognized issuer is informational,
 * not a hard cryptographic failure.
 */
import type {
  CheckOutcome,
  VerificationCheck,
  VerificationContext,
  VerificationSubject,
  VerificationSuite
} from '@interop/verifier-core'
import { getCachedRegistryClient } from '@/lib/registryManager'

/**
 * Extracts the issuer DID from a credential, handling both the string and
 * `{ id }` object forms of the `issuer` property.
 *
 * @param credential {Record<string, unknown>}
 * @returns {string | undefined}
 */
function getIssuerDid(credential: Record<string, unknown>): string | undefined {
  const issuer = credential.issuer as string | { id?: string } | undefined
  if (typeof issuer === 'string') {
    return issuer
  }
  if (issuer && typeof issuer === 'object' && typeof issuer.id === 'string') {
    return issuer.id
  }
  return undefined
}

const issuerDetailsCheck: VerificationCheck = {
  id: 'trust.issuer-details',
  name: 'Issuer Registry Details',
  description:
    'Looks up rich issuer metadata for the credential issuer in the configured registries.',
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

    if (!context.registries || context.registries.length === 0) {
      return {
        status: 'skipped',
        reason: 'No registries configured in verification context.'
      }
    }

    const issuerDid = getIssuerDid(credential)
    if (!issuerDid) {
      return {
        status: 'skipped',
        reason: 'Credential has no issuer DID.'
      }
    }

    const client = getCachedRegistryClient({ registries: context.registries })
    const { matchingIssuers } = await client.lookupIssuersFor(issuerDid)

    const count = matchingIssuers.length
    return {
      status: 'success',
      message:
        count > 0
          ? `Issuer found in ${count} registr${count === 1 ? 'y' : 'ies'}.`
          : 'Issuer not found in any configured registry.',
      payload: { matchingIssuers }
    }
  }
}

/**
 * The issuer-details suite, appended to the verifier pipeline via
 * `additionalSuites`. This is the authoritative source of rich issuer data
 * for freewallet's issuer detail screen.
 */
export const issuerDetailsSuite: VerificationSuite = {
  id: 'trust',
  name: 'Issuer Trust',
  description: 'Surfaces rich issuer registry metadata.',
  phase: 'trust',
  checks: [issuerDetailsCheck]
}
