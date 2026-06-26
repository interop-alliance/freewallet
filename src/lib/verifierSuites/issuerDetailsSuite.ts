/**
 * Rich issuer registry lookup for verification UI. Uses `registryManager`
 * instead of verifier-core's boolean registry suite (non-fatal when unknown).
 */
import type {
  CheckOutcome,
  VerificationCheck,
  VerificationContext,
  VerificationSubject,
  VerificationSuite
} from '@interop/verifier-core'
import { registryManager } from '@/lib/registryManager'

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
    _context: VerificationContext
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

    const issuerDid = getIssuerDid(credential)
    if (!issuerDid) {
      return {
        status: 'skipped',
        reason: 'Credential has no issuer DID.'
      }
    }

    const { matchingIssuers } = await registryManager.lookupDid(issuerDid)
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

export const issuerDetailsSuite: VerificationSuite = {
  id: 'trust',
  name: 'Issuer Trust',
  description: 'Surfaces rich issuer registry metadata.',
  phase: 'trust',
  checks: [issuerDetailsCheck]
}
