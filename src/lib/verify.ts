/**
 * Adapter from @interop/verifier-core to the legacy `log[]` payload consumed by
 * the verification UI. Issuer recognition uses `issuerDetailsSuite` +
 * `registryManager`; the built-in registry suite is disabled (`registries: []`).
 *
 * Unpublished status lists (`STATUS_LIST_NOT_FOUND`) are dropped rather than
 * treated as revocation.
 */
import {
  verifyCredential as coreVerify,
  ProblemTypes,
  expirationSuite,
  createIssuerDetailsSuite
} from '@interop/verifier-core'
import type {
  CredentialVerificationResult,
  CheckResult
} from '@interop/verifier-core'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { registryManager } from '@/lib/registryManager'
import type { VerifyCredentialPayload } from '@/types/credential'

const issuerDetailsSuite = createIssuerDetailsSuite({
  lookupDid: (did: string) => registryManager.lookupDid(did)
})

const CredentialErrorTypes = {
  CouldNotBeVerified:
    'Credential could not be checked for verification and may be malformed.',
  DidNotInRegistry: 'Could not find issuer in registry with given DID.'
} as const

const CHECK_ID = {
  signature: 'proof.signature',
  status: 'status.bitstring',
  expiration: 'validity.expiration',
  issuerDetails: 'trust.issuer-details',
  parsing: 'parsing.envelope'
} as const

type MatchingIssuer = Record<string, unknown>
type LegacyLogEntry = NonNullable<VerifyCredentialPayload['log']>[number]

export async function verifyCredential(
  credential: IVerifiableCredential
): Promise<VerifyCredentialPayload> {
  try {
    const core = (await coreVerify({
      credential: credential as never,
      registries: [],
      additionalSuites: [expirationSuite, issuerDetailsSuite],
      verbose: true
    })) as CredentialVerificationResult

    const parseFailure = core.results.find(
      result =>
        result.check === CHECK_ID.parsing && result.outcome.status === 'failure'
    )
    if (parseFailure) {
      return createFatalErrorResult(
        credential,
        problemDetail(parseFailure) ?? CredentialErrorTypes.CouldNotBeVerified
      )
    }

    return mapCoreResultToLegacyPayload(core)
  } catch (err) {
    console.warn(err)
    return createFatalErrorResult(
      credential,
      CredentialErrorTypes.CouldNotBeVerified
    )
  }
}

function mapCoreResultToLegacyPayload(
  core: CredentialVerificationResult
): VerifyCredentialPayload {
  const byCheck = (checkId: string): CheckResult | undefined =>
    core.results.find(result => result.check === checkId)

  const log: LegacyLogEntry[] = []

  const signature = byCheck(CHECK_ID.signature)
  if (signature) {
    log.push(legacyEntryFromCheck('valid_signature', signature))
  }

  const status = byCheck(CHECK_ID.status)
  if (status && status.outcome.status !== 'skipped') {
    const entry = legacyEntryFromCheck('revocation_status', status)
    if (
      status.outcome.status === 'failure' &&
      status.outcome.problems[0]?.type === ProblemTypes.STATUS_LIST_NOT_FOUND
    ) {
      entry.error = { ...entry.error, name: 'status_list_not_found' }
    }
    log.push(entry)
  }

  const expiration = byCheck(CHECK_ID.expiration)
  if (expiration && expiration.outcome.status !== 'skipped') {
    log.push(legacyEntryFromCheck('expiration', expiration))
  }

  const matchingIssuers = matchingIssuersFrom(byCheck(CHECK_ID.issuerDetails))
  log.push({
    id: 'registered_issuer',
    valid: matchingIssuers.length > 0,
    matchingIssuers,
    ...(matchingIssuers.length === 0
      ? { error: { message: CredentialErrorTypes.DidNotInRegistry } }
      : {})
  })

  const revocationIndex = log.findIndex(
    entry =>
      entry.id === 'revocation_status' &&
      entry.error?.name === 'status_list_not_found'
  )
  if (revocationIndex !== -1) {
    log.splice(revocationIndex, 1)
  }

  const hasStatusError = log.some(
    entry => entry.id === 'revocation_status' && !!entry.error
  )

  const verified = log.every(entry => entry.valid)

  return {
    verified,
    credential: core.verifiableCredential,
    log,
    results: [{ verified, log, credential: core.verifiableCredential }],
    ...(hasStatusError ? { hasStatusError } : {})
  }
}

function matchingIssuersFrom(check: CheckResult | undefined): MatchingIssuer[] {
  if (!check || check.outcome.status !== 'success') {
    return []
  }
  const payload = check.outcome.payload as
    { matchingIssuers?: MatchingIssuer[] } | undefined
  return payload?.matchingIssuers ?? []
}

function legacyEntryFromCheck(id: string, check: CheckResult): LegacyLogEntry {
  if (check.outcome.status === 'success') {
    return { id, valid: true }
  }
  const message = problemDetail(check)
  return {
    id,
    valid: false,
    ...(message ? { error: { message } } : {})
  }
}

function problemDetail(check: CheckResult): string | undefined {
  if (check.outcome.status !== 'failure') {
    return undefined
  }
  const problem = check.outcome.problems[0]
  if (!problem) {
    return undefined
  }
  return problem.detail || problem.title
}

function createFatalErrorResult(
  credential: IVerifiableCredential,
  message: string
): VerifyCredentialPayload {
  const result: VerifyCredentialPayload = {
    verified: false,
    results: [
      {
        verified: false,
        credential,
        log: [
          { id: 'expiration', valid: false },
          { id: 'valid_signature', valid: false },
          { id: 'issuer_did_resolves', valid: false },
          { id: 'revocation_status', valid: false }
        ]
      }
    ]
  }
  addErrorToResult(result as { results: unknown[] }, message, true)
  return result
}

function addErrorToResult(
  result: { results: unknown[] },
  message: string,
  isFatal = true
) {
  ;(result.results[0] as Record<string, unknown>).error = {
    details: {
      cause: {
        message,
        name: 'Error'
      }
    },
    message,
    name: 'Error',
    isFatal
  }
}
