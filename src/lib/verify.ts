/**
 * Adapter from @interop/verifier-core to the legacy `log[]` payload consumed by
 * the verification UI. Every remote fetch verification makes (DID documents,
 * JSON-LD contexts, status lists) goes direct first and retries through the
 * CORS proxy on a rejected fetch. Issuer recognition uses `issuerDetailsSuite` +
 * `registryManager` (which routes each registry request direct or through the
 * CORS proxy by what a browser can reach); the
 * built-in registry suite is disabled (`registries: []`).
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
  CheckResult,
  ProblemDetail
} from '@interop/verifier-core'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { registryManager } from '@/lib/registryManager'
import { proxyFallbackHttpGetService } from '@/lib/corsProxy'
import type { VerifyCredentialPayload } from '@/types/credential'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:verify')

// One instance for the module's life: verifier-core memoizes its document
// loader per service instance, so a fresh one per call would defeat it.
const httpGetService = proxyFallbackHttpGetService()

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
      verbose: true,
      httpGetService
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
    log.warn('Credential verification threw', { err })
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

  // verifier-core judges the validity dates only once the signature has
  // verified, so a `proof.signature` failure typed as expired or not yet
  // valid proves an authentic, out-of-date credential: the signature row
  // passes and the expiry row carries the failure instead.
  const signature = byCheck(CHECK_ID.signature)
  const outOfDate = signature && outOfDateProblem(signature)
  if (outOfDate) {
    log.push({ id: 'valid_signature', valid: true })
  } else if (signature) {
    log.push(legacyEntryFromCheck('valid_signature', signature))
  }

  const status = byCheck(CHECK_ID.status)
  // A status check that failed only because the status list could not be
  // fetched says nothing about the credential, so it is left out of the log
  // entirely rather than counting as a failed check.
  const statusListMissing =
    status?.outcome.status === 'failure' &&
    status.outcome.problems[0]?.type === ProblemTypes.STATUS_LIST_NOT_FOUND
  if (status && status.outcome.status !== 'skipped' && !statusListMissing) {
    log.push(legacyEntryFromCheck('revocation_status', status))
  }

  // A fatal signature failure halts the opt-in expiration suite, but the
  // signature row having already claimed the expiry keeps one row either way.
  const expiration = byCheck(CHECK_ID.expiration)
  if (outOfDate) {
    log.push({
      id: 'expiration',
      valid: false,
      error: { message: problemMessage(outOfDate) }
    })
  } else if (expiration && expiration.outcome.status !== 'skipped') {
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

const OUT_OF_DATE_PROBLEM_TYPES: readonly string[] = [
  ProblemTypes.CREDENTIAL_EXPIRED,
  ProblemTypes.CREDENTIAL_NOT_YET_VALID
]

/**
 * The expired or not-yet-valid problem a failed signature check reports,
 * or undefined for a success, a skip, or any other failure (a tampered
 * credential included). A check reporting a date problem beside any other
 * problem is not out of date: a crypto service may report a bad signature
 * and an expiry together, and the signature row must not pass on it.
 */
function outOfDateProblem(check: CheckResult): ProblemDetail | undefined {
  if (check.outcome.status !== 'failure') {
    return undefined
  }
  const { problems } = check.outcome
  const allOutOfDate =
    problems.length > 0 &&
    problems.every(problem => OUT_OF_DATE_PROBLEM_TYPES.includes(problem.type))
  return allOutOfDate ? problems[0] : undefined
}

function problemDetail(check: CheckResult): string | undefined {
  if (check.outcome.status !== 'failure') {
    return undefined
  }
  const problem = check.outcome.problems[0]
  if (!problem) {
    return undefined
  }
  return problemMessage(problem)
}

function problemMessage(problem: ProblemDetail): string {
  return problem.detail || problem.title
}

function createFatalErrorResult(
  credential: IVerifiableCredential,
  message: string
): VerifyCredentialPayload {
  return {
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
        ],
        error: {
          details: { cause: { message, name: 'Error' } },
          message,
          name: 'Error',
          isFatal: true
        }
      }
    ]
  }
}
