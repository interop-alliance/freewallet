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
 * treated as revocation. The non-fatal `proof.unsupported-proofs` row (a proof
 * in a proof set no suite could check) has no legacy row and is not mapped;
 * it is logged as a diagnostic instead.
 */
import {
  verifyCredential as coreVerify,
  ProblemTypes,
  createIssuerDetailsSuite
} from '@interop/verifier-core'
import type {
  CredentialVerificationResult,
  CheckResult,
  ValidityPeriodPayload
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

// The phase-qualified ids verifier-core stamps on `results[]` rows.
const CHECK_ID = {
  signature: 'cryptographic.proof.signature',
  status: 'cryptographic.status.bitstring',
  validityPeriod: 'cryptographic.proof.validity-period',
  unsupportedProofs: 'cryptographic.proof.unsupported-proofs',
  issuerDetails: 'trust.issuer-details',
  parsing: 'cryptographic.parsing.envelope'
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
      additionalSuites: [issuerDetailsSuite],
      httpGetService
    })) as CredentialVerificationResult

    const parseFailure = core.results.find(
      result =>
        result.id === CHECK_ID.parsing && result.outcome.status === 'failure'
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
  const byId = (checkId: string): CheckResult | undefined =>
    core.results.find(result => result.id === checkId)

  const legacyLog: LegacyLogEntry[] = []

  // `proof.signature` judges the proof alone, so an authentic out-of-date
  // credential passes here and fails `proof.validity-period` below.
  const signature = byId(CHECK_ID.signature)
  if (signature) {
    legacyLog.push(legacyEntryFromCheck('valid_signature', signature))
  }

  const status = byId(CHECK_ID.status)
  // A status check that failed only because the status list could not be
  // fetched says nothing about the credential, so it is left out of the log
  // entirely rather than counting as a failed check.
  const statusListMissing =
    status?.outcome.status === 'failure' &&
    status.outcome.problems[0]?.type === ProblemTypes.STATUS_LIST_NOT_FOUND
  if (status && status.outcome.status !== 'skipped' && !statusListMissing) {
    legacyLog.push(legacyEntryFromCheck('revocation_status', status))
  }

  // The legacy `expiration` row is the one validity-date row the checklist
  // has, so a not-yet-valid credential rides it with the library's detail.
  // The check passes a credential stating no end date, where the checklist
  // expects no row at all, so the pass makes a row only when the check's
  // payload names the end date it judged.
  const validityPeriod = byId(CHECK_ID.validityPeriod)
  if (validityPeriod?.outcome.status === 'failure') {
    legacyLog.push(legacyEntryFromCheck('expiration', validityPeriod))
  } else if (validityPeriod?.outcome.status === 'success') {
    const judged = validityPeriod.outcome.payload as
      ValidityPeriodPayload | undefined
    if (judged?.end !== undefined) {
      legacyLog.push({ id: 'expiration', valid: true })
    }
  }

  const unsupportedProofs = byId(CHECK_ID.unsupportedProofs)
  if (unsupportedProofs?.outcome.status === 'failure') {
    log.warn('Some proofs in the credential could not be checked', {
      credentialId: core.verifiableCredential?.id,
      proofs: unsupportedProofs.outcome.problems.map(problem => problem.detail)
    })
  }

  const matchingIssuers = matchingIssuersFrom(byId(CHECK_ID.issuerDetails))
  legacyLog.push({
    id: 'registered_issuer',
    valid: matchingIssuers.length > 0,
    matchingIssuers,
    ...(matchingIssuers.length === 0
      ? { error: { message: CredentialErrorTypes.DidNotInRegistry } }
      : {})
  })

  const hasStatusError = legacyLog.some(
    entry => entry.id === 'revocation_status' && !!entry.error
  )

  const verified = legacyLog.every(entry => entry.valid)

  return {
    verified,
    credential: core.verifiableCredential,
    log: legacyLog,
    results: [
      { verified, log: legacyLog, credential: core.verifiableCredential }
    ],
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
