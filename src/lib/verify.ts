/**
 * Credential verification against the DCC Known Registries.
 *
 * Adapter over @interop/verifier-core: a single `verifyCredential` call runs
 * the fork's default suite pipeline plus two custom suites
 * (`expirationSuite`, `issuerDetailsSuite`), then translates the unified
 * `CredentialVerificationResult` back into freewallet's legacy
 * `VerifyCredentialPayload` (the flat `log[]` shape) so the view layer
 * (`mapVerificationToUi`, `issuerRegistryInfo`, `VerificationPanel`,
 * `IssuerDetailPage`, ...) stays unchanged.
 *
 * Notable special case: if the revocation check fails because the referenced
 * status list could not be fetched (`STATUS_LIST_NOT_FOUND`), that row is
 * dropped and the credential is not treated as revoked (the status list simply
 * isn't published).
 */
import {
  verifyCredential as coreVerify,
  ProblemTypes
} from '@interop/verifier-core'
import type {
  CredentialVerificationResult,
  CheckResult,
  EntityIdentityRegistry
} from '@interop/verifier-core'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { KNOWN_REGISTRIES_URL, KnownDidRegistries } from '@/app.config'
import { expirationSuite } from '@/lib/verifierSuites/expirationSuite'
import { issuerDetailsSuite } from '@/lib/verifierSuites/issuerDetailsSuite'
import type { VerifyCredentialPayload } from '@/types/credential'

const CredentialErrorTypes = {
  CouldNotBeVerified:
    'Credential could not be checked for verification and may be malformed.',
  DidNotInRegistry: 'Could not find issuer in registry with given DID.'
} as const

/**
 * Dot-separated check ids emitted by the verifier-core pipeline (and the two
 * custom suites) that the adapter maps onto legacy log entries.
 */
const CHECK_ID = {
  signature: 'proof.signature',
  status: 'status.bitstring',
  expiration: 'validity.expiration',
  issuerDetails: 'trust.issuer-details',
  parsing: 'parsing.envelope'
} as const

/**
 * Legacy `registered_issuer` rich entries. Mirrors `MatchingIssuerEntry` in
 * `issuerRegistryInfo.ts`; kept loose here since it is copied through verbatim.
 */
type MatchingIssuer = Record<string, unknown>

type LegacyLogEntry = NonNullable<VerifyCredentialPayload['log']>[number]

/**
 * Fetches the remote DCC Known Registries list, falling back to the bundled
 * KnownDidRegistries const on any failure.
 *
 * @returns {Promise<EntityIdentityRegistry[]>}
 */
async function loadKnownDIDRegistries(): Promise<EntityIdentityRegistry[]> {
  try {
    const regRes = await fetch(KNOWN_REGISTRIES_URL)
    if (!regRes.ok) {
      throw new Error(`Registry fetch failed: ${regRes.status}`)
    }
    return (await regRes.json()) as EntityIdentityRegistry[]
  } catch (err) {
    console.warn('Using fallback KnownDidRegistries:', err)
    return KnownDidRegistries
  }
}

export async function verifyCredential(
  credential: IVerifiableCredential
): Promise<VerifyCredentialPayload> {
  try {
    const registries = await loadKnownDIDRegistries()

    const core = (await coreVerify({
      credential: credential as never,
      registries,
      additionalSuites: [expirationSuite, issuerDetailsSuite],
      // verbose so results[] carries EVERY check (incl. successes), not just
      // failures folded into summary[].
      verbose: true
    })) as CredentialVerificationResult

    // A structural / parse failure means the credential is malformed -- surface
    // it as a fatal error, matching the previous library's `errors` handling.
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

/**
 * Translates a verifier-core `CredentialVerificationResult` into the legacy
 * `VerifyCredentialPayload` the freewallet view layer consumes.
 *
 * @param core {CredentialVerificationResult}
 * @returns {VerifyCredentialPayload}
 */
function mapCoreResultToLegacyPayload(
  core: CredentialVerificationResult
): VerifyCredentialPayload {
  const byCheck = (checkId: string): CheckResult | undefined =>
    core.results.find(result => result.check === checkId)

  const log: LegacyLogEntry[] = []

  // valid_signature -- from proof.signature.
  const signature = byCheck(CHECK_ID.signature)
  if (signature) {
    log.push(legacyEntryFromCheck('valid_signature', signature))
  }

  // revocation_status -- from status.bitstring. Omitted when skipped (the
  // credential has no credentialStatus, so the view layer reports no status).
  const status = byCheck(CHECK_ID.status)
  if (status && status.outcome.status !== 'skipped') {
    const entry = legacyEntryFromCheck('revocation_status', status)
    if (
      status.outcome.status === 'failure' &&
      status.outcome.problems[0]?.type === ProblemTypes.STATUS_LIST_NOT_FOUND
    ) {
      // Tag so the drop-this-row special case below fires: an unpublished
      // status list is not a revocation.
      entry.error = { ...entry.error, name: 'status_list_not_found' }
    }
    log.push(entry)
  }

  // expiration -- from validity.expiration. Omitted when skipped so the view
  // layer's fallback (mapVerificationToUi) recomputes from the credential.
  const expiration = byCheck(CHECK_ID.expiration)
  if (expiration && expiration.outcome.status !== 'skipped') {
    log.push(legacyEntryFromCheck('expiration', expiration))
  }

  // registered_issuer -- from the trust.issuer-details payload (rich entries).
  const matchingIssuers = matchingIssuersFrom(byCheck(CHECK_ID.issuerDetails))
  log.push({
    id: 'registered_issuer',
    valid: matchingIssuers.length > 0,
    matchingIssuers,
    ...(matchingIssuers.length === 0
      ? { error: { message: CredentialErrorTypes.DidNotInRegistry } }
      : {})
  })

  // Drop a status_list_not_found revocation row: an unpublished status list
  // means the credential is simply unchecked, not revoked.
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
    // results[0].log shares the same array so getVerifyLogFromPayload (which
    // prefers results[0].log) sees the rich entries, incl. matchingIssuers.
    results: [{ verified, log, credential: core.verifiableCredential }],
    ...(hasStatusError ? { hasStatusError } : {})
  }
}

/**
 * Pulls the rich `matchingIssuers` array off the issuer-details check payload.
 *
 * @param check {CheckResult | undefined}
 * @returns {MatchingIssuer[]}
 */
function matchingIssuersFrom(check: CheckResult | undefined): MatchingIssuer[] {
  if (!check || check.outcome.status !== 'success') {
    return []
  }
  const payload = check.outcome.payload as
    | { matchingIssuers?: MatchingIssuer[] }
    | undefined
  return payload?.matchingIssuers ?? []
}

/**
 * Builds a legacy `{ id, valid, error? }` log entry from a verifier-core
 * check result (success -> valid; failure -> invalid + first problem message).
 *
 * @param id {string}
 * @param check {CheckResult}
 * @returns {LegacyLogEntry}
 */
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

/**
 * Returns the human-readable text of a failed check's first problem (detail,
 * falling back to title), or undefined for non-failure outcomes.
 *
 * @param check {CheckResult}
 * @returns {string | undefined}
 */
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
