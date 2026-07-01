/**
 * Cryptosuite negotiation and proof-suite construction for signed Verifiable
 * Presentations. Ported from DCW's `presentationSuite.ts`.
 */
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { eddsaRdfc2022 } from '@interop/ed25519-signature/eddsa-rdfc-2022'
import type { ISigner } from '@interop/data-integrity-core'
import type { IVPRQuery } from './types'

/**
 * VCALM cryptosuite identifier for the modern EdDSA Data Integrity proof. This
 * is what a verifier lists in `acceptedCryptosuites` to ask for a
 * `DataIntegrityProof` (VC 2.0) presentation instead of the legacy default.
 *
 * @see https://www.w3.org/TR/vc-data-integrity/
 */
export const EDDSA_RDFC_2022 = 'eddsa-rdfc-2022'

/**
 * Cryptosuites this wallet can produce for a presentation proof when a verifier
 * offers a choice via VCALM `acceptedCryptosuites`. `Ed25519Signature2020` is
 * deliberately absent: it is the wallet's default, used as a fallback whenever
 * the verifier expresses no (supported) preference, for backwards compatibility
 * with verifiers that predate cryptosuite negotiation.
 */
const SUPPORTED_CRYPTOSUITES = [EDDSA_RDFC_2022]

/** VC Data Model 2.0 context URL. */
const CREDENTIALS_CONTEXT_V2_URL = 'https://www.w3.org/ns/credentials/v2'

/**
 * Returns true if a JSON-LD `@context` value contains the given URL.
 */
function contextIncludes(context: unknown, url: string): boolean {
  if (typeof context === 'string') {
    return context === url
  }
  if (Array.isArray(context)) {
    return context.includes(url)
  }
  return false
}

/**
 * Decides the cryptosuite the wallet should sign a presentation with, in two
 * tiers:
 *
 * 1. The explicit, spec-sanctioned signal: an `acceptedCryptosuites` preference
 *    (allowed on both DIDAuthentication and QueryByExample queries). The
 *    verifier's stated order is honored, picking the first listed suite the
 *    wallet supports. If the verifier listed suites but none are supported, the
 *    wallet falls back to its default rather than overriding their explicit
 *    choice with the heuristic below.
 * 2. A fallback heuristic when no `acceptedCryptosuites` is given: if a
 *    QueryByExample asks for a VC 2.0 example credential, infer the verifier
 *    wants a VC 2.0 `DataIntegrityProof` (eddsa-rdfc-2022) response.
 *
 * Returns `undefined` when neither tier yields a supported suite, signalling
 * that the caller should sign with the wallet default (Ed25519Signature2020,
 * VC 1.0).
 *
 * @param queries {IVPRQuery[]}
 * @returns {string | undefined}
 * @see https://w3c.github.io/vcalm/ -- the `acceptedCryptosuites` query field
 */
export function negotiateCryptosuite(queries: IVPRQuery[]): string | undefined {
  const accepted = queries.flatMap(query =>
    'acceptedCryptosuites' in query && query.acceptedCryptosuites
      ? query.acceptedCryptosuites.map(({ cryptosuite }) => cryptosuite)
      : []
  )
  if (accepted.length > 0) {
    return accepted.find(cryptosuite =>
      SUPPORTED_CRYPTOSUITES.includes(cryptosuite)
    )
  }

  // Fallback: a QueryByExample requesting a VC 2.0 example credential implies
  // the verifier operates in the VC 2.0 data model, so respond in kind.
  const requestsV2Example = queries.some(
    query =>
      query.type === 'QueryByExample' &&
      contextIncludes(
        query.credentialQuery?.example?.['@context'],
        CREDENTIALS_CONTEXT_V2_URL
      )
  )
  return requestsV2Example ? EDDSA_RDFC_2022 : undefined
}

/**
 * Builds the proof suite and the VC Data Model version to use for a presentation
 * proof. The negotiated `eddsa-rdfc-2022` cryptosuite emits a
 * `DataIntegrityProof` and requires the VC 2.0 context (which defines
 * `challenge`/`domain` only within the `DataIntegrityProof` scope); the default
 * `Ed25519Signature2020` suite uses the VC 1.0 context.
 *
 * @param options {object}
 * @param options.signer {ISigner}
 * @param [options.cryptosuite] {string}
 * @returns {{ suite: DataIntegrityProof, version: number }}
 */
export function presentationSuiteFor({
  signer,
  cryptosuite
}: {
  signer: ISigner
  cryptosuite?: string
}): { suite: DataIntegrityProof; version: number } {
  if (cryptosuite === EDDSA_RDFC_2022) {
    return {
      suite: new DataIntegrityProof({ signer, cryptosuite: eddsaRdfc2022 }),
      version: 2.0
    }
  }
  return { suite: new Ed25519Signature2020({ signer }), version: 1.0 }
}
