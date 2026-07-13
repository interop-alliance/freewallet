/**
 * Small shape helpers for reading the loosely-typed fields of a Verifiable
 * Credential (its `type`, `issuer`, and `credentialSubject.id`), each of which
 * the VC data model allows in more than one form. Shared by the wallet-request
 * matching logic and the self-issued Login Credential module so the
 * normalization lives in exactly one place.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'

/**
 * Normalizes a `type` value (string or array) to an array of strings.
 *
 * @param type {unknown}
 * @returns {string[]}
 */
export function typeArray(type: unknown): string[] {
  if (typeof type === 'string') {
    return [type]
  }
  return Array.isArray(type)
    ? type.filter((entry): entry is string => typeof entry === 'string')
    : []
}

/**
 * Extracts a DID / id string from an issuer value that may be a string or an
 * `{ id }` object.
 *
 * @param issuer {unknown}
 * @returns {string | undefined}
 */
export function issuerId(issuer: unknown): string | undefined {
  if (typeof issuer === 'string') {
    return issuer
  }
  if (issuer && typeof issuer === 'object' && 'id' in issuer) {
    const { id } = issuer as { id?: unknown }
    return typeof id === 'string' ? id : undefined
  }
  return undefined
}

/**
 * The credentialSubject id of a VC, when present.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function subjectId(
  credential: IVerifiableCredential
): string | undefined {
  const subject = credential.credentialSubject as { id?: unknown } | undefined
  return subject && typeof subject.id === 'string' ? subject.id : undefined
}
