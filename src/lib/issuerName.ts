import type { IVerifiableCredential } from '@digitalcredentials/ssi'

/**
 * Extracts a human-readable issuer name from a Verifiable Credential.
 * Handles both plain DID strings and issuer objects with a name field.
 */
export function issuerName(credential: IVerifiableCredential): string {
  const { issuer } = credential
  if (typeof issuer === 'string') {
    return issuer
  }
  return issuer.name ?? issuer.id ?? 'Unknown Issuer'
}
