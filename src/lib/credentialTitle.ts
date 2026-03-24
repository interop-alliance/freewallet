import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export function credentialTitle(credential: IVerifiableCredential): string {
  return credential.name ?? 'Verifiable Credential'
}
