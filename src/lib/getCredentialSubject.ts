import type { IVerifiableCredential } from '@digitalcredentials/ssi'

/** First `credentialSubject` entry when the property is an array. */
export function getCredentialSubject(vc: IVerifiableCredential): any {
  const sbj = vc.credentialSubject
  return Array.isArray(sbj) ? sbj[0] : sbj
}
