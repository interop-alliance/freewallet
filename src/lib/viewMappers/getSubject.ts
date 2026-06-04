import type { IVerifiableCredential } from '@interop/data-integrity-core'

/**
 * First `credentialSubject` entry when the property is an array.
 */
export function getSubject(vc: IVerifiableCredential) {
  const sbj = vc.credentialSubject
  return Array.isArray(sbj) ? sbj[0] : sbj
}
