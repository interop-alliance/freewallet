import type { IVerifiableCredential } from '@interop/data-integrity-core'

export function getProofCreatedIso(vc: IVerifiableCredential): string {
  const proof = vc.proof
  if (proof == null) {
    return ''
  }
  const first = Array.isArray(proof) ? proof[0] : proof
  if (!first || typeof first !== 'object') {
    return ''
  }
  const created = (first as { created?: unknown }).created
  return typeof created === 'string' ? created : ''
}
