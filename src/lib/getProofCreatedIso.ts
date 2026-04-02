import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export function getProofCreatedIso(vc: IVerifiableCredential): string {
  const p = vc.proof
  if (p == null) {
    return ''
  }
  const first = Array.isArray(p) ? p[0] : p
  if (!first || typeof first !== 'object') {
    return ''
  }
  const created = (first as { created?: unknown }).created
  return typeof created === 'string' ? created : ''
}
