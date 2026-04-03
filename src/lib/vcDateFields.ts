import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { VC_V2_CONTEXT_URL } from '@/app.config'

export function isVc2FirstContext(vc: IVerifiableCredential): boolean {
  const ctx = vc['@context']
  return (Array.isArray(ctx) ? ctx[0] : ctx) === VC_V2_CONTEXT_URL
}

export function getExpirationDateIso(vc: IVerifiableCredential): string {
  if (isVc2FirstContext(vc)) {
    return vc.validUntil ?? ''
  }
  return vc.expirationDate ?? ''
}

export function getExpirationInstant(vc: IVerifiableCredential): Date | null {
  const iso = getExpirationDateIso(vc)
  if (!iso) {
    return null
  }
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}
