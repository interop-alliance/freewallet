import type { IVerifiableCredential } from '@digitalcredentials/ssi'

import { DATE_FMT, VC_V2_CONTEXT_URL } from '@/app.config'

/**
 * Formats an ISO date string to a human-readable form (e.g. "Jan 15, 2025").
 * Returns empty string for falsy input, falls back to raw string on parse error.
 */
export function formatDate({
  isoDate,
  locale = 'en-US'
}: {
  isoDate: string
  locale?: string
}): string {
  if (!isoDate) {
    return ''
  }
  try {
    return new Intl.DateTimeFormat(locale, DATE_FMT).format(new Date(isoDate))
  } catch {
    return isoDate
  }
}

export function formatDateTime(date: Date, locale = 'en-US'): string {
  try {
    return new Intl.DateTimeFormat(locale, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(date)
  } catch {
    return date.toISOString()
  }
}

// --- VC data model: expiry fields (VC 2.0 `validUntil` vs VC 1.x `expirationDate`) ---

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
