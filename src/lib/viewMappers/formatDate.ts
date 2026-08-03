import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getExpirationDate } from '@interop/wallet-core/display'

import { DATE_FMT } from '@/app.config'

/**
 * Formats an ISO date string to a human-readable form (e.g. "Jan 15, 2025").
 * Returns empty string for falsy input, falls back to raw string on parse
 * error. `locale` is required (not defaulted) so a caller can't forget it and
 * silently render in the wrong language -- pass `i18n.language`. Timezone is
 * not a caller concern: `Intl.DateTimeFormat` already renders in the
 * runtime's local timezone unless a `timeZone` option overrides it, and
 * neither this function nor `DATE_FMT` ever sets one.
 */
export function formatDate({
  isoDate,
  locale
}: {
  isoDate: string
  locale: string
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

export function formatDateTime(date: Date, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(date)
  } catch {
    return date.toISOString()
  }
}

// --- VC data model: expiry (`validUntil` preferred, else VC 1.x `expirationDate`) ---

/**
 * The credential's raw ISO expiration string, or `''` when none. Thin
 * empty-string wrapper over the library's `getExpirationDate` (which returns
 * `undefined`).
 */
export function getExpirationDateIso(vc: IVerifiableCredential): string {
  return getExpirationDate(vc) ?? ''
}

export { getExpirationInstant } from '@interop/wallet-core/display'
