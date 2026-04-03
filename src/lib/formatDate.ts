import { DATE_FMT } from '@/app.config'

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
