const DATE_FMT: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'short',
  day: 'numeric'
}

/**
 * Formats an ISO date string to a human-readable form (e.g. "Jan 15, 2025").
 * Returns empty string for falsy input, falls back to raw string on parse error.
 */
export function formatDate(iso: string): string {
  if (!iso) {
    return ''
  }
  try {
    return new Intl.DateTimeFormat('en-US', DATE_FMT).format(new Date(iso))
  } catch {
    return iso
  }
}
