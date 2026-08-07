const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

/**
 * Splits a byte count into its numeric amount and unit (base-1024, e.g.
 * `{ amount: '2.4', unit: 'MB' }`). The primitive both display paths share --
 * {@link formatBytes} is the joined form.
 *
 * @param bytes {number}   the byte count to format
 * @returns {{ amount: string, unit: string }}
 */
export function formatBytesParts(bytes: number): {
  amount: string
  unit: string
} {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return { amount: '0', unit: 'B' }
  }

  const unitIndex = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    UNITS.length - 1
  )
  const value = bytes / 1024 ** unitIndex

  return {
    amount: unitIndex === 0 ? `${Math.round(value)}` : value.toFixed(1),
    unit: UNITS[unitIndex]
  }
}

/**
 * Formats a byte count for display (base-1024, e.g. "2.4 MB").
 *
 * @param bytes {number}   the byte count to format
 * @returns {string}
 */
export function formatBytes(bytes: number): string {
  const { amount, unit } = formatBytesParts(bytes)
  return `${amount} ${unit}`
}
