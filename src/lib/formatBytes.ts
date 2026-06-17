const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

/**
 * Formats a byte count for display (base-1024, e.g. "2.4 MB").
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B'
  }

  const unitIndex = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    UNITS.length - 1
  )
  const value = bytes / 1024 ** unitIndex

  if (unitIndex === 0) {
    return `${Math.round(value)} B`
  }

  return `${value.toFixed(1)} ${UNITS[unitIndex]}`
}

/**
 * Splits a byte count into its numeric amount and unit.
 * @param bytes {number} - The byte count to format.
 * @returns {Object} - An object containing the numeric amount and unit.
 * @property {string} amount - The numeric amount.
 * @property {string} unit - The unit.
 */
export function formatBytesParts(bytes: number): {
  amount: string
  unit: string
} {
  const formatted = formatBytes(bytes)
  const separator = formatted.lastIndexOf(' ')
  if (separator === -1) {
    return { amount: formatted, unit: '' }
  }
  return {
    amount: formatted.slice(0, separator),
    unit: formatted.slice(separator + 1)
  }
}
