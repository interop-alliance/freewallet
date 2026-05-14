const UNITS = [
  { max: 60, value: 1_000, unit: 'second' },
  { max: 60, value: 60_000, unit: 'minute' },
  { max: 24, value: 3_600_000, unit: 'hour' },
  { max: 7, value: 86_400_000, unit: 'day' },
  { max: 4.34524, value: 604_800_000, unit: 'week' },
  { max: 12, value: 2_592_000_000, unit: 'month' },
  { max: Infinity, value: 31_536_000_000, unit: 'year' }
] as const

export function formatRelativeTime(
  input: string,
  locale?: string | string[]
): string {
  const date = new Date(input)
  if (Number.isNaN(date.getTime())) {
    return ''
  }

  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  const diff = date.getTime() - Date.now()

  for (const unit of UNITS) {
    const delta = diff / unit.value
    if (Math.abs(delta) < unit.max) {
      return rtf.format(Math.round(delta), unit.unit)
    }
  }

  return ''
}
