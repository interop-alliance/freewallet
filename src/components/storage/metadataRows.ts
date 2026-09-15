/**
 * The metadata card's row derivation: turning a Resource's or a Collection's
 * `/meta` document into the ordered, labeled rows the card renders. Kept
 * beside the component rather than inside it so the formatting rules are unit
 * testable on their own.
 */
import { formatBytes } from '@/lib/formatBytes'
import { formatDateTime } from '@/lib/viewMappers/formatDate'

// The members whose value is rendered as a timestamp rather than as its raw
// string.
const TIMESTAMP_KEYS = ['createdAt', 'updatedAt']

/**
 * Renders one metadata value for display, or returns null when the value has
 * no flat rendering (a nested object such as the `encryption` descriptor,
 * which the raw source view carries instead).
 *
 * @param options {object}
 * @param options.key {string}   the member name, which selects the formatting
 * @param options.value {unknown}
 * @param options.locale {string}
 * @returns {string | null}
 */
export function formatMetadataValue({
  key,
  value,
  locale
}: {
  key: string
  value: unknown
  locale: string
}): string | null {
  if (value === null || value === undefined) {
    return null
  }
  if (key === 'size' && typeof value === 'number') {
    return formatBytes(value)
  }
  if (TIMESTAMP_KEYS.includes(key) && typeof value === 'string') {
    const date = new Date(value)
    if (!Number.isNaN(date.getTime())) {
      return formatDateTime({ date, locale })
    }
    return value
  }
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value)
  }
  if (Array.isArray(value)) {
    const parts = value.filter(
      entry =>
        typeof entry === 'string' ||
        typeof entry === 'number' ||
        typeof entry === 'boolean'
    )
    return parts.length === value.length && parts.length > 0
      ? parts.map(entry => String(entry)).join(', ')
      : null
  }
  return null
}

/**
 * Derives the card's rows from a metadata document: the known members first,
 * in the order the caller listed them, then anything else the server sent
 * that has a flat rendering, so a member this wallet does not know about
 * still shows up. `custom` is excluded -- the card renders it separately.
 *
 * @param options {object}
 * @param options.meta {Record<string, unknown>}
 * @param options.fieldOrder {string[]}   the known members, in display order
 * @param options.locale {string}
 * @returns {Array<{ key: string, value: string }>}
 */
export function metadataRows({
  meta,
  fieldOrder,
  locale
}: {
  meta: Record<string, unknown>
  fieldOrder: string[]
  locale: string
}): Array<{ key: string; value: string }> {
  const ordered = [
    ...fieldOrder.filter(key => key in meta),
    ...Object.keys(meta).filter(key => !fieldOrder.includes(key))
  ]
  const rows: Array<{ key: string; value: string }> = []
  for (const key of ordered) {
    if (key === 'custom') {
      continue
    }
    const value = formatMetadataValue({ key, value: meta[key], locale })
    if (value !== null && value !== '') {
      rows.push({ key, value })
    }
  }
  return rows
}

/**
 * Combines a `/meta` read with the collection's encryption probe (a
 * governing-log read), keeping the two concurrent while letting a failed
 * probe never discard a successful meta read. On a probe rejection (a
 * continuity refusal, an unreachable host), `onProbeError` is called and
 * `encrypted` falls back to the document's own `encryption` member, which is
 * absent from a Resource Metadata object and so reads as `false` there.
 *
 * @param options {object}
 * @param options.fetchMeta {() => Promise<Record<string, unknown> | null>}
 * @param options.probeEncrypted {() => Promise<boolean>}   resolves whether
 *   the collection's governing log currently names an encryption descriptor
 * @param [options.onProbeError] {(err: unknown) => void}
 * @returns {Promise<{ meta: Record<string, unknown> | null; encrypted: boolean }>}
 */
export async function fetchMetaWithEncryptionProbe({
  fetchMeta,
  probeEncrypted,
  onProbeError
}: {
  fetchMeta: () => Promise<Record<string, unknown> | null>
  probeEncrypted: () => Promise<boolean>
  onProbeError?: (err: unknown) => void
}): Promise<{ meta: Record<string, unknown> | null; encrypted: boolean }> {
  const metaRead = fetchMeta()
  let governed = false
  try {
    governed = await probeEncrypted()
  } catch (err) {
    onProbeError?.(err)
  }
  const meta = await metaRead
  return { meta, encrypted: governed || Boolean(meta?.encryption) }
}
