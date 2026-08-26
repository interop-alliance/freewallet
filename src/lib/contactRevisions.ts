/**
 * The contact-revision ordering shared by both synced-collection backends
 * (the local `BrowserStore` replica and the remote-direct backend): revisions
 * sort by the logical timestamp their payloads carry, never by row insertion
 * order, so a history read is identical whichever backend served it.
 */
import type { ContactRevisionPayload } from '@interop/social-core'

/**
 * Orders two contact revisions newest first by the LOGICAL timestamp their
 * payloads carry, not by the order the local rows happened to be written --
 * the same `ORDER BY timestamp DESC, writerId DESC` the mobile wallet applies
 * to its `contact_revisions` table, so a history replicated from another
 * writer reads identically in both wallets.
 *
 * Timestamps are compared as parsed instants, falling back to a lexical
 * comparison of the raw strings when either side is unparseable or the two
 * instants are equal -- ISO stamps minted by different writers differ in
 * fractional-second precision, so the raw strings are only a tiebreak, never
 * the primary key. Equal timestamps are broken by `writerId` descending, the
 * same "lexically greater writerId wins" convention as social-core's
 * `remotePayloadWins`.
 *
 * @param first {ContactRevisionPayload}
 * @param second {ContactRevisionPayload}
 * @returns {number}
 */
export function compareContactRevisionsNewestFirst(
  first: ContactRevisionPayload,
  second: ContactRevisionPayload
): number {
  const firstInstant = Date.parse(first.timestamp ?? '')
  const secondInstant = Date.parse(second.timestamp ?? '')
  if (
    Number.isFinite(firstInstant) &&
    Number.isFinite(secondInstant) &&
    firstInstant !== secondInstant
  ) {
    return secondInstant - firstInstant
  }
  const firstStamp = first.timestamp ?? ''
  const secondStamp = second.timestamp ?? ''
  if (firstStamp !== secondStamp) {
    return firstStamp < secondStamp ? 1 : -1
  }
  const firstWriter = first.writerId ?? ''
  const secondWriter = second.writerId ?? ''
  if (firstWriter === secondWriter) {
    return 0
  }
  return firstWriter < secondWriter ? 1 : -1
}
