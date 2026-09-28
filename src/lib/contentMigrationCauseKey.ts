/**
 * The cause-name to i18n key mapping the content-migration report renders
 * through, in the style of `src/session/loginErrorKey.ts`.
 *
 * The report carries error names rather than sentences: `stoppedBy` on a
 * collection, `stoppedAt.cause` on the whole walk, and each key of
 * `unopenableCauses`. They are minted in `@interop/wallet-backup` and in the
 * packages under it, so they reach the page as bare strings and are matched
 * as such -- an `instanceof` check against a linked or duplicated copy would
 * silently miss. A name with no arm of its own falls back to a sentence that
 * shows the raw name, so a package that adds a cause still reads as something
 * rather than as nothing.
 */

/**
 * The i18n keys the known cause names map to.
 */
const CAUSE_KEYS: Record<string, string> = {
  // No user key generation the old secret opened unwraps this row's epoch.
  KeyUnwrapError: 'storage.migration.causes.keyUnwrap',
  // The row names a key epoch the archived roster does not carry.
  UnknownEpochError: 'storage.migration.causes.unknownEpoch',
  // The archived Resource is chunked, which the walk does not reassemble.
  ChunkedResourceUnsupportedError: 'storage.migration.causes.chunked',
  // The collection's governing log would not read, so its epochs are unknown.
  CollectionLogUnreadableError: 'storage.migration.causes.logUnreadable',
  // This account's Space is full; the walk stops rather than retry.
  QuotaExceededError: 'storage.migration.causes.quotaExceeded',
  // One row is larger than this server accepts.
  PayloadTooLargeError: 'storage.migration.causes.payloadTooLarge',
  // The account already holds this app collection in a different shape, so
  // it was left as it is. Minted app-side, in the storage manager.
  AppCollectionMismatchError: 'storage.migration.causes.appCollectionMismatch',
  // The outcome word, reported when a write failed without throwing.
  failed: 'storage.migration.causes.failed'
}

/**
 * Maps one cause name from a migration report to the key its sentence lives
 * under.
 *
 * @param cause {string}   the error name, or the outcome word `failed`
 * @returns {object}   the i18n key, and the raw name when the key is the
 *   unknown-cause fallback that renders it
 */
export function contentMigrationCauseKey(cause: string): {
  key: string
  name?: string
} {
  const key = CAUSE_KEYS[cause]
  if (key) {
    return { key }
  }
  return { key: 'storage.migration.causes.unknown', name: cause }
}
