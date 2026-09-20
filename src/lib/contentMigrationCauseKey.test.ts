// @vitest-environment node
/**
 * Unit tests for the migration report's cause-name copy mapping
 * (`src/lib/contentMigrationCauseKey.ts`): every name the report can carry
 * maps to its own key, an unknown name falls back to the sentence that shows
 * it, and every key the migration dialog renders stands in both locales.
 */
import { describe, expect, it } from 'vitest'
import { contentMigrationCauseKey } from '@/lib/contentMigrationCauseKey'
import enLocale from '@/i18n/locales/en.json'
import esLocale from '@/i18n/locales/es.json'

/**
 * Every dotted leaf key under one locale subtree.
 *
 * @param subtree {unknown}
 * @returns {string[]}
 */
function leafKeys(subtree: unknown): string[] {
  return Object.entries(subtree as Record<string, unknown>).flatMap(
    ([segment, value]) =>
      value !== null && typeof value === 'object'
        ? leafKeys(value).map(leaf => `${segment}.${leaf}`)
        : [segment]
  )
}

/**
 * The value at a dotted i18n key, or undefined when a segment is missing.
 *
 * @param options {object}
 * @param options.locale {object}   the parsed locale file
 * @param options.key {string}   the dotted key
 * @returns {unknown}
 */
function valueAt({ locale, key }: { locale: unknown; key: string }): unknown {
  return key
    .split('.')
    .reduce<unknown>(
      (node, segment) =>
        (node as Record<string, unknown> | undefined)?.[segment],
      locale
    )
}

const CAUSE_NAMES = [
  'KeyUnwrapError',
  'UnknownEpochError',
  'ChunkedResourceUnsupportedError',
  'CollectionLogUnreadableError',
  'QuotaExceededError',
  'PayloadTooLargeError',
  'failed'
]

const ERROR_KEYS = [
  'storage.migration.errors.bundleInvalid',
  'storage.migration.errors.accountArchiveMissing',
  'storage.migration.errors.secretNotRecipient',
  'storage.migration.errors.cancelled',
  'storage.migration.errors.quotaExceeded',
  'storage.migration.errors.failed'
]

describe('contentMigrationCauseKey', () => {
  it('maps every name the report can carry to its own key', () => {
    const keys = CAUSE_NAMES.map(name => contentMigrationCauseKey(name).key)
    expect(new Set(keys).size).toBe(CAUSE_NAMES.length)
    for (const key of keys) {
      expect(key.startsWith('storage.migration.causes.')).toBe(true)
      expect(key).not.toBe('storage.migration.causes.unknown')
    }
  })

  it('names the outcome word apart from the thrown causes', () => {
    expect(contentMigrationCauseKey('failed').key).toBe(
      'storage.migration.causes.failed'
    )
    expect(contentMigrationCauseKey('QuotaExceededError').key).toBe(
      'storage.migration.causes.quotaExceeded'
    )
  })

  it('falls back to the sentence that shows an unknown name raw', () => {
    // A package that adds a cause still reads as something: the name travels
    // beside the key so the copy can render it.
    const outcome = contentMigrationCauseKey('SomeNewError')
    expect(outcome.key).toBe('storage.migration.causes.unknown')
    expect(outcome.name).toBe('SomeNewError')
  })

  it('carries every migration key in both locales', () => {
    // The dialog and the ceremony render out of this one subtree, so its leaf
    // set is the list rather than a hand-maintained copy of it.
    const enKeys = leafKeys(enLocale.storage.migration).sort()
    const esKeys = leafKeys(esLocale.storage.migration).sort()
    expect(esKeys).toEqual(enKeys)
    for (const key of enKeys) {
      for (const locale of [enLocale, esLocale]) {
        expect(
          valueAt({ locale, key: `storage.migration.${key}` })
        ).toBeTruthy()
      }
    }
  })

  it('resolves every key the report and the refusals map to', () => {
    const mapped = [
      ...[...CAUSE_NAMES, 'SomeNewError'].map(
        name => contentMigrationCauseKey(name).key
      ),
      ...ERROR_KEYS
    ]
    for (const key of mapped) {
      for (const locale of [enLocale, esLocale]) {
        expect(valueAt({ locale, key })).toBeTruthy()
      }
    }
  })
})
