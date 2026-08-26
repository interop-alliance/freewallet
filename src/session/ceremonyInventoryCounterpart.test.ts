// @vitest-environment node
/**
 * The doc counterpart test for the ceremony vocabulary: parses
 * ARCHITECTURE.md's "## Ceremony inventory" table and asserts it names
 * exactly the ids `FREEWALLET_CEREMONY_IDS` exports, that every id is
 * kebab-case and unique, and that every module path a row names actually
 * exists. A new ceremony added to the table with no id mapping here, or an
 * id exported with no table row, fails the test -- the seam that keeps the
 * doc and the code from drifting apart.
 */
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { FREEWALLET_CEREMONY_IDS } from '@/session/ceremonies'

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const ARCHITECTURE_PATH = path.join(REPO_ROOT, 'ARCHITECTURE.md')

/**
 * The one place a table row's Ceremony title is mapped to its ceremony id.
 * An undocumented ceremony (a row with no entry here) fails loudly instead
 * of being silently skipped.
 */
const TITLE_TO_ID: Record<string, string> = {
  'Account genesis (durable)': 'account-genesis',
  'Credential-anchored genesis': 'credential-anchored-genesis',
  'Self-enrollment at login': 'self-enrollment',
  'Client enrollment (two-party)': 'client-enrollment',
  'Client revocation + epoch cascade': 'client-revocation',
  'Recovery-code issuance': 'recovery-code-issuance',
  'Recovery spend (durable and transient)': 'recovery-code-spend',
  'Recovery-code revocation': 'recovery-code-revocation',
  'Unlock-credential rotation': 'unlock-credential-rotation',
  'Forget ceremony': 'forget-client',
  'Last-client transition': 'last-client-transition',
  'Update-key rotation': 'update-key-rotation',
  'Account deletion': 'account-deletion',
  'Shared wipe (executor, not user-facing)': 'wallet-wipe'
}

interface CeremonyRow {
  ceremony: string
  moduleCell: string
}

/**
 * Extracts the "## Ceremony inventory" markdown table's rows: the Ceremony
 * (first) and Module (third) columns of every `| ... |` row after the
 * header separator, stopping at the first non-table line.
 */
function parseCeremonyTable(markdown: string): CeremonyRow[] {
  const headingIndex = markdown.indexOf('## Ceremony inventory')
  if (headingIndex === -1) {
    throw new Error('ARCHITECTURE.md has no "## Ceremony inventory" section')
  }
  const lines = markdown.slice(headingIndex).split('\n')
  const rows: CeremonyRow[] = []
  let sawHeader = false
  let sawSeparator = false
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('|')) {
      if (sawSeparator) {
        break
      }
      continue
    }
    const cells = trimmed
      .split('|')
      .slice(1, -1)
      .map((cell) => cell.trim())
    if (!sawHeader) {
      sawHeader = true
      continue
    }
    if (!sawSeparator) {
      sawSeparator = true
      continue
    }
    rows.push({ ceremony: cells[0], moduleCell: cells[2] })
  }
  if (rows.length === 0) {
    throw new Error('Parsed zero rows from the Ceremony inventory table')
  }
  return rows
}

/**
 * Extracts every backticked path in a Module cell, resolving a bare
 * filename (no `/`) against the directory of the previous backticked path
 * in the same cell -- the shape of the "Account deletion" row's
 * `src/session/accountSettings.ts` + `wipe.ts`.
 */
function extractModulePaths(moduleCell: string): string[] {
  const matches = [...moduleCell.matchAll(/`([^`]+)`/g)].map((match) => match[1])
  const resolved: string[] = []
  let previousDir: string | null = null
  for (const raw of matches) {
    if (raw.includes('/')) {
      resolved.push(raw)
      previousDir = path.dirname(raw)
    } else if (previousDir) {
      resolved.push(path.join(previousDir, raw))
    } else {
      resolved.push(raw)
    }
  }
  return resolved
}

describe('ceremony inventory counterpart', () => {
  const markdown = readFileSync(ARCHITECTURE_PATH, 'utf8')
  const rows = parseCeremonyTable(markdown)

  it('parses at least one row from ARCHITECTURE.md', () => {
    expect(rows.length).toBeGreaterThan(0)
  })

  const documentedRows = rows.filter((row) => row.moduleCell !== '---')
  const exemptRows = rows.filter((row) => row.moduleCell === '---')

  it('exempts only ceremonies with no module yet', () => {
    for (const row of exemptRows) {
      expect(row.ceremony).toBe('Step-up ceremony')
    }
  })

  it('maps every documented row to a known ceremony id', () => {
    const mappedIds = documentedRows.map((row) => {
      const id = TITLE_TO_ID[row.ceremony]
      if (!id) {
        throw new Error(
          `No id mapping for ARCHITECTURE.md Ceremony inventory row "${row.ceremony}" -- ` +
            'add it to TITLE_TO_ID in this test.'
        )
      }
      return id
    })

    expect(new Set(mappedIds)).toEqual(new Set(FREEWALLET_CEREMONY_IDS))
  })

  it('exports only kebab-case, unique ceremony ids', () => {
    const seen = new Set<string>()
    for (const id of FREEWALLET_CEREMONY_IDS) {
      expect(id).toMatch(/^[a-z]+(-[a-z]+)*$/)
      expect(seen.has(id)).toBe(false)
      seen.add(id)
    }
  })

  it('names only module paths that exist', () => {
    for (const row of documentedRows) {
      const modulePaths = extractModulePaths(row.moduleCell)
      expect(modulePaths.length).toBeGreaterThan(0)
      for (const modulePath of modulePaths) {
        const absolutePath = path.join(REPO_ROOT, modulePath)
        expect(
          existsSync(absolutePath),
          `Row "${row.ceremony}" names missing module path "${modulePath}"`
        ).toBe(true)
      }
    }
  })
})
