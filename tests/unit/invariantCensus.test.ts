// @vitest-environment node
/**
 * The invariant census (`tests/shared/invariantCensus.ts`) against the mender
 * registry's declarations: one row per declared invariant and no other, a
 * reason on every row a reader cannot check, and a stored check in the
 * auditor for exactly the rows the census calls `stored`.
 */
import { describe, expect, it } from 'vitest'
import { MENDER_INVARIANTS } from '../../src/session/menders/index.js'
import { censusIdsOfKind, INVARIANT_CENSUS } from '../shared/invariantCensus'
import { STORED_CHECK_IDS } from '../shared/invariantAudit'

describe('the invariant census', () => {
  it('has exactly one row per declared invariant', () => {
    const declared = MENDER_INVARIANTS.map(declaration => declaration.id)
    expect(Object.keys(INVARIANT_CENSUS).sort()).toEqual([...declared].sort())
  })

  it('gives every unchecked and browser-local row a reason', () => {
    for (const id of [
      ...censusIdsOfKind({ kind: 'unchecked' }),
      ...censusIdsOfKind({ kind: 'browser-local' })
    ]) {
      expect(INVARIANT_CENSUS[id].reason.trim(), id).not.toBe('')
    }
  })

  it('has a stored check for exactly the stored rows', () => {
    expect([...STORED_CHECK_IDS].sort()).toEqual(
      censusIdsOfKind({ kind: 'stored' }).sort()
    )
  })

  it('names a key-holder half only on a stored row', () => {
    const withHalf = Object.entries(INVARIANT_CENSUS)
      .filter(([, row]) => row.keyHolderHalf !== undefined)
      .map(([id, row]) => [id, row.kind])
    expect(withHalf.every(([, kind]) => kind === 'stored')).toBe(true)
  })
})
