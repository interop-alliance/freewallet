/**
 * Tests for the Applications surface's revoke-outcome wording
 * (`revokeOutcomeKey`): what was actually withdrawn outranks the row's
 * marker, and a row nothing was withdrawn from reads as access that had
 * already ended, naming the disconnect only where the account document can
 * vouch for one.
 */
import { describe, expect, it } from 'vitest'
import { revokeOutcomeKey } from '@/session/applications'

describe('revokeOutcomeKey', () => {
  it('reports a revocation when a capability was withdrawn', () => {
    expect(revokeOutcomeKey({ grantsState: 'orphaned', withdrew: true })).toBe(
      'applications.revokeSuccess'
    )
  })

  it('names the disconnect on an orphaned row nothing was withdrawn from', () => {
    expect(revokeOutcomeKey({ grantsState: 'orphaned', withdrew: false })).toBe(
      'applications.revokeSuccessOrphaned'
    )
  })

  it('reports access already ended on any other row nothing was withdrawn from', () => {
    // An annex-signed grant whose generation was collected: the row derived
    // as unknown, and the server refused each revocation POST.
    expect(revokeOutcomeKey({ grantsState: 'unknown', withdrew: false })).toBe(
      'applications.revokeSuccessEnded'
    )
  })
})
