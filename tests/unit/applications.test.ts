/**
 * Tests for the Applications surface's revoke-outcome wording
 * (`revokeOutcomeKey`): what was actually withdrawn outranks the row's
 * marker, and a row nothing was withdrawn from reads as access that had
 * already ended, naming the disconnect only where the account document can
 * vouch for one. `withdrew` counts only what the run itself took away.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  revokeAgent,
  revokeApplication,
  revokeOutcomeKey
} from '@/session/applications'
import type { ConnectedAgent, ConnectedApp } from '@/lib/connectedApps'
import type { Session } from '@/types/auth'

const access = vi.hoisted(() => ({
  outcome: { revoked: 0, withdrawn: 0, skipped: 0, rotated: 0 }
}))

vi.mock('@/lib/connectedApps', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/connectedApps')>()),
  revokeAppAccess: vi.fn(async () => access.outcome),
  revokeAgentAccess: vi.fn(async () => access.outcome)
}))

const session = { storage: {}, user: {} } as unknown as Session

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

describe('revokeApplication and revokeAgent', () => {
  it('reads a grant the server had already revoked as access that had ended', async () => {
    // The grant stage counts it as revoked, but this run withdrew nothing.
    access.outcome = { revoked: 1, withdrawn: 0, skipped: 0, rotated: 0 }

    expect(
      await revokeApplication({
        session,
        app: {} as ConnectedApp,
        grantsState: 'active'
      })
    ).toEqual({ outcomeKey: 'applications.revokeSuccessEnded' })
    expect(await revokeAgent({ session, agent: {} as ConnectedAgent })).toEqual(
      { withdrew: false }
    )
  })

  it('reads a grant this run revoked as withdrawn', async () => {
    access.outcome = { revoked: 1, withdrawn: 1, skipped: 0, rotated: 0 }

    expect(
      await revokeApplication({
        session,
        app: {} as ConnectedApp,
        grantsState: 'active'
      })
    ).toEqual({ outcomeKey: 'applications.revokeSuccess' })
    expect(await revokeAgent({ session, agent: {} as ConnectedAgent })).toEqual(
      { withdrew: true }
    )
  })

  it('reads a collection this run re-keyed as withdrawn', async () => {
    access.outcome = { revoked: 0, withdrawn: 0, skipped: 1, rotated: 1 }

    expect(await revokeAgent({ session, agent: {} as ConnectedAgent })).toEqual(
      { withdrew: true }
    )
  })
})
