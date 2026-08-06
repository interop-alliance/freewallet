// @vitest-environment node
/**
 * Unit tests for the shared enrolled-client context
 * (`src/session/enrolledContext.ts`): the one resolution behind every ceremony
 * that acts AS the account, the per-miss error messages the ceremonies throw,
 * and -- the point of sharing it -- the boolean gates being DERIVED from it,
 * so the Settings panels cannot enable an action whose ceremony then throws
 * (Disconnect used to be enabled on a session holding no client key material).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

import {
  enrolledClientContext,
  requireEnrolledClientContext
} from '@/session/enrolledContext'
import { canManageAccountClients } from '@/session/clients'
import { canIssueRecoveryCode } from '@/session/recovery'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

/**
 * A session fixture carrying exactly the context's inputs; an override key
 * present with `undefined` pokes that hole.
 */
function sessionWith(
  overrides: Partial<{
    isGuest: boolean
    remoteStore: unknown
    pointerDid: string | undefined
    clientWebvhKeys: unknown
    clientKeyAgreementKey: unknown
    keyAgent: unknown
    puk: unknown
  }> = {}
): Session {
  return {
    user: { id: 'did:key:z6MkThisClient' },
    isGuest: overrides.isGuest ?? false,
    storage: {
      remoteStore:
        'remoteStore' in overrides ? overrides.remoteStore : { isStore: true }
    },
    profile: {
      accountPointer:
        'pointerDid' in overrides && overrides.pointerDid === undefined
          ? undefined
          : { ...POINTER, did: overrides.pointerDid ?? POINTER.did },
      accountController: 'did:key:z6MkAccountController',
      clientWebvhKeys:
        'clientWebvhKeys' in overrides
          ? overrides.clientWebvhKeys
          : { updateSeed: new Uint8Array(32), stagedSeed: new Uint8Array(32) },
      clientKeyAgreementKey:
        'clientKeyAgreementKey' in overrides
          ? overrides.clientKeyAgreementKey
          : { id: 'did:key:z6MkThisClient#z6LSThisClient' },
      keyAgent:
        'keyAgent' in overrides
          ? overrides.keyAgent
          : { id: 'did:key:z6MkThisClient' },
      puk: 'puk' in overrides ? overrides.puk : { id: 'did:key:z6LSPuk' }
    }
  } as unknown as Session
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
})

describe('the enrolled-client context', () => {
  it('resolves the stores, pointer, key material, and controller', () => {
    const session = sessionWith()
    const context = requireEnrolledClientContext({
      session,
      action: 'Client revocation'
    })
    expect(context.remoteStore).toBe(session.storage.remoteStore)
    expect(context.pointer.did).toBe(POINTER.did)
    expect(context.clientWebvhKeys).toBe(session.profile.clientWebvhKeys)
    expect(context.clientKeyAgreementKey).toBe(
      session.profile.clientKeyAgreementKey
    )
    expect(context.controller).toBe('did:key:z6MkAccountController')
  })

  it('names the missing precondition, opening with the action', () => {
    state.wasUrl = undefined
    expect(() =>
      requireEnrolledClientContext({
        session: sessionWith(),
        action: 'Client revocation'
      })
    ).toThrow('Client revocation requires a configured storage server.')

    state.wasUrl = 'https://was.example.test'
    expect(() =>
      requireEnrolledClientContext({
        session: sessionWith({ pointerDid: 'did:key:z6MkNotPromoted' }),
        action: 'Recovery-code issuance'
      })
    ).toThrow('promoted did:webvh')
    expect(() =>
      requireEnrolledClientContext({
        session: sessionWith({ clientWebvhKeys: undefined }),
        action: 'Client revocation'
      })
    ).toThrow('update keys')
    expect(() =>
      requireEnrolledClientContext({
        session: sessionWith({ clientKeyAgreementKey: undefined }),
        action: 'Client revocation'
      })
    ).toThrow('key-agreement key')
  })

  it('reports a guest and a store-less session as no context', () => {
    expect(enrolledClientContext({ session: sessionWith() })).not.toBeNull()
    expect(
      enrolledClientContext({ session: sessionWith({ isGuest: true }) })
    ).toBeNull()
    expect(
      enrolledClientContext({
        session: sessionWith({ remoteStore: undefined })
      })
    ).toBeNull()
  })
})

describe('the gates derived from it', () => {
  it('enables both surfaces for an enrolled client on a promoted account', () => {
    const session = sessionWith()
    expect(canManageAccountClients({ session })).toBe(true)
    expect(canIssueRecoveryCode({ session })).toBe(true)
  })

  it("refuses to enable Disconnect without this client's key material", () => {
    // The bug the shared context fixes: the clients gate checked only the
    // remote store and the pointer, so Disconnect was enabled on a session
    // whose cascade would then throw on the missing key material.
    expect(
      canManageAccountClients({
        session: sessionWith({ clientWebvhKeys: undefined })
      })
    ).toBe(false)
    expect(
      canManageAccountClients({
        session: sessionWith({ clientKeyAgreementKey: undefined })
      })
    ).toBe(false)
  })

  it('additionally requires the per-user key to issue a recovery code', () => {
    const session = sessionWith({ puk: undefined })
    // Nothing else is missing: the clients surface stays enabled.
    expect(canManageAccountClients({ session })).toBe(true)
    expect(canIssueRecoveryCode({ session })).toBe(false)
  })
})
