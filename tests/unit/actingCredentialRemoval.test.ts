// @vitest-environment node
/**
 * Unit tests for the acting-credential refusal
 * (`removeAccountPasskey`, `src/session/accountSettings.ts`).
 *
 * On the ladder branch every stage of a passkey removal acts through the
 * credential the session entered on: the strike entry is signed by its rung,
 * the licensed roster append by its ladder VM, and the annex strike by its
 * committed rung. Removing that very passkey would take the authority all
 * three run on, so the removal refuses by name before anything is written.
 * A remembered session is unaffected: its strike takes no key it invokes
 * with, so it may still remove its own login passkey.
 *
 * The same removal also runs the rule for a struck signer on the ladder
 * branch: the strike takes the removed passkey's ladder VM out of the
 * document, so the generation delegation that VM may have signed is replaced
 * BEFORE the strike lands, naming the retiring VM. A replacement that did
 * not install refuses the removal there, before anything is written.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  context: null as unknown,
  revoked: [] as unknown[],
  // How the mocked generation-delegation renewal resolves: a delegation
  // installed by default, or the named skip reason.
  renewal: 'installed' as 'installed' | 'failed' | 'no-ladder-vm' | 'no-pointer'
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  // The live-rides thunk: the ceremonies read the invocation capability off
  // the context each time they spread it, so the mock must expose it too.
  ceremonyRides:
    ({ context }: { context: { invoker?: { capability?: unknown } } | null }) =>
    () =>
      context?.invoker?.capability
        ? { capability: context.invoker.capability }
        : {},
  accountCeremonyContext: vi.fn(async () => state.context),
  enrolledCeremonyContext: vi.fn(() => null),
  requireEnrolledCeremonyContext: vi.fn(() => {
    throw new Error('not an enrolled session')
  })
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  canRevokeWithoutCeremony: vi.fn(() => true),
  revokeUnlockMethod: vi.fn(async (options: unknown) => {
    state.revoked.push(options)
    return null
  }),
  revokeUnlockMethodByCeremony: vi.fn(async (options: unknown) => {
    state.revoked.push(options)
    return null
  })
}))

// The real module is kept: several modules in this graph import other members
// of it at load time, and only the renewal is under test here.
vi.mock('@/session/annexReach', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/annexReach')>()),
  tryRenewTransientGenerationDelegation: vi.fn(async () => {
    if (state.renewal === 'failed') {
      // What the real renewal does on a caught failure: it logs it and
      // resolves with the error rather than throwing.
      return {
        skipped: 'failed',
        err: new Error('the annex log would not resolve')
      }
    }
    if (state.renewal !== 'installed') {
      return { skipped: state.renewal }
    }
    return { delegation: { id: 'urn:zcap:generation-fresh' } }
  })
}))

import {
  ActingCredentialRemovalError,
  removeAccountPasskey
} from '@/session/accountSettings'
import { revokeUnlockMethod } from '@/session/unlockMethods'
import {
  GenerationDelegationRenewalError,
  tryRenewTransientGenerationDelegation
} from '@/session/annexReach'
import type { PasskeyUnlockMethod } from '@/session/unlockMethods'
import type { Session } from '@/types/auth'

const ACCOUNT_DID = 'did:webvh:QmScid:localhost:space:space-123:id'

/**
 * The removed passkey's own ladder VM key multibase: every record's bridge
 * delegation is signed by that record's own credential's ladder VM, so the
 * fragment of `delegationKeyId` names it.
 */
const LADDER_VM_MULTIBASE = 'z6MkRemovedPasskeyLadderVm'

const ENTRY: PasskeyUnlockMethod = {
  type: 'passkey',
  label: 'Passkey',
  createdAt: '2026-01-01T00:00:00.000Z',
  credentialId: 'Y3JlZC1pZA',
  transports: ['internal'],
  backupEligibility: false,
  backupState: false,
  unlockSpaceId: 'unlock-space-acting',
  delegationKeyId: `${ACCOUNT_DID}#${LADDER_VM_MULTIBASE}`
}

/**
 * A session whose only member under test is `registryReady`; every authority
 * arrives through the mocked ceremony context.
 */
function sessionStub(): Session {
  return {
    user: { id: 'did:key:z6MkVisitKey' },
    registryReady: Promise.resolve(),
    storage: { spaceId: 'space-123' },
    profile: {
      accountPointer: { spaceUrl: 'http://localhost/space/space-123/' }
    }
  } as unknown as Session
}

beforeEach(() => {
  state.context = null
  state.revoked = []
  state.renewal = 'installed'
  vi.clearAllMocks()
})

describe('removing a passkey from the session it signed in with', () => {
  it('refuses by name on the ladder branch', async () => {
    state.context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: {}
    }
    await expect(
      removeAccountPasskey({ session: sessionStub(), entry: ENTRY })
    ).rejects.toBeInstanceOf(ActingCredentialRemovalError)
    expect(vi.mocked(revokeUnlockMethod)).not.toHaveBeenCalled()
  })

  it('removes another passkey from the same ladder session', async () => {
    state.context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: {}
    }
    await removeAccountPasskey({
      session: sessionStub(),
      entry: { ...ENTRY, unlockSpaceId: 'unlock-space-other' }
    })
    expect(vi.mocked(revokeUnlockMethod)).toHaveBeenCalledTimes(1)
  })

  it('lets a remembered session remove its own login passkey', async () => {
    state.context = {
      kind: 'enrolled',
      invoker: {}
    }
    await removeAccountPasskey({ session: sessionStub(), entry: ENTRY })
    expect(vi.mocked(revokeUnlockMethod)).toHaveBeenCalledTimes(1)
  })

  it('passes the context and its invoker through to the revocation', async () => {
    const context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: { capability: { id: 'urn:zcap:generation' } }
    }
    state.context = context
    await removeAccountPasskey({
      session: sessionStub(),
      entry: { ...ENTRY, unlockSpaceId: 'unlock-space-other' }
    })
    expect(state.revoked[0]).toMatchObject({ context })
  })
})

describe('the rule for a struck signer on a passkey removal', () => {
  it('renews the generation delegation before the strike, naming the removed ladder VM', async () => {
    state.context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: {}
    }
    await removeAccountPasskey({
      session: sessionStub(),
      entry: { ...ENTRY, unlockSpaceId: 'unlock-space-other' }
    })

    const renewal = vi.mocked(tryRenewTransientGenerationDelegation)
    expect(renewal).toHaveBeenCalledTimes(1)
    expect(renewal.mock.calls[0]![0]).toMatchObject({
      // The recorded verification-method id goes over verbatim: the
      // staleness check reads either that form or a bare multibase.
      retiringKeyMultibases: [`${ACCOUNT_DID}#${LADDER_VM_MULTIBASE}`]
    })
    // Before the strike: the replacement is signed by the ACTING credential's
    // ladder VM, which stands throughout, and has to be adopted while the
    // removed passkey's VM is still in the document.
    expect(renewal.mock.invocationCallOrder[0]!).toBeLessThan(
      vi.mocked(revokeUnlockMethod).mock.invocationCallOrder[0]!
    )
  })

  it('names no retiring key when the entry records no bridge signer', async () => {
    state.context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: {}
    }
    const { delegationKeyId: _unused, ...entry } = ENTRY
    await removeAccountPasskey({
      session: sessionStub(),
      entry: { ...entry, unlockSpaceId: 'unlock-space-other' }
    })

    const renewal = vi.mocked(tryRenewTransientGenerationDelegation)
    expect(renewal).toHaveBeenCalledTimes(1)
    // The renewal falls back to its own staleness policy rather than being
    // handed an empty retiring set.
    expect(renewal.mock.calls[0]![0]).not.toHaveProperty(
      'retiringKeyMultibases'
    )
  })

  it('runs no renewal on a remembered session', async () => {
    state.context = { kind: 'enrolled', invoker: {} }
    await removeAccountPasskey({ session: sessionStub(), entry: ENTRY })

    expect(
      vi.mocked(tryRenewTransientGenerationDelegation)
    ).not.toHaveBeenCalled()
    expect(vi.mocked(revokeUnlockMethod)).toHaveBeenCalledTimes(1)
  })

  it('refuses before the strike when the replacement fails', async () => {
    // The strike entry is the removal's pivot, so nothing has been written
    // yet. Publishing it anyway could take the key the visit's delegation
    // chains to out of the document, leaving the rest of the removal with
    // no authority.
    state.context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: {}
    }
    state.renewal = 'failed'
    const refusal = removeAccountPasskey({
      session: sessionStub(),
      entry: { ...ENTRY, unlockSpaceId: 'unlock-space-other' }
    })

    await expect(refusal).rejects.toBeInstanceOf(
      GenerationDelegationRenewalError
    )
    await expect(refusal).rejects.toMatchObject({
      reason: 'failed',
      cause: { message: 'the annex log would not resolve' }
    })
    // The account document is unchanged: the revocation, whose first write
    // is the strike entry, never ran.
    expect(vi.mocked(revokeUnlockMethod)).not.toHaveBeenCalled()
    expect(state.revoked).toEqual([])
  })

  it('refuses before the strike when the document anchors no ladder VM', async () => {
    // The ladder kind's roster and collection stores sign with the acting
    // credential's ladder VM, so with none in the document every append
    // after the strike would be refused.
    state.context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: {}
    }
    state.renewal = 'no-ladder-vm'
    const refusal = removeAccountPasskey({
      session: sessionStub(),
      entry: { ...ENTRY, unlockSpaceId: 'unlock-space-other' }
    })

    await expect(refusal).rejects.toBeInstanceOf(
      GenerationDelegationRenewalError
    )
    await expect(refusal).rejects.toMatchObject({ reason: 'no-ladder-vm' })
    expect(vi.mocked(revokeUnlockMethod)).not.toHaveBeenCalled()
  })

  it('proceeds when the session holds no annex generation to renew', async () => {
    // Unreachable on a ladder-kind context, which resolves from the ladder
    // members and the annex generation alike, so the removal carries on.
    state.context = {
      kind: 'ladder',
      unlockSpaceId: 'unlock-space-acting',
      invoker: {}
    }
    state.renewal = 'no-pointer'
    await removeAccountPasskey({
      session: sessionStub(),
      entry: { ...ENTRY, unlockSpaceId: 'unlock-space-other' }
    })
    expect(vi.mocked(revokeUnlockMethod)).toHaveBeenCalledTimes(1)
  })
})
