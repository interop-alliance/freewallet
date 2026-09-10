/**
 * The Settings "wallets connected to this account" glue
 * (`src/session/clients.ts`), at its one write path: the disconnect drives
 * the revocation cascade and then reports the cascade's ceremony-tail entry.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import type { AccountClientView } from '@interop/wallet-core/clients'

const REVOKED_KEYS = {
  signingKeyMultibase: 'z6MkRevokedSigning',
  keyAgreementKeyMultibase: 'z6LSRevokedKak',
  updateKeyMultibase: 'z6MkRevokedUpdate'
}

const MENDED = [
  {
    invariant: 'generation-delegation-is-current',
    ceremonies: ['client-revocation'],
    outcome: 'clean'
  }
] as const

const state = {
  calls: [] as string[],
  /** whether dropping the disconnected client's label fails */
  labelDropFails: false
}

vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  revokedClientKeysFor: vi.fn(() => REVOKED_KEYS)
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  removeClientLabel: vi.fn(async () => {
    state.calls.push('removeClientLabel')
    if (state.labelDropFails) {
      throw new Error('the labels resource is unreachable')
    }
  })
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  accountCeremonyContext: vi.fn(async () => ({
    remoteStore: { clientLabelsStore: () => ({ isLabelStore: true }) }
  })),
  canRunAccountCeremonies: vi.fn(() => true),
  enrolledCeremonyContext: vi.fn(() => null)
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(async () => ({ doc: {} }))
}))

vi.mock('@/session/revocation', () => ({
  revokeEnrolledClient: vi.fn(async () => {
    state.calls.push('revokeEnrolledClient')
    return {
      rotated: true,
      collections: { outcomes: {}, failed: [] },
      mended: MENDED
    }
  })
}))

vi.mock('@/session/menders/ceremonyTail', () => ({
  reportCeremonyTail: vi.fn(() => {
    state.calls.push('reportCeremonyTail')
  })
}))

import { disconnectAccountClient } from '@/session/clients'
import { revokeEnrolledClient } from '@/session/revocation'
import { reportCeremonyTail } from '@/session/menders/ceremonyTail'

/**
 * A settled session: its login chain resolved long ago, so the disconnect's
 * wait on the registry passes returns at once.
 *
 * @returns {Session}
 */
function makeSession(): Session {
  return {
    user: { id: 'did:key:z6MkUser' },
    registryReady: Promise.resolve(),
    profile: {},
    storage: {}
  } as unknown as Session
}

/**
 * One listed row.
 *
 * @returns {AccountClientView}
 */
function makeClient(): AccountClientView {
  return {
    signingKeyMultibase: REVOKED_KEYS.signingKeyMultibase,
    label: 'Old phone'
  } as unknown as AccountClientView
}

beforeEach(() => {
  state.calls = []
  state.labelDropFails = false
  vi.clearAllMocks()
})

describe('disconnectAccountClient', () => {
  it("reports the cascade's ceremony-tail entry from this call site", async () => {
    // The entry carries no registration, so no login chain's runner ever
    // sees it: without this call the cascade's report reaches nobody.
    const outcome = await disconnectAccountClient({
      session: makeSession(),
      client: makeClient()
    })

    expect(vi.mocked(revokeEnrolledClient)).toHaveBeenCalledOnce()
    expect(vi.mocked(reportCeremonyTail)).toHaveBeenCalledWith({
      mended: MENDED
    })
    expect(outcome.mended).toEqual(MENDED)
  })

  it('reports it before the label hygiene, and whatever that does', async () => {
    state.labelDropFails = true
    await disconnectAccountClient({
      session: makeSession(),
      client: makeClient()
    })

    expect(state.calls).toEqual([
      'revokeEnrolledClient',
      'reportCeremonyTail',
      'removeClientLabel'
    ])
  })
})
