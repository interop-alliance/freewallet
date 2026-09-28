/**
 * The Settings "wallets connected to this account" glue
 * (`src/session/clients.ts`), at its one write path: the disconnect drives
 * the revocation cascade and then reports the cascade's ceremony-tail entry.
 * Also the user key generation kids a collection key rotation keeps, read
 * off the verified user key roster.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import type { AccountClientView } from '@interop/wallet-core/clients'
import { epochKeyIdFor, mintEpoch } from '@interop/was-client/edv'

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
  labelDropFails: false,
  /** whether this session resolves an account-ceremony context */
  contextResolves: true,
  /** what the context's roster store `read()` does */
  rosterRead: (async () => null) as () => Promise<unknown>
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
  accountCeremonyContext: vi.fn(async () =>
    state.contextResolves
      ? {
          remoteStore: { clientLabelsStore: () => ({ isLabelStore: true }) },
          rosterStore: { read: () => state.rosterRead() }
        }
      : null
  ),
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

import {
  accountUserKeyGenerationKids,
  disconnectAccountClient
} from '@/session/clients'
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
  state.contextResolves = true
  state.rosterRead = async () => null
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

describe('accountUserKeyGenerationKids', () => {
  it('returns one kid per roster epoch, oldest first, as a collection epoch names it', async () => {
    const epochs = await Promise.all([mintEpoch(), mintEpoch(), mintEpoch()])
    state.rosterRead = async () => ({
      descriptor: {
        epochs: epochs.map(({ epochId }) => ({ id: epochId })),
        currentEpoch: epochs[2].epochId
      },
      etag: '"3"'
    })

    const kids = await accountUserKeyGenerationKids({ session: makeSession() })

    expect(kids).toEqual(epochs.map(({ epochId }) => epochKeyIdFor(epochId)))
    for (const [index, kid] of kids.entries()) {
      expect(kid.startsWith(`${epochs[index].epochId}#z`)).toBe(true)
    }
  })

  it('resolves an empty list when the account has no roster yet', async () => {
    state.rosterRead = async () => null
    await expect(
      accountUserKeyGenerationKids({ session: makeSession() })
    ).resolves.toEqual([])
  })

  it('resolves an empty list, reading no roster, when no account-ceremony context resolves', async () => {
    state.contextResolves = false
    const rosterRead = vi.fn(async () => null)
    state.rosterRead = rosterRead

    await expect(
      accountUserKeyGenerationKids({ session: makeSession() })
    ).resolves.toEqual([])
    expect(rosterRead).not.toHaveBeenCalled()
  })

  it('propagates a roster read failure rather than dropping the generations', async () => {
    const failure = Object.assign(new Error('roster chain does not verify'), {
      name: 'UserKeyRosterIntegrityError'
    })
    state.rosterRead = async () => {
      throw failure
    }

    await expect(
      accountUserKeyGenerationKids({ session: makeSession() })
    ).rejects.toBe(failure)
  })
})
