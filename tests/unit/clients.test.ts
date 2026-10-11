/**
 * The Settings "wallets connected to this account" glue
 * (`src/session/clients.ts`): the disconnect drives the revocation cascade
 * and then reports the cascade's ceremony-tail entry; the listing names its
 * rows from the `connections` directory's wallet-client entries; and the
 * rename writes the user's `label` on the client's entry. Also the user key
 * generation kids a collection key rotation keeps, read off the verified
 * user key roster.
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

const ACCOUNT_DID = 'did:webvh:QmScid:was.example:space:s:id'

/**
 * A one-entry verified account log whose document lists the revoked client
 * and a second one as enrolled clients, for the real listing to read.
 */
const ACCOUNT_LOG = [
  {
    versionId: '1-QmEntry',
    versionTime: '2026-01-01T00:00:00Z',
    parameters: {},
    state: {
      id: ACCOUNT_DID,
      capabilityInvocation: [
        `${ACCOUNT_DID}#${REVOKED_KEYS.signingKeyMultibase}`,
        `${ACCOUNT_DID}#z6MkSecond`
      ]
    }
  }
]

const MENDED = [
  {
    invariant: 'generation-delegation-is-current',
    ceremonies: ['client-revocation'],
    outcome: 'clean'
  }
] as const

const state = {
  calls: [] as string[],
  /** whether this session resolves an account-ceremony context */
  contextResolves: true,
  /** what the context's roster store `read()` does */
  rosterRead: (async () => null) as () => Promise<unknown>,
  /** the session's `connections` directory */
  directory: memoryConnectionsStore()
}

vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  revokedClientKeysFor: vi.fn(() => REVOKED_KEYS),
  // The verified document lists the revoked client and this listing's two
  // rows, so the directory may create an entry for any of them.
  currentAccountSigningKeys: vi.fn(
    async () => new Set([REVOKED_KEYS.signingKeyMultibase, 'z6MkSecond'])
  )
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  accountCeremonyContext: vi.fn(async () =>
    state.contextResolves
      ? {
          pointer: {
            did: 'did:webvh:QmScid:was.example:space:s:id',
            spaceId: 's',
            host: 'https://was.example'
          },
          rosterStore: { read: () => state.rosterRead() }
        }
      : null
  ),
  canRunAccountCeremonies: vi.fn(() => true),
  enrolledCeremonyContext: vi.fn(() => null)
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(async () => ({
    doc: ACCOUNT_LOG[0]!.state,
    log: ACCOUNT_LOG
  }))
}))

vi.mock('@/session/revocation', () => ({
  walletClientDid: ({ signingKeyMultibase }: { signingKeyMultibase: string }) =>
    `did:key:${signingKeyMultibase}`,
  revokeEnrolledClient: vi.fn(async () => {
    state.calls.push('revokeEnrolledClient')
    return {
      rotated: true,
      collections: { outcomes: {}, failed: [] },
      mended: MENDED
    }
  })
}))

vi.mock('@/session/menders/ceremonyTail', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/menders/ceremonyTail')>()),
  reportCeremonyTail: vi.fn(() => {
    state.calls.push('reportCeremonyTail')
  })
}))

import {
  connectionResourceId,
  parseConnectionEntry
} from '@interop/wallet-core/connections'
import {
  accountUserKeyGenerationKids,
  disconnectAccountClient,
  listAccountClients,
  renameAccountClient
} from '@/session/clients'
import { HMAC_KEY, memoryConnectionsStore } from './memoryConnections'
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
    storage: {
      connectionsDirectory: async () => ({
        store: state.directory.store,
        hmacKey: HMAC_KEY,
        spaceUrl: 'https://was.example/space/s/'
      })
    }
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
  state.directory = memoryConnectionsStore()
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
      ceremony: 'client-revocation',
      mended: MENDED
    })
    expect(outcome.mended).toEqual(MENDED)
  })

  it('reports it after the cascade, which retires the entry itself', async () => {
    await disconnectAccountClient({
      session: makeSession(),
      client: makeClient()
    })

    expect(state.calls).toEqual(['revokeEnrolledClient', 'reportCeremonyTail'])
    // The history row names the client as the listing did.
    expect(vi.mocked(revokeEnrolledClient)).toHaveBeenCalledWith(
      expect.objectContaining({ label: 'Old phone' })
    )
  })

  it("names the history row by the client's own name when it has no label", async () => {
    await disconnectAccountClient({
      session: makeSession(),
      client: {
        signingKeyMultibase: REVOKED_KEYS.signingKeyMultibase,
        name: 'Freewallet'
      } as unknown as AccountClientView
    })
    expect(vi.mocked(revokeEnrolledClient)).toHaveBeenCalledWith(
      expect.objectContaining({ label: 'Freewallet' })
    )
  })
})

describe('the Connected wallets listing and rename over the directory', () => {
  it("writes the user's label on the client's wallet-client entry", async () => {
    const session = makeSession()
    await renameAccountClient({
      session,
      signingKeyMultibase: 'z6MkSecond',
      label: 'Work laptop'
    })

    const resourceId = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: 'did:key:z6MkSecond'
    })
    const entry = parseConnectionEntry(
      state.directory.rows.get(resourceId)?.body
    )
    expect(entry).toMatchObject({
      kind: 'wallet-client',
      id: 'did:key:z6MkSecond',
      label: 'Work laptop',
      grants: []
    })
  })

  it('names the listed rows from the entries, joined on the did:key', async () => {
    const session = makeSession()
    await renameAccountClient({
      session,
      signingKeyMultibase: 'z6MkSecond',
      label: 'Work laptop'
    })

    const rows = await listAccountClients({ session })
    expect(rows.map(row => [row.signingKeyMultibase, row.label])).toEqual([
      [REVOKED_KEYS.signingKeyMultibase, undefined],
      ['z6MkSecond', 'Work laptop']
    ])
  })

  it('refuses to create an entry for a client the document does not list', async () => {
    await expect(
      renameAccountClient({
        session: makeSession(),
        signingKeyMultibase: 'z6MkNotEnrolled',
        label: 'Stranger'
      })
    ).rejects.toThrow('verified account document')
    expect(state.directory.writes).toEqual([])
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
