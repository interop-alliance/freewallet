// @vitest-environment node
/**
 * Unit tests for the session-lifetime verified-log memo
 * (`src/session/verifiedLog.ts`) and the two enrolled-client wrappers that
 * read through it (`src/session/clients.ts`): one verification per session
 * rather than one per surface, a rejected verification never cached, a
 * pointer change never served from the old memo, every log-writing ceremony's
 * invalidation honored, and a label rename costing no re-verification.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
}))

const logState = vi.hoisted(() => ({
  verifications: 0,
  failWith: undefined as unknown
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn(async ({ did }: { did: string }) => {
    logState.verifications += 1
    if (logState.failWith) {
      throw logState.failWith
    }
    return {
      doc: { id: did, verificationMethod: [] },
      log: [],
      updateKeys: [],
      nextKeyHashes: []
    }
  })
}))

const sharedState = vi.hoisted(() => ({
  listings: 0,
  lastVerifiedLog: undefined as unknown,
  labelWrites: 0
}))

vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  listAccountClients: vi.fn(
    async ({ verifiedLog }: { verifiedLog?: unknown }) => {
      sharedState.listings += 1
      sharedState.lastVerifiedLog = verifiedLog
      return []
    }
  )
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  setClientLabel: vi.fn(async () => {
    sharedState.labelWrites += 1
  })
}))

import {
  createVerifiedLogCache,
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import { listAccountClients, renameAccountClient } from '@/session/clients'

const POINTER = {
  did: 'did:webvh:QmScid:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

/**
 * A session whose profile is exactly what the memo and the listing wrappers
 * read: a promoted account pointer, a remote store, and this client's keys.
 */
function sessionWith({ pointer = POINTER } = {}): Session {
  return {
    user: { id: 'did:key:z6MkTest' },
    isGuest: false,
    storage: {
      remoteStore: {
        clientLabelsStore: () => ({}),
        pukRosterStore: () => ({}),
        webvhIdStore: () => ({})
      }
    },
    profile: {
      accountPointer: pointer,
      clientWebvhKeys: {
        updateSeed: new Uint8Array(32),
        stagedSeed: new Uint8Array(32)
      },
      clientKeyAgreementKey: { id: 'did:key:z6LSx#z6LSx' },
      keyAgent: { id: 'did:key:z6MkThisClient' },
      puk: { id: 'did:key:z6LSpuk' }
    }
  } as unknown as Session
}

beforeEach(() => {
  logState.verifications = 0
  logState.failWith = undefined
  sharedState.listings = 0
  sharedState.lastVerifiedLog = undefined
  sharedState.labelWrites = 0
})

describe('the verified-log memo', () => {
  it('verifies once and serves every later read from the memo', async () => {
    const session = sessionWith()
    const first = await verifiedAccountLog({ profile: session.profile })
    const second = await verifiedAccountLog({ profile: session.profile })
    expect(logState.verifications).toBe(1)
    expect(second).toBe(first)
  })

  it('shares one in-flight verification between concurrent readers', async () => {
    const session = sessionWith()
    await Promise.all([
      verifiedAccountLog({ profile: session.profile }),
      verifiedAccountLog({ profile: session.profile })
    ])
    expect(logState.verifications).toBe(1)
  })

  it('re-verifies after a ceremony invalidates the memo', async () => {
    const session = sessionWith()
    await verifiedAccountLog({ profile: session.profile })
    invalidateVerifiedLog({ profile: session.profile })
    await verifiedAccountLog({ profile: session.profile })
    expect(logState.verifications).toBe(2)
  })

  it('never serves a different pointer from the old memo', async () => {
    const session = sessionWith()
    await verifiedAccountLog({ profile: session.profile })
    await verifiedAccountLog({
      profile: session.profile,
      pointer: { ...POINTER, did: 'did:webvh:QmOther:was.example.test' }
    })
    expect(logState.verifications).toBe(2)
  })

  it('does not cache a failed verification', async () => {
    const session = sessionWith()
    logState.failWith = new Error('the host is unreachable')
    await expect(
      verifiedAccountLog({ profile: session.profile })
    ).rejects.toThrow('unreachable')
    logState.failWith = undefined
    await verifiedAccountLog({ profile: session.profile })
    expect(logState.verifications).toBe(2)
  })

  it('refuses a session holding no promoted pointer', async () => {
    const cache = createVerifiedLogCache()
    expect(cache.invalidate()).toBeUndefined()
    await expect(
      verifiedAccountLog({ profile: { verifiedLog: cache } as never })
    ).rejects.toThrow(/account pointer/)
  })
})

describe('the enrolled-client listing over the memo', () => {
  it('passes the memoized log to the shared listing', async () => {
    const session = sessionWith()
    await listAccountClients({ session })
    expect(sharedState.listings).toBe(1)
    expect(sharedState.lastVerifiedLog).toBeTruthy()
    expect(logState.verifications).toBe(1)
  })

  it('re-lists after a label rename without re-verifying the log', async () => {
    const session = sessionWith()
    await listAccountClients({ session })
    await renameAccountClient({
      session,
      signingKeyMultibase: 'z6MkSomeClient',
      label: 'Laptop'
    })
    await listAccountClients({ session })
    expect(sharedState.labelWrites).toBe(1)
    expect(sharedState.listings).toBe(2)
    expect(logState.verifications).toBe(1)
  })
})
