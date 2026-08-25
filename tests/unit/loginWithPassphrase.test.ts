// @vitest-environment node
/**
 * Unit tests for the keyring-v2 login (`loginWithPassphrase` in
 * `src/session/initSession.ts`). The keyring is the only login path: the
 * passphrase resolves through `fetchKeyring` to the account pointer and this
 * client's local key set -- never to any account-reconstructing secret. The
 * keyring module is mocked so the branch matrix (enrolled hit, located but
 * not enrolled, controller mismatch, miss, fetch rejection) runs
 * deterministically; the network-touching boundaries
 * (`StorageManager.initStorageClients`, `ensureKeystore`) are stubbed, while
 * the CapabilityAgent seed derivation runs for real so the controller sanity
 * check exercises the true did:key.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/keyring')>()),
  fetchKeyring: vi.fn(),
  fetchTransientKeyring: vi.fn()
}))

// Mocked with a full factory (no importOriginal): the module imports
// `initSessionFromSeed` back from the module under test, and loading the
// original inside the factory would hand that cycle the REAL composition.
// The routing decision itself is covered in transientLogin.test.ts; here
// only the entry-point glue over its result is exercised.
vi.mock('@/session/transientLogin', () => ({
  routeUnlockLogin: vi.fn(),
  transientSessionFromKeyringHit: vi.fn()
}))
vi.mock('@/lib/kms', () => ({ ensureKeystore: vi.fn() }))
// A full factory: the durable resume heal is the only consumer here, and the
// real module drags in the whole establishment stack.
vi.mock('@/session/credentialAnchoredGenesis', () => ({
  establishCredentialAnchoredAccount: vi.fn(async () => ({
    did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
    unlockSpaceId: 'unlock-space-test',
    standingFields: {}
  }))
}))
vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))
vi.mock('@/session/standingUnlock', () => ({
  canSelfEnroll: vi.fn(() => false),
  selfEnrollStandingClient: vi.fn()
}))
// A full factory like the ones above, with a real (constructible) error
// class: the popup guard constructs it, and the mapping matches instanceof.
vi.mock('@/session/pendingEnrollment', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/pendingEnrollment')>()),
  isPendingKeyringHit: vi.fn(() => false),
  resumePendingEnrollment: vi.fn()
}))

// A full factory (no importOriginal): `initSession.ts` imports
// `assertClientStillEnrolled` and `wipeStaleClientResidue` from this module,
// and loading the original would drag in network / IndexedDB code the way
// the mock-cycle gotcha describes for the other full-factory mocks above.
vi.mock('@/session/forget', () => ({
  assertClientStillEnrolled: vi.fn(async () => undefined),
  wipeStaleClientResidue: vi.fn(async () => ({ failed: [], unverified: [] }))
}))

import { StorageManager } from '@/stores/storageManager'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import {
  canSelfEnroll,
  selfEnrollStandingClient
} from '@/session/standingUnlock'
import {
  isPendingKeyringHit,
  PendingEnrollmentError,
  resumePendingEnrollment
} from '@/session/pendingEnrollment'
import {
  fetchKeyring,
  fetchTransientKeyring,
  KeyringRecordUnusableError
} from '@/session/keyring'
import {
  routeUnlockLogin,
  transientSessionFromKeyringHit
} from '@/session/transientLogin'
import { transientSessionPersistence } from '@/session/persistence'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import { loginWithPassphrase } from '@/session/initSession'
import { ensureKeystore } from '@/lib/kms'
import { mintUserKey } from '@interop/wallet-core/keys'
import { epochKeyIdFor } from '@interop/was-client/edv'
import {
  assertClientStillEnrolled,
  wipeStaleClientResidue
} from '@/session/forget'

const PASSPHRASE = 'correct horse battery staple'
const POINTER: AccountPointer = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

/**
 * A storage stub carrying the `ensureUserCollections` seam that session
 * creation fires (as `session.storageReady`).
 */
function makeFakeStorage() {
  return {
    isFakeStorage: true,
    ensureUserCollections: vi.fn().mockResolvedValue(undefined)
  } as unknown as StorageManager
}
let fakeStorage = makeFakeStorage()

/**
 * The did:key a client seed reconstitutes to under the bootstrap parameters --
 * the identity `initSessionFromSeed` assigns and the controller a valid
 * keyring record carries for its enrolling client.
 */
async function didFromSeed(seed: Uint8Array): Promise<string> {
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'bootstrap',
    keyName: 'boostrap-key'
  })
  return agent.id
}

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

beforeEach(() => {
  fakeStorage = makeFakeStorage()
  vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
    storage: fakeStorage,
    userExists: false
  })
  vi.mocked(ensureKeystore).mockResolvedValue(undefined as never)
  vi.mocked(fetchKeyring).mockReset()
  vi.mocked(fetchTransientKeyring).mockReset()
  vi.mocked(transientSessionFromKeyringHit).mockReset()
  // The durable route by default, matching the pre-routing behavior the
  // branch matrix below exercises.
  vi.mocked(routeUnlockLogin).mockReset()
  vi.mocked(routeUnlockLogin).mockImplementation(async ({ credential }) => ({
    durability: 'durable',
    ...(credential ? { credential } : {})
  }))
  vi.mocked(canSelfEnroll).mockReset()
  vi.mocked(canSelfEnroll).mockReturnValue(false)
  vi.mocked(selfEnrollStandingClient).mockReset()
  vi.mocked(isPendingKeyringHit).mockReset()
  vi.mocked(isPendingKeyringHit).mockReturnValue(false)
  vi.mocked(resumePendingEnrollment).mockReset()
  vi.mocked(wipeStaleClientResidue).mockReset()
  vi.mocked(wipeStaleClientResidue).mockResolvedValue({
    failed: [],
    unverified: []
  })
  vi.mocked(assertClientStillEnrolled).mockReset()
  vi.mocked(assertClientStillEnrolled).mockResolvedValue(undefined as never)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('loginWithPassphrase -- enrolled keyring hit', () => {
  it('builds the session from the local client key set', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      pointer: POINTER,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fakeStorage,
      userExists: true
    })

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).not.toBeNull()
    expect(session!.user.id).toBe(controller)
    expect(userExists).toBe(true)
  })

  it('stamps the account pointer on the profile', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      pointer: POINTER,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(session!.profile.accountPointer).toEqual(POINTER)
  })

  it('makes the recovered user key recipient zero (the profile KAK) and carries it on the profile', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    const userKey = await mintUserKey()
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed, userKey },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    const { profile } = vi.mocked(StorageManager.initStorageClients).mock
      .calls[0][0]
    expect(profile.keyAgreementKey!.id).toBe(epochKeyIdFor(userKey.id))
    expect(session!.profile.userKey).toBe(userKey)
  })

  it('keeps the seed-derived KAK for a legacy record with no user key', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    const { profile } = vi.mocked(StorageManager.initStorageClients).mock
      .calls[0][0]
    // The legacy vault KAK is the Montgomery twin of the signing key, so its
    // id is rooted in the account's own did:key controller.
    expect(profile.keyAgreementKey!.id.startsWith(controller)).toBe(true)
    expect(session!.profile.userKey).toBeUndefined()
  })

  it('fires ensureUserCollections as storageReady by default', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(fakeStorage.ensureUserCollections).toHaveBeenCalledOnce()
    expect(session!.storageReady).toBeInstanceOf(Promise)
  })

  it('forwards provisionStorage: false (the signup probe) to skip provisioning', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })

    const { session } = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      provisionStorage: false
    })

    expect(fakeStorage.ensureUserCollections).not.toHaveBeenCalled()
    expect(session!.storageReady).toBeUndefined()
  })

  it('reports userExists: false when the data Space is missing (half-finished signup)', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fakeStorage,
      userExists: false
    })

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).not.toBeNull()
    expect(userExists).toBe(false)
  })

  it('throws on a controller / identity mismatch (corrupt record)', async () => {
    // The record carries no `pointerDid` at all (and no `pointer` on the
    // hit either), so the pointer-based stale check never fires: the login
    // flows straight past it and past the (mocked) forgotten-browser
    // detector to the late bound-controller check, which finds the
    // unwrapped controller does not match the derived identity and refuses
    // in a single pass -- no wipe, no retry.
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkWrongControllerForThisSeed',
      clientKeys: { clientSeed: randomSeed() },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toThrow(KeyringRecordUnusableError)
    expect(wipeStaleClientResidue).not.toHaveBeenCalled()
    expect(routeUnlockLogin).toHaveBeenCalledOnce()
  })
})

describe('loginWithPassphrase -- stale client-key record from another account', () => {
  // The pointer-based discriminator: `clientKeys.pointerDid` names a
  // different account than the unlock record's own `pointer.did`
  // (`POINTER.did`). `clientKeys.controller` is carried along too (a real
  // stale record still has one), but it is not the discriminator, so its
  // value is not what triggers the check below.
  const STALE_POINTER_DID =
    'did:webvh:QmOldScid:was.example.test:space:old-space:id'

  it('wipes the stale record and re-routes as a record-less browser (transient)', async () => {
    const staleHit = {
      controller: 'did:key:z6MkNewAccountController',
      pointer: POINTER,
      clientKeys: {
        clientSeed: randomSeed(),
        userKey: await mintUserKey(),
        controller: 'did:key:z6MkOldAccountController',
        pointerDid: STALE_POINTER_DID
      },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    }
    vi.mocked(fetchKeyring).mockResolvedValue(staleHit as never)
    vi.mocked(routeUnlockLogin).mockReset()
    vi.mocked(routeUnlockLogin).mockResolvedValueOnce({ durability: 'durable' })
    const persistence = transientSessionPersistence()
    const transientCredential = {
      unlock: { spaceId: 'unlock-space-test' },
      standing: {}
    } as never
    vi.mocked(routeUnlockLogin).mockResolvedValueOnce({
      durability: 'transient',
      credential: transientCredential,
      persistence
    })
    const transientFound = {
      controller: 'did:key:z6MkNewAccountController',
      unlockSpaceId: 'unlock-space-test'
    }
    vi.mocked(fetchTransientKeyring).mockResolvedValue(transientFound as never)
    const transientResult = {
      session: { isTransient: true } as never,
      userExists: true
    }
    vi.mocked(transientSessionFromKeyringHit).mockResolvedValue(
      transientResult as never
    )

    const result = await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(wipeStaleClientResidue).toHaveBeenCalledTimes(1)
    expect(wipeStaleClientResidue).toHaveBeenCalledWith(
      expect.objectContaining({ found: staleHit })
    )
    expect(routeUnlockLogin).toHaveBeenCalledTimes(2)
    expect(transientSessionFromKeyringHit).toHaveBeenCalledOnce()
    expect(result).toBe(transientResult)
  })

  it('the detector never fires on a record bound to another account', async () => {
    const staleHit = {
      controller: 'did:key:z6MkNewAccountController',
      pointer: POINTER,
      clientKeys: {
        clientSeed: randomSeed(),
        userKey: await mintUserKey(),
        controller: 'did:key:z6MkOldAccountController',
        pointerDid: STALE_POINTER_DID
      },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    }
    vi.mocked(fetchKeyring).mockResolvedValue(staleHit as never)
    vi.mocked(routeUnlockLogin).mockReset()
    vi.mocked(routeUnlockLogin).mockResolvedValueOnce({ durability: 'durable' })
    vi.mocked(routeUnlockLogin).mockResolvedValueOnce({
      durability: 'transient',
      credential: {
        unlock: { spaceId: 'unlock-space-test' },
        standing: {}
      } as never,
      persistence: transientSessionPersistence()
    })
    vi.mocked(fetchTransientKeyring).mockResolvedValue({
      controller: 'did:key:z6MkNewAccountController',
      unlockSpaceId: 'unlock-space-test'
    } as never)
    vi.mocked(transientSessionFromKeyringHit).mockResolvedValue({
      session: { isTransient: true } as never,
      userExists: true
    } as never)

    await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(assertClientStillEnrolled).not.toHaveBeenCalled()
  })

  it('self-enrolls on the retry under rememberBrowser: true', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    const staleHit = {
      controller,
      pointer: POINTER,
      clientKeys: {
        clientSeed: randomSeed(),
        userKey: await mintUserKey(),
        controller: 'did:key:z6MkOldAccountController',
        pointerDid: STALE_POINTER_DID
      },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    }
    const notEnrolledHit = {
      controller,
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString(),
      standing: { delegation: {}, ladderSeed: randomSeed() }
    }
    vi.mocked(fetchKeyring)
      .mockResolvedValueOnce(staleHit as never)
      .mockResolvedValueOnce(notEnrolledHit as never)
    vi.mocked(routeUnlockLogin).mockReset()
    vi.mocked(routeUnlockLogin).mockResolvedValue({ durability: 'durable' })
    vi.mocked(canSelfEnroll).mockReturnValue(true)
    const persist = vi.fn(async () => {})
    vi.mocked(selfEnrollStandingClient).mockResolvedValue({
      clientKeys: { clientSeed, controller },
      persistClientKeys: persist
    } as never)

    const { session } = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      rememberBrowser: true
    })

    expect(wipeStaleClientResidue).toHaveBeenCalledOnce()
    expect(selfEnrollStandingClient).toHaveBeenCalledOnce()
    expect(session).not.toBeNull()
    expect(session!.user.id).toBe(controller)
  })

  it('a second stale signal surfaces KeyringRecordUnusableError', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    const staleHit = {
      controller,
      pointer: POINTER,
      clientKeys: {
        clientSeed: randomSeed(),
        userKey: await mintUserKey(),
        controller: 'did:key:z6MkOldAccountController',
        pointerDid: STALE_POINTER_DID
      },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    }
    vi.mocked(fetchKeyring).mockResolvedValue(staleHit as never)
    vi.mocked(routeUnlockLogin).mockReset()
    vi.mocked(routeUnlockLogin).mockResolvedValue({ durability: 'durable' })

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toThrow(KeyringRecordUnusableError)
    expect(wipeStaleClientResidue).toHaveBeenCalledTimes(2)
  })
})

describe('loginWithPassphrase -- located but not enrolled', () => {
  it('returns a null session and userExists: true when this client holds no key set', async () => {
    // The passphrase located the account (the record exists and unwraps) but
    // there are no local client keys: unlocking is not sufficient to BE the
    // account, so no session is built and storage is never touched.
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkDataControllerForTests',
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    })

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).toBeNull()
    expect(userExists).toBe(true)
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- self-enrolling standing credential', () => {
  it('self-enrolls a fresh browser and proceeds as an enrolled login', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    const found = {
      controller,
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString(),
      standing: { delegation: {}, ladderSeed: randomSeed() }
    }
    vi.mocked(fetchKeyring).mockResolvedValue(found as never)
    vi.mocked(canSelfEnroll).mockReturnValue(true)
    const persist = vi.fn(async () => {})
    vi.mocked(selfEnrollStandingClient).mockResolvedValue({
      clientKeys: { clientSeed, controller },
      persistClientKeys: persist
    } as never)
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fakeStorage,
      userExists: true
    })

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(selfEnrollStandingClient).toHaveBeenCalledWith(
      expect.objectContaining({ found })
    )
    expect(session).not.toBeNull()
    expect(session!.user.id).toBe(controller)
    expect(session!.profile.persistClientKeys).toBe(persist)
    expect(userExists).toBe(true)
  })

  it('propagates a self-enrollment refusal instead of building a session', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkDataControllerForTests',
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString(),
      standing: { delegation: {}, ladderSeed: randomSeed() }
    } as never)
    vi.mocked(canSelfEnroll).mockReturnValue(true)
    const refusal = new Error('no rung committed')
    refusal.name = 'LadderAttributionError'
    vi.mocked(selfEnrollStandingClient).mockRejectedValue(refusal)

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toMatchObject({ name: 'LadderAttributionError' })
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })

  it('stays in the not-enrolled state for a remote-direct (popup) session', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkDataControllerForTests',
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString(),
      standing: { delegation: {}, ladderSeed: randomSeed() }
    } as never)
    vi.mocked(canSelfEnroll).mockReturnValue(true)

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      remoteDirectStorage: true
    })

    expect(session).toBeNull()
    expect(userExists).toBe(true)
    expect(selfEnrollStandingClient).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- pending-record resume routing (FW-280)', () => {
  it('routes a pending-shape record to the resume, not the detector, and builds the session from its result', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      pointer: POINTER,
      clientKeys: { clientSeed, controller },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    } as never)
    vi.mocked(isPendingKeyringHit).mockReturnValue(true)
    const userKey = await mintUserKey()
    const persist = vi.fn(async () => {})
    vi.mocked(resumePendingEnrollment).mockResolvedValue({
      clientKeys: { clientSeed, userKey, controller },
      persistClientKeys: persist
    } as never)

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(resumePendingEnrollment).toHaveBeenCalledOnce()
    expect(session).not.toBeNull()
    expect(session!.user.id).toBe(controller)
    expect(session!.profile.userKey).toBe(userKey)
    expect(session!.profile.persistClientKeys).toBe(persist)
  })

  it('fails closed when the resume throws: no session is ever built over the pending record', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkDataControllerForTests',
      pointer: POINTER,
      clientKeys: { clientSeed: randomSeed() },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    } as never)
    vi.mocked(isPendingKeyringHit).mockReturnValue(true)
    vi.mocked(resumePendingEnrollment).mockRejectedValue(
      new PendingEnrollmentError({ reason: 'resume-failed' })
    )

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toMatchObject({ name: 'PendingEnrollmentError' })
    // Fail-closed: session construction (seed-derived vault keys) was never
    // reached with a userKey-less record on a promoted account.
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })

  it('guards the remote-direct popup: a pending record refuses instead of resuming there', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkDataControllerForTests',
      pointer: POINTER,
      clientKeys: { clientSeed: randomSeed() },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    } as never)
    vi.mocked(isPendingKeyringHit).mockReturnValue(true)

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE, remoteDirectStorage: true })
    ).rejects.toMatchObject({ name: 'PendingEnrollmentError', reason: 'popup' })
    expect(resumePendingEnrollment).not.toHaveBeenCalled()
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- durable resume of a torn remembered signup', () => {
  const CREDENTIAL = {
    unlock: { spaceId: 'unlock-space-test' },
    standing: {}
  } as never
  // A remembered signup torn before the establishment's re-bind: the record
  // carries the ladder seed but the pointer names no did:webvh yet.
  const TORN_POINTER: AccountPointer = {
    spaceId: 'space-123',
    host: 'https://was.example.test'
  }

  it('re-runs the establishment under rememberBrowser: true, then self-enrolls from the refreshed record', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    const ladderSeed = randomSeed()
    const tornHit = {
      controller,
      pointer: TORN_POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: '2026-08-25T00:00:00.000Z',
      standing: { delegation: {}, ladderSeed }
    }
    const healedHit = {
      controller,
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: '2026-08-25T00:00:01.000Z',
      standing: { delegation: {}, ladderSeed }
    }
    vi.mocked(fetchKeyring)
      .mockResolvedValueOnce(tornHit as never)
      .mockResolvedValueOnce(healedHit as never)
    vi.mocked(establishCredentialAnchoredAccount).mockResolvedValue({
      did: POINTER.did,
      unlockSpaceId: 'unlock-space-test',
      standingFields: {}
    } as never)
    vi.mocked(canSelfEnroll).mockReturnValue(true)
    const persist = vi.fn(async () => {})
    vi.mocked(selfEnrollStandingClient).mockResolvedValue({
      clientKeys: { clientSeed, controller },
      persistClientKeys: persist
    } as never)

    const { session } = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      credential: CREDENTIAL,
      rememberBrowser: true
    })

    expect(establishCredentialAnchoredAccount).toHaveBeenCalledOnce()
    expect(establishCredentialAnchoredAccount).toHaveBeenCalledWith(
      expect.objectContaining({
        credential: CREDENTIAL,
        ladderSeed,
        pointer: TORN_POINTER,
        lowEntropy: true,
        priorCreatedAt: tornHit.createdAt
      })
    )
    // The keyring was re-fetched after the heal, and the self-enrollment ran
    // over the refreshed (promoted) hit.
    expect(fetchKeyring).toHaveBeenCalledTimes(2)
    expect(selfEnrollStandingClient).toHaveBeenCalledWith(
      expect.objectContaining({ found: healedHit })
    )
    expect(session).not.toBeNull()
    expect(session!.user.id).toBe(controller)
  })

  it('never fires on the default (non-remembered) durable login', async () => {
    const tornHit = {
      controller: 'did:key:z6MkDataControllerForTests',
      pointer: TORN_POINTER,
      unlockSpaceId: 'unlock-space-test',
      createdAt: '2026-08-25T00:00:00.000Z',
      standing: { delegation: {}, ladderSeed: randomSeed() }
    }
    vi.mocked(fetchKeyring).mockResolvedValue(tornHit as never)
    vi.mocked(establishCredentialAnchoredAccount).mockClear()

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      credential: CREDENTIAL
    })

    expect(establishCredentialAnchoredAccount).not.toHaveBeenCalled()
    // The existing routing stands: not enrolled, no session.
    expect(session).toBeNull()
    expect(userExists).toBe(true)
  })
})

describe('loginWithPassphrase -- keyring miss', () => {
  it('returns a null session and userExists: false when no keyring exists', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue(null)

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).toBeNull()
    expect(userExists).toBe(false)
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- fetch failure', () => {
  it('propagates a fetchKeyring rejection (e.g. remote unreachable)', async () => {
    vi.mocked(fetchKeyring).mockRejectedValue(new Error('storage unreachable'))

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toThrow('storage unreachable')
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- durability routing glue', () => {
  const CREDENTIAL = {
    unlock: { spaceId: 'unlock-space-test' },
    standing: {}
  } as never

  it('hands the routing the login inputs it decides on', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue(null)
    await loginWithPassphrase({
      passphrase: PASSPHRASE,
      credential: CREDENTIAL,
      remoteDirectStorage: true,
      rememberBrowser: true
    })
    expect(routeUnlockLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        secret: PASSPHRASE,
        credential: CREDENTIAL,
        remoteDirectStorage: true,
        rememberBrowser: true
      })
    )
  })

  it('runs the transient route over the shared in-memory handle', async () => {
    const persistence = transientSessionPersistence()
    vi.mocked(routeUnlockLogin).mockResolvedValue({
      durability: 'transient',
      credential: CREDENTIAL,
      persistence
    })
    const found = { controller: 'did:key:z6MkC', unlockSpaceId: 'u' }
    vi.mocked(fetchTransientKeyring).mockResolvedValue(found as never)
    const transientResult = {
      session: { isTransient: true },
      userExists: true
    }
    vi.mocked(transientSessionFromKeyringHit).mockResolvedValue(
      transientResult as never
    )

    const result = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      credential: CREDENTIAL
    })

    expect(result).toBe(transientResult)
    expect(fetchKeyring).not.toHaveBeenCalled()
    // The record fetch and the composition share the visit's in-memory pins.
    expect(fetchTransientKeyring).toHaveBeenCalledWith({
      credential: CREDENTIAL,
      accountLogPinStore: persistence.logPins
    })
    expect(transientSessionFromKeyringHit).toHaveBeenCalledWith({
      found,
      type: 'passphrase',
      email: undefined,
      persistence,
      // The credential rides along so the composition can arm the torn
      // credential-anchored-signup heal (the establishment re-run needs it).
      credential: CREDENTIAL
    })
  })

  it('reports no account on a transient keyring miss', async () => {
    vi.mocked(routeUnlockLogin).mockResolvedValue({
      durability: 'transient',
      credential: CREDENTIAL,
      persistence: transientSessionPersistence()
    })
    vi.mocked(fetchTransientKeyring).mockResolvedValue(null)
    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE, credential: CREDENTIAL })
    ).resolves.toEqual({ session: null, userExists: false })
    expect(transientSessionFromKeyringHit).not.toHaveBeenCalled()
    expect(fetchKeyring).not.toHaveBeenCalled()
  })

  it('threads the routing-derived credential into the durable fetch', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      pointer: POINTER,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test',
      createdAt: new Date().toISOString()
    } as never)

    const { session } = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      credential: CREDENTIAL
    })

    expect(session).not.toBeNull()
    expect(fetchTransientKeyring).not.toHaveBeenCalled()
    // The routing's derived credential is threaded on, so the KDF ran once.
    expect(vi.mocked(fetchKeyring).mock.calls[0]![0].credential).toBe(
      CREDENTIAL
    )
  })
})
