// @vitest-environment node
/**
 * The transient chain's collection fan-out (the first registration of
 * `TRANSIENT_REGISTRATIONS` in `src/session/menders/registrations.ts`),
 * over wallet-core's real cascade driver and real key material. The scenario
 * is a user-key rotation torn mid-fan-out on a credential-anchored account:
 * the roster's current epoch names generation G1, one collection already
 * moved onto G1, and another still names G0. The next transient login's
 * converge moves the straggler onto G1, leaves the other alone, and a second
 * converge over the result writes nothing.
 */
import { describe, expect, it, vi } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import { epochKeyIdFor, initRecipients } from '@interop/was-client/edv'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  mintUserKey,
  readUserKeyRoster,
  rotateCollectionEpochsToUserKey,
  rotateUserKeyRoster,
  unwrapUserKeyGenerations,
  userKeyAsRecipient,
  type KeyAgreementDocument,
  type UserKey,
  type UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import {
  TRANSIENT_REGISTRATIONS,
  type LoginMenderDeps
} from '@/session/menders/registrations'
import { memoryDescriptorStores } from './fakeDescriptorStores'

const COLLECTION_A = 'app-notes-a'
const COLLECTION_B = 'app-notes-b'

/**
 * The registration under test, reached through the exported list rather
 * than a production export of its own.
 */
const collectionCascade = TRANSIENT_REGISTRATIONS[0]!

/**
 * A did:key-identified X25519 key-agreement key, the shape a standing
 * credential's key-agreement key takes.
 *
 * @returns {Promise<IKeyAgreementKey & { publicKeyMultibase: string }>}
 */
async function makeKak(): Promise<
  IKeyAgreementKey & { publicKeyMultibase: string }
> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return kak as IKeyAgreementKey & { publicKeyMultibase: string }
}

/**
 * The account document's `keyAgreement` half, publishing each key verbatim.
 *
 * @param kaks {Array<{ publicKeyMultibase: string }>}
 * @returns {KeyAgreementDocument}
 */
function documentFor(
  kaks: Array<{ publicKeyMultibase: string }>
): KeyAgreementDocument {
  const did = 'did:webvh:QmScid:example.com:space:abc:id'
  return {
    verificationMethod: kaks.map(kak => ({
      id: `${did}#${kak.publicKeyMultibase}`,
      publicKeyMultibase: kak.publicKeyMultibase
    })),
    keyAgreement: kaks.map(kak => `${did}#${kak.publicKeyMultibase}`)
  } as KeyAgreementDocument
}

/**
 * The current epoch's recipient kids of a descriptor.
 *
 * @param descriptor {CollectionEncryption}
 * @returns {string[]}
 */
function currentKids(descriptor: CollectionEncryption): string[] {
  const current = descriptor.epochs!.find(
    epoch => epoch.id === descriptor.currentEpoch
  )!
  return current.recipients.map(entry => entry.header.kid)
}

/**
 * A two-generation roster escrowed to the standing credential: G0 minted at
 * genesis, then rotated to G1 when a second party's wrap was retired.
 *
 * @returns {Promise<object>}
 */
async function rotatedRoster(): Promise<{
  standingKak: IKeyAgreementKey
  generation0: UserKey
  generation1: UserKey
  rosterRead: UserKeyRosterReadResult
}> {
  const standingKak = await makeKak()
  const departed = await makeKak()
  const generation0 = await mintUserKey()
  const rosterStores = memoryDescriptorStores()
  const rosterStore = rosterStores.storeFor('key-map')
  await ensureUserKeyRoster({
    store: rosterStore,
    userKey: generation0,
    clientKeyAgreementKey: standingKak
  })
  await addUserKeyRosterRecipient({
    store: rosterStore,
    recipient: {
      id: departed.id!,
      publicKeyMultibase: departed.publicKeyMultibase
    },
    ownerKeyAgreementKey: standingKak
  })
  await rotateUserKeyRoster({
    store: rosterStore,
    document: documentFor([standingKak as never]),
    retireRecipientId: departed.id!
  })
  const rosterRead = (await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: standingKak
  }))!
  const generation1 = rosterRead.userKey
  expect(generation1.id).not.toBe(generation0.id)
  return { standingKak, generation0, generation1, rosterRead }
}

/**
 * The torn state: both collections were provisioned on G0, and the rotation's
 * fan-out moved A onto G1 before it stopped, leaving B on G0.
 *
 * @returns {Promise<object>}
 */
async function tornAccount() {
  const roster = await rotatedRoster()
  const stores = memoryDescriptorStores()
  for (const collectionId of [COLLECTION_A, COLLECTION_B]) {
    await initRecipients({
      store: stores.storeFor(collectionId),
      recipients: [userKeyAsRecipient({ userKey: roster.generation0 })]
    })
  }
  const generations = await unwrapUserKeyGenerations({
    descriptor: roster.rosterRead.descriptor,
    clientKeyAgreementKey: roster.standingKak
  })
  await expect(
    rotateCollectionEpochsToUserKey({
      store: stores.storeFor(COLLECTION_A),
      userKey: roster.generation1,
      generations
    })
  ).resolves.toBe('rotated')
  stores.writes.length = 0
  return { ...roster, stores }
}

/**
 * Transient chain deps whose `context()` resolves a ladder-kind context stub
 * carrying the parts the fan-out reads.
 *
 * @param options {object}
 * @param options.standingKak {IKeyAgreementKey}
 * @param options.rosterRead {UserKeyRosterReadResult}
 * @param options.collectionStore {function}
 * @param [options.kind] {string}
 * @param [options.strandedCollectionIds] {string[]}   the collections the
 *   session's storage built with a stranded refusing cipher
 * @returns {object}
 */
function transientDeps({
  standingKak,
  rosterRead,
  collectionStore,
  kind = 'ladder',
  strandedCollectionIds = []
}: {
  standingKak: IKeyAgreementKey
  rosterRead: UserKeyRosterReadResult
  collectionStore: unknown
  kind?: 'ladder' | 'enrolled'
  strandedCollectionIds?: string[]
}) {
  const refreshEncryptedDescriptors = vi.fn(async () => {})
  const listCollectionPublicStates = vi.fn(async () => [
    { id: COLLECTION_A, isPublic: false },
    { id: COLLECTION_B, isPublic: false }
  ])
  const context = vi.fn(async () => ({
    kind,
    remoteStore: { listCollectionPublicStates },
    collectionStore,
    standingKeyAgreementKey: standingKak
  }))
  const deps = {
    chain: 'transient',
    session: {
      storage: { refreshEncryptedDescriptors, strandedCollectionIds }
    },
    found: {},
    context,
    registry: {},
    rosterRead,
    generationDelegation: {}
  } as unknown as LoginMenderDeps
  return { deps, refreshEncryptedDescriptors, listCollectionPublicStates }
}

describe('the transient collection fan-out registration', () => {
  it('runs first in the transient block, ahead of every registry pass', () => {
    expect(collectionCascade.trigger).toBe('transient-login-chain')
    expect(collectionCascade.reports).toEqual([
      'collection-epochs-name-the-current-user-key',
      'governed-log-heads-anchor-past-the-membership-change'
    ])
    expect(
      TRANSIENT_REGISTRATIONS.slice(1).some(registration =>
        registration.reports.includes(
          'collection-epochs-name-the-current-user-key'
        )
      )
    ).toBe(false)
  })

  it('completes a rotation torn mid-fan-out, then converges to a no-op', async () => {
    const { standingKak, generation0, generation1, rosterRead, stores } =
      await tornAccount()
    const descriptorA = structuredClone(stores.descriptorOf(COLLECTION_A))
    expect(currentKids(stores.descriptorOf(COLLECTION_B)!)).toEqual([
      epochKeyIdFor(generation0.id)
    ])

    const first = transientDeps({
      standingKak,
      rosterRead,
      collectionStore: stores.storeFor
    })
    await expect(collectionCascade.converge(first.deps)).resolves.toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'clean'
      },
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'noop'
      }
    ])
    const kidsB = currentKids(stores.descriptorOf(COLLECTION_B)!)
    expect(kidsB).toContain(epochKeyIdFor(generation1.id))
    expect(kidsB).not.toContain(epochKeyIdFor(generation0.id))
    expect(stores.descriptorOf(COLLECTION_A)).toEqual(descriptorA)
    expect(stores.writes).toEqual([COLLECTION_B])
    expect(first.refreshEncryptedDescriptors).toHaveBeenCalledOnce()

    // A second visit over the converged state writes nothing.
    const second = transientDeps({
      standingKak,
      rosterRead,
      collectionStore: stores.storeFor
    })
    await expect(collectionCascade.converge(second.deps)).resolves.toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'noop'
      },
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'noop'
      }
    ])
    expect(stores.writes).toEqual([COLLECTION_B])
    expect(second.refreshEncryptedDescriptors).not.toHaveBeenCalled()
  })

  it('rebuilds the ciphers on a no-op run when the session built a stranded one', async () => {
    const { standingKak, rosterRead, stores } = await tornAccount()
    // Another client finished the fan-out between this session's build and
    // its mender block: the run rotates nothing, but the cipher built
    // stranded must still be rebuilt.
    await collectionCascade.converge(
      transientDeps({
        standingKak,
        rosterRead,
        collectionStore: stores.storeFor
      }).deps
    )
    const run = transientDeps({
      standingKak,
      rosterRead,
      collectionStore: stores.storeFor,
      strandedCollectionIds: [COLLECTION_B]
    })
    await expect(collectionCascade.converge(run.deps)).resolves.toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'noop'
      },
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'noop'
      }
    ])
    expect(run.refreshEncryptedDescriptors).toHaveBeenCalledOnce()
  })

  it('reports a no-op on a non-ladder context without touching anything', async () => {
    const { standingKak, rosterRead, stores } = await tornAccount()
    const collectionStore = vi.fn(stores.storeFor)
    const run = transientDeps({
      standingKak,
      rosterRead,
      collectionStore,
      kind: 'enrolled'
    })
    await expect(collectionCascade.converge(run.deps)).resolves.toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'noop',
        detail: { reason: 'no-ladder-context' }
      },
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'noop',
        detail: { reason: 'no-ladder-context' }
      }
    ])
    expect(run.listCollectionPublicStates).not.toHaveBeenCalled()
    expect(collectionStore).not.toHaveBeenCalled()
    expect(run.refreshEncryptedDescriptors).not.toHaveBeenCalled()
    expect(stores.writes).toEqual([])
  })

  it('reports a no-op when no account-ceremony context resolves', async () => {
    const { standingKak, rosterRead, stores } = await tornAccount()
    const run = transientDeps({
      standingKak,
      rosterRead,
      collectionStore: stores.storeFor
    })
    ;(run.deps as unknown as { context: () => Promise<null> }).context =
      async () => null
    await expect(collectionCascade.converge(run.deps)).resolves.toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'noop',
        detail: { reason: 'no-ladder-context' }
      },
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'noop',
        detail: { reason: 'no-ladder-context' }
      }
    ])
    expect(stores.writes).toEqual([])
  })

  it('reports partial when a collection store fails', async () => {
    const { standingKak, generation0, rosterRead } = await tornAccount()
    const failing = memoryDescriptorStores({
      failFor: collectionId => collectionId === COLLECTION_B
    })
    await initRecipients({
      store: failing.storeFor(COLLECTION_A),
      recipients: [userKeyAsRecipient({ userKey: generation0 })]
    })
    failing.writes.length = 0
    const run = transientDeps({
      standingKak,
      rosterRead,
      collectionStore: failing.storeFor
    })
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(collectionCascade.converge(run.deps)).resolves.toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'partial',
        detail: { failedCollections: 1 }
      },
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'partial',
        detail: { failedCollections: 1 }
      }
    ])
    warn.mockRestore()
    // The failure stays per collection: A still rotated, and the visit's
    // ciphers are rebuilt on its fresh epoch.
    expect(failing.writes).toEqual([COLLECTION_A])
    expect(run.refreshEncryptedDescriptors).toHaveBeenCalledOnce()
  })
  it('reports the governed-log half clean when a collection log was sealed', async () => {
    const { standingKak, rosterRead, stores } = await tornAccount()
    // Converge the tear first, so both collections sit on the current key
    // and the second pass reaches each store's seal backstop.
    await collectionCascade.converge(
      transientDeps({
        standingKak,
        rosterRead,
        collectionStore: stores.storeFor
      }).deps
    )
    // A's log head is anchored before the latest assertion-key removal (a
    // forget's removal entry), so its seal appends; B's is already past it.
    const sealing = (collectionId: string) => {
      const store = stores.storeFor(collectionId)
      return {
        ...store,
        async seal() {
          await store.seal()
          return collectionId === COLLECTION_A
            ? ('sealed' as const)
            : ('noop' as const)
        }
      }
    }
    const run = transientDeps({
      standingKak,
      rosterRead,
      collectionStore: sealing
    })
    await expect(collectionCascade.converge(run.deps)).resolves.toEqual([
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'noop'
      },
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'clean'
      }
    ])
    expect(stores.seals).toEqual(
      expect.arrayContaining([COLLECTION_A, COLLECTION_B])
    )
    expect(run.refreshEncryptedDescriptors).not.toHaveBeenCalled()
  })
})
