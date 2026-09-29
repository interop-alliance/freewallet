/**
 * Unit tests for the content-migration ceremony: the sink's merge rules over
 * real bundles, and the run record it writes afterwards.
 *
 * Every bundle here is genuinely encrypted -- a user key roster wrapped to a
 * recovery code's identity, one epoch per collection wrapped to that user key,
 * and real envelopes over was-client's own cipher -- packed by
 * `@interop/space-archive` and `@interop/wallet-backup`'s own writers. The
 * account side is a `StorageManager` over a memory-RxDB `BrowserStore` with
 * real ciphers, so a row really round-trips through encrypt and decrypt and no
 * dedupe can be masked by a plaintext store's idempotent insert.
 *
 * A recovery code is the secret throughout: it derives through HKDF where a
 * passphrase would pay Argon2id per test for nothing this file asserts.
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CONTACTS_COLLECTION,
  CONTACTS_HISTORY_COLLECTION
} from '@interop/social-core'
import { QuotaExceededError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createEdvEncryptOnlyDocCipher,
  mintEpoch,
  ownerRecipient,
  toEpochConfigurationState,
  wrapEpochSecret,
  EDV_SCHEME_VERSION
} from '@interop/was-client/edv/core'
import type { RecipientPublicKey } from '@interop/was-client/edv/core'
import {
  collectBytes,
  fileNameFor,
  packSpaceArchive
} from '@interop/space-archive'
import type { ArchiveEntry, ArchiveFile } from '@interop/space-archive'
import { writeBundle, BUNDLE_ROLE } from '@interop/wallet-backup'
import type { MigrationSecret } from '@interop/wallet-backup'
import {
  generateRecoveryCode,
  recoveryClientFromCode
} from '@interop/wallet-core/recovery/recoveryCode'
import { mintUserKey } from '@interop/wallet-core/keys/userKey'
import { userKeyAsRecipient } from '@interop/wallet-core/keys/userKeyGenerations'
import {
  APP_CONNECTIONS_COLLECTION,
  KEY_MAP_COLLECTION,
  PRIVATE_CREDENTIALS_COLLECTION,
  USER_KEY_ROSTER_LOG_RESOURCE,
  WALLET_ACTIVITY_COLLECTION
} from '@interop/wallet-core/space/collections'
import { useSyncStatusStore } from '@/stores/syncStatusStore'
import type { WalletActivity } from '@/stores/storageManager'
import {
  closeMemoryStores,
  memorySession
} from '@/stores/testing/memoryStorageManager'
import {
  authorityActivityRow,
  credentialActivityRow,
  credentialRow,
  headRow,
  revisionRow
} from '@/stores/testing/migrationFixtures'
import type { Session } from '@/types/auth'
import {
  contentMigrationErrorKey,
  migrateContent
} from '@/session/contentMigration'

const SPACE_ID = 'zMigrationFixtureSpace'

beforeEach(() => {
  // Any request at all is a bug: the walk reads the bundle alone, and the
  // account side here has no remote store.
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      throw new Error('The content migration must issue no HTTP request.')
    })
  )
})

afterEach(async () => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  useSyncStatusStore.getState().reset()
  await closeMemoryStores()
})

/**
 * Encodes one JSON document as an archive file.
 *
 * @param options {object}
 * @param options.name {string}
 * @param options.document {unknown}
 * @returns {ArchiveFile}
 */
function jsonFile({
  name,
  document
}: {
  name: string
  document: unknown
}): ArchiveFile {
  return { name, bytes: new TextEncoder().encode(JSON.stringify(document)) }
}

/**
 * One collection directory of the fixture archive.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param options.files {ArchiveFile[]}
 * @param [options.metadata] {unknown}   the Collection Metadata file's body;
 *   `{ id }` by default
 * @returns {ArchiveEntry}
 */
function collectionDir({
  collectionId,
  files,
  metadata
}: {
  collectionId: string
  files: ArchiveFile[]
  metadata?: unknown
}): ArchiveEntry {
  return {
    name: collectionId,
    files: [
      jsonFile({
        name: `.collection.${collectionId}.json`,
        document: metadata ?? { id: collectionId }
      }),
      ...files
    ]
  }
}

/**
 * The one-entry JSON Lines log body whose head declares an encryption
 * descriptor.
 *
 * @param descriptor {CollectionEncryption}
 * @returns {string}
 */
function logBody(descriptor: CollectionEncryption): string {
  return `${JSON.stringify({
    state: toEpochConfigurationState(descriptor)
  })}\n`
}

/**
 * One fixture collection: the rows it carries, sealed under an epoch of its
 * own.
 */
interface FixtureCollection {
  collectionId: string
  rows: unknown[]
  metadata?: unknown
}

/**
 * Builds one fixture bundle: a user key roster wrapped to a fresh recovery
 * code's identity, one epoch per collection wrapped to that user key, and
 * every row sealed under it.
 *
 * @param collections {FixtureCollection[]}
 * @returns {Promise<{ bundle: Uint8Array; secret: MigrationSecret }>}
 */
async function makeBundle(
  collections: FixtureCollection[]
): Promise<{ bundle: Uint8Array; secret: MigrationSecret }> {
  const code = generateRecoveryCode()
  const client = await recoveryClientFromCode({ code })
  const recipient = ownerRecipient({
    keyAgreementKey: client.agents.keyAgreementKey as Parameters<
      typeof ownerRecipient
    >[0]['keyAgreementKey']
  }) as RecipientPublicKey
  const userKey = await mintUserKey()
  const roster: CollectionEncryption = {
    scheme: 'edv',
    version: EDV_SCHEME_VERSION,
    currentEpoch: userKey.id,
    epochs: [
      {
        id: userKey.id,
        recipients: [
          await wrapEpochSecret({ epochSecret: userKey.secret, recipient })
        ]
      }
    ]
  }
  const entries: ArchiveEntry[] = [
    jsonFile({
      name: `.space.${SPACE_ID}.json`,
      document: { id: SPACE_ID, type: ['Space'] }
    }),
    collectionDir({
      collectionId: KEY_MAP_COLLECTION.id,
      files: [
        {
          name: fileNameFor({
            resourceId: USER_KEY_ROSTER_LOG_RESOURCE,
            contentType: 'application/json'
          }),
          bytes: new TextEncoder().encode(logBody(roster))
        }
      ]
    })
  ]
  for (const { collectionId, rows, metadata } of collections) {
    const { epochId, secret } = await mintEpoch()
    const encryption: CollectionEncryption = {
      scheme: 'edv',
      version: EDV_SCHEME_VERSION,
      currentEpoch: epochId,
      epochs: [
        {
          id: epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: secret,
              recipient: userKeyAsRecipient({ userKey })
            })
          ]
        }
      ]
    }
    const cipher = await createEdvEncryptOnlyDocCipher({
      collectionId,
      encryption
    })
    const files: ArchiveFile[] = [
      jsonFile({
        name: `.collectionlog.${collectionId}.json`,
        document: {
          generation: 'zFixtureLogGeneration',
          version: 1,
          body: logBody(encryption)
        }
      })
    ]
    for (const row of rows) {
      const { id, envelope } = await cipher.encrypt({
        data: row as Parameters<typeof cipher.encrypt>[0]['data']
      })
      files.push(
        jsonFile({
          name: fileNameFor({
            resourceId: id,
            contentType: 'application/json'
          }),
          document: envelope
        })
      )
    }
    entries.push(collectionDir({ collectionId, files, metadata }))
  }
  const archive = await collectBytes(
    (await packSpaceArchive({
      spaceId: SPACE_ID,
      entries
    })) as unknown as AsyncIterable<Uint8Array>
  )
  const pack = await writeBundle({
    meta: {
      created: '2026-09-18T00:00:00.000Z',
      createdBy: {
        controller: 'did:webvh:zFixtureScid:example.com:space:zOld:id',
        client: { name: 'Fixture Wallet', url: 'https://example.com/' }
      }
    },
    spaces: [
      { spaceId: SPACE_ID, role: BUNDLE_ROLE.accountSpaceArchive, archive }
    ]
  })
  const bundle = await collectBytes(
    pack as unknown as AsyncIterable<Uint8Array>
  )
  return { bundle, secret: { recoveryCode: code } }
}

/**
 * The account's Import activity rows, newest read order first.
 *
 * @param session {Session}
 * @returns {Promise<WalletActivity[]>}
 */
async function importActivities(session: Session): Promise<WalletActivity[]> {
  const { entries: items } = await session.storage.listHistoryItems()
  return items
    .map(({ doc }) => doc)
    .filter(doc => (doc.type ?? []).includes('Import'))
}

describe('migrateContent', () => {
  it('leaves exactly one import activity after two runs, with the second run counts', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: PRIVATE_CREDENTIALS_COLLECTION,
        rows: [credentialRow('first'), credentialRow('second')]
      }
    ])

    const first = await migrateContent({ session, bundle, secret })
    expect(
      first.report.collections[PRIVATE_CREDENTIALS_COLLECTION]
    ).toMatchObject({ accepted: 2, skipped: 0 })

    const second = await migrateContent({ session, bundle, secret })
    expect(
      second.report.collections[PRIVATE_CREDENTIALS_COLLECTION]
    ).toMatchObject({ accepted: 0, skipped: 2 })

    const rows = await importActivities(session)
    expect(rows).toHaveLength(1)
    const object = rows[0].object as {
      collections: Record<string, { accepted: number; skipped: number }>
      provenance: string
    }
    expect(object.provenance).toBe('unverified')
    expect(object.collections[PRIVATE_CREDENTIALS_COLLECTION]).toEqual({
      accepted: 0,
      skipped: 2,
      failed: 0
    })
  })

  it('brings every archived Create activity across on the re-run after an abort', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: PRIVATE_CREDENTIALS_COLLECTION,
        rows: [credentialRow('first'), credentialRow('second')]
      },
      {
        collectionId: WALLET_ACTIVITY_COLLECTION,
        rows: [
          credentialActivityRow({ id: 'act-1', type: 'Create', cid: 'cid-1' }),
          credentialActivityRow({ id: 'act-2', type: 'Create', cid: 'cid-2' })
        ]
      }
    ])

    // Killed once the credentials are in and before any activity row lands.
    const controller = new AbortController()
    await expect(
      migrateContent({
        session,
        bundle,
        secret,
        signal: controller.signal,
        onProgress: ({ collectionId }) => {
          if (collectionId === PRIVATE_CREDENTIALS_COLLECTION) {
            controller.abort()
          }
        }
      })
    ).rejects.toBeDefined()
    expect(await importActivities(session)).toHaveLength(0)

    const rerun = await migrateContent({ session, bundle, secret })
    expect(rerun.report.collections[WALLET_ACTIVITY_COLLECTION]).toMatchObject({
      accepted: 2,
      skipped: 0
    })
  })

  it('drops an archived Create only when the account already records one for that cid', async () => {
    const session = await memorySession()
    await session.storage.importActivity({
      activity: credentialActivityRow({
        id: 'held-create',
        type: 'Create',
        cid: 'cid-held'
      }),
      held: await session.storage.snapshotHeldContent()
    })

    const { bundle, secret } = await makeBundle([
      {
        collectionId: WALLET_ACTIVITY_COLLECTION,
        rows: [
          credentialActivityRow({
            id: 'archived-held',
            type: 'Create',
            cid: 'cid-held'
          }),
          credentialActivityRow({
            id: 'archived-fresh',
            type: 'Create',
            cid: 'cid-fresh'
          })
        ]
      }
    ])

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.collections[WALLET_ACTIVITY_COLLECTION]).toMatchObject(
      { accepted: 1, skipped: 1 }
    )

    const { entries: items } = await session.storage.listHistoryItems()
    const ids = items.map(({ doc }) => doc.id)
    expect(ids).toContain('archived-fresh')
    expect(ids).not.toContain('archived-held')
  })

  it('migrates the four credential activity types and no authority row', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: WALLET_ACTIVITY_COLLECTION,
        rows: [
          credentialActivityRow({ id: 'a-1', type: 'Create', cid: 'cid-1' }),
          credentialActivityRow({ id: 'a-2', type: 'Delete', cid: 'cid-1' }),
          credentialActivityRow({ id: 'a-3', type: 'Share', cid: 'cid-1' }),
          credentialActivityRow({ id: 'a-4', type: 'Unshare', cid: 'cid-1' }),
          authorityActivityRow({ id: 'a-5', type: 'Login' }),
          authorityActivityRow({ id: 'a-6', type: 'Revoke' }),
          authorityActivityRow({ id: 'a-7', type: 'CollectionShare' })
        ]
      }
    ])

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.collections[WALLET_ACTIVITY_COLLECTION]).toMatchObject(
      { accepted: 4, skipped: 3 }
    )

    const { entries: items } = await session.storage.listHistoryItems()
    const ids = items.map(({ doc }) => doc.id)
    expect(ids).toEqual(expect.arrayContaining(['a-1', 'a-2', 'a-3', 'a-4']))
    for (const absent of ['a-5', 'a-6', 'a-7']) {
      expect(ids).not.toContain(absent)
    }
    const landed = items.find(({ doc }) => doc.id === 'a-3')?.doc
    expect(landed?.created).toBe('2024-03-04T05:06:09.000Z')
  })

  it('skips a revision whose head failed, and an orphan revision', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: CONTACTS_COLLECTION,
        rows: [headRow({ contactId: 'contact-1', displayName: 'Ada' })]
      },
      {
        collectionId: CONTACTS_HISTORY_COLLECTION,
        rows: [
          revisionRow({ contactId: 'contact-1', displayName: 'Ada' }),
          revisionRow({ contactId: 'contact-orphan', displayName: 'Nobody' })
        ]
      }
    ])
    vi.spyOn(session.storage, 'importContactHead').mockResolvedValue('failed')
    const importRevision = vi.spyOn(session.storage, 'importContactRevision')

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.collections[CONTACTS_COLLECTION]).toMatchObject({
      failed: 1
    })
    // The failed head's revision is skipped rather than failed, so a head
    // that will not write cannot end the collection through the walk's
    // consecutive-failure stop; the re-run retries the head and lands both.
    expect(
      result.report.collections[CONTACTS_HISTORY_COLLECTION]
    ).toMatchObject({ failed: 0, skipped: 2, accepted: 0 })
    expect(importRevision).not.toHaveBeenCalled()
  })

  it('does not end contacts-history on one failed head with many revisions', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: CONTACTS_COLLECTION,
        rows: [
          headRow({ contactId: 'contact-bad', displayName: 'Ada' }),
          headRow({ contactId: 'contact-good', displayName: 'Grace' })
        ]
      },
      {
        collectionId: CONTACTS_HISTORY_COLLECTION,
        rows: [
          ...Array.from({ length: 12 }, (_, index) =>
            revisionRow({
              contactId: 'contact-bad',
              displayName: `Ada ${index}`
            })
          ),
          revisionRow({ contactId: 'contact-good', displayName: 'Grace' })
        ]
      }
    ])
    const importHead = session.storage.importContactHead.bind(session.storage)
    vi.spyOn(session.storage, 'importContactHead').mockImplementation(
      async options =>
        options.head.contactId === 'contact-bad'
          ? 'failed'
          : await importHead(options)
    )

    const result = await migrateContent({ session, bundle, secret })
    const history = result.report.collections[CONTACTS_HISTORY_COLLECTION]
    expect(history).toMatchObject({ accepted: 1, skipped: 12, failed: 0 })
    expect(history.stoppedBy).toBeUndefined()
  })

  it('holds a head this run wrote for a duplicated copy behind it', async () => {
    const session = await memorySession()
    const head = headRow({ contactId: 'contact-1', displayName: 'Ada' })
    const { bundle, secret } = await makeBundle([
      { collectionId: CONTACTS_COLLECTION, rows: [head, head] },
      {
        collectionId: CONTACTS_HISTORY_COLLECTION,
        rows: [revisionRow({ contactId: 'contact-1', displayName: 'Ada' })]
      }
    ])

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.collections[CONTACTS_COLLECTION]).toMatchObject({
      accepted: 1,
      skipped: 1
    })
    // The second copy's skip reads as already-held, not as a seed twin, so
    // the contact's revisions still land.
    expect(
      result.report.collections[CONTACTS_HISTORY_COLLECTION]
    ).toMatchObject({ accepted: 1 })
    expect(await session.storage.listContacts()).toHaveLength(1)
  })

  it('imports a revision whose head this run wrote', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: CONTACTS_COLLECTION,
        rows: [headRow({ contactId: 'contact-1', displayName: 'Ada' })]
      },
      {
        collectionId: CONTACTS_HISTORY_COLLECTION,
        rows: [revisionRow({ contactId: 'contact-1', displayName: 'Ada' })]
      }
    ])

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.collections[CONTACTS_COLLECTION]).toMatchObject({
      accepted: 1
    })
    expect(
      result.report.collections[CONTACTS_HISTORY_COLLECTION]
    ).toMatchObject({ accepted: 1 })
    const revisions = await session.storage.listContactRevisions({
      contactId: 'contact-1'
    })
    expect(revisions).toHaveLength(1)
    expect(revisions[0].writerId).toBe('old-writer')
  })

  it('counts the app-connections rows as not migrated and lands no app key', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: APP_CONNECTIONS_COLLECTION,
        rows: [credentialRow('an app key'), credentialRow('another app key')]
      },
      {
        collectionId: PRIVATE_CREDENTIALS_COLLECTION,
        rows: [credentialRow('a real credential')]
      }
    ])

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.notMigrated[APP_CONNECTIONS_COLLECTION]).toBe(2)
    expect(
      result.report.collections[APP_CONNECTIONS_COLLECTION]
    ).toBeUndefined()
    expect((await session.storage.listAppKeys()).appKeys).toHaveLength(0)
    expect(await session.storage.listCredentials()).toHaveLength(1)
  })

  it('leaves an app collection in the backup on a session that cannot create it', async () => {
    const session = await memorySession()
    expect(session.storage.canProvisionAppCollections).toBe(false)
    const { bundle, secret } = await makeBundle([
      { collectionId: 'app-notes', rows: [{ id: 'a' }, { id: 'b' }] }
    ])

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.notMigrated['app-notes']).toBe(2)
    expect(result.report.collections['app-notes']).toBeUndefined()
  })

  it('re-creates an app collection with its attribution, reading the held rows once', async () => {
    const session = await memorySession()
    const { storage } = session
    vi.spyOn(storage, 'canProvisionAppCollections', 'get').mockReturnValue(true)
    const generator = {
      id: 'did:key:z6MkApp',
      origin: 'https://app.example',
      url: 'https://app.example/',
      name: 'Example App'
    }
    const ensure = vi
      .spyOn(storage, 'ensureImportedAppCollection')
      .mockResolvedValue(undefined)
    const held = new Map([['id:a', 'zHeldCid']])
    const snapshot = vi
      .spyOn(storage, 'snapshotAppCollection')
      .mockResolvedValue(held)
    const importResource = vi
      .spyOn(storage, 'importAppCollectionResource')
      .mockResolvedValue('accepted')
    const { bundle, secret } = await makeBundle([
      {
        collectionId: 'app-notes',
        rows: [{ id: 'a' }, { id: 'b' }],
        metadata: { id: 'app-notes', generator }
      }
    ])

    const result = await migrateContent({ session, bundle, secret })

    expect(ensure).toHaveBeenCalledExactlyOnceWith({
      collectionId: 'app-notes',
      encrypted: true,
      generator
    })
    expect(snapshot).toHaveBeenCalledExactlyOnceWith({
      collectionId: 'app-notes',
      encrypted: true
    })
    expect(importResource).toHaveBeenCalledTimes(2)
    for (const [args] of importResource.mock.calls) {
      expect(args).toMatchObject({
        collectionId: 'app-notes',
        encrypted: true,
        contentType: 'application/json',
        held
      })
    }
    expect(importResource.mock.calls.map(([args]) => args.content)).toEqual(
      expect.arrayContaining([{ json: { id: 'a' } }, { json: { id: 'b' } }])
    )
    expect(result.report.collections['app-notes']?.accepted).toBe(2)
    const [activity] = await importActivities(session)
    // The Import activity carries the app collection's counts beside the
    // standard collections'.
    expect(
      (
        activity as unknown as {
          object: { collections: Record<string, { accepted: number }> }
        }
      ).object.collections['app-notes']
    ).toEqual({ accepted: 2, skipped: 0, failed: 0 })
  })

  it('carries on past a failed row and ends a collection after ten consecutive failures', async () => {
    const session = await memorySession()
    const credentials = Array.from({ length: 12 }, (_unused, index) =>
      credentialRow(`credential-${index}`)
    )
    const { bundle, secret } = await makeBundle([
      {
        collectionId: PRIVATE_CREDENTIALS_COLLECTION,
        rows: credentials
      },
      {
        collectionId: WALLET_ACTIVITY_COLLECTION,
        rows: [
          credentialActivityRow({ id: 'act-1', type: 'Create', cid: 'cid-1' })
        ]
      }
    ])
    vi.spyOn(session.storage, 'importCredential').mockResolvedValue('failed')

    const result = await migrateContent({ session, bundle, secret })
    const credentialCounts =
      result.report.collections[PRIVATE_CREDENTIALS_COLLECTION]
    expect(credentialCounts.failed).toBe(10)
    expect(credentialCounts.stoppedBy).toBe('failed')
    // The stop is the collection's alone: the walk moves on.
    expect(result.report.collections[WALLET_ACTIVITY_COLLECTION]).toMatchObject(
      { accepted: 1 }
    )
    expect(result.report.stoppedAt).toBeUndefined()
  })

  it('stops the whole walk on a quota refusal and records it in the import activity', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: PRIVATE_CREDENTIALS_COLLECTION,
        rows: [credentialRow('first')]
      },
      {
        collectionId: WALLET_ACTIVITY_COLLECTION,
        rows: [
          credentialActivityRow({ id: 'act-1', type: 'Create', cid: 'cid-1' })
        ]
      }
    ])
    vi.spyOn(session.storage, 'importCredential').mockRejectedValue(
      new QuotaExceededError('The Space is full.')
    )
    const importActivity = vi.spyOn(session.storage, 'importActivity')

    const result = await migrateContent({ session, bundle, secret })
    expect(result.report.stoppedAt).toEqual({
      collectionId: PRIVATE_CREDENTIALS_COLLECTION,
      cause: 'QuotaExceededError'
    })
    expect(importActivity).not.toHaveBeenCalled()

    const rows = await importActivities(session)
    expect(rows).toHaveLength(1)
    expect(
      (rows[0].object as { stoppedAt?: { cause: string } }).stoppedAt
    ).toEqual({
      collectionId: PRIVATE_CREDENTIALS_COLLECTION,
      cause: 'QuotaExceededError'
    })
  })

  it('writes no import activity when the run is aborted', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: PRIVATE_CREDENTIALS_COLLECTION,
        rows: [credentialRow('first'), credentialRow('second')]
      }
    ])
    const controller = new AbortController()
    controller.abort()

    await expect(
      migrateContent({ session, bundle, secret, signal: controller.signal })
    ).rejects.toBeDefined()
    expect(await importActivities(session)).toHaveLength(0)
  })

  it('issues no HTTP request', async () => {
    const session = await memorySession()
    const { bundle, secret } = await makeBundle([
      {
        collectionId: PRIVATE_CREDENTIALS_COLLECTION,
        rows: [credentialRow('first')]
      }
    ])

    await migrateContent({ session, bundle, secret })
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('contentMigrationErrorKey', () => {
  it('names one key per refusal the walk raises', () => {
    const named = (name: string): Error => {
      const err = new Error('refused')
      err.name = name
      return err
    }

    expect(contentMigrationErrorKey(named('BundleInvalidError'))).toBe(
      'storage.migration.errors.bundleInvalid'
    )
    expect(
      contentMigrationErrorKey(named('AccountSpaceArchiveMissingError'))
    ).toBe('storage.migration.errors.accountArchiveMissing')
    expect(contentMigrationErrorKey(named('BundleRecipientMissingError'))).toBe(
      'storage.migration.errors.secretNotRecipient'
    )
    expect(contentMigrationErrorKey(named('AbortError'))).toBe(
      'storage.migration.errors.cancelled'
    )
    expect(
      contentMigrationErrorKey(new QuotaExceededError('The Space is full.'))
    ).toBe('storage.migration.errors.quotaExceeded')
    expect(contentMigrationErrorKey(new Error('something else'))).toBe(
      'storage.migration.errors.failed'
    )
  })
})
