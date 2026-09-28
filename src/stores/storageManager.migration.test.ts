/**
 * Unit tests for the content-migration import methods (`importCredential`,
 * `importContactHead`, `importContactRevision`, `importActivity`) over the
 * held-content snapshot they decide against, the put-then-delete-others write
 * of the import activity, and the failure rule both of them report under.
 *
 * The manager runs over a real BrowserStore on memory RxDB with real EDV
 * ciphers: the plaintext store's `insertIfNotExists` path is idempotent by
 * itself and would mask a missing dedupe, so every archived row here really
 * round-trips through encrypt/decrypt under a nondeterministic envelope.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ContactData, ContactHeadPayload } from '@interop/social-core'
import { QuotaExceededError } from '@interop/was-client'
import { mintAppKeyCredential } from '@interop/wallet-request'
import { SEED_CONTACT_NAMES } from '@/fixtures/defaultContacts'
import {
  closeMemoryStores,
  memoryStorageManager
} from '@/stores/testing/memoryStorageManager'
import {
  activityRow,
  credentialRow,
  headRow,
  revisionRow
} from '@/stores/testing/migrationFixtures'
import { BrowserStore } from './browserStore'

afterEach(async () => {
  vi.restoreAllMocks()
  await closeMemoryStores()
})

describe('StorageManager.importCredential', () => {
  it('accepts an archived credential once and skips the re-import', async () => {
    const { storage } = await memoryStorageManager()
    const credential = credentialRow('Ada')

    expect(await storage.importCredential({ credential })).toBe('accepted')
    expect(await storage.importCredential({ credential })).toBe('skipped')
    expect(await storage.listCredentials()).toHaveLength(1)
  })

  it('records no credential-created activity, unlike the interactive method', async () => {
    const { storage, user } = await memoryStorageManager()

    await storage.importCredential({ credential: credentialRow('Ada') })
    expect((await storage.listHistoryItems()).entries).toEqual([])

    await storage.addCredential({ credential: credentialRow('Grace'), user })
    expect((await storage.listHistoryItems()).entries).toHaveLength(1)
  })

  it('screens an app key out of the bundle and stores it nowhere', async () => {
    const { storage } = await memoryStorageManager()
    const { credential } = await mintAppKeyCredential({
      app: { name: 'Text Editor', appUrl: 'https://app.example/editor' },
      origin: 'https://app.example'
    })

    expect(await storage.importCredential({ credential })).toBe('skipped')
    expect(await storage.listCredentials()).toEqual([])
    expect((await storage.listAppKeys()).appKeys).toEqual([])
  })
})

describe('StorageManager.importContactHead', () => {
  it('writes the archived head verbatim and skips the re-import', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    const head = headRow({ contactId: 'contact-1', displayName: 'Ada' })

    expect(await storage.importContactHead({ head, held })).toBe('accepted')
    expect(await storage.importContactHead({ head, held })).toBe('skipped')

    const contacts = await storage.listContacts()
    expect(contacts).toHaveLength(1)
    expect(contacts[0].contactId).toBe('contact-1')
    expect(contacts[0].updatedAt).toBe('2024-03-04T05:06:07.000Z')
    expect(contacts[0].contact.displayName).toBe('Ada')
  })

  it('keeps the archived writerId, so a head differing only there conflicts', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    await storage.importContactHead({
      held,
      head: headRow({ contactId: 'contact-1', displayName: 'Ada' })
    })

    const outcome = await storage.importContactHead({
      held,
      head: headRow({
        contactId: 'contact-1',
        displayName: 'Ada',
        writerId: 'another-writer'
      })
    })
    expect(outcome).toBe('conflicting')
  })

  it('reports a differing payload under a held contactId as conflicting and touches nothing', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    await storage.importContactHead({
      held,
      head: headRow({ contactId: 'contact-1', displayName: 'Ada' })
    })

    const outcome = await storage.importContactHead({
      held,
      head: headRow({
        contactId: 'contact-1',
        displayName: 'Doctored',
        updatedAt: '2025-01-01T00:00:00.000Z'
      })
    })

    expect(outcome).toBe('conflicting')
    const contacts = await storage.listContacts()
    expect(contacts).toHaveLength(1)
    expect(contacts[0].contact.displayName).toBe('Ada')
    expect(contacts[0].updatedAt).toBe('2024-03-04T05:06:07.000Z')
  })

  it('records no create revision, unlike the interactive method', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    const head = headRow({ contactId: 'contact-1', displayName: 'Ada' })
    await storage.importContactHead({ head, held })

    expect(
      await storage.listContactRevisions({ contactId: 'contact-1' })
    ).toEqual([])

    const stored = await storage.addContact({
      contact: { displayName: 'Grace' } as ContactData
    })
    expect(
      await storage.listContactRevisions({ contactId: stored.contactId })
    ).toHaveLength(1)
  })

  it('refuses a head that carries no contactId and stores nothing', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    const head = headRow({ contactId: 'contact-1', displayName: 'Ada' })
    delete (head as Partial<ContactHeadPayload>).contactId

    expect(await storage.importContactHead({ head, held })).toBe('conflicting')
    expect(await storage.importContactHead({ head, held })).toBe('conflicting')
    expect(await storage.listContacts()).toEqual([])
  })

  it('reads the collection once per snapshot rather than once per row', async () => {
    const { storage } = await memoryStorageManager()
    const listHeads = vi.spyOn(BrowserStore.prototype, 'listContactHeads')
    const held = await storage.snapshotHeldContent()

    for (const name of ['Ada', 'Grace', 'Edith']) {
      await storage.importContactHead({
        held,
        head: headRow({ contactId: `contact-${name}`, displayName: name })
      })
    }

    expect(listHeads).toHaveBeenCalledTimes(1)
    expect(await storage.listContacts()).toHaveLength(3)
  })

  it('skips a bundle contact the new account already seeded', async () => {
    const { storage } = await memoryStorageManager()
    // The seeded row the new account planted at signup, under its own id.
    await storage.addContact({
      contact: { displayName: SEED_CONTACT_NAMES[0] } as ContactData
    })
    const held = await storage.snapshotHeldContent()

    const outcome = await storage.importContactHead({
      held,
      head: headRow({
        contactId: 'contact-seed',
        displayName: SEED_CONTACT_NAMES[0]
      })
    })

    // The seed-twin match is its own outcome: the ceremony maps it to
    // `skipped` for the walk, and reads it to hold the contact's revisions.
    expect(outcome).toBe('seed-twin')
    expect(await storage.listContacts()).toHaveLength(1)
  })

  it('lands the bundle copy beside a customized local seed row', async () => {
    const { storage } = await memoryStorageManager()
    await storage.addContact({
      contact: {
        displayName: SEED_CONTACT_NAMES[0],
        note: 'grown by the user'
      } as ContactData
    })
    const held = await storage.snapshotHeldContent()

    const outcome = await storage.importContactHead({
      held,
      head: headRow({
        contactId: 'contact-seed',
        displayName: SEED_CONTACT_NAMES[0]
      })
    })

    expect(outcome).toBe('accepted')
    expect(await storage.listContacts()).toHaveLength(2)
  })
})

describe('StorageManager.importContactRevision', () => {
  it('keeps the archived timestamp and writerId, and resolves to its contact', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    await storage.importContactHead({
      held,
      head: headRow({ contactId: 'contact-1', displayName: 'Ada' })
    })
    const revision = revisionRow({
      contactId: 'contact-1',
      displayName: 'Ada Lovelace'
    })

    expect(await storage.importContactRevision({ revision, held })).toBe(
      'accepted'
    )

    const revisions = await storage.listContactRevisions({
      contactId: 'contact-1'
    })
    expect(revisions).toHaveLength(1)
    expect(revisions[0].timestamp).toBe('2024-03-04T05:06:07.000Z')
    expect(revisions[0].writerId).toBe('old-writer')
    expect(revisions[0].snapshot.displayName).toBe('Ada Lovelace')
  })

  it('skips a revision it already holds and accepts a differing one', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    const revision = revisionRow({
      contactId: 'contact-1',
      displayName: 'Ada'
    })

    expect(await storage.importContactRevision({ revision, held })).toBe(
      'accepted'
    )
    expect(await storage.importContactRevision({ revision, held })).toBe(
      'skipped'
    )
    expect(
      await storage.importContactRevision({
        held,
        revision: revisionRow({
          contactId: 'contact-1',
          displayName: 'Ada',
          timestamp: '2024-05-06T07:08:09.000Z'
        })
      })
    ).toBe('accepted')
    expect(
      await storage.listContactRevisions({ contactId: 'contact-1' })
    ).toHaveLength(2)
  })

  it('writes a revision whose contact is absent rather than crashing', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()

    expect(
      await storage.importContactRevision({
        held,
        revision: revisionRow({ contactId: 'orphan', displayName: 'Nobody' })
      })
    ).toBe('accepted')
    expect(
      await storage.listContactRevisions({ contactId: 'orphan' })
    ).toHaveLength(1)
  })

  it('reports a failed write and keeps the archived row out', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    vi.spyOn(BrowserStore.prototype, 'addContactRevision').mockRejectedValue(
      new Error('the write did not land')
    )

    expect(
      await storage.importContactRevision({
        held,
        revision: revisionRow({ contactId: 'contact-1', displayName: 'Ada' })
      })
    ).toBe('failed')
  })

  it('propagates a QuotaExceededError so the walk stops', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    vi.spyOn(BrowserStore.prototype, 'addContactRevision').mockRejectedValue(
      new QuotaExceededError('The Space is full.', { status: 507 })
    )

    await expect(
      storage.importContactRevision({
        held,
        revision: revisionRow({ contactId: 'contact-1', displayName: 'Ada' })
      })
    ).rejects.toThrow(QuotaExceededError)
  })
})

describe('StorageManager.importActivity', () => {
  it('writes the archived activity under its own id and skips the re-import', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    const activity = activityRow({ id: 'activity-1', summary: 'Credential x' })

    expect(await storage.importActivity({ activity, held })).toBe('accepted')
    expect(await storage.importActivity({ activity, held })).toBe('skipped')

    const { entries: items } = await storage.listHistoryItems()
    expect(items).toHaveLength(1)
    expect(items[0].id).toBe('activity-1')
    expect(items[0].doc.summary).toBe('Credential x')
  })

  it('reports a differing body under a held activity id as conflicting', async () => {
    const { storage } = await memoryStorageManager()
    const held = await storage.snapshotHeldContent()
    await storage.importActivity({
      held,
      activity: activityRow({ id: 'activity-1', summary: 'Credential x' })
    })

    const outcome = await storage.importActivity({
      held,
      activity: activityRow({ id: 'activity-1', summary: 'Doctored' })
    })

    expect(outcome).toBe('conflicting')
    const { entries: items } = await storage.listHistoryItems()
    expect(items).toHaveLength(1)
    expect(items[0].doc.summary).toBe('Credential x')
  })
})

describe('StorageManager.putHistoryItemReplacingOthers', () => {
  it('leaves exactly one row for the id, carrying the second run counts', async () => {
    const { storage, localStore } = await memoryStorageManager()
    await storage.putHistoryItemReplacingOthers({
      activity: activityRow({ id: 'import-1', summary: 'Imported 3 rows' })
    })
    await storage.putHistoryItemReplacingOthers({
      activity: activityRow({ id: 'import-1', summary: 'Imported 7 rows' })
    })

    const { entries: items } = await storage.listHistoryItems()
    expect(items).toHaveLength(1)
    expect(items[0].doc.summary).toBe('Imported 7 rows')
    // Not merely collapsed at read time: the stale row is really gone.
    expect(
      await localStore.findHistoryItemsByInnerId({ id: 'import-1' })
    ).toHaveLength(1)
  })
})
