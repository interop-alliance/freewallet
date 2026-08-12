/**
 * Unit tests for the local-only `contacts-history` projection index and the
 * contact point read that sits beside it. Drives a REAL `BrowserStore` over
 * RxDB memory storage with a counting stub cipher, so the assertions are about
 * how many envelopes a read actually decrypts, not about a mocked seam.
 *
 * @vitest-environment node
 */
import { createHash } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { RxStorage } from 'rxdb/plugins/core'
import type { ContactData, ContactRevisionPayload } from '@interop/social-core'
import type { DocCipher } from '@interop/was-client/edv'
import type { Json } from '@/lib/sync'
import { BrowserStore } from '@/stores/browserStore'
import type { User } from '@/types/auth'

const user = { id: 'did:key:zTestContactsHistoryIndex' } as User
const writerId = 'writer-1'

/**
 * A minimal stand-in for the EDV document cipher: it produces bodies that
 * `isEncryptedEnvelope` recognizes (an object `jwe`), mints a content-derived
 * id the way the real content-addressed ciphers do, and counts every decrypt
 * so a test can assert exactly which rows a read had to open. A body whose
 * ciphertext is not decodable throws, standing in for a corrupted row.
 */
function createCountingCipher(): DocCipher & {
  decryptCount: number
  resetCount(): void
} {
  const cipher = {
    decryptCount: 0,
    resetCount() {
      cipher.decryptCount = 0
    },
    async encrypt({ data }: { data: Json }) {
      const ciphertext = Buffer.from(JSON.stringify(data)).toString('base64')
      const id = createHash('sha256').update(ciphertext).digest('hex')
      return { id, envelope: { jwe: { ciphertext } } as unknown as Json }
    },
    async decrypt({ envelope }: { envelope: Json }) {
      cipher.decryptCount += 1
      const ciphertext = (envelope as { jwe: { ciphertext: string } }).jwe
        .ciphertext
      const plaintext = Buffer.from(ciphertext, 'base64').toString('utf8')
      if (!plaintext.startsWith('{')) {
        throw new Error('Cannot decrypt this envelope.')
      }
      return JSON.parse(plaintext) as Json
    }
  }
  return cipher
}

/**
 * Waits out a couple of milliseconds so consecutive writes get distinct
 * `updatedAt` stamps.
 *
 * @returns {Promise<void>}
 */
function tick(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 2))
}

/**
 * A revision payload for one contact, carrying a snapshot that a round-trip
 * assertion can recognize.
 */
function revisionFor({
  contactId,
  displayName,
  timestamp,
  writer = writerId
}: {
  contactId: string
  displayName: string
  timestamp?: string
  writer?: string
}): ContactRevisionPayload {
  return {
    contactId,
    action: 'update',
    timestamp: timestamp ?? new Date().toISOString(),
    writerId: writer,
    snapshot: { displayName } as ContactData
  }
}

describe('contacts-history projection index', () => {
  let storage: RxStorage<unknown, unknown>
  let cipher: ReturnType<typeof createCountingCipher>
  let store: BrowserStore
  let warn: ReturnType<typeof vi.spyOn>

  /**
   * Opens a BrowserStore over the shared memory storage and db prefix -- a
   * second call stands in for a new session on the same local database (RxDB's
   * memory storage keeps a closed database's rows), with an empty in-memory
   * decrypt cache.
   */
  async function openStore(): Promise<BrowserStore> {
    const opened = new BrowserStore({
      dbPrefix: 'contacts-history-index-test',
      storage,
      ciphers: { contacts: cipher, contactsHistory: cipher }
    })
    await opened.ensureUserCollections({ user })
    return opened
  }

  beforeEach(async () => {
    storage = getRxStorageMemory()
    cipher = createCountingCipher()
    warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    store = await openStore()
  })

  afterEach(async () => {
    await store.wipeStorage()
    warn.mockRestore()
  })

  it('loads one contact by row id and misses cleanly', async () => {
    const stored = await store.addContact({
      contact: { displayName: 'Ada Lovelace' } as ContactData,
      writerId
    })

    const loaded = await store.loadContact({ id: stored.id })
    expect(loaded?.contactId).toBe(stored.contactId)
    expect(loaded?.contact.displayName).toBe('Ada Lovelace')

    expect(await store.loadContact({ id: 'no-such-row' })).toBeUndefined()
  })

  it('returns only the requested contact revisions, most recent first', async () => {
    // The rows are written in the opposite order to their logical timestamps
    // (and spaced so their `updatedAt` write stamps, whose resolution is a
    // millisecond, really do differ), so only the payload timestamp can
    // produce the expected order.
    await store.addContactRevision({
      revision: revisionFor({
        contactId: 'contact-a',
        displayName: 'A two',
        timestamp: '2026-08-12T10:00:02.000Z'
      })
    })
    await tick()
    await store.addContactRevision({
      revision: revisionFor({
        contactId: 'contact-b',
        displayName: 'B one',
        timestamp: '2026-08-12T10:00:03.000Z'
      })
    })
    await tick()
    await store.addContactRevision({
      revision: revisionFor({
        contactId: 'contact-a',
        displayName: 'A one',
        timestamp: '2026-08-12T10:00:01.000Z'
      })
    })

    const revisions = await store.listContactRevisions({
      contactId: 'contact-a'
    })
    expect(revisions).toHaveLength(2)
    expect(revisions.map(revision => revision.snapshot.displayName)).toEqual([
      'A two',
      'A one'
    ])
    expect(
      revisions.every(revision => revision.contactId === 'contact-a')
    ).toBe(true)
  })

  it('breaks a timestamp tie on writerId, descending', async () => {
    const timestamp = '2026-08-12T10:00:00.000Z'
    for (const writer of ['writer-b', 'writer-a', 'writer-c']) {
      await store.addContactRevision({
        revision: revisionFor({
          contactId: 'contact-a',
          displayName: writer,
          timestamp,
          writer
        })
      })
      await tick()
    }

    const revisions = await store.listContactRevisions({
      contactId: 'contact-a'
    })
    expect(revisions.map(revision => revision.writerId)).toEqual([
      'writer-c',
      'writer-b',
      'writer-a'
    ])
  })

  it('falls back to a lexical comparison for an unparseable timestamp', async () => {
    await store.addContactRevision({
      revision: revisionFor({
        contactId: 'contact-a',
        displayName: 'parseable',
        timestamp: '2026-08-12T10:00:00.000Z'
      })
    })
    await tick()
    await store.addContactRevision({
      revision: revisionFor({
        contactId: 'contact-a',
        displayName: 'nonsense',
        timestamp: 'not-a-timestamp'
      })
    })

    const revisions = await store.listContactRevisions({
      contactId: 'contact-a'
    })
    expect(revisions).toHaveLength(2)
    // Lexically, 'not-a-timestamp' sorts after the ISO stamp, so it comes
    // first under a newest-first order -- the point being that the read
    // returns both rows rather than throwing.
    expect(revisions.map(revision => revision.snapshot.displayName)).toEqual([
      'nonsense',
      'parseable'
    ])
  })

  it('skips write-time indexed rows of other contacts without decrypting', async () => {
    await store.addContactRevision({
      revision: revisionFor({ contactId: 'contact-a', displayName: 'A one' })
    })
    await store.addContactRevision({
      revision: revisionFor({ contactId: 'contact-b', displayName: 'B one' })
    })
    await store.addContactRevision({
      revision: revisionFor({ contactId: 'contact-b', displayName: 'B two' })
    })

    // A new session over the same database: the write-time index rows survive,
    // the in-memory decrypt cache does not.
    const fresh = await openStore()
    cipher.resetCount()
    const revisions = await fresh.listContactRevisions({
      contactId: 'contact-a'
    })
    expect(revisions).toHaveLength(1)
    // Only contact-a's single row was opened; neither of contact-b's was.
    expect(cipher.decryptCount).toBe(1)
    await fresh.close()
  })

  it('backfills the index so an unindexed row is decrypted at most once', async () => {
    // Rows that predate the index: written straight into the history
    // collection, so nothing indexed them at write time.
    for (const [contactId, displayName] of [
      ['contact-a', 'A one'],
      ['contact-b', 'B one'],
      ['contact-b', 'B two']
    ]) {
      const { envelope, id } = await cipher.encrypt({
        data: revisionFor({ contactId, displayName }) as unknown as Json
      })
      await store.rxCollection('contactsHistory').insertIfNotExists({
        id,
        updatedAt: new Date().toISOString(),
        version: 0,
        data: envelope
      })
    }

    // The first read has no index to lean on, so it opens every row -- and
    // backfills each one's true contactId.
    cipher.resetCount()
    expect(
      await store.listContactRevisions({ contactId: 'contact-a' })
    ).toHaveLength(1)
    expect(cipher.decryptCount).toBe(3)

    // A new session (fresh decrypt cache) now pays only for contact-a's row.
    const fresh = await openStore()
    cipher.resetCount()
    expect(
      await fresh.listContactRevisions({ contactId: 'contact-a' })
    ).toHaveLength(1)
    expect(cipher.decryptCount).toBe(1)
    await fresh.close()
  })

  it('skips an undecryptable row without failing the read or poisoning the index', async () => {
    await store.addContactRevision({
      revision: revisionFor({ contactId: 'contact-a', displayName: 'A one' })
    })
    await store.rxCollection('contactsHistory').insertIfNotExists({
      id: 'corrupt-row',
      updatedAt: new Date().toISOString(),
      version: 0,
      data: { jwe: { ciphertext: 'bm90LWpzb24=' } }
    })

    const revisions = await store.listContactRevisions({
      contactId: 'contact-a'
    })
    expect(revisions).toHaveLength(1)
    expect(warn).toHaveBeenCalled()

    // The bad row stayed unindexed, so a later read retries it rather than
    // trusting a guessed attribution.
    const fresh = await openStore()
    cipher.resetCount()
    expect(
      await fresh.listContactRevisions({ contactId: 'contact-a' })
    ).toHaveLength(1)
    expect(cipher.decryptCount).toBe(2)
    await fresh.close()
  })
})
