/**
 * Unit tests for the `contacts` conflict binding: the decision closure this
 * app hands `@interop/was-sync`'s conflict-handler factory. Two properties are
 * this app's rather than the package's -- that the collection's cipher is read
 * at resolve time, so the epoch cascade's `setCiphers` swap is honored, and
 * that an unreadable side falls back to the remote master, which is
 * wallet-core's documented contacts rule and not the package's default
 * resolver.
 */
import { describe, expect, it } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
// The driver logs through was-sync's own seam, which the app's logging module
// wires to the `sync` namespace on import.
import '@/lib/log'
import type { DocCipher } from '@interop/was-client/edv'
import type { SyncedDoc, WithDeleted } from '@interop/was-sync'
import { createContactsConflictHandler } from './contactsConflictHandler'

const CONTACT_ID = 'urn:uuid:c0ffee'

/**
 * A stored contact head row, carrying an envelope the fake ciphers below key
 * their answer on.
 *
 * @param options {object}
 * @param options.envelopeId {string}
 * @param options.version {number}
 * @returns {WithDeleted<SyncedDoc>}
 */
function row({
  envelopeId,
  version
}: {
  envelopeId: string
  version: number
}): WithDeleted<SyncedDoc> {
  return {
    id: 'row-1',
    updatedAt: '000000000001',
    version,
    _deleted: false,
    data: { jwe: { ciphertext: envelopeId } }
  }
}

/**
 * A cipher that decrypts each envelope into a head payload with the given
 * edit stamp, and throws for any envelope named in `unreadable`.
 *
 * @param options {object}
 * @param options.stamps {Record<string, string>}   envelope id to `updatedAt`
 * @param [options.unreadable] {string[]}
 * @returns {DocCipher}
 */
function fakeCipher({
  stamps,
  unreadable = []
}: {
  stamps: Record<string, string>
  unreadable?: string[]
}): DocCipher {
  return {
    async decrypt({ envelope }: { envelope: unknown }) {
      const ciphertext = (envelope as { jwe: { ciphertext: string } }).jwe
        .ciphertext
      if (unreadable.includes(ciphertext)) {
        throw new Error(`no key epoch for ${ciphertext}`)
      }
      return {
        contactId: CONTACT_ID,
        updatedAt: stamps[ciphertext],
        writerId: ciphertext,
        contact: { displayName: 'Ada Lovelace' }
      }
    }
  } as unknown as DocCipher
}

describe('the contacts conflict binding', () => {
  it('reads the cipher at resolve time, so a setCiphers swap is honored', async () => {
    // The first cipher can read neither side, which the rule settles as
    // remote. The swap makes the local side readable and fresher, and the same
    // handler instance must then answer local.
    let cipher = fakeCipher({
      stamps: {},
      unreadable: ['remote-env', 'local-env']
    })
    const handler = createContactsConflictHandler({ getCipher: () => cipher })
    const input = {
      realMasterState: row({ envelopeId: 'remote-env', version: 4 }),
      newDocumentState: row({ envelopeId: 'local-env', version: 3 })
    }

    expect(await handler.resolve(input)).toBe(input.realMasterState)

    cipher = fakeCipher({
      stamps: {
        'remote-env': '2026-01-01T00:00:00.000Z',
        'local-env': '2026-02-01T00:00:00.000Z'
      }
    })
    expect(await handler.resolve(input)).toBe(input.newDocumentState)
  })

  it('falls back to the remote master when the local side will not decrypt', async () => {
    // Freewallet's policy, not the package's default resolver's: an
    // undecryptable side (a stale descriptor after another client's rekey)
    // simply loses.
    const handler = createContactsConflictHandler({
      getCipher: () =>
        fakeCipher({
          stamps: { 'remote-env': '2026-01-01T00:00:00.000Z' },
          unreadable: ['local-env']
        })
    })
    const input = {
      realMasterState: row({ envelopeId: 'remote-env', version: 4 }),
      newDocumentState: row({ envelopeId: 'local-env', version: 3 })
    }

    expect(await handler.resolve(input)).toBe(input.realMasterState)
  })

  it('treats a revision-only difference as a real difference', async () => {
    // The equality RxDB asks for before it resolves anything must count the
    // server revision: this replica's own write comes back off the feed
    // byte-identical but one revision ahead, and a state that compared equal
    // would leave every later conditional write sending a stale `If-Match`.
    const handler = createContactsConflictHandler({
      getCipher: () => undefined
    })
    const local = row({ envelopeId: 'local-env', version: 3 })

    expect(handler.isEqual(local, local)).toBe(true)
    expect(
      handler.isEqual(local, row({ envelopeId: 'local-env', version: 4 }))
    ).toBe(false)
  })

  it("reports a resolver failure on the driver's sync namespace", async () => {
    // Both sides' own unreachability is fail-safe inside
    // resolveContactHeadConflict; what can still throw out of this binding's
    // resolve closure is `getCipher` itself, and `makeConflictHandler` is the
    // one that reports it before the failure propagates and fails the
    // replication cycle.
    const handler = createContactsConflictHandler({
      getCipher: () => {
        throw new Error('cipher unavailable')
      }
    })
    const input = {
      realMasterState: row({ envelopeId: 'remote-env', version: 4 }),
      newDocumentState: row({ envelopeId: 'local-env', version: 3 })
    }

    const capture = captureSink()
    const removeSink = addSink(capture.sink)
    try {
      await expect(handler.resolve(input)).rejects.toThrow('cipher unavailable')
    } finally {
      removeSink()
    }

    expect(capture.events.map(event => [event.ns, event.level])).toEqual([
      ['sync', 'error']
    ])
  })
})
