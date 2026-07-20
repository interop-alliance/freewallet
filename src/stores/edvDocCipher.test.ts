/**
 * Unit tests for the local EDV document cipher seam: real X25519 keys drive
 * the was-client EDV codec end to end (encrypt to a content-derived-id
 * envelope, decrypt back), plus the envelope structural guard.
 *
 * @vitest-environment node
 */
import { describe, expect, it } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  PreconditionFailedError,
  type Collection,
  type CollectionEncryption,
  type Space
} from '@interop/was-client'
import {
  addRecipient,
  epochKeyIdFor,
  initRecipients,
  removeRecipient
} from '@interop/was-client/edv'
import {
  createEdvDocCipher,
  isEncryptedEnvelope,
  ownerRecipient,
  UnknownEpochError,
  type DocCipher
} from './edvDocCipher'

/**
 * A generated X25519 key pair plus the single-key resolver the session profile
 * supplies alongside it (a resolver that returns the key's own public form).
 */
async function generateKey(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkTestController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  return { keyAgreementKey: key as IKeyAgreementKey, keyResolver }
}

/**
 * Builds a cipher over a freshly generated X25519 key pair, mirroring how the
 * session profile supplies keys (a key agreement key plus a resolver that
 * returns its public form).
 */
async function makeCipher(): Promise<DocCipher> {
  const { keyAgreementKey, keyResolver } = await generateKey()
  return await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: 'private-credentials'
  })
}

/**
 * A minimal in-memory `Collection` for driving the real recipient/epoch
 * operations: it holds one Collection Description with an `encryption` marker
 * and a monotonic version counter used as the compare-and-swap etag, so
 * `initRecipients` / `addRecipient` / `removeRecipient` exercise their real CAS
 * write path against it.
 */
function makeFakeCollection(): {
  collection: Collection
  marker(): CollectionEncryption
} {
  let version = 0
  let description: {
    name?: string
    backend?: unknown
    encryption: CollectionEncryption
  } = {
    name: 'private-credentials',
    encryption: { scheme: 'edv' }
  }
  const fake = {
    async describeWithEtag() {
      return { description: { ...description }, etag: `v${version}` }
    },
    async replaceDescription(
      fields: {
        name?: string
        backend?: unknown
        encryption: CollectionEncryption
      },
      { ifMatch }: { ifMatch?: string }
    ) {
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale collection description etag')
      }
      description = { ...description, ...fields }
      version++
    }
  }
  return {
    collection: fake as unknown as Collection,
    marker: () => description.encryption
  }
}

/**
 * A minimal in-memory `Space` that records the zcaps handed to `revoke`, so a
 * removal test can assert the pull-axis half fired.
 */
function makeFakeSpace(): { space: Space; revoked: unknown[] } {
  const revoked: unknown[] = []
  const fake = {
    async revoke(zcap: unknown) {
      revoked.push(zcap)
    }
  }
  return { space: fake as unknown as Space, revoked }
}

describe('createEdvDocCipher', () => {
  it('round-trips a JSON document through an EDV envelope', async () => {
    const cipher = await makeCipher()
    const data = { hello: 'world', nested: { count: 3 } }

    const { id, envelope } = await cipher.encrypt({ data })

    // The stored body is an opaque envelope: EDV id + JWE, no plaintext.
    expect(isEncryptedEnvelope(envelope)).toBe(true)
    expect((envelope as { id?: string }).id).toBe(id)
    expect(id).toMatch(/^z[1-9A-HJ-NP-Za-km-z]{21,}$/)
    expect(JSON.stringify(envelope)).not.toContain('world')

    await expect(cipher.decrypt({ envelope })).resolves.toEqual(data)
  })

  it('mints a fresh id per encryption (nondeterministic JWE)', async () => {
    const cipher = await makeCipher()
    const data = { same: 'content' }

    const first = await cipher.encrypt({ data })
    const second = await cipher.encrypt({ data })

    expect(first.id).not.toBe(second.id)
  })
})

/**
 * The JWE recipient key ids an EDV envelope names (the epoch key id on an epoch
 * envelope; the vault key id on a single-recipient envelope).
 */
function envelopeKids(envelope: unknown): string[] {
  const recipients =
    (envelope as { jwe?: { recipients?: { header?: { kid?: string } }[] } })
      ?.jwe?.recipients ?? []
  return recipients.map(recipient => recipient.header?.kid ?? '')
}

describe('createEdvDocCipher (multi-recipient / key epochs)', () => {
  it('owner writes under the current epoch and stamps the epoch key kid', async () => {
    const { collection, marker } = makeFakeCollection()
    const owner = await generateKey()
    const encryption = await initRecipients({
      collection,
      recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
    })

    const cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption
    })
    const { envelope, epoch } = await cipher.encrypt({
      data: { secret: 'value' }
    })

    expect(epoch).toBe(encryption.currentEpoch)
    expect(envelopeKids(envelope)).toEqual([
      epochKeyIdFor(encryption.currentEpoch!)
    ])
    // Sanity: the marker the fake collection now holds carries the epoch.
    expect(marker().currentEpoch).toBe(encryption.currentEpoch)
    await expect(cipher.decrypt({ envelope })).resolves.toEqual({
      secret: 'value'
    })
  })

  it('two recipients both read the same envelope', async () => {
    const { collection } = makeFakeCollection()
    const owner = await generateKey()
    const reader = await generateKey()
    const encryption = await initRecipients({
      collection,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: reader.keyAgreementKey })
      ]
    })

    const ownerCipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption
    })
    const readerCipher = await createEdvDocCipher({
      keyAgreementKey: reader.keyAgreementKey,
      keyResolver: reader.keyResolver,
      collectionId: 'private-credentials',
      encryption
    })
    const { envelope } = await ownerCipher.encrypt({ data: { shared: true } })

    await expect(ownerCipher.decrypt({ envelope })).resolves.toEqual({
      shared: true
    })
    await expect(readerCipher.decrypt({ envelope })).resolves.toEqual({
      shared: true
    })
  })

  it('a recipient added via addRecipient reads pre- and post-add envelopes (escrow)', async () => {
    const { collection } = makeFakeCollection()
    const owner = await generateKey()
    const encryption1 = await initRecipients({
      collection,
      recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
    })

    // A resource written BEFORE the third reader is added.
    const ownerCipher1 = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: encryption1
    })
    const preAdd = await ownerCipher1.encrypt({ data: { when: 'before' } })

    // Escrow the third reader into every epoch (no rotation).
    const added = await generateKey()
    const encryption2 = await addRecipient({
      collection,
      recipient: ownerRecipient({ keyAgreementKey: added.keyAgreementKey }),
      owner: { keyAgreementKey: owner.keyAgreementKey }
    })
    // addRecipient does not rotate: the current epoch is unchanged.
    expect(encryption2.currentEpoch).toBe(encryption1.currentEpoch)

    // A resource written AFTER the add (still the same, escrowed epoch).
    const ownerCipher2 = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: encryption2
    })
    const postAdd = await ownerCipher2.encrypt({ data: { when: 'after' } })

    const addedCipher = await createEdvDocCipher({
      keyAgreementKey: added.keyAgreementKey,
      keyResolver: added.keyResolver,
      collectionId: 'private-credentials',
      encryption: encryption2
    })
    await expect(
      addedCipher.decrypt({ envelope: preAdd.envelope })
    ).resolves.toEqual({ when: 'before' })
    await expect(
      addedCipher.decrypt({ envelope: postAdd.envelope })
    ).resolves.toEqual({ when: 'after' })
  })

  it('removeRecipient rotates: removed reader loses new writes, keeps old; remaining reads both; zcap revoked', async () => {
    const { collection } = makeFakeCollection()
    const { space, revoked } = makeFakeSpace()
    const owner = await generateKey()
    const removed = await generateKey()
    const kept = await generateKey()
    const encryption1 = await initRecipients({
      collection,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: removed.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: kept.keyAgreementKey })
      ]
    })

    // A pre-rotation resource, and the removed reader's cipher built from the
    // PRE-rotation marker (building it from the rotated marker would throw,
    // since the removed reader is in no epoch there).
    const ownerCipher1 = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: encryption1
    })
    const preRotation = await ownerCipher1.encrypt({ data: { era: 'old' } })
    const removedCipher = await createEdvDocCipher({
      keyAgreementKey: removed.keyAgreementKey,
      keyResolver: removed.keyResolver,
      collectionId: 'private-credentials',
      encryption: encryption1
    })

    // Remove the reader: rotate the epoch AND revoke its pull-axis zcap.
    const revocationZcap = {
      id: 'urn:zcap:delegated:reader'
    } as unknown as Parameters<typeof removeRecipient>[0]['revoke']
    const encryption2 = await removeRecipient({
      collection,
      space,
      recipientId: removed.keyAgreementKey.id!,
      revoke: revocationZcap
    })
    expect(encryption2.currentEpoch).not.toBe(encryption1.currentEpoch)
    expect(revoked).toEqual([revocationZcap])

    // A post-rotation resource, under the new epoch.
    const ownerCipher2 = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: encryption2
    })
    const postRotation = await ownerCipher2.encrypt({ data: { era: 'new' } })

    // Read axis: the removed reader (stale marker) cannot route the new epoch's
    // kid -- UnknownEpochError, its cue to re-read the Collection Description.
    await expect(
      removedCipher.decrypt({ envelope: postRotation.envelope })
    ).rejects.toBeInstanceOf(UnknownEpochError)
    // ...but a pre-rotation resource it already holds still decrypts.
    await expect(
      removedCipher.decrypt({ envelope: preRotation.envelope })
    ).resolves.toEqual({ era: 'old' })

    // The remaining reader reads both eras.
    const keptCipher = await createEdvDocCipher({
      keyAgreementKey: kept.keyAgreementKey,
      keyResolver: kept.keyResolver,
      collectionId: 'private-credentials',
      encryption: encryption2
    })
    await expect(
      keptCipher.decrypt({ envelope: preRotation.envelope })
    ).resolves.toEqual({ era: 'old' })
    await expect(
      keptCipher.decrypt({ envelope: postRotation.envelope })
    ).resolves.toEqual({ era: 'new' })
  })

  it('an epoch-aware cipher decrypts a pre-epoch envelope for the same KAK', async () => {
    const { collection } = makeFakeCollection()
    const owner = await generateKey()

    // A marker-less cipher writes an envelope straight to the vault KAK.
    const preEpochCipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials'
    })
    const { envelope, epoch } = await preEpochCipher.encrypt({
      data: { legacy: true }
    })
    // No epoch on a single-key write, and the envelope names the vault KAK.
    expect(epoch).toBeUndefined()
    expect(envelopeKids(envelope)).toEqual([owner.keyAgreementKey.id])

    // The same KAK, now epoch-aware, still decrypts that pre-epoch envelope.
    const encryption = await initRecipients({
      collection,
      recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
    })
    const epochCipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption
    })
    await expect(epochCipher.decrypt({ envelope })).resolves.toEqual({
      legacy: true
    })
  })

  it('a marker-less cipher throws UnknownEpochError on an envelope for a different KAK', async () => {
    const mine = await generateKey()
    const theirs = await generateKey()

    const theirCipher = await createEdvDocCipher({
      keyAgreementKey: theirs.keyAgreementKey,
      keyResolver: theirs.keyResolver,
      collectionId: 'private-credentials'
    })
    const { envelope } = await theirCipher.encrypt({ data: { not: 'mine' } })

    const myCipher = await createEdvDocCipher({
      keyAgreementKey: mine.keyAgreementKey,
      keyResolver: mine.keyResolver,
      collectionId: 'private-credentials'
    })
    await expect(myCipher.decrypt({ envelope })).rejects.toBeInstanceOf(
      UnknownEpochError
    )
  })
})

describe('isEncryptedEnvelope', () => {
  it('accepts only an object carrying an object jwe', () => {
    expect(isEncryptedEnvelope({ id: 'z123', jwe: { ciphertext: 'x' } })).toBe(
      true
    )
    expect(isEncryptedEnvelope({ jwe: 'not-an-object' })).toBe(false)
    expect(isEncryptedEnvelope({ name: 'plaintext doc' })).toBe(false)
    expect(isEncryptedEnvelope(undefined)).toBe(false)
    expect(isEncryptedEnvelope(null)).toBe(false)
    expect(isEncryptedEnvelope('jwe')).toBe(false)
  })
})
