// @vitest-environment node
/**
 * Unit tests for the stored record envelope codec
 * (`src/session/recordEnvelope.ts`): the signed round trip the unlock-methods
 * registry rides, the three ways a signed record is refused (a tampered body,
 * a foreign signer, no proof at all), the verify path's independence from the
 * frame version stamped on the record, and the unsigned round trip the
 * browser-local client-key record keeps. The real EDV cipher and the real
 * Ed25519 derivations run unmocked.
 */
import { describe, expect, it } from 'vitest'
import { mintUserKey, userKeyVaultKeys } from '@interop/wallet-core/keys'
import {
  recordSignerFromSeed,
  type RecordSigner
} from '@interop/wallet-core/keyring'
import {
  RecordEnvelopeDecryptError,
  unwrapRecordEnvelope,
  wrapRecordEnvelope
} from '@/session/recordEnvelope'

const COLLECTION_ID = 'test-records'
const SIGNED_VERSION = 2
const UNSIGNED_VERSION = 1

/**
 * A user key's vault keys plus its record signer -- everything a signed
 * record's writer and reader need.
 *
 * @returns {Promise<object>}
 */
async function signingParty(): Promise<{
  keyAgreementKey: Awaited<
    ReturnType<typeof userKeyVaultKeys>
  >['keyAgreementKey']
  keyResolver: Awaited<ReturnType<typeof userKeyVaultKeys>>['keyResolver']
  signer: RecordSigner
}> {
  const userKey = await mintUserKey()
  const { keyAgreementKey, keyResolver } = userKeyVaultKeys({ userKey })
  return {
    keyAgreementKey,
    keyResolver,
    signer: await recordSignerFromSeed({ seed: userKey.secret })
  }
}

describe('the signed record envelope', () => {
  it('round-trips a body under its signing key', async () => {
    const { keyAgreementKey, keyResolver, signer } = await signingParty()
    const record = await wrapRecordEnvelope({
      data: { hello: 'world' },
      version: SIGNED_VERSION,
      collectionId: COLLECTION_ID,
      keyAgreementKey,
      keyResolver,
      signer
    })

    expect(record.proof?.cryptosuite).toBe('eddsa-jcs-2022')
    await expect(
      unwrapRecordEnvelope({
        record,
        version: SIGNED_VERSION,
        collectionId: COLLECTION_ID,
        keyAgreementKey,
        keyResolver,
        label: 'test',
        verify: { keyMultibase: signer.keyMultibase }
      })
    ).resolves.toEqual({ hello: 'world' })
  })

  it('refuses a record whose sealed body was swapped', async () => {
    const { keyAgreementKey, keyResolver, signer } = await signingParty()
    const record = (await wrapRecordEnvelope({
      data: { hello: 'world' },
      version: SIGNED_VERSION,
      collectionId: COLLECTION_ID,
      keyAgreementKey,
      keyResolver,
      signer
    })) as { wrapped: { jwe: { ciphertext: string } } }
    record.wrapped.jwe.ciphertext = 'dGFtcGVyZWQ'

    await expect(
      unwrapRecordEnvelope({
        record,
        version: SIGNED_VERSION,
        collectionId: COLLECTION_ID,
        keyAgreementKey,
        keyResolver,
        label: 'test',
        verify: { keyMultibase: signer.keyMultibase }
      })
    ).rejects.toMatchObject({ name: 'RecordProofError' })
  })

  it('reads a record signed by another key as one it cannot open', async () => {
    const author = await signingParty()
    const reader = await signingParty()
    const record = await wrapRecordEnvelope({
      data: { hello: 'world' },
      version: SIGNED_VERSION,
      collectionId: COLLECTION_ID,
      keyAgreementKey: author.keyAgreementKey,
      keyResolver: author.keyResolver,
      signer: author.signer
    })

    await expect(
      unwrapRecordEnvelope({
        record,
        version: SIGNED_VERSION,
        collectionId: COLLECTION_ID,
        keyAgreementKey: author.keyAgreementKey,
        keyResolver: author.keyResolver,
        label: 'test',
        verify: { keyMultibase: reader.signer.keyMultibase }
      })
    ).rejects.toBeInstanceOf(RecordEnvelopeDecryptError)
  })

  it("verifies at a frame version other than wallet-core's own", async () => {
    const { keyAgreementKey, keyResolver, signer } = await signingParty()
    const foreignVersion = 7
    const record = await wrapRecordEnvelope({
      data: { hello: 'world' },
      version: foreignVersion,
      collectionId: COLLECTION_ID,
      keyAgreementKey,
      keyResolver,
      signer
    })

    expect(record.proof?.cryptosuite).toBe('eddsa-jcs-2022')
    await expect(
      unwrapRecordEnvelope({
        record,
        version: foreignVersion,
        collectionId: COLLECTION_ID,
        keyAgreementKey,
        keyResolver,
        label: 'test',
        verify: { keyMultibase: signer.keyMultibase }
      })
    ).resolves.toEqual({ hello: 'world' })
  })

  it('refuses an unsigned frame stamped at the signed version', async () => {
    const { keyAgreementKey, keyResolver, signer } = await signingParty()
    const record = await wrapRecordEnvelope({
      data: { hello: 'world' },
      version: SIGNED_VERSION,
      collectionId: COLLECTION_ID,
      keyAgreementKey,
      keyResolver
    })

    await expect(
      unwrapRecordEnvelope({
        record,
        version: SIGNED_VERSION,
        collectionId: COLLECTION_ID,
        keyAgreementKey,
        keyResolver,
        label: 'test',
        verify: { keyMultibase: signer.keyMultibase }
      })
    ).rejects.toMatchObject({ name: 'RecordProofError' })
  })
})

describe('the unsigned record envelope (the client-key record path)', () => {
  it('round-trips with neither a signer nor a verifier', async () => {
    const { keyAgreementKey, keyResolver } = await signingParty()
    const record = await wrapRecordEnvelope({
      data: { clientSeed: 'zSeed' },
      version: UNSIGNED_VERSION,
      collectionId: COLLECTION_ID,
      keyAgreementKey,
      keyResolver
    })

    expect(record.proof).toBeUndefined()
    await expect(
      unwrapRecordEnvelope({
        record,
        version: UNSIGNED_VERSION,
        collectionId: COLLECTION_ID,
        keyAgreementKey,
        keyResolver,
        label: 'test'
      })
    ).resolves.toEqual({ clientSeed: 'zSeed' })
  })

  it('refuses a body sealed to another key', async () => {
    const author = await signingParty()
    const reader = await signingParty()
    const record = await wrapRecordEnvelope({
      data: { clientSeed: 'zSeed' },
      version: UNSIGNED_VERSION,
      collectionId: COLLECTION_ID,
      keyAgreementKey: author.keyAgreementKey,
      keyResolver: author.keyResolver
    })

    await expect(
      unwrapRecordEnvelope({
        record,
        version: UNSIGNED_VERSION,
        collectionId: COLLECTION_ID,
        keyAgreementKey: reader.keyAgreementKey,
        keyResolver: reader.keyResolver,
        label: 'test'
      })
    ).rejects.toBeInstanceOf(RecordEnvelopeDecryptError)
  })
})
