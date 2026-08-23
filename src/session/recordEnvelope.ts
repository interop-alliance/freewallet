/**
 * Self-contained encrypted record envelopes: the `{ version, encryption,
 * wrapped }` frame the locally stored records (the client-key record, the
 * unlock-methods registry) seal into. Under the epoch-from-birth model every
 * envelope seals to a key epoch -- was-client 0.29.x deleted the direct-to-KAK
 * single-recipient cipher -- so a record carries its own one-epoch descriptor:
 * epoch[0] freshly minted per wrap, wrapped to the given KAK alone, stored in
 * the record's `encryption` member. The construction is the wallet-core
 * keyring record's, imported from `@interop/wallet-core/keyring`: the seal
 * half (`mintRecordEncryption` / `recordCipher`) and the frame validation
 * (`parseRecordFrame`); this module adds only the frame stamp and the cipher
 * rebuild. Records stored by earlier versions (`{ version, wrapped }`, no
 * `encryption`) are refused as unusable rather than migrated.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CollectionEncryption, Json } from '@interop/was-client'
import {
  mintRecordEncryption,
  parseRecordFrame,
  recordCipher
} from '@interop/wallet-core/keyring'

// Re-exported for the test harnesses that need a local epoch-bearing
// descriptor for a cipher without a server.
export { mintRecordEncryption } from '@interop/wallet-core/keyring'

/**
 * Wraps a record body into its stored envelope: a fresh record-own descriptor
 * is minted, the body is sealed under its epoch, and the frame carries all
 * three members.
 *
 * @param options {object}
 * @param options.data {Json}   the record body to seal
 * @param options.version {number}   the frame version to stamp
 * @param options.collectionId {string}   the cipher context failures are
 *   labeled with (these records live outside any real collection)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the wrapping KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<object>}   the `{ version, encryption, wrapped }` frame
 */
export async function wrapRecordEnvelope({
  data,
  version,
  collectionId,
  keyAgreementKey,
  keyResolver
}: {
  data: Json
  version: number
  collectionId: string
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<{
  version: number
  encryption: CollectionEncryption
  wrapped: unknown
}> {
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    collectionId,
    encryption
  })
  const { envelope } = await cipher.encrypt({ data })
  return { version, encryption, wrapped: envelope }
}

/**
 * A stored envelope whose frame is well formed but which does not open under
 * the supplied key -- the record is sealed to some other one. Covers both
 * refusal points: the cipher build (the key is no recipient of the record's
 * epoch) and the decrypt itself. Named separately from the frame refusals so
 * a caller can tell "sealed to a key I do not hold" apart from "not a record
 * of this kind or version".
 */
export class RecordEnvelopeDecryptError extends Error {
  constructor(options?: { cause?: unknown }) {
    super('The stored record did not decrypt under the supplied key.', options)
    this.name = 'RecordEnvelopeDecryptError'
  }
}

/**
 * Unwraps a stored `{ version, encryption, wrapped }` frame: validates the
 * frame (any other shape -- including the retired `{ version, wrapped }` form
 * with no descriptor -- is refused), rebuilds the record cipher over the
 * carried descriptor, and decrypts the body. Callers validate the decrypted
 * contents themselves -- which is also each record kind's swap protection
 * (the cipher context is a diagnostic label; the codec is agnostic to it).
 *
 * @param options {object}
 * @param options.record {unknown}   the stored frame
 * @param options.version {number}   the one frame version accepted
 * @param options.collectionId {string}   the cipher context failures are
 *   labeled with
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unwrapping KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.label {string}   names the record kind in refusals
 * @returns {Promise<Json>}   the decrypted record body
 * @throws {RecordEnvelopeDecryptError}   when the frame is well formed but
 *   the body does not decrypt under the given key
 */
export async function unwrapRecordEnvelope({
  record,
  version,
  collectionId,
  keyAgreementKey,
  keyResolver,
  label
}: {
  record: unknown
  version: number
  collectionId: string
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  label: string
}): Promise<Json> {
  const { encryption, wrapped } = parseRecordFrame({ record, label, version })
  // The frame is this record kind's, at this version; everything from here on
  // is key work, and every way it can fail means the same thing to a caller:
  // the envelope does not open under the key it was handed. That includes the
  // cipher build, where a key that is no recipient of the record's own epoch
  // refuses first.
  try {
    const cipher = await recordCipher({
      keyAgreementKey,
      keyResolver,
      collectionId,
      encryption
    })
    return await cipher.decrypt({ envelope: wrapped as never })
  } catch (err) {
    throw new RecordEnvelopeDecryptError({ cause: err })
  }
}
