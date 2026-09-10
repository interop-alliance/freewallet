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
 *
 * Signing is optional here because the two record kinds differ in who serves
 * them. The unlock-methods registry is served by the storage host, which can
 * read the record's own descriptor and seal a body of its own that decrypts
 * cleanly, so it is signed: `wrapRecordEnvelope` takes a `signer` and stamps
 * a Data Integrity proof over the frame members, and `unwrapRecordEnvelope`
 * takes the one key multibase that may have signed it and verifies BEFORE
 * decrypting. The client-key record is browser-local -- no host ever serves
 * it, and anything able to author it already holds this browser's storage --
 * so it stays unsigned at its own frame version, and that path passes neither
 * option.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CollectionEncryption, Json } from '@interop/was-client'
import {
  mintRecordEncryption,
  parseRecordFrame,
  recordCipher,
  recordProofKeyMultibase,
  RecordProofError,
  signRecordFrame,
  verifyRecordProof,
  type RecordProof,
  type RecordSigner
} from '@interop/wallet-core/keyring'

// Re-exported for the test harnesses that need a local epoch-bearing
// descriptor for a cipher without a server.
export { mintRecordEncryption } from '@interop/wallet-core/keyring'

/**
 * Wraps a record body into its stored envelope: a fresh record-own descriptor
 * is minted, the body is sealed under its epoch, and the frame carries all
 * three members. With a `signer` in hand the frame is signed too, and the
 * returned record carries the `proof` over its sibling members.
 *
 * @param options {object}
 * @param options.data {Json}   the record body to seal
 * @param options.version {number}   the frame version to stamp
 * @param options.collectionId {string}   the cipher context failures are
 *   labeled with (these records live outside any real collection)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the wrapping KAK
 * @param options.keyResolver {IKeyResolver}
 * @param [options.signer] {RecordSigner}   the signing key of a record kind
 *   whose authenticity a reader checks; omitted for an unsigned record kind
 * @returns {Promise<object>}   the `{ version, encryption, wrapped }` frame,
 *   with `proof` when a signer was given
 */
export async function wrapRecordEnvelope({
  data,
  version,
  collectionId,
  keyAgreementKey,
  keyResolver,
  signer
}: {
  data: Json
  version: number
  collectionId: string
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  signer?: RecordSigner
}): Promise<{
  version: number
  encryption: CollectionEncryption
  wrapped: unknown
  proof?: RecordProof
}> {
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    collectionId,
    encryption
  })
  const { envelope } = await cipher.encrypt({ data })
  if (!signer) {
    return { version, encryption, wrapped: envelope }
  }
  return await signRecordFrame({
    version,
    encryption,
    wrapped: envelope,
    signer
  })
}

/**
 * A stored envelope whose frame is well formed but which does not open under
 * the supplied key -- the record is sealed to some other one. Covers both
 * refusal points: the cipher build (the key is no recipient of the record's
 * epoch) and the decrypt itself. Named separately from the frame refusals so
 * a caller can tell "sealed to a key I do not hold" apart from "not a record
 * of this kind or version".
 *
 * A signed record whose proof names a signing key other than the one the
 * caller handed in is the same state: the record belongs to another key
 * generation (or to nobody), so it is refused here rather than as a proof
 * failure. A proof that names the right key and does not verify is the
 * tampering refusal instead, and rides wallet-core's `RecordProofError`.
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
 * with no descriptor -- is refused), verifies the record's proof when the
 * caller names the key that may have signed it, rebuilds the record cipher
 * over the carried descriptor, and decrypts the body. Callers validate the
 * decrypted contents themselves -- which is also each record kind's swap
 * protection (the cipher context is a diagnostic label; the codec is agnostic
 * to it).
 *
 * Verification runs before any cipher work, and there is no path past it: a
 * caller that passes `verify` gets a decrypted body only from a record its
 * own key signed.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored frame
 * @param options.version {number}   the one frame version accepted
 * @param options.collectionId {string}   the cipher context failures are
 *   labeled with
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unwrapping KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.label {string}   names the record kind in refusals
 * @param [options.verify] {object}   the signed record kinds' authenticity
 *   check; omitted for an unsigned record kind
 * @param options.verify.keyMultibase {string}   the one signing key this
 *   caller accepts on the record
 * @returns {Promise<Json>}   the decrypted record body
 * @throws {RecordEnvelopeDecryptError}   when the frame is well formed but
 *   the body does not decrypt under the given key, or the proof names a
 *   different signing key
 * @throws {RecordProofError}   when the proof names this caller's key and
 *   does not verify over the record's members
 */
export async function unwrapRecordEnvelope({
  record,
  version,
  collectionId,
  keyAgreementKey,
  keyResolver,
  label,
  verify
}: {
  record: unknown
  version: number
  collectionId: string
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  label: string
  verify?: { keyMultibase: string }
}): Promise<Json> {
  const { encryption, wrapped } = parseRecordFrame({
    record,
    label,
    version
  })
  if (verify) {
    // The frame's own `proof` member is not read here: `parseRecordFrame`
    // returns it only for wallet-core's own keyring record version, so a
    // record kind stamping any other version would find it absent and refuse
    // forever. The proof comes off the raw record instead, and
    // `verifyRecordProof` below re-checks its shape, its signer, and the
    // signature.
    const { proof } = record as { proof?: { verificationMethod?: unknown } }
    if (typeof proof?.verificationMethod !== 'string') {
      throw new RecordProofError(`The ${label} record carries no proof.`)
    }
    const signedBy = recordProofKeyMultibase({
      verificationMethod: proof.verificationMethod,
      label
    })
    if (signedBy !== verify.keyMultibase) {
      // Another key generation's record (or nobody's). That is the same state
      // to a caller as an envelope sealed to a key it does not hold, and the
      // read paths route both the same way, so it refuses as a decrypt
      // failure rather than as tampering.
      throw new RecordEnvelopeDecryptError()
    }
    await verifyRecordProof({
      record,
      allowedKeyMultibases: verify.keyMultibase,
      label
    })
  }
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
