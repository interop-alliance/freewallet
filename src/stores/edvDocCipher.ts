/**
 * The wallet's local encrypt/decrypt seam for its end-to-end encrypted
 * collections (`private-credentials`, `wallet-activity`). Wraps the same
 * `@interop/was-client` EDV codec the remote handles use, but points it at the
 * local replica: a write encrypts the document into an EDV envelope
 * (`{ id, sequence, jwe }`) whose id is content-derived (a truncated SHA-256 of
 * the JWE ciphertext, `idDerivation: 'content'`), and a read decrypts the
 * stored envelope back. The envelope is what the local RxDB store holds
 * (encrypted-at-rest) and what background replication ships verbatim, so the
 * same bytes -- and the same content-derived resource id -- appear on every
 * replica. The sync layer itself never touches these keys.
 *
 * A collection may be single-recipient (only the wallet's own vault
 * key-agreement key reads it) or multi-recipient. Multi-recipient collections
 * carry a `CollectionEncryption` marker with key epochs: each epoch wraps one
 * collection key to every reader, writes encrypt under the marker's
 * `currentEpoch`, and removing a reader appends a fresh epoch that excludes it.
 * Two independent axes gate a reader: the **pull** axis (the zcap the server
 * checks before serving ciphertext) and the **read** axis (possession of an
 * epoch key). This module is the read axis only -- it turns a reader's own
 * key-agreement key plus the marker into a cipher that encrypts under the
 * current epoch and decrypts any epoch that reader still holds a key for.
 *
 * Rotation is prospective, never retroactive: appending an epoch does not
 * rewrite existing resources, and because resource ids are content-derived they
 * stay stable across a rotation. Reads therefore stay tolerant of unstamped
 * pre-epoch resources indefinitely -- an envelope encrypted straight to the
 * vault key-agreement key (before any epoch existed) always decrypts through
 * the single-key path, even on an epoch-aware cipher.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { KeyUnwrapError, type CollectionEncryption } from '@interop/was-client'
import {
  createEdvEncryption,
  epochKeyIdFor,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import type { Json } from '@/lib/sync'

/**
 * A per-collection document cipher: encrypts a JSON document into its stored
 * EDV envelope (minting the content-derived resource id) and decrypts a stored
 * envelope back to the document. Injected into `BrowserStore` for each
 * encrypted collection.
 *
 * On a multi-recipient collection, `encrypt` also surfaces the `epoch` id the
 * write encrypted under (the marker's `currentEpoch`); it is absent on a
 * single-key collection.
 */
export interface DocCipher {
  encrypt(options: {
    data: Json
  }): Promise<{ id: string; envelope: Json; epoch?: string }>
  decrypt(options: { envelope: Json }): Promise<Json>
}

/**
 * Thrown by {@link DocCipher.decrypt} when a stored envelope names a JWE
 * recipient (`kid`) this cipher cannot route: neither the vault key-agreement
 * key nor -- on an epoch-aware cipher -- any epoch this cipher knows about. This
 * is the caller's signal that its cached Collection Description may be stale and
 * should be re-read before retrying: an epoch rotation emits no change-feed
 * entry, so a cipher built from a pre-rotation marker meets envelopes stamped
 * with the newer epoch it has never seen. It also fires on a single-key cipher
 * that meets an envelope encrypted to a different key-agreement key entirely.
 */
export class UnknownEpochError extends Error {
  constructor({
    collectionId,
    kids
  }: {
    collectionId: string
    kids: string[]
  }) {
    super(
      `Cannot decrypt a resource in collection "${collectionId}": its ` +
        `envelope names recipient key id(s) [${kids.join(', ')}] that match ` +
        'neither the vault key-agreement key nor any known key epoch. The ' +
        'cached Collection Description may be stale (an epoch rotation emits ' +
        'no change-feed entry); re-read it and rebuild the cipher.'
    )
    this.name = 'UnknownEpochError'
  }
}

/**
 * Whether a stored document body is an EDV encryption envelope (carries an
 * object `jwe`) as opposed to a plaintext document. Used by the read paths to
 * stay tolerant of legacy plaintext rows (local writes before
 * migration, or rows replicated from a collection written before its
 * encryption marker was declared) and by the one-time local migration to find
 * the rows it must re-key.
 *
 * @param data {Json | undefined}
 * @returns {boolean}
 */
export function isEncryptedEnvelope(data: Json | undefined): boolean {
  if (data === undefined || data === null || typeof data !== 'object') {
    return false
  }
  const jwe = (data as { jwe?: unknown }).jwe
  return jwe !== null && typeof jwe === 'object'
}

/**
 * The wallet's own key-agreement key as a `RecipientPublicKey` -- the "recipient
 * zero" entry a caller passes to `initRecipients` when it first makes a
 * collection multi-recipient (the owner must be a recipient of every epoch, or
 * it could write envelopes it cannot itself read). The wallet vault
 * `X25519KeyAgreementKey2020` already carries a did:key-shaped `id` and a
 * `publicKeyMultibase`, so its `kid`'s fragment resolves through the default
 * did:key recipient resolver.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK
 * @returns {RecipientPublicKey}
 */
export function ownerRecipient({
  keyAgreementKey
}: {
  keyAgreementKey: IKeyAgreementKey
}): RecipientPublicKey {
  const { id } = keyAgreementKey
  const { publicKeyMultibase, type } = keyAgreementKey as {
    publicKeyMultibase?: string
    type?: string
  }
  if (typeof id !== 'string' || typeof publicKeyMultibase !== 'string') {
    throw new Error(
      'Cannot build an owner recipient: the vault key-agreement key lacks an ' +
        'id or publicKeyMultibase (a public X25519 key is required to wrap an ' +
        'epoch key to it).'
    )
  }
  return { id, publicKeyMultibase, type }
}

/**
 * Extracts the JWE recipient key ids (`kid`) an EDV envelope names. An epoch
 * envelope carries one kid (the epoch key id); a legacy single-recipient
 * envelope carries the vault key-agreement key id. Returns `[]` for a malformed
 * envelope, so routing falls through to letting a codec surface its own error.
 *
 * @param envelope {Json}
 * @returns {string[]}
 */
function envelopeRecipientKids(envelope: Json): string[] {
  if (envelope === null || typeof envelope !== 'object') {
    return []
  }
  const jwe = (envelope as { jwe?: unknown }).jwe
  if (jwe === null || typeof jwe !== 'object') {
    return []
  }
  const recipients = (jwe as { recipients?: unknown }).recipients
  if (!Array.isArray(recipients)) {
    return []
  }
  const kids: string[] = []
  for (const recipient of recipients) {
    const kid = (recipient as { header?: { kid?: unknown } })?.header?.kid
    if (typeof kid === 'string') {
      kids.push(kid)
    }
  }
  return kids
}

/**
 * Builds a {@link DocCipher} for one encrypted collection from the session
 * profile's key material (the passphrase-derived X25519 key agreement key).
 * Deterministic keys mean a returning user -- on any device -- decrypts the
 * same envelopes; guests get a working cipher too (their data is simply
 * unrecoverable once the random guest secret is discarded, like the rest of a
 * guest session).
 *
 * With no `encryption` marker (or a marker with no epochs) the cipher is
 * single-recipient: the vault key-agreement key encrypts and decrypts directly,
 * exactly the pre-epoch behavior. With epochs on the marker the cipher becomes
 * multi-recipient: it ALSO builds an epoch codec that encrypts every write under
 * the marker's `currentEpoch` and decrypts any epoch this reader still holds a
 * key for. The single-key codec stays built either way, so a pre-epoch envelope
 * encrypted straight to the vault key-agreement key keeps decrypting -- a
 * permanent tolerance, not a migration shim.
 *
 * The reader must be a recipient of every epoch on the marker (in particular the
 * owner is "recipient zero"). If it is a recipient of none, building the epoch
 * codec throws {@link KeyUnwrapError}; this surfaces it with a clearer error
 * rather than silently writing envelopes other recipients cannot read.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}   the WAS collection id (labels errors;
 *   the codec itself is collection-agnostic)
 * @param [options.encryption] {CollectionEncryption}   the collection's
 *   encryption marker; when it carries key epochs, the cipher becomes
 *   multi-recipient
 * @returns {Promise<DocCipher>}
 */
export async function createEdvDocCipher({
  keyAgreementKey,
  keyResolver,
  collectionId,
  encryption
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  collectionId: string
  encryption?: CollectionEncryption
}): Promise<DocCipher> {
  // The provider is the same keystore-to-codec factory the remote handles use;
  // keys are supplied directly (no keystore lookup), and `'content'` id
  // derivation makes every minted id a hash of the JWE ciphertext -- the
  // stable, replica-independent primary key replication needs.
  const provider = createEdvEncryption({
    resolveKeys: async () => null,
    idDerivation: 'content'
  })
  // The direct (single-key) codec is always built exactly as before: it both
  // decrypts pre-epoch envelopes (encrypted straight to the vault KAK) and is
  // the whole cipher for a single-recipient collection.
  const directCodec = await provider.codecFor({
    spaceId: 'local',
    collectionId,
    scheme: 'edv',
    keys: { keyAgreementKey, keyResolver }
  })
  if (!directCodec) {
    throw new Error(
      `Could not build the EDV cipher for collection "${collectionId}".`
    )
  }

  // On a multi-recipient collection, ALSO build the epoch codec: same provider,
  // same keys, but with the marker so `codecFor` resolves this reader's
  // per-epoch keys. Writes go under the marker's `currentEpoch`; reads pick the
  // epoch key matching the envelope's recipient kid.
  const hasEpochs =
    encryption?.epochs !== undefined && encryption.epochs.length > 0
  let epochCodec: Awaited<ReturnType<typeof provider.codecFor>> | undefined
  if (hasEpochs) {
    try {
      epochCodec = await provider.codecFor({
        spaceId: 'local',
        collectionId,
        scheme: 'edv',
        encryption,
        keys: { keyAgreementKey, keyResolver }
      })
    } catch (err) {
      if (err instanceof KeyUnwrapError) {
        throw new Error(
          `Cannot build the multi-recipient EDV cipher for collection ` +
            `"${collectionId}": the wallet's key-agreement key is not a ` +
            'recipient of any key epoch on this collection. The owner must be ' +
            'a recipient of every epoch (recipient zero) before writing, or it ' +
            'would encrypt envelopes it cannot itself read.',
          { cause: err }
        )
      }
      throw err
    }
    if (!epochCodec) {
      throw new Error(
        `Could not build the multi-recipient EDV cipher for collection ` +
          `"${collectionId}".`
      )
    }
  }

  // The kids that route to the direct codec (the vault KAK itself) and, on an
  // epoch cipher, the per-epoch key ids that route to the epoch codec.
  const vaultKid = keyAgreementKey.id
  const knownEpochKids = new Set<string>(
    (encryption?.epochs ?? []).map(epoch => epochKeyIdFor(epoch.id))
  )

  return {
    async encrypt({ data }: { data: Json }) {
      // Writes always go under the current epoch when this is a multi-recipient
      // cipher; otherwise the single-key codec. `encode` with no caller id is
      // the `add()` path: encrypt first, then derive and stamp the content-hash
      // id on the envelope.
      const codec = epochCodec ?? directCodec
      const encoded = await codec.encode({
        data: data as Extract<Json, object>
      })
      if (
        typeof encoded.id !== 'string' ||
        !(encoded.body instanceof Uint8Array)
      ) {
        throw new Error(
          `EDV encrypt for collection "${collectionId}" returned no ` +
            'id/envelope body.'
        )
      }
      const envelope = JSON.parse(
        new TextDecoder().decode(encoded.body)
      ) as Json
      // `epoch` is surfaced only by the epoch codec (the `currentEpoch` it
      // stamped); absent on the single-key path.
      return {
        id: encoded.id,
        envelope,
        ...(typeof encoded.epoch === 'string' && { epoch: encoded.epoch })
      }
    },

    async decrypt({ envelope }: { envelope: Json }) {
      // Route by the envelope's JWE recipient kids:
      //   1. any kid is the vault KAK id -- a pre-epoch envelope encrypted
      //      straight to the vault key, so the direct codec (permanent
      //      tolerance, not a migration shim);
      //   2. else, on an epoch cipher, any kid names a known epoch -- the epoch
      //      codec;
      //   3. else UnknownEpochError: the marker is likely stale (a rotation
      //      minted an epoch this cipher has never seen), or a single-key cipher
      //      met an envelope encrypted to a different key entirely.
      const kids = envelopeRecipientKids(envelope)
      const codec = selectCodec()

      // `decode` reads `response.data` when present, so a minimal stand-in for
      // the HTTP response suffices for a locally stored envelope.
      const response = {
        data: envelope,
        json: async () => envelope
      } as unknown as Parameters<typeof codec.decode>[0]
      return (await codec.decode(response)) as Json

      function selectCodec() {
        if (kids.some(kid => kid === vaultKid)) {
          return directCodec!
        }
        if (epochCodec && kids.some(kid => knownEpochKids.has(kid))) {
          return epochCodec
        }
        // A malformed/empty-kid envelope (no kids at all) falls through to the
        // direct codec so it can surface its own decrypt error, matching the
        // prior behavior; a non-empty set of unroutable kids is the stale-marker
        // signal.
        if (kids.length === 0) {
          return directCodec!
        }
        throw new UnknownEpochError({ collectionId, kids })
      }
    }
  }
}
