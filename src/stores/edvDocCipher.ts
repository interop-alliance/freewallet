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
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { createEdvEncryption } from '@interop/was-client/edv'
import type { Json } from '@/lib/sync'

/**
 * A per-collection document cipher: encrypts a JSON document into its stored
 * EDV envelope (minting the content-derived resource id) and decrypts a stored
 * envelope back to the document. Injected into `BrowserStore` for each
 * encrypted collection.
 */
export interface DocCipher {
  encrypt(options: { data: Json }): Promise<{ id: string; envelope: Json }>
  decrypt(options: { envelope: Json }): Promise<Json>
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
 * Builds a {@link DocCipher} for one encrypted collection from the session
 * profile's key material (the passphrase-derived X25519 key agreement key).
 * Deterministic keys mean a returning user -- on any device -- decrypts the
 * same envelopes; guests get a working cipher too (their data is simply
 * unrecoverable once the random guest secret is discarded, like the rest of a
 * guest session).
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}   the WAS collection id (labels errors;
 *   the codec itself is collection-agnostic)
 * @returns {Promise<DocCipher>}
 */
export async function createEdvDocCipher({
  keyAgreementKey,
  keyResolver,
  collectionId
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  collectionId: string
}): Promise<DocCipher> {
  // The provider is the same keystore-to-codec factory the remote handles use;
  // keys are supplied directly (no keystore lookup), and `'content'` id
  // derivation makes every minted id a hash of the JWE ciphertext -- the
  // stable, replica-independent primary key replication needs.
  const provider = createEdvEncryption({
    resolveKeys: async () => null,
    idDerivation: 'content'
  })
  const codec = await provider.codecFor({
    spaceId: 'local',
    collectionId,
    scheme: 'edv',
    keys: { keyAgreementKey, keyResolver }
  })
  if (!codec) {
    throw new Error(
      `Could not build the EDV cipher for collection "${collectionId}".`
    )
  }

  return {
    async encrypt({ data }: { data: Json }) {
      // `encode` with no caller id is the `add()` path: encrypt first, then
      // derive and stamp the content-hash id on the envelope.
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
      return { id: encoded.id, envelope }
    },

    async decrypt({ envelope }: { envelope: Json }) {
      // `decode` reads `response.data` when present, so a minimal stand-in for
      // the HTTP response suffices for a locally stored envelope.
      const response = {
        data: envelope,
        json: async () => envelope
      } as unknown as Parameters<typeof codec.decode>[0]
      return (await codec.decode(response)) as Json
    }
  }
}
