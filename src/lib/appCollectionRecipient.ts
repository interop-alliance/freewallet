/**
 * Derives the recipient key for an App Connect app-provisioned collection. An
 * app keeps a 32-byte seed in the user's wallet (its app-key credential); from
 * that seed and a collection id, both the wallet and the app derive the SAME
 * deterministic per-collection X25519 key-agreement key via
 * `deriveCollectionKeys` (HKDF-SHA256, label `kak:v1:<collectionId>`). The
 * wallet uses the public half of that key as the app's epoch-recipient entry
 * when it provisions the collection, so the app -- deriving the private half
 * from the same seed -- can decrypt what it writes there. The derivation MUST
 * match the app side byte-for-byte, so both import `deriveCollectionKeys` from
 * `@interop/wallet-core/identity` and never reimplement the HKDF.
 */
import { deriveCollectionKeys } from '@interop/wallet-core/identity'
import type { RecipientPublicKey } from '@interop/was-client/edv'

/**
 * Derives the app's per-collection recipient public key from its seed and a
 * collection id. The returned `RecipientPublicKey` (`{ id, publicKeyMultibase,
 * type }`) is the public half of the deterministic per-collection KAK; its `id`
 * is the recipient `kid` an epoch roster entry carries, identical on the app
 * side by construction.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the app-key seed (32 bytes)
 * @param options.collectionId {string}   the WAS collection id (the HKDF label)
 * @returns {Promise<RecipientPublicKey>}
 */
export async function deriveAppCollectionRecipient({
  seed,
  collectionId
}: {
  seed: Uint8Array
  collectionId: string
}): Promise<RecipientPublicKey> {
  const { keyAgreementKey } = await deriveCollectionKeys({ seed, collectionId })
  const { id, publicKeyMultibase, type } = keyAgreementKey as {
    id?: string
    publicKeyMultibase?: string
    type?: string
  }
  if (typeof id !== 'string' || typeof publicKeyMultibase !== 'string') {
    throw new Error(
      'Cannot derive an app collection recipient: the per-collection ' +
        'key-agreement key lacks an id or publicKeyMultibase.'
    )
  }
  return { id, publicKeyMultibase, type }
}
