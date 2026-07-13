/**
 * A single-key `IKeyResolver` factory. Wallet key agreement happens against one
 * known KAK at a time (the vault KAK for the data identity, the unlock KAK for
 * the keyring), so the resolver only ever needs to answer for that one key. Any
 * other key id is an error. Shared by the data-identity bootstrap
 * (`agentsFromSeed`) and the unlock-identity derivation (`deriveUnlockIdentity`).
 */
import type { IKeyResolver } from '@interop/data-integrity-core'

/**
 * Builds an `IKeyResolver` that resolves exactly one key -- the supplied key
 * agreement key -- and throws for any other id.
 *
 * @param options {object}
 * @param options.keyAgreementKey {object}   the one KAK this resolver answers
 *   for; only its `id`, `type`, and `publicKeyMultibase` are read
 * @param [options.keyAgreementKey.id] {string}
 * @param [options.keyAgreementKey.type] {string}
 * @param [options.keyAgreementKey.publicKeyMultibase] {string}
 * @returns {IKeyResolver}
 */
export function singleKeyResolver({
  keyAgreementKey
}: {
  keyAgreementKey: {
    id?: string
    type?: string
    publicKeyMultibase?: string
  }
}): IKeyResolver {
  return async ({ id }: { id?: string }) => {
    if (id !== keyAgreementKey.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: keyAgreementKey.id,
      type: keyAgreementKey.type,
      publicKeyMultibase: keyAgreementKey.publicKeyMultibase
    }
  }
}
