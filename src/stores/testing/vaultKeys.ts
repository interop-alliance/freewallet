/**
 * A test fixture for the vault key material every `StorageManager` holds: a
 * freshly generated X25519 key-agreement key and a resolver answering its
 * public half.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'

/**
 * Generates a vault key-agreement key and its resolver.
 *
 * @param [options] {object}
 * @param [options.controller] {string}   the test key's controller DID
 * @returns {Promise<{ keyAgreementKey: IKeyAgreementKey, keyResolver: IKeyResolver }>}
 */
export async function generateVaultKeys({
  controller = 'did:key:z6MkTestVaultController'
}: {
  controller?: string
} = {}): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const generated = await X25519KeyAgreementKey2020.generate({ controller })
  const keyResolver: IKeyResolver = async () => ({
    id: generated.id!,
    type: generated.type,
    publicKeyMultibase: generated.publicKeyMultibase
  })
  return { keyAgreementKey: generated as IKeyAgreementKey, keyResolver }
}
