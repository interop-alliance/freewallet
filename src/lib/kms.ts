/**
 * WebKMS keystore provisioning. Ensures the logged-in controller has
 * a keystore on the configured KMS server and returns a KeystoreAgent bound
 * to it. The keystore controller is the passphrase-derived did:key -- the
 * root key stays strictly client-side; only operational keys generated
 * later live server-side.
 */
import type { AsymmetricKey, CapabilityAgent } from '@interop/webkms-client'
import { KeystoreAgent, KmsClient } from '@interop/webkms-client'
import type { ZcapClient } from '@interop/ezcap'

/**
 * The WebKMS key type of the Ed25519 signing keys the wallet fetches to sign
 * with (the did:web `authentication` key and the did:webvh update key). The
 * single home for the constant both signer sites pass to `getAsymmetricKey`.
 */
export const KMS_ED25519_KEY_TYPE = 'Ed25519VerificationKey2020'

/**
 * Wraps a WebKMS `AsymmetricKey.sign` as a plain own-property closure. The
 * data-integrity suites and the did:webvh library shallow-spread the signer
 * (`{ ...signer }`), which would drop `AsymmetricKey.sign` (a prototype
 * method); a closure survives the spread. The single home for that workaround.
 *
 * @param options {object}
 * @param options.key {AsymmetricKey}   a WebKMS key (fetched or constructed).
 * @returns {(input: { data: Uint8Array }) => Promise<Uint8Array>}
 */
export function kmsSignFunction({
  key
}: {
  key: AsymmetricKey
}): (input: { data: Uint8Array }) => Promise<Uint8Array> {
  return ({ data }) => key.sign({ data })
}

/**
 * Fetches a KMS-held Ed25519 `AsymmetricKey` from the keystore agent by its id
 * and KMS key id, and returns a shallow-spread-safe sign closure over it (see
 * {@link kmsSignFunction}). The single home for the "get an AsymmetricKey from
 * the KMS and wrap a signer" seam shared by the did:web authentication signer
 * and the did:webvh update-key signer; each caller keeps its own signer shape
 * (the did:web `{ id, algorithm, sign }` wrapper, the did:webvh library bridge)
 * around the returned closure.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.id {string}   the key's id (its did:key / verification-method
 *   alias), passed through to `getAsymmetricKey`.
 * @param options.kmsKeyId {string}   the server-generated KMS key id used to
 *   invoke signing.
 * @returns {Promise<(input: { data: Uint8Array }) => Promise<Uint8Array>>}
 */
export async function getKmsSignFunction({
  keystoreAgent,
  id,
  kmsKeyId
}: {
  keystoreAgent: KeystoreAgent
  id: string
  kmsKeyId: string
}): Promise<(input: { data: Uint8Array }) => Promise<Uint8Array>> {
  const key = await keystoreAgent.getAsymmetricKey({
    id,
    kmsId: kmsKeyId,
    type: KMS_ED25519_KEY_TYPE
  })
  return kmsSignFunction({ key })
}

/**
 * Finds the user's keystore on the KMS server, creating it if this is the
 * first login. Keystore ids are server-generated random ids, so a returning
 * user discovers theirs by listing keystores by controller (one extra
 * signed GET per login). Freewallet's convention is one keystore per
 * controller; if more than one exists (only possible via out-of-band
 * creation), the first listed is used.
 *
 * @param options {object}
 * @param options.kmsServerUrl {string} - KMS base URL (e.g. `<was>/kms`).
 * @param options.keyAgent {CapabilityAgent} - The session's root key agent;
 *   its did:key becomes (or already is) the keystore controller.
 * @param options.zcapClient {ZcapClient} - The session's zcap client, used
 *   for the list-by-controller request (root zcap, action `read`).
 * @returns {Promise<KeystoreAgent>} A KeystoreAgent bound to the keystore.
 */
export async function ensureKeystore({
  kmsServerUrl,
  keyAgent,
  zcapClient
}: {
  kmsServerUrl: string
  keyAgent: CapabilityAgent
  zcapClient: ZcapClient
}): Promise<KeystoreAgent> {
  const keystoresUrl = `${kmsServerUrl}/keystores`
  const controller = keyAgent.id

  const response = await zcapClient.request({
    url: `${keystoresUrl}?controller=${encodeURIComponent(controller)}`,
    method: 'GET',
    action: 'read'
  })
  const { results } = response.data as { results: Array<{ id: string }> }

  let config: { id: string } | undefined = results[0]
  if (!config) {
    const created = await KmsClient.createKeystore({
      url: keystoresUrl,
      config: { sequence: 0, controller },
      invocationSigner: keyAgent.getSigner()
    })
    if (!created.id) {
      throw new Error('KMS keystore creation returned no keystore id.')
    }
    config = { id: created.id }
  }

  return new KeystoreAgent({
    capabilityAgent: keyAgent,
    keystoreId: config.id,
    kmsClient: new KmsClient({ keystoreId: config.id })
  })
}
