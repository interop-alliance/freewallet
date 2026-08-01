/**
 * WebKMS keystore provisioning. Ensures the logged-in controller has
 * a keystore on the configured KMS server and returns a KeystoreAgent bound
 * to it. The keystore controller starts as the first client's did:key and is
 * promoted to the account's did:webvh alongside the Space controller -- the
 * controlling key stays strictly client-side either way; only operational
 * keys generated later live server-side (never update keys or encryption
 * recipients).
 */
import type { AsymmetricKey, CapabilityAgent } from '@interop/webkms-client'
import { KeystoreAgent, KmsClient } from '@interop/webkms-client'
import type { ZcapClient } from '@interop/ezcap'
import type { ICapabilityAgent } from '@/types/auth'

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
 *   the keystore is created under its did:key on first login and its key
 *   signs every keystore invocation.
 * @param options.zcapClient {ZcapClient} - The session's zcap client, used
 *   for the list-by-controller request (root zcap, action `read`). Must sign
 *   with a keyId the keystore's current controller resolves.
 * @param [options.controller] {string} - The keystore controller to look up
 *   under (the account's did:webvh once promoted); defaults to the key
 *   agent's did:key. A missing keystore is always created under the did:key
 *   (creation precedes promotion in the provisioning order).
 * @param [options.capabilityAgent] {ICapabilityAgent} - The agent identity
 *   the returned KeystoreAgent invokes with (a did:webvh-shaped wrapper once
 *   promoted); defaults to `keyAgent`.
 * @param [options.fallbackZcapClient] {ZcapClient} - Signs the did:key
 *   fallback listing when a promoted controller's lookup misses (a keystore
 *   whose own promotion has not landed yet); the returned agent then binds
 *   as the did:key so provisioning can promote it.
 * @returns {Promise<KeystoreAgent>} A KeystoreAgent bound to the keystore.
 */
export async function ensureKeystore({
  kmsServerUrl,
  keyAgent,
  zcapClient,
  controller = keyAgent.id,
  capabilityAgent,
  fallbackZcapClient
}: {
  kmsServerUrl: string
  keyAgent: CapabilityAgent
  zcapClient: ZcapClient
  controller?: string
  capabilityAgent?: ICapabilityAgent
  fallbackZcapClient?: ZcapClient
}): Promise<KeystoreAgent> {
  const keystoresUrl = `${kmsServerUrl}/keystores`

  const listByController = async (byController: string, client: ZcapClient) => {
    const response = await client.request({
      url: `${keystoresUrl}?controller=${encodeURIComponent(byController)}`,
      method: 'GET',
      action: 'read'
    })
    const { results } = response.data as { results: Array<{ id: string }> }
    return results[0] as { id: string } | undefined
  }

  let config = await listByController(controller, zcapClient)
  let agent = capabilityAgent ?? keyAgent
  if (!config && controller !== keyAgent.id && fallbackZcapClient) {
    // A promoted account whose keystore promotion tore (or has not run yet):
    // the keystore still lives under the client's did:key. Bind as the
    // did:key so its invocations verify; provisioning promotes the keystore
    // and rebinds the agent.
    config = await listByController(keyAgent.id, fallbackZcapClient)
    if (config) {
      agent = keyAgent
    }
  }
  if (!config) {
    const created = await KmsClient.createKeystore({
      url: keystoresUrl,
      config: { sequence: 0, controller: keyAgent.id },
      invocationSigner: keyAgent.getSigner()
    })
    if (!created.id) {
      throw new Error('KMS keystore creation returned no keystore id.')
    }
    config = { id: created.id }
    agent = keyAgent
  }

  return new KeystoreAgent({
    capabilityAgent: agent as CapabilityAgent,
    keystoreId: config.id,
    kmsClient: new KmsClient({ keystoreId: config.id })
  })
}

/**
 * Rebinds a KeystoreAgent to a different invoking identity (the
 * did:webvh-shaped wrapper after keystore promotion, or the plain did:key
 * agent to authorize the promotion itself), keeping the keystore binding and
 * KMS client.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.capabilityAgent {ICapabilityAgent}
 * @returns {KeystoreAgent}
 */
export function rebindKeystoreAgent({
  keystoreAgent,
  capabilityAgent
}: {
  keystoreAgent: KeystoreAgent
  capabilityAgent: ICapabilityAgent
}): KeystoreAgent {
  return new KeystoreAgent({
    capabilityAgent: capabilityAgent as CapabilityAgent,
    keystoreId: keystoreAgent.keystoreId,
    kmsClient: keystoreAgent.kmsClient
  })
}

/**
 * Promotes the keystore's controller to the account's did:webvh -- the
 * operational-keystore half of controller promotion: KMS-held keys stay fine
 * for what server custody is fine for, but the identity that authorizes the
 * keystore becomes the same did:webvh that controls the Space. Reads the
 * current config for its sequence, no-ops when already promoted, and writes
 * the bumped config authorized by the current controller's key.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}   bound to the keystore, with
 *   the CURRENT controller's invocation authority
 * @param options.controller {string}   the account's did:webvh DID
 * @returns {Promise<boolean>}   true when a promotion was written, false when
 *   the keystore already names the controller
 */
export async function promoteKeystoreController({
  keystoreAgent,
  controller
}: {
  keystoreAgent: KeystoreAgent
  controller: string
}): Promise<boolean> {
  const { kmsClient, capabilityAgent } = keystoreAgent
  const invocationSigner = capabilityAgent.getSigner()
  const config = (await kmsClient.getKeystore({ invocationSigner })) as {
    id: string
    sequence: number
    controller: string
  }
  if (config.controller === controller) {
    return false
  }
  await kmsClient.updateKeystore({
    config: { ...config, sequence: config.sequence + 1, controller },
    invocationSigner
  })
  return true
}
