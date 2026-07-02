/**
 * WebKMS keystore provisioning. Ensures the logged-in controller has
 * a keystore on the configured KMS server and returns a KeystoreAgent bound
 * to it. The keystore controller is the passphrase-derived did:key -- the
 * root key stays strictly client-side; only operational keys generated
 * later live server-side.
 */
import type { CapabilityAgent } from '@interop/webkms-client'
import { KeystoreAgent, KmsClient } from '@interop/webkms-client'
import type { ZcapClient } from '@interop/ezcap'

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
