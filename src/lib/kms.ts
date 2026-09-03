/**
 * WebKMS keystore provisioning, and the one KMS-held key the account
 * document publishes. Ensures the logged-in controller has a keystore on the
 * configured KMS server and returns a KeystoreAgent bound to it. The keystore
 * controller starts as the first client's did:key and is promoted to the
 * account's did:webvh alongside the Space controller -- the controlling key
 * stays strictly client-side either way; only operational keys generated
 * later live server-side (never update keys or encryption recipients).
 *
 * The KMS-authentication stage below mints that one key and records its
 * binding in `key-map/keys.json`; the genesis entry then republishes it under
 * the account's own controller. No KMS-held key is minted for any other
 * relation: none may appear under `assertionMethod`, where membership confers
 * resource-log append authority as the account, nor under `keyAgreement`,
 * where no server-held key may be a wrap target.
 */
import type { CapabilityAgent } from '@interop/webkms-client'
import { KeystoreAgent, KmsClient } from '@interop/webkms-client'
import type { ZcapClient } from '@interop/ezcap'
import type { ISigner } from '@interop/data-integrity-core'
import { multibaseOf } from '@interop/wallet-core/webvh'
import type {
  DidWebKey,
  DidWebKeyMapV2,
  KmsAuthenticationBinding,
  WebvhIdStore
} from '@interop/wallet-core/webvh'
import { createLogger } from '@/lib/log'
import type { ICapabilityAgent, Session } from '@/types/auth'

const log = createLogger('fw:kms')

/**
 * The WebKMS key type of the Ed25519 signing keys the wallet fetches to sign
 * with (the did:web `authentication` key and the did:webvh update key).
 */
const KMS_ED25519_KEY_TYPE = 'Ed25519VerificationKey2020'

/**
 * The backoff between the adopt path's keystore-listing attempts, one entry
 * per retry (so three attempts in all). The whole budget stays well under the
 * caller's stage timeout, since a stage that outlives it is collected as the
 * same failure a refusal is.
 */
const KEYSTORE_LISTING_RETRY_DELAYS_MS = [250, 500]

/**
 * Waits out a backoff between keystore-listing attempts. The default the
 * adopt path uses when the caller injects none.
 *
 * @param ms {number}
 * @returns {Promise<void>}
 */
function realSleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * The publicAliasTemplate placeholder the WebKMS server expands to the
 * generated key's multibase fingerprint. The fragment (`#z6Mk...`) is thus
 * self-describing, did:key-style -- so the verification method id already
 * carries the key's `publicKeyMultibase` and no key-description fetch is ever
 * needed to recover it.
 */
const PUBLIC_KEY_MULTIBASE_PLACEHOLDER = '{publicKeyMultibase}'

/**
 * Fetches a KMS-held Ed25519 `AsymmetricKey` from the keystore agent by its id
 * and KMS key id, and returns a shallow-spread-safe sign closure over it: the
 * data-integrity suites and the did:webvh library shallow-spread the signer
 * (`{ ...signer }`), which would drop `AsymmetricKey.sign` (a prototype
 * method), while a closure survives the spread. The single home for the "get
 * an AsymmetricKey from the KMS and wrap a signer" seam shared by the did:web
 * authentication signer and the did:webvh update-key signer; each caller keeps
 * its own signer shape
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
  return ({ data }) => key.sign({ data })
}

/**
 * The options every keystore lookup takes, shared by the non-creating
 * {@link findKeystoreAgent} and the create-on-miss {@link ensureKeystore}.
 */
interface KeystoreLookupOptions {
  kmsServerUrl: string
  keyAgent: ICapabilityAgent
  zcapClient: ZcapClient
  controller?: string
  capabilityAgent?: ICapabilityAgent
  fallbackZcapClient?: ZcapClient
}

/**
 * Lists the controller's keystore, with the did:key fallback, and reports the
 * identity the caller should bind the returned agent as. Creates nothing: the
 * lookup half both entry points below share.
 *
 * @param options {KeystoreLookupOptions}
 * @returns {Promise<{ config: { id: string }; agent: ICapabilityAgent } |
 *   undefined>}   undefined when no keystore is listed under either identity
 */
async function lookupKeystore({
  kmsServerUrl,
  keyAgent,
  zcapClient,
  controller = keyAgent.id,
  capabilityAgent,
  fallbackZcapClient
}: KeystoreLookupOptions): Promise<
  { config: { id: string }; agent: ICapabilityAgent } | undefined
> {
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
  return config && { config, agent }
}

/**
 * Builds a KeystoreAgent over a listed (or freshly created) keystore.
 *
 * @param options {object}
 * @param options.config {object}   the keystore config, for its id
 * @param options.agent {ICapabilityAgent}   the invoking identity
 * @returns {KeystoreAgent}
 */
function keystoreAgentFor({
  config,
  agent
}: {
  config: { id: string }
  agent: ICapabilityAgent
}): KeystoreAgent {
  return new KeystoreAgent({
    capabilityAgent: agent as CapabilityAgent,
    keystoreId: config.id,
    kmsClient: new KmsClient({ keystoreId: config.id })
  })
}

/**
 * Finds the controller's keystore WITHOUT creating one, or `undefined` when
 * none is listed. For the caller whose whole question is whether a keystore
 * this identity controls already exists -- the KMS-authentication stage's
 * adopt path, which verifies a served `keys.json` against the keystore's own
 * listing and must not mint a keystore to answer a verification question.
 *
 * @param options {KeystoreLookupOptions}   as {@link ensureKeystore} takes
 *   them
 * @returns {Promise<KeystoreAgent | undefined>}
 */
export async function findKeystoreAgent(
  options: KeystoreLookupOptions
): Promise<KeystoreAgent | undefined> {
  const found = await lookupKeystore(options)
  return found && keystoreAgentFor(found)
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
 * @param options.keyAgent {ICapabilityAgent} - The creating identity's key
 *   agent (the session's root key agent, or the credential-anchored
 *   establishment's bootstrap did:key); the keystore is created under its
 *   did:key on first contact and its key signs every keystore invocation.
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
}: KeystoreLookupOptions): Promise<KeystoreAgent> {
  const keystoresUrl = `${kmsServerUrl}/keystores`
  const found = await lookupKeystore({
    kmsServerUrl,
    keyAgent,
    zcapClient,
    controller,
    capabilityAgent,
    fallbackZcapClient
  })
  if (found) {
    return keystoreAgentFor(found)
  }
  if (controller !== keyAgent.id) {
    // A promoted account with no keystore under either identity -- an
    // enrolled client whose account keystore was created under the FIRST
    // client's did:key and never promoted. Creating one here would mint an
    // orphan keystore per enrolled client, with keys.json's `kmsKeyId`s
    // still pointing into the account's real keystore. Surface the state
    // instead (the caller treats provisioning failures as non-fatal and the
    // settings page shows it); the promotion retry at the first client's
    // next login heals it.
    throw new Error(
      'No keystore was found under the promoted account controller or this ' +
        "client's did:key; refusing to create an orphan keystore."
    )
  }
  const created = await KmsClient.createKeystore({
    url: keystoresUrl,
    config: { sequence: 0, controller: keyAgent.id },
    invocationSigner: keyAgent.getSigner()
  })
  if (!created.id) {
    throw new Error('KMS keystore creation returned no keystore id.')
  }
  return keystoreAgentFor({ config: { id: created.id }, agent: keyAgent })
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

/**
 * Whether a parsed `keys.json` body carries a well-formed `authentication`
 * binding: a `vmId` and a `kmsKeyId`. It is the only binding the map records.
 * A legacy map's `keyAgreement` member, and any `assertionMethod` member, are
 * ignored here and never republished.
 */
function isKmsAuthenticationMap(value: unknown): value is DidWebKeyMapV2 {
  if (!value || typeof value !== 'object') {
    return false
  }
  const entry = (value as Record<string, unknown>).authentication as
    Record<string, unknown> | undefined
  return (
    !!entry &&
    typeof entry.vmId === 'string' &&
    typeof entry.kmsKeyId === 'string'
  )
}

/**
 * Generates the KMS `authentication` key and returns its binding: the
 * verification-method id and the KMS key id. The publicAliasTemplate makes
 * the key's description id the did:web verification-method URL (fragment =
 * multibase fingerprint), which the projection publishes verbatim; the sign
 * route ignores the alias, so the same key signs under the account's
 * did:webvh verification-method id too.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.did {string}   the did:web projection id
 * @returns {Promise<DidWebKey>}
 */
async function generateAuthenticationKey({
  keystoreAgent,
  did
}: {
  keystoreAgent: KeystoreAgent
  did: string
}): Promise<DidWebKey> {
  const key = await keystoreAgent.generateKey({
    category: 'asymmetric',
    publicAliasTemplate: `${did}#${PUBLIC_KEY_MULTIBASE_PLACEHOLDER}`
  })
  if (!key.id || !key.kmsId) {
    throw new Error(
      'KMS generateKey returned no id for the authentication key.'
    )
  }
  return { vmId: key.id, kmsKeyId: key.kmsId }
}

/**
 * Whether the session's own keystore lists a key with this multibase. The
 * genesis takes a served `vmId` VERBATIM into the world-readable account
 * document, so a host serving a `keys.json` naming an attacker's key would
 * otherwise get that key published under `authentication`, signed by the
 * account itself. A listing that throws propagates, so the caller can tell a
 * listing that answered from one that could not be had at all.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.multibase {string}   the fragment of the served `vmId`
 * @returns {Promise<boolean>}
 */
async function keystoreListsKey({
  keystoreAgent,
  multibase
}: {
  keystoreAgent: KeystoreAgent
  multibase: string
}): Promise<boolean> {
  const listed = await keystoreAgent.listKeys()
  return listed.some(
    key =>
      key.publicKeyMultibase === multibase ||
      (typeof key.id === 'string' && multibaseOf(key.id) === multibase)
  )
}

/**
 * The KMS-authentication stage: idempotently provisions the one KMS-held key
 * the account document publishes, and records its binding in
 * `key-map/keys.json`.
 *
 * Nothing but the `keys.json` write touches the account Space, so the stage
 * runs alongside Space provisioning: the probe starts at once, the keystore
 * the MINT path needs is acquired only past the probe's miss (a run that
 * short-circuits on a served map never creates a keystore it will not use),
 * and the write joins on `spaceReady`. On a fresh signup the probe's 404 --
 * from an absent Space and from an absent `keys.json` alike -- is the right
 * answer, which is why the caller's probe must read through a plaintext
 * codec.
 *
 * A served map is adopted only after the multibase in its `vmId` is checked
 * against this session's own keystore listing. That verification creates
 * nothing: it performs a non-creating keystore lookup plus a `listKeys` round
 * trip. It ends in one of two verdicts, told apart because their remedies
 * differ. A listing that RETURNED without naming the served key is an
 * integrity refusal -- as is a lookup that finds no keystore -- and it refuses
 * at once, since a retry answers the same. A lookup or listing that THREW is
 * transport: the KMS is down, slow, or refusing the invocation, and the
 * served map is neither good nor bad but unverified, so the attempt is
 * retried a few times behind a short backoff and only then refused, with the
 * last error as `cause`.
 *
 * A map this keystore cannot account for is refused rather than adopted and
 * rather than overwritten: the write is create-if-absent, so overwriting is
 * not available, and minting against it would leave an orphan key per
 * attempt. Either refusal is the collected, non-fatal stage failure -- the
 * account then publishes no `authentication` relation and presents did:key.
 *
 * @param options {object}
 * @param options.lookupKeystoreAgent {Function}   `() =>
 *   Promise<KeystoreAgent | undefined>` -- the ADOPT path's non-creating
 *   keystore lookup, called only when a map is served
 * @param options.provideKeystoreAgent {Function}   `() =>
 *   Promise<KeystoreAgent>` -- the MINT path's create-or-find, called only
 *   past the probe's miss
 * @param options.remoteStore {object}   the `keys.json` probe and the
 *   `id`-collection store (`WASRemoteStore` satisfies it structurally)
 * @param options.did {string}   the did:web projection id, from
 *   {@link didWebFromSpace}
 * @param options.spaceReady {Promise<unknown>}   resolves once the account
 *   Space exists; already resolved on every path that provisions no Space
 * @param [options.sleep] {Function}   `(ms: number) => Promise<void>` -- the
 *   backoff between keystore-listing attempts; defaults to a real timer, and
 *   a test injects a zero-delay spy
 * @returns {Promise<KmsAuthenticationBinding>}   the map to fold into the
 *   genesis entry, and the `keys.json` ETag this stage's own write produced
 *   (absent when it adopted a served map)
 */
export async function ensureKmsAuthentication({
  lookupKeystoreAgent,
  provideKeystoreAgent,
  remoteStore,
  did,
  spaceReady,
  sleep = realSleep
}: {
  lookupKeystoreAgent: () => Promise<KeystoreAgent | undefined>
  provideKeystoreAgent: () => Promise<KeystoreAgent>
  remoteStore: {
    getKeyMap(): Promise<unknown>
    webvhIdStore(): WebvhIdStore
  }
  did: string
  spaceReady: Promise<unknown>
  sleep?: (ms: number) => Promise<void>
}): Promise<KmsAuthenticationBinding> {
  const attempts = KEYSTORE_LISTING_RETRY_DELAYS_MS.length + 1

  const verifyServedKey = async ({
    vmId,
    multibase
  }: {
    vmId: string
    multibase: string
  }): Promise<void> => {
    let lastError: unknown
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      let listsKey: boolean
      try {
        const keystoreAgent = await lookupKeystoreAgent()
        listsKey =
          !!keystoreAgent &&
          (await keystoreListsKey({ keystoreAgent, multibase }))
      } catch (err) {
        lastError = err
        const backoff = KEYSTORE_LISTING_RETRY_DELAYS_MS[attempt - 1]
        if (backoff !== undefined) {
          await sleep(backoff)
        }
        continue
      }
      if (!listsKey) {
        log.warn('The keystore does not list the served authentication key', {
          vmId
        })
        throw new Error(
          'The served keys.json names an authentication key this keystore ' +
            `does not list (${vmId}); refusing to publish it.`
        )
      }
      return
    }
    log.warn(
      'The keystore could not be listed, so the served keys.json ' +
        'stays unverified',
      { vmId, attempts, err: lastError }
    )
    throw new Error(
      'The keystore could not be listed, so the served keys.json could not ' +
        `be verified (${vmId}); refusing to publish it.`,
      { cause: lastError }
    )
  }

  const adopt = async (served: unknown): Promise<DidWebKeyMapV2> => {
    if (!isKmsAuthenticationMap(served)) {
      throw new Error('The served keys.json carries no authentication binding.')
    }
    const { vmId } = served.authentication
    await verifyServedKey({ vmId, multibase: multibaseOf(vmId) })
    return served
  }

  const existing = await remoteStore.getKeyMap()
  if (existing !== undefined && existing !== null) {
    return { keys: await adopt(existing) }
  }

  const keystoreAgent = await provideKeystoreAgent()
  const authentication = await generateAuthenticationKey({ keystoreAgent, did })
  const keys: DidWebKeyMapV2 = { authentication }
  await spaceReady
  try {
    const written = await remoteStore
      .webvhIdStore()
      .putKeyMap({ content: keys, ifNoneMatch: true })
    return {
      keys,
      ...(written?.etag !== undefined && { etag: written.etag })
    }
  } catch (err) {
    // A concurrent establishment (a second tab, or a signup racing a mend)
    // won the create: adopt what it wrote, after the same listing check. The
    // key minted just above is then orphaned in the account's own keystore,
    // in no document and usable by nothing.
    if ((err as { name?: string } | null)?.name !== 'PreconditionFailedError') {
      throw err
    }
    return { keys: await adopt(await remoteStore.getKeyMap()) }
  }
}

/**
 * A KMS-backed `authentication`-key signer for DIDAuth under the
 * verification-method id the caller names, or `undefined` when the session
 * holds no KMS binding or cannot reach the key. One key signs under every id
 * the account publishes it as -- the did:web projection's and the account's
 * did:webvh one -- because the KMS sign route reads `kmsKeyId` and ignores
 * the description's alias. The root key invokes the keystore's root
 * capability.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.verificationMethodId {string}   the id the proof names
 * @returns {Promise<ISigner | undefined>}
 */
export async function kmsAuthenticationSigner({
  session,
  verificationMethodId
}: {
  session: Session
  verificationMethodId: string
}): Promise<ISigner | undefined> {
  const { kmsAuthentication, keystoreAgent } = session.profile
  if (!kmsAuthentication || !keystoreAgent) {
    return undefined
  }
  const { kmsKeyId } = kmsAuthentication

  // `id` is the verification-method id so the proof names the right
  // `verificationMethod`; `algorithm` satisfies the suite's `Ed25519` check.
  // `getKmsSignFunction` returns the sign closure as an own property, so the
  // data-integrity suites' shallow spread (`{ ...signer }`) preserves it.
  return {
    id: verificationMethodId,
    algorithm: 'Ed25519',
    sign: await getKmsSignFunction({
      keystoreAgent,
      id: verificationMethodId,
      kmsKeyId
    })
  } as unknown as ISigner
}
