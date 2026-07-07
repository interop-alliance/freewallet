/**
 * The session vault envelope: lets a restored (`delegated` tier) session
 * unlock the vault without the passphrase.
 *
 * At full login the vault KAK -- the X25519 key agreement key that
 * encrypts/decrypts the EDV envelopes -- is exported and encrypted (AES-GCM)
 * under a fresh non-extractable WebCrypto key. Both halves are persisted in
 * the `freewallet-session` IndexedDB database alongside the browser session
 * key, with their own TTL (`SESSION_VAULT_TTL_MS`, independent of the zcap
 * TTL). On the next page load the envelope is decrypted back into a live KAK,
 * so the restored session's vault is unlocked. Only the KAK is ever wrapped
 * -- never the data seed and never the root signing key -- so a compromised
 * envelope yields vault decryption on this device, not the wallet identity.
 *
 * Fail closed: anything wrong with the envelope (absent, expired, wrong
 * controller, undecryptable, malformed) leaves the vault locked -- the
 * restored session still works over its delegated zcaps, and a passphrase
 * re-login unlocks. Setting `VITE_REQUIRE_PASSPHRASE_FOR_VAULT` disables the
 * envelope entirely: nothing is persisted (any prior envelope is deleted) and
 * restored sessions always need the passphrase for vault access.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import {
  REQUIRE_PASSPHRASE_FOR_VAULT,
  SESSION_VAULT_TTL_MS
} from '@/app.config'
import {
  deleteVaultEnvelope,
  loadVaultEnvelope,
  saveVaultEnvelope
} from '@/lib/sessionKey'

/**
 * The persisted envelope: an AES-GCM ciphertext of the JSON-encoded
 * {@link VaultEnvelopePayload} plus its IV. `CryptoKey`s, `Uint8Array`s and
 * `ArrayBuffer`s all survive the IndexedDB structured clone.
 */
interface VaultEnvelope {
  version: 1
  iv: Uint8Array<ArrayBuffer>
  ciphertext: ArrayBuffer
}

/**
 * What the ciphertext holds: the vault KAK's serialized form (private key
 * material included) plus the envelope's own expiry and the identity it
 * belongs to. `expires` and `controller` live *inside* the ciphertext, where
 * GCM makes them tamper-evident.
 */
interface VaultEnvelopePayload {
  controller: string
  expires: string
  keyPair: Record<string, unknown>
}

/**
 * Wraps the vault KAK under a fresh non-extractable AES-GCM key and persists
 * the pair. Called (fire-and-forget) alongside the delegated-session record
 * at full login; a failure here only costs passphrase-free vault access on
 * the next restore.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK (an
 *   `X25519KeyAgreementKey2020` at runtime -- it must support `export()`)
 * @param options.controller {string}   the root did:key the KAK belongs to
 * @param [options.idb] {IDBFactory}   where to persist; the CHAPI popup
 *   passes the first-party Storage Access API factory
 * @returns {Promise<void>}
 */
export async function persistVaultEnvelope({
  keyAgreementKey,
  controller,
  idb
}: {
  keyAgreementKey: IKeyAgreementKey
  controller: string
  idb?: IDBFactory
}): Promise<void> {
  if (REQUIRE_PASSPHRASE_FOR_VAULT) {
    // The switch may have been flipped after an envelope was persisted;
    // deleting here retires it on the next full login.
    await deleteVaultEnvelope({ idb })
    return
  }
  const exportable = keyAgreementKey as IKeyAgreementKey & {
    export?: (options: {
      publicKey?: boolean
      privateKey?: boolean
    }) => Promise<Record<string, unknown>>
  }
  if (typeof exportable.export !== 'function') {
    throw new Error('The vault key agreement key is not exportable.')
  }
  const keyPair = await exportable.export({ publicKey: true, privateKey: true })
  const payload: VaultEnvelopePayload = {
    controller,
    expires: new Date(Date.now() + SESSION_VAULT_TTL_MS).toISOString(),
    keyPair
  }
  // A fresh non-extractable wrapping key per login: script can use it to
  // decrypt while a page is open, but it can never be exported -- copied out
  // of the browser, the persisted pair is inert.
  const wrappingKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    new TextEncoder().encode(JSON.stringify(payload))
  )
  const envelope: VaultEnvelope = { version: 1, iv, ciphertext }
  await saveVaultEnvelope({ wrappingKey, envelope, idb })
}

/**
 * Decrypts the persisted vault envelope back into a live KAK (and the
 * key resolver the EDV cipher stack expects), or returns `null` when the
 * vault must stay locked. Fail closed: expiry, a controller mismatch, a
 * missing half, or any decrypt/parse failure all return `null`, and a
 * known-bad envelope is deleted so the next restore does not retry it.
 *
 * @param options {object}
 * @param options.controller {string}   the restored session's root did:key;
 *   the envelope must have been minted for the same identity
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ keyAgreementKey: IKeyAgreementKey,
 *   keyResolver: IKeyResolver } | null>}
 */
export async function unwrapVaultEnvelope({
  controller,
  idb
}: {
  controller: string
  idb?: IDBFactory
}): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
} | null> {
  if (REQUIRE_PASSPHRASE_FOR_VAULT) {
    return null
  }
  try {
    const stored = await loadVaultEnvelope({ idb })
    if (!stored) {
      return null
    }
    const envelope = stored.envelope as VaultEnvelope
    if (envelope?.version !== 1) {
      throw new Error('Unrecognized vault envelope version.')
    }
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: envelope.iv },
      stored.wrappingKey,
      envelope.ciphertext
    )
    const payload = JSON.parse(
      new TextDecoder().decode(plaintext)
    ) as VaultEnvelopePayload
    if (new Date(payload.expires).getTime() <= Date.now()) {
      // Routine expiry, not an error -- just re-lock and tidy up.
      await deleteVaultEnvelope({ idb })
      return null
    }
    if (payload.controller !== controller) {
      throw new Error('The vault envelope belongs to a different identity.')
    }
    const keyAgreementKey = await X25519KeyAgreementKey2020.from(
      payload.keyPair
    )
    // The same resolver shape a full login builds (`agentsFromSeed` in
    // `src/session/initSession.ts`): resolve the KAK's own id to its public
    // form during encrypt.
    const keyResolver: IKeyResolver = async ({ id }: { id?: string }) => {
      if (id !== keyAgreementKey.id) {
        throw new Error(`Unknown key id "${id}".`)
      }
      return {
        id: keyAgreementKey.id,
        type: keyAgreementKey.type,
        publicKeyMultibase: keyAgreementKey.publicKeyMultibase
      }
    }
    return { keyAgreementKey: keyAgreementKey as IKeyAgreementKey, keyResolver }
  } catch (err) {
    console.warn('Could not unwrap the session vault envelope:', err)
    // Fail closed; delete so a known-bad envelope is not retried forever.
    try {
      await deleteVaultEnvelope({ idb })
    } catch {
      // Deleting is best-effort -- the vault stays locked either way.
    }
    return null
  }
}
