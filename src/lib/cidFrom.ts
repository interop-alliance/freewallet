/**
 * Byte-encoding helpers shared across the wallet. `digestHash` and
 * `bufferToBase64Url` compose into the content-addressing and id derivation used
 * for the WAS spaceId, the local `dbPrefix`, and stored resource ids.
 *
 * The content-id (CID) derivation itself -- `base64url(SHA-256(JCS(doc)))` --
 * now lives in `@interop/was-client/sync` as `cidFrom` / `contentCid`; import it
 * from there rather than re-deriving it here.
 */
import { base64urlnopad } from '@scure/base'

/**
 * SHA-256 of a UTF-8 string, as a raw `ArrayBuffer`.
 *
 * @param original {string}
 * @returns {Promise<ArrayBuffer>}
 */
export async function digestHash(original: string) {
  // encode as (utf-8) Uint8Array
  const msgUint8 = new TextEncoder().encode(original)

  return await globalThis.crypto.subtle.digest('SHA-256', msgUint8)
}

/**
 * Encodes raw bytes as an unpadded, URL-safe base64 string. Accepts either an
 * ArrayBuffer or a Uint8Array; both are normalized to a byte view for the
 * codec. Output is byte-for-byte the unpadded base64url that every CID,
 * dbPrefix, and spaceId depends on.
 *
 * @param buffer {ArrayBuffer | Uint8Array}
 * @returns {string}
 */
export function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return base64urlnopad.encode(bytes)
}
