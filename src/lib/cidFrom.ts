/**
 * Content-addressed identifier helpers. A CID is a base64url-encoded SHA-256
 * hash of a JCS-canonicalized JSON document. CIDs serve as the primary key
 * for stored credentials (see StoredCredential in types/credential.ts) and as
 * the basis for the WAS spaceId.
 */
import { canonicalize as jcsCanonicalize } from 'json-canonicalize'
import { base64urlnopad } from '@scure/base'

/**
 * Create a CID (Content-addressed Identifier) from a given JSON object
 * @param doc {object}
 * @returns {string} base64url-encoded digest hash
 */
export async function cidFrom({ doc }: { doc: object }) {
  const canonicalized = jcsCanonicalize(doc)
  const hashBuffer = await digestHash(canonicalized)
  return bufferToBase64Url(hashBuffer)
}

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
