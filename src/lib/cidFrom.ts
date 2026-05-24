/**
 * Content-addressed identifier helpers. A CID is a base64url-encoded SHA-256
 * hash of a JCS-canonicalized JSON document. CIDs serve as the primary key
 * for stored credentials (see StoredCredential in types/credential.ts) and as
 * the basis for the WAS spaceId.
 */
import { canonicalize as jcsCanonicalize } from 'json-canonicalize'

/**
 * Create a CID (Content-addressed Identifier) from a given JSON object
 * @param doc {object}
 * @returns {string} base64url-encoded digest hash
 */
export async function cidFrom({ doc }: { doc: object }) {
  const canonicalized = JSON.stringify(jcsCanonicalize(doc))
  const hashBuffer = await digestHash(canonicalized)
  return bufferToBase64Url(hashBuffer)
}

export async function digestHash(original: string) {
  // encode as (utf-8) Uint8Array
  const msgUint8 = new TextEncoder().encode(original)

  return await globalThis.crypto.subtle.digest('SHA-256', msgUint8)
}

export function bufferToBase64Url(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
