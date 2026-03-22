import { canonicalize as jcsCanonicalize } from 'json-canonicalize'

/**
 * Create a CID (Content-addressed Identifier) from a given JSON object
 * @param doc {object}
 * @returns {string} base64url-encoded digest hash
 */
export async function cidFrom({ doc }: { doc: object }) {
  const canonicalized = JSON.stringify(jcsCanonicalize(doc))
  // encode as (utf-8) Uint8Array
  const msgUint8 = new TextEncoder().encode(canonicalized)
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8)

  return bufferToBase64Url(hashBuffer)
}

export function bufferToBase64Url(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
