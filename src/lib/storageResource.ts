/**
 * Types and content-type helpers for WAS collection resources fetched by
 * WASRemoteStore. The FetchedCollectionResource discriminated union lets
 * callers branch on how to render or save content without inspecting raw
 * Content-Type strings themselves.
 */
import { typeArray } from '@/lib/vcShape'

export type FetchedCollectionResource =
  | { kind: 'json'; data: unknown }
  | { kind: 'text'; text: string }
  | { kind: 'binary'; blob: Blob; contentType: string }

export function isJsonLikeContentType(
  contentType: string | undefined
): boolean {
  if (!contentType) {
    return false
  }
  const ct = contentType.toLowerCase()
  return ct.includes('json') || ct.includes('ld+json')
}

export function isTextLikeContentType(
  contentType: string | undefined
): boolean {
  if (!contentType) {
    return false
  }
  return contentType.toLowerCase().startsWith('text/')
}

/**
 * True when parsed JSON is a W3C Verifiable Credential document.
 */
export function isVerifiableCredentialData(data: unknown): boolean {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return false
  }
  const type = (data as Record<string, unknown>).type
  return typeArray(type).includes('VerifiableCredential')
}
