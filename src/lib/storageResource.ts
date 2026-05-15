export type FetchedCollectionResource =
  | { kind: 'json'; data: unknown }
  | { kind: 'text'; text: string }
  | { kind: 'binary'; blob: Blob; contentType: string }

export function isJsonLikeContentType(contentType: string | undefined): boolean {
  if (!contentType) {
    return false
  }
  const ct = contentType.toLowerCase()
  return ct.includes('json') || ct.includes('ld+json')
}

export function isTextLikeContentType(contentType: string | undefined): boolean {
  if (!contentType) {
    return false
  }
  return contentType.toLowerCase().startsWith('text/')
}
