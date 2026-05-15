/** Map response Content-Type to a sensible download file extension. */
export function extensionFromMime(contentType: string): string {
  const base = contentType.split(';')[0]?.trim()?.toLowerCase() || ''
  const map: Record<string, string> = {
    'application/pdf': 'pdf',
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/gif': 'gif',
    'application/json': 'json',
    'application/zip': 'zip',
    'text/plain': 'txt'
  }
  return map[base] ?? ''
}
