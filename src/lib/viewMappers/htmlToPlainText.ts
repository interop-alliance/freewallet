export function htmlToPlainText(raw: string): string {
  const trimmed = raw.trim()
  if (!trimmed) {
    return ''
  }
  if (!trimmed.includes('<')) {
    return trimmed
  }
  if (typeof window !== 'undefined') {
    try {
      const doc = new DOMParser().parseFromString(trimmed, 'text/html')
      const text = doc.body.textContent ?? ''
      return text.replace(/\s+/g, ' ').trim()
    } catch {
      /* fall through to regex strip */
    }
  }
  return trimmed
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}
