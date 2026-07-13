/**
 * Trigger a browser download of an in-memory Blob under a chosen filename.
 *
 * Wraps the standard object-URL ritual: create an object URL for the blob,
 * synthesise a hidden anchor pointing at it, click the anchor to start the
 * download, then remove the anchor and revoke the object URL to release memory.
 */
export function downloadBlob({
  blob,
  filename
}: {
  blob: Blob
  filename: string
}): void {
  const blobUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = blobUrl
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(blobUrl)
}
