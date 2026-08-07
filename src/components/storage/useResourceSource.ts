/**
 * Shared pieces of the storage browser's "resource source" feature: the two
 * views (decrypted document / stored EDV envelope) that both the collection
 * contents page and the single-resource page offer over a fetched resource
 * body, plus the copy-to-clipboard configuration they use for the snippet.
 */
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import type { Json } from '@/lib/sync'
import type { FetchedCollectionResource } from '@/lib/storageResource'
import type { StorageManager } from '@/stores/storageManager'

/**
 * The clipboard hook as the storage browser configures it: a two-second
 * "Copied" flash, the non-secure-context fallback enabled, and a failed copy
 * logged rather than surfaced.
 *
 * @returns {{ copied: boolean, copy: (text: string) => Promise<boolean>,
 *   reset: () => void }}
 */
export function useResourceSourceCopy() {
  return useCopyToClipboard({
    resetDelay: 2000,
    fallbackToExecCommand: true,
    onError: (err: unknown) => {
      console.warn('Copy to clipboard failed:', err)
    }
  })
}

/**
 * Best-effort decryption of a fetched resource body. An encrypted-collection
 * resource arrives as an EDV envelope; with an unlocked vault this recovers
 * the document behind it so the caller can offer both source views. Returns
 * undefined for a plaintext body, a body that is not JSON, or a missing
 * collection id.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param [options.collectionId] {string}   the WAS collection id
 * @param options.body {FetchedCollectionResource}   the fetched resource body
 * @returns {Promise<Json | undefined>}
 */
export async function decryptResourceBody({
  storage,
  collectionId,
  body
}: {
  storage: StorageManager
  collectionId?: string
  body: FetchedCollectionResource
}): Promise<Json | undefined> {
  if (body.kind !== 'json' || !collectionId) {
    return undefined
  }
  return await storage.decryptCollectionResource({
    collectionId,
    data: body.data as Json
  })
}
