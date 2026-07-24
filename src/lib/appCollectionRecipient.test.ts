// @vitest-environment node
/**
 * The app-collection recipient derivation must agree byte-for-byte with the
 * app side: both derive the per-collection key-agreement key from the same seed
 * via `deriveCollectionKeys`, so the recipient `kid` (its `id`) and public key
 * are identical. These tests pin that the wallet helper returns exactly the
 * public half of `deriveCollectionKeys` and is deterministic per (seed,
 * collectionId).
 */
import { describe, it, expect } from 'vitest'
import { deriveCollectionKeys } from '@interop/wallet-core/identity'
import { deriveAppCollectionRecipient } from './appCollectionRecipient'

const SEED = new Uint8Array(32).fill(7)

describe('deriveAppCollectionRecipient', () => {
  it('returns the public half of deriveCollectionKeys for the same inputs', async () => {
    const collectionId = 'text-editor-document'
    const recipient = await deriveAppCollectionRecipient({
      seed: SEED,
      collectionId
    })
    const { keyAgreementKey } = await deriveCollectionKeys({
      seed: SEED,
      collectionId
    })
    const key = keyAgreementKey as unknown as {
      id: string
      publicKeyMultibase: string
      type: string
    }
    expect(recipient.id).toBe(key.id)
    expect(recipient.publicKeyMultibase).toBe(key.publicKeyMultibase)
    expect(recipient.type).toBe(key.type)
    // The kid is a self-describing did:key so the default recipient resolver can
    // resolve it (did:key:z...#z...).
    expect(recipient.id).toMatch(/^did:key:z.+#z.+/)
  })

  it('derives distinct keys per collection and is deterministic per collection', async () => {
    const first = await deriveAppCollectionRecipient({
      seed: SEED,
      collectionId: 'collection-a'
    })
    const second = await deriveAppCollectionRecipient({
      seed: SEED,
      collectionId: 'collection-b'
    })
    const firstAgain = await deriveAppCollectionRecipient({
      seed: SEED,
      collectionId: 'collection-a'
    })
    expect(first.id).not.toBe(second.id)
    expect(firstAgain.id).toBe(first.id)
  })
})
