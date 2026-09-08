/**
 * The self-refreshing cipher for a mutable-head collection (`contacts`): the
 * one collection whose decrypt runs somewhere the session's read-level
 * refresh guard cannot reach. Its head conflicts are settled inside
 * `@interop/was-sync`'s conflict handler, which decrypts both sides through
 * the cipher it is handed and runs no refresh of its own. A side sealed under
 * an epoch this session's descriptor has not seen would otherwise count as
 * undecryptable and be adopted unread. So the contacts cipher is was-client's
 * `createRefreshingEdvDocCipher`: on an unknown-epoch decrypt it re-reads the
 * descriptor once per instance, rebuilds, and retries.
 *
 * The cipher is primed with the descriptor the session already acquired, so
 * building it costs no second verifying log read: the source's first answer
 * is that descriptor, and every later acquisition (the refresh) goes to the
 * real source. With no source at all (a local-only session, or an account
 * whose pointer names no did:webvh) the descriptor in hand is all there is,
 * and the refresh path is inert exactly as a plain cipher's would be.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createRefreshingEdvDocCipher,
  type DocCipher,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource
} from '@interop/was-client/edv'

/**
 * @param options {object}
 * @param options.collectionId {string}   the WAS collection id
 * @param [options.idDerivation] {'content' | 'random'}
 * @param options.descriptor {CollectionEncryption}   the descriptor the
 *   session acquired, which primes the cipher's first build
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @param options.keyResolver {IKeyResolver}
 * @param [options.source] {EncryptionDescriptorSource}   the verifying
 *   source a refresh re-reads; absent leaves the refresh inert
 * @param [options.cache] {EncryptionDescriptorCache}   the session's cache
 *   a refreshed descriptor is written to; absent (no remote Space to cache
 *   for) leaves the descriptor in hand as the only copy
 * @param [options.onFetchError] {function}   observes a swallowed refresh
 *   fetch failure
 * @returns {Promise<DocCipher>}
 */
export async function refreshingCollectionCipher({
  collectionId,
  idDerivation,
  descriptor,
  keyAgreementKey,
  keyResolver,
  source,
  cache,
  onFetchError
}: {
  collectionId: string
  idDerivation?: 'content' | 'random'
  descriptor: CollectionEncryption
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  source?: EncryptionDescriptorSource
  cache?: EncryptionDescriptorCache
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<DocCipher> {
  let primed = false
  const primedSource: EncryptionDescriptorSource | undefined = source && {
    async collectionEncryption(options) {
      if (!primed) {
        primed = true
        return descriptor
      }
      return source.collectionEncryption(options)
    }
  }
  return createRefreshingEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId,
    idDerivation,
    ...(primedSource ? { source: primedSource } : {}),
    cache: cache ?? {
      readDescriptor: async () => descriptor,
      writeDescriptor: async () => {}
    },
    onFetchError
  })
}
