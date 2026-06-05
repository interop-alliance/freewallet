/**
 * Shared issuer registry client. Holds a module-level singleton
 * `RegistryClient` (from @digitalcredentials/issuer-registry-client) loaded
 * once with the configured registries, so the issuer-details verification
 * suite can look up rich issuer metadata without re-parsing the registry
 * config on every credential. Keeps registry fetch/caching out of the hot
 * path. Used by `issuerDetailsSuite`.
 */
import { RegistryClient } from '@digitalcredentials/issuer-registry-client'
import type { EntityIdentityRegistry } from '@interop/verifier-core'

let cachedClient: RegistryClient | undefined

/**
 * Returns a process-wide singleton RegistryClient, loading it with the given
 * registries on first call. Subsequent calls return the same instance and
 * ignore their `registries` argument (the first caller wins) -- the registry
 * config is app-wide and stable for the lifetime of the session.
 *
 * @param options {object}
 * @param options.registries {EntityIdentityRegistry[]}   Registries to load on
 *   first initialization.
 * @returns {RegistryClient}
 */
export function getCachedRegistryClient({
  registries
}: {
  registries: EntityIdentityRegistry[]
}): RegistryClient {
  if (!cachedClient) {
    cachedClient = new RegistryClient()
    cachedClient.use({ registries })
  }
  return cachedClient
}
