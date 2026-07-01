/**
 * Singleton issuer-registry client for `issuerDetailsSuite`. Loads the known
 * registries list once per session, then reuses the same RegistryClient.
 */
import {
  RegistryClient,
  type LookupResult
} from '@digitalcredentials/issuer-registry-client'
import type { EntityIdentityRegistry } from '@interop/verifier-core'
import {
  KNOWN_REGISTRIES_URL,
  KnownDidRegistries,
  WAS_SERVER_URL
} from '@/app.config'

const EMPTY_RESULT: LookupResult = {
  matchingIssuers: [],
  uncheckedRegistries: []
}

let cachedClient: RegistryClient | undefined
let registriesLoadPromise: Promise<EntityIdentityRegistry[]> | undefined

/**
 * Fetches a registry list from the given URL and validates the HTTP response.
 */
async function fetchRegistries(url: string): Promise<EntityIdentityRegistry[]> {
  const regRes = await fetch(url)
  if (!regRes.ok) {
    throw new Error(`Registry fetch failed: ${regRes.status}`)
  }
  return (await regRes.json()) as EntityIdentityRegistry[]
}

/**
 * Loads issuer registries by trying the direct URL first, then the WAS proxy,
 * and finally the local fallback list.
 */
async function loadRegistries(): Promise<EntityIdentityRegistry[]> {
  if (!registriesLoadPromise) {
    registriesLoadPromise = (async () => {
      try {
        return await fetchRegistries(KNOWN_REGISTRIES_URL)
      } catch (directError) {
        if (WAS_SERVER_URL) {
          try {
            return await fetchRegistries(
              `${WAS_SERVER_URL}/api/cors?url=${encodeURIComponent(KNOWN_REGISTRIES_URL)}`
            )
          } catch (proxyError) {
            console.warn('Using fallback KnownDidRegistries:', proxyError)
            return KnownDidRegistries
          }
        }
        console.warn('Using fallback KnownDidRegistries:', directError)
        return KnownDidRegistries
      }
    })()
  }
  return registriesLoadPromise
}

/**
 * Creates the singleton registry client after registries have been loaded.
 */
async function ensureClient(): Promise<RegistryClient> {
  if (!cachedClient) {
    const registries = await loadRegistries()
    cachedClient = new RegistryClient()
    cachedClient.use({ registries })
  }
  return cachedClient
}

export const registryManager = {
  /**
   * Looks up issuer registries for a DID.
   */
  async lookupDid(did: string): Promise<LookupResult> {
    if (!did) {
      return EMPTY_RESULT
    }
    const client = await ensureClient()
    return client.lookupIssuersFor(did)
  }
}
