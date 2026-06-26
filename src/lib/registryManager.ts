/**
 * Singleton issuer-registry client for `issuerDetailsSuite`. Loads the known
 * registries list once per session, then reuses the same RegistryClient.
 */
import {
  RegistryClient,
  type LookupResult
} from '@digitalcredentials/issuer-registry-client'
import type { EntityIdentityRegistry } from '@interop/verifier-core'
import { KNOWN_REGISTRIES_URL, KnownDidRegistries } from '@/app.config'

const EMPTY_RESULT: LookupResult = {
  matchingIssuers: [],
  uncheckedRegistries: []
}

let cachedClient: RegistryClient | undefined
let registriesLoadPromise: Promise<EntityIdentityRegistry[]> | undefined

async function loadRegistries(): Promise<EntityIdentityRegistry[]> {
  if (!registriesLoadPromise) {
    registriesLoadPromise = (async () => {
      try {
        const regRes = await fetch(KNOWN_REGISTRIES_URL)
        if (!regRes.ok) {
          throw new Error(`Registry fetch failed: ${regRes.status}`)
        }
        return (await regRes.json()) as EntityIdentityRegistry[]
      } catch (err) {
        console.warn('Using fallback KnownDidRegistries:', err)
        return KnownDidRegistries
      }
    })()
  }
  return registriesLoadPromise
}

async function ensureClient(): Promise<RegistryClient> {
  if (!cachedClient) {
    const registries = await loadRegistries()
    cachedClient = new RegistryClient()
    cachedClient.use({ registries })
  }
  return cachedClient
}

export const registryManager = {
  async lookupDid(did: string): Promise<LookupResult> {
    if (!did) {
      return EMPTY_RESULT
    }
    const client = await ensureClient()
    return client.lookupIssuersFor(did)
  }
}
