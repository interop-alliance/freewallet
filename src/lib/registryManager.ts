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
import { createLogger } from '@/lib/log'

const log = createLogger('fw:registries')

/**
 * Deadline for a whole registries load.
 */
export const REGISTRY_LOAD_TIMEOUT_MS = 10_000

const EMPTY_RESULT: LookupResult = {
  matchingIssuers: [],
  uncheckedRegistries: []
}

let cachedClient: RegistryClient | undefined
let registriesLoadPromise: Promise<EntityIdentityRegistry[]> | undefined

/**
 * Loads issuer registries directly from `KNOWN_REGISTRIES_URL` -- GitHub
 * Pages serves it with `Access-Control-Allow-Origin: *`, so no CORS proxy
 * hop is needed. Rejects on failure rather than substituting the fallback
 * list, so the caller can decide what to cache.
 *
 * A rejected load is evicted from the module-level cache so a later lookup
 * retries the fetch, rather than every subsequent caller receiving the same
 * poisoned, permanently-rejected promise. The eviction is guarded on identity
 * so an in-flight retry is not clobbered by a stale rejection.
 *
 * @returns {Promise<EntityIdentityRegistry[]>}
 */
async function loadRegistries(): Promise<EntityIdentityRegistry[]> {
  if (registriesLoadPromise) {
    return registriesLoadPromise
  }

  /**
   * Bound the load with an AbortController deadline: the fetch and the
   * body read were both uncancellable, so a stalled load never settled
   * and the fallback branch stayed unreachable, leaving issuer lookups pending.
   */
  const thisLoad = (async function fetchRegistries() {
    const controller = new AbortController()
    const timeoutId = setTimeout(
      () => controller.abort(),
      REGISTRY_LOAD_TIMEOUT_MS
    )
    try {
      const regRes = await fetch(KNOWN_REGISTRIES_URL, {
        signal: controller.signal
      })
      if (!regRes.ok) {
        throw new Error(`Registry fetch failed: ${regRes.status}`)
      }
      return (await regRes.json()) as EntityIdentityRegistry[]
    } finally {
      clearTimeout(timeoutId)
    }
  })()
  thisLoad.catch(() => {
    if (registriesLoadPromise === thisLoad) {
      registriesLoadPromise = undefined
    }
  })
  registriesLoadPromise = thisLoad
  return thisLoad
}

/**
 * Creates the singleton registry client after registries have been loaded.
 *
 * A failed load falls back to the local `KnownDidRegistries` list for this
 * lookup only -- the fallback client is deliberately NOT cached, so a single
 * flaky fetch cannot pin the wallet to the fallback list for the whole
 * session; the next lookup fetches again.
 *
 * @returns {Promise<RegistryClient>}
 */
async function ensureClient(): Promise<RegistryClient> {
  if (cachedClient) {
    return cachedClient
  }
  let registries: EntityIdentityRegistry[]
  try {
    registries = await loadRegistries()
  } catch (err) {
    log.warn('Using fallback KnownDidRegistries', { err })
    const fallbackClient = new RegistryClient()
    fallbackClient.use({ registries: KnownDidRegistries })
    return fallbackClient
  }
  const loadedClient = new RegistryClient()
  loadedClient.use({ registries })
  cachedClient = loadedClient
  return loadedClient
}

/**
 * Resets the module-level registry cache. Test-only hook so each case starts
 * from a clean loader state.
 */
export function __resetRegistryCacheForTests(): void {
  cachedClient = undefined
  registriesLoadPromise = undefined
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
