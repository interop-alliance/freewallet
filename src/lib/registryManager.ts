/**
 * Singleton issuer-registry client for `issuerDetailsSuite`. Loads the known
 * registries list and answers each DID lookup through
 * `@digitalcredentials/issuer-registry-client`, which handles both registry
 * types (`dcc-legacy` list files and `oidf` OpenID Federation trust anchors).
 *
 * The wallet supplies only the client's `fetch`, which routes each request by
 * what a browser can actually reach: the `oidf` trust anchors send no CORS
 * headers on either hop, so those go through the CORS proxy, while the
 * `dcc-legacy` registry files are served with `Access-Control-Allow-Origin: *`
 * and are fetched directly. The registries list itself is direct for the same
 * reason.
 */
import { RegistryClient } from '@digitalcredentials/issuer-registry-client'
import type { LookupResult } from '@digitalcredentials/issuer-registry-client'
import type { EntityIdentityRegistry } from '@interop/verifier-core'
import { KNOWN_REGISTRIES_URL, KnownDidRegistries } from '@/app.config'
import { corsProxyFetch } from './corsProxy'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:registries')

/**
 * Deadline for a network load: the whole registries fetch, and one whole DID
 * lookup across every registry and both of an `oidf` registry's hops.
 */
export const LOAD_TIMEOUT_MS = 10_000

let cachedRegistries: EntityIdentityRegistry[] | undefined
let registriesLoadPromise: Promise<EntityIdentityRegistry[]> | undefined

/**
 * Loads issuer registries directly from `KNOWN_REGISTRIES_URL`. Rejects on
 * failure rather than substituting the fallback list, so the caller decides
 * what to cache.
 *
 * A rejected load is evicted so a later lookup retries, guarded on identity so
 * an in-flight retry is not clobbered by a stale rejection.
 *
 * @returns {Promise<EntityIdentityRegistry[]>}
 */
async function loadRegistries(): Promise<EntityIdentityRegistry[]> {
  if (registriesLoadPromise) {
    return registriesLoadPromise
  }

  // The deadline matters because fetch and the body read are both uncancellable.
  const thisLoad = (async function fetchRegistries() {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), LOAD_TIMEOUT_MS)
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
 * Resolves the registry list for one lookup. A failed load falls back to
 * `KnownDidRegistries` for that lookup only -- the fallback set is deliberately
 * NOT cached, so one flaky fetch cannot pin the wallet to it for the whole
 * session.
 *
 * @returns {Promise<EntityIdentityRegistry[]>}
 */
async function ensureRegistries(): Promise<EntityIdentityRegistry[]> {
  if (cachedRegistries) {
    return cachedRegistries
  }
  try {
    cachedRegistries = await loadRegistries()
  } catch (err) {
    log.warn('Using fallback KnownDidRegistries', { err })
    return KnownDidRegistries
  }
  return cachedRegistries
}

/**
 * The registry URLs this browser can fetch without the proxy: every
 * non-`oidf` registry, which is a list file served with
 * `Access-Control-Allow-Origin: *`. An `oidf` registry contributes nothing
 * here -- neither its trust anchor nor the federation fetch endpoint it names
 * is directly reachable -- so both of its hops fall through to the proxy.
 *
 * @param registries {EntityIdentityRegistry[]}
 * @returns {Set<string>}
 */
function directlyFetchableUrls(
  registries: EntityIdentityRegistry[]
): Set<string> {
  const urls = registries
    .filter(registry => registry.type !== 'oidf')
    .map(registry => ('url' in registry ? registry.url : undefined))
    .filter((url): url is string => typeof url === 'string' && url.length > 0)
  return new Set(urls)
}

/**
 * Resets the module-level registry cache. Test-only hook so each case starts
 * from a clean loader state.
 */
export function __resetRegistryCacheForTests(): void {
  cachedRegistries = undefined
  registriesLoadPromise = undefined
}

export const registryManager = {
  /**
   * Looks up issuer registries for a DID. The client is built per lookup so
   * that one abort signal bounds the whole lookup -- every request AND every
   * body read the client makes -- rather than each request separately.
   *
   * @param did {string}
   * @returns {Promise<LookupResult>}
   */
  async lookupDid(did: string): Promise<LookupResult> {
    if (!did) {
      return { matchingIssuers: [], uncheckedRegistries: [] }
    }
    const registries = await ensureRegistries()
    const directUrls = directlyFetchableUrls(registries)

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), LOAD_TIMEOUT_MS)
    try {
      const client = new RegistryClient({
        fetch: async url =>
          directUrls.has(url)
            ? await fetch(url, { signal: controller.signal })
            : await corsProxyFetch({ url, signal: controller.signal })
      })
      client.use({ registries })
      return await client.lookupIssuersFor(did)
    } finally {
      clearTimeout(timeoutId)
    }
  }
}
