/**
 * Singleton issuer-registry client for `issuerDetailsSuite`. Loads the known
 * registries list and answers each DID lookup through
 * `@digitalcredentials/issuer-registry-client`, which handles both registry
 * types (`dcc-legacy` list files and `oidf` OpenID Federation trust anchors).
 *
 * The wallet supplies only the client's `fetch`, which routes each request by
 * what a browser can actually reach: the `oidf` trust anchors send no CORS
 * headers on either hop, so those go straight through the CORS proxy, while
 * the `dcc-legacy` registry files are served with `Access-Control-Allow-Origin:
 * *` and are tried directly first, falling back to the proxy when the direct
 * request fails. The registries list itself is direct for the same reason.
 */
import { RegistryClient } from '@digitalcredentials/issuer-registry-client'
import type { LookupResult } from '@digitalcredentials/issuer-registry-client'
import type { EntityIdentityRegistry } from '@interop/verifier-core'
import { KNOWN_REGISTRIES_URL, KnownDidRegistries } from '@/app.config'
import { corsProxyFetch } from './corsProxy'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:registries')

/**
 * Deadline for one network hop: the registries fetch, or one request the
 * registry client makes.
 *
 * The budget is per hop rather than per lookup because an `oidf` registry
 * makes two SEQUENTIAL requests, and the CORS proxy bounds each of its own
 * upstream hops at 10s. A lookup-wide deadline shorter than the sum of those
 * would abort a hop the proxy was still willing to serve, reporting a healthy
 * registry as unchecked. Registries are looked up concurrently, so this bounds
 * a whole lookup at two hops regardless of how many are listed.
 */
export const HOP_TIMEOUT_MS = 12_000

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

  // The deadline covers the body read as well as the request, so it is cleared
  // only once the body has been parsed.
  const thisLoad = (async function fetchRegistries() {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), HOP_TIMEOUT_MS)
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
 * The registry URLs this browser tries to fetch without the proxy: every
 * non-`oidf` registry, which is a list file served with
 * `Access-Control-Allow-Origin: *`. A host that stops sending that header
 * falls back to the proxy rather than failing, so this set is an optimization
 * rather than a claim about any host. An `oidf` registry contributes nothing
 * here -- neither its trust anchor nor the federation fetch endpoint it names
 * is directly reachable -- so both of its hops go straight to the proxy.
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
 * Fetches a directly-reachable registry URL, retrying once through the CORS
 * proxy when the direct request throws.
 *
 * The registries list is third-party-controlled and already names hosts
 * outside GitHub Pages, so a listed registry can stop sending
 * `Access-Control-Allow-Origin: *` at any time. The browser then blocks the
 * request and `fetch` rejects; without this retry the registry client would
 * catch that and silently report a reachable registry as unchecked, so its
 * issuers would stop being recognized. The retry costs a round trip only on
 * the already-failing path.
 *
 * A deadline abort is not retried -- this hop's budget is already spent.
 *
 * @param options {object}
 * @param options.url {string}
 * @param options.signal {AbortSignal}
 * @returns {Promise<Response>}
 */
async function fetchDirectWithProxyFallback({
  url,
  signal
}: {
  url: string
  signal: AbortSignal
}): Promise<Response> {
  try {
    return await fetch(url, { signal })
  } catch (err) {
    if (signal.aborted) {
      throw err
    }
    log.warn('Direct registry fetch failed, retrying through the CORS proxy', {
      url,
      err
    })
    return corsProxyFetch({ url, signal })
  }
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
   * that each request the client makes carries an abort signal of its own,
   * bounding both the request AND the body read the client performs after it.
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

    // A hop's timer is deliberately not cleared when its response resolves:
    // the signal has to stay armed to bound the client's body read, which
    // happens after the fetch returns. They are all cleared once the lookup
    // ends, whether it resolved or threw.
    const hopTimers: ReturnType<typeof setTimeout>[] = []
    try {
      const client = new RegistryClient({
        fetch: async url => {
          const controller = new AbortController()
          hopTimers.push(setTimeout(() => controller.abort(), HOP_TIMEOUT_MS))
          const signal = controller.signal
          return directUrls.has(url)
            ? await fetchDirectWithProxyFallback({ url, signal })
            : await corsProxyFetch({ url, signal })
        }
      })
      client.use({ registries })
      return await client.lookupIssuersFor(did)
    } finally {
      hopTimers.forEach(clearTimeout)
    }
  }
}
