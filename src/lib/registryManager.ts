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
 *
 * Two caches sit on top of the list cache. A lookup is memoized by DID, so a
 * dashboard whose credentials share one issuer resolves that issuer once. One
 * layer down, the DID-independent registry bodies (each `dcc-legacy` list
 * file, each `oidf` entity configuration) are cached by URL, so distinct DIDs
 * download each body once; a request whose URL carries the DID (the `oidf`
 * federation fetch) is made per lookup. Both entries expire after
 * `LOOKUP_CACHE_TTL_MS`, so a registry change reaches an open tab, and both
 * caches are cleared at logout. Neither cache keeps a failure: a body fetch
 * that threw, answered non-ok, or served a body the client could not parse is
 * not cached, and a lookup that left a registry unchecked or ran on the
 * fallback list is not memoized, so the next lookup retries exactly the hop
 * that failed.
 */
import { RegistryClient } from '@digitalcredentials/issuer-registry-client'
import type { LookupResult } from '@digitalcredentials/issuer-registry-client'
import type { EntityIdentityRegistry } from '@interop/verifier-core'
import { base64urlnopad } from '@scure/base'
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

/**
 * How long a memoized lookup and a cached registry body stay fresh. Long
 * enough that every card on a dashboard mount shares one download, short
 * enough that an issuer added to a registry reaches an open tab.
 */
export const LOOKUP_CACHE_TTL_MS = 5 * 60 * 1000

let cachedRegistries: EntityIdentityRegistry[] | undefined
let registriesLoadPromise: Promise<EntityIdentityRegistry[]> | undefined

/**
 * A cache slot: the value's promise, set before the work it awaits so that
 * concurrent misses share one run, and the instant it stops being fresh.
 */
interface CacheEntry<T> {
  value: Promise<T>
  expires: number
}

/**
 * Registry bodies read to completion, by URL. The text is replayed as a fresh
 * `Response` on every hit so the client can consume it each time.
 */
const cachedBodies = new Map<string, CacheEntry<string>>()
const cachedLookups = new Map<string, CacheEntry<LookupResult>>()

/**
 * A fresh entry of `cache`, or `undefined` when the slot is empty or stale.
 *
 * @param cache {Map<string, CacheEntry<T>>}
 * @param key {string}
 * @returns {CacheEntry<T> | undefined}
 */
function freshEntry<T>(
  cache: Map<string, CacheEntry<T>>,
  key: string
): CacheEntry<T> | undefined {
  const entry = cache.get(key)
  return entry && entry.expires > Date.now() ? entry : undefined
}

/**
 * Stores `value` under `key`, evicting it again if it rejects. The eviction is
 * guarded on identity so a slot already re-filled by a retry is left alone.
 *
 * @param cache {Map<string, CacheEntry<T>>}
 * @param key {string}
 * @param value {Promise<T>}
 * @returns {CacheEntry<T>}
 */
function setEntry<T>(
  cache: Map<string, CacheEntry<T>>,
  key: string,
  value: Promise<T>
): CacheEntry<T> {
  const entry = { value, expires: Date.now() + LOOKUP_CACHE_TTL_MS }
  cache.set(key, entry)
  value.catch(() => {
    if (cache.get(key) === entry) {
      cache.delete(key)
    }
  })
  return entry
}

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
 * Whether a registry body is one the client can parse: a JSON document (a
 * `dcc-legacy` list file) or a JWT whose payload is one (an `oidf` entity
 * statement). Caching an ok response with an unparseable body -- a captive
 * portal page, a maintenance page -- would replay the same failure on every
 * retry until the entry expired.
 *
 * @param text {string}
 * @returns {boolean}
 */
function parseableRegistryBody(text: string): boolean {
  const parses = (json: string): boolean => {
    try {
      JSON.parse(json)
      return true
    } catch {
      return false
    }
  }
  if (parses(text)) {
    return true
  }
  const segments = text.trim().split('.')
  if (segments.length !== 3) {
    return false
  }
  try {
    return parses(new TextDecoder().decode(base64urlnopad.decode(segments[1])))
  } catch {
    return false
  }
}

/**
 * Serves a DID-independent registry body from the cache, fetching and reading
 * it under this hop's signal on a miss. The body read happens here rather than
 * in the client so the cached text is complete and the deadline still bounds
 * it. Only an ok, parseable body is cached: a non-ok response is passed
 * through as-is so the client reports the registry unchecked, and a fetch
 * that threw or a body the client could not parse is evicted, so the next
 * lookup retries.
 *
 * The slot is filled before the fetch is awaited, so concurrent misses share
 * one request. A lookup joining an in-flight read rides the first hop's
 * deadline; if that read fails (the first hop's deadline fired, or its
 * response was bad), the joiner fetches for itself under its own signal
 * rather than failing with it.
 *
 * @param options {object}
 * @param options.url {string}
 * @param options.signal {AbortSignal}
 * @param options.fetchBody {(options: { url: string, signal: AbortSignal }) => Promise<Response>}
 * @returns {Promise<Response>}
 */
async function cachedBodyResponse({
  url,
  signal,
  fetchBody
}: {
  url: string
  signal: AbortSignal
  fetchBody: (options: {
    url: string
    signal: AbortSignal
  }) => Promise<Response>
}): Promise<Response> {
  const hit = freshEntry(cachedBodies, url)
  if (hit) {
    try {
      return new Response(await hit.value)
    } catch {
      // The read this lookup joined failed; fetch for ourselves below.
    }
  }
  let nonOk: Response | undefined
  const thisRead = (async function readBody(): Promise<string> {
    const response = await fetchBody({ url, signal })
    if (!response.ok) {
      nonOk = response
      throw new Error(`Registry body fetch failed: ${response.status}`)
    }
    const text = await response.text()
    if (!parseableRegistryBody(text)) {
      throw new Error(`Registry body at ${url} is not JSON or a JWT`)
    }
    return text
  })()
  const entry = setEntry(cachedBodies, url, thisRead)
  try {
    return new Response(await entry.value)
  } catch (err) {
    if (nonOk) {
      return nonOk
    }
    throw err
  }
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
  clearRegistryLookupCaches()
}

/**
 * Drops every memoized lookup and cached registry body. Run at logout, so a
 * session's issuer answers do not carry into the next account's; the
 * registries list itself is account-independent and stays.
 *
 * @returns {void}
 */
export function clearRegistryLookupCaches(): void {
  cachedBodies.clear()
  cachedLookups.clear()
}

/**
 * One uncached lookup: builds the client, runs it over the registries list,
 * and reports whether the result is worth memoizing.
 *
 * The client is built per lookup so that each request it makes carries an
 * abort signal of its own, bounding both the request AND the body read the
 * client performs after it.
 *
 * @param did {string}
 * @returns {Promise<{ result: LookupResult, memoizable: boolean }>}
 */
async function runLookup(
  did: string
): Promise<{ result: LookupResult; memoizable: boolean }> {
  const registries = await ensureRegistries()
  const directUrls = directlyFetchableUrls(registries)
  // A URL carrying the DID (the `oidf` federation fetch, which interpolates
  // it as `?sub=`) answers for this DID alone and must not be cached by URL
  // for another; the test is on the URL itself rather than on a list of
  // which registry fields the client fetches, so it cannot drift from the
  // client.
  const didIndependent = (url: string): boolean =>
    !url.includes(did) && !url.includes(encodeURIComponent(did))

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
        const fetchBody = directUrls.has(url)
          ? fetchDirectWithProxyFallback
          : corsProxyFetch
        return didIndependent(url)
          ? await cachedBodyResponse({ url, signal, fetchBody })
          : await fetchBody({ url, signal })
      }
    })
    client.use({ registries })
    const result = await client.lookupIssuersFor(did)
    // A result on the fallback list, or with a registry left unchecked, would
    // pin a transient failure to this DID for the session.
    const memoizable =
      registries === cachedRegistries && result.uncheckedRegistries.length === 0
    return { result, memoizable }
  } finally {
    hopTimers.forEach(clearTimeout)
  }
}

export const registryManager = {
  /**
   * Looks up issuer registries for a DID, memoized by DID for
   * `LOOKUP_CACHE_TTL_MS`. Concurrent lookups of one DID share a single run.
   * A run that threw, ran on the fallback list, or left a registry unchecked
   * is evicted once it settles, so the next lookup retries.
   *
   * @param did {string}
   * @returns {Promise<LookupResult>}
   */
  async lookupDid(did: string): Promise<LookupResult> {
    if (!did) {
      return { matchingIssuers: [], uncheckedRegistries: [] }
    }
    const hit = freshEntry(cachedLookups, did)
    if (hit) {
      return hit.value
    }
    const thisLookup = runLookup(did)
    const entry = setEntry(
      cachedLookups,
      did,
      thisLookup.then(({ result }) => result)
    )
    thisLookup.then(
      ({ memoizable }) => {
        if (!memoizable && cachedLookups.get(did) === entry) {
          cachedLookups.delete(did)
        }
      },
      () => undefined
    )
    return entry.value
  }
}
