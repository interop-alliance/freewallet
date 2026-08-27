/**
 * Singleton issuer-registry client for `issuerDetailsSuite`. Answers each
 * lookup from two halves: `dcc-legacy` registries through `RegistryClient`,
 * and `oidf` registries through this module's own CORS-proxied lookup.
 *
 * The split exists because `RegistryClient` fetches directly, and the `oidf`
 * trust anchors send no CORS headers on either hop.
 */
import { RegistryClient } from '@digitalcredentials/issuer-registry-client'
import type {
  EntityIdentityRegistry,
  OidfEntityIdentityRegistry
} from '@interop/verifier-core'
import { KNOWN_REGISTRIES_URL, KnownDidRegistries } from '@/app.config'
import { corsProxyFetch } from './corsProxy'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:registries')

/**
 * Deadline for a network load: the whole registries fetch, and each `oidf`
 * registry lookup across both of its hops.
 */
export const LOAD_TIMEOUT_MS = 10_000

/**
 * One registry's answer for an issuer DID. Both members carry the `metadata`
 * decoded from the relevant entity statement, which is what the credential UI
 * renders.
 */
export interface RegistryIssuerMatch {
  issuer?: Record<string, unknown>
  registry?: Record<string, unknown>
}

/**
 * The merged result of looking one DID up across every configured registry.
 * `uncheckedRegistries` holds entries that could not be reached at all, which
 * is distinct from a registry answering "not registered here".
 */
export interface RegistryLookupResult {
  matchingIssuers: RegistryIssuerMatch[]
  uncheckedRegistries: EntityIdentityRegistry[]
}

/**
 * The loaded registry list, split into the halves each lookup path handles.
 */
interface RegistryLookupSet {
  client: RegistryClient
  oidfRegistries: OidfEntityIdentityRegistry[]
}

let cachedLookupSet: RegistryLookupSet | undefined
let registriesLoadPromise: Promise<EntityIdentityRegistry[]> | undefined

/**
 * Loads issuer registries directly from `KNOWN_REGISTRIES_URL`, which is served
 * with `Access-Control-Allow-Origin: *`. Rejects on failure rather than
 * substituting the fallback list, so the caller decides what to cache.
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
 * Splits a registry list into the two lookup halves. The client is handed only
 * what it can reach; given the `oidf` entries it would report every one as
 * unchecked after a failed direct fetch.
 *
 * @param registries {EntityIdentityRegistry[]}
 * @returns {RegistryLookupSet}
 */
function lookupSetFrom(
  registries: EntityIdentityRegistry[]
): RegistryLookupSet {
  const oidfRegistries = registries.filter(
    (registry): registry is OidfEntityIdentityRegistry =>
      registry.type === 'oidf'
  )
  const client = new RegistryClient()
  client.use({ registries: registries.filter(entry => entry.type !== 'oidf') })
  return { client, oidfRegistries }
}

/**
 * Creates the singleton lookup set after registries have been loaded. A failed
 * load falls back to `KnownDidRegistries` for this lookup only -- the fallback
 * set is deliberately NOT cached, so one flaky fetch cannot pin the wallet to
 * it for the whole session.
 *
 * @returns {Promise<RegistryLookupSet>}
 */
async function ensureLookupSet(): Promise<RegistryLookupSet> {
  if (cachedLookupSet) {
    return cachedLookupSet
  }
  let registries: EntityIdentityRegistry[]
  try {
    registries = await loadRegistries()
  } catch (err) {
    log.warn('Using fallback KnownDidRegistries', { err })
    return lookupSetFrom(KnownDidRegistries)
  }
  cachedLookupSet = lookupSetFrom(registries)
  return cachedLookupSet
}

/**
 * Reads an entity statement's `metadata`, decoding the JWT payload without
 * verifying its signature -- trust rests on the registry list naming the trust
 * anchor, and upstream does not verify either. Decoded through `TextDecoder`
 * so non-ASCII fields survive.
 *
 * @param jwt {string}
 * @returns {Record<string, unknown> | undefined}
 */
function entityStatementMetadata(
  jwt: string
): Record<string, unknown> | undefined {
  const segment = jwt.split('.')[1]
  if (!segment) {
    throw new Error('Malformed entity statement: no JWT payload segment')
  }
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    '='
  )
  const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0))
  const { metadata } = JSON.parse(new TextDecoder().decode(bytes))
  if (!metadata || typeof metadata !== 'object') {
    return undefined
  }
  return metadata as Record<string, unknown>
}

/**
 * Looks a DID up in one OpenID Federation registry, both hops through the CORS
 * proxy: the trust anchor's entity configuration, then its federation fetch
 * endpoint. Resolves to `undefined` when the registry does not list the issuer;
 * throws when it could not be checked at all.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.registry {OidfEntityIdentityRegistry}
 * @param options.signal {AbortSignal}
 * @returns {Promise<RegistryIssuerMatch | undefined>}
 */
async function lookupOidfRegistry({
  did,
  registry,
  signal
}: {
  did: string
  registry: OidfEntityIdentityRegistry
  signal: AbortSignal
}): Promise<RegistryIssuerMatch | undefined> {
  const ecRes = await corsProxyFetch({ url: registry.trustAnchorEC, signal })
  if (!ecRes.ok) {
    throw new Error(`Entity configuration fetch failed: ${ecRes.status}`)
  }
  const registryMetadata = entityStatementMetadata(await ecRes.text())
  if (!registryMetadata) {
    throw new Error('Entity configuration carried no metadata')
  }
  const federationEntity = registryMetadata.federation_entity as
    { federation_fetch_endpoint?: unknown } | undefined
  const endpoint = federationEntity?.federation_fetch_endpoint
  if (typeof endpoint !== 'string' || !endpoint) {
    throw new Error('Entity configuration named no federation fetch endpoint')
  }

  const lookupRes = await corsProxyFetch({
    url: `${endpoint}?sub=${encodeURIComponent(did)}`,
    signal
  })
  // A real answer ("not registered here"), not a failure.
  if (lookupRes.status === 404) {
    return undefined
  }
  if (!lookupRes.ok) {
    throw new Error(`Federation fetch failed: ${lookupRes.status}`)
  }
  const issuer = entityStatementMetadata(await lookupRes.text())
  if (!issuer) {
    throw new Error('Federation fetch carried no issuer metadata')
  }
  return { issuer, registry: registryMetadata }
}

/**
 * Looks a DID up across every `oidf` registry in parallel, collecting the ones
 * that could not be reached as unchecked rather than failing the whole lookup.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.registries {OidfEntityIdentityRegistry[]}
 * @returns {Promise<RegistryLookupResult>}
 */
async function lookupOidfRegistries({
  did,
  registries
}: {
  did: string
  registries: OidfEntityIdentityRegistry[]
}): Promise<RegistryLookupResult> {
  if (registries.length === 0) {
    return { matchingIssuers: [], uncheckedRegistries: [] }
  }
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), LOAD_TIMEOUT_MS)
  try {
    const outcomes = await Promise.all(
      registries.map(async registry => {
        try {
          return {
            registry,
            match: await lookupOidfRegistry({
              did,
              registry,
              signal: controller.signal
            })
          }
        } catch (err) {
          log.warn('Could not check oidf registry', {
            registry: registry.name,
            err
          })
          return { registry, unchecked: true as const }
        }
      })
    )
    return {
      matchingIssuers: outcomes
        .map(outcome => ('match' in outcome ? outcome.match : undefined))
        .filter((match): match is RegistryIssuerMatch => !!match),
      uncheckedRegistries: outcomes
        .filter(outcome => 'unchecked' in outcome)
        .map(outcome => outcome.registry)
    }
  } finally {
    clearTimeout(timeoutId)
  }
}

/**
 * Resets the module-level registry cache. Test-only hook so each case starts
 * from a clean loader state.
 */
export function __resetRegistryCacheForTests(): void {
  cachedLookupSet = undefined
  registriesLoadPromise = undefined
}

export const registryManager = {
  /**
   * Looks up issuer registries for a DID.
   */
  async lookupDid(did: string): Promise<RegistryLookupResult> {
    if (!did) {
      return { matchingIssuers: [], uncheckedRegistries: [] }
    }
    const { client, oidfRegistries } = await ensureLookupSet()
    const [legacy, oidf] = await Promise.all([
      client.lookupIssuersFor(did),
      lookupOidfRegistries({ did, registries: oidfRegistries })
    ])
    return {
      // Through `unknown` because upstream declares `issuer` as a fixed
      // `IssuerMetaData`, while its `dcc-legacy` branch actually returns the
      // same `federation_entity` shape the `oidf` half does.
      matchingIssuers: [
        ...(legacy.matchingIssuers as unknown as RegistryIssuerMatch[]),
        ...oidf.matchingIssuers
      ],
      uncheckedRegistries: [
        ...(legacy.uncheckedRegistries as EntityIdentityRegistry[]),
        ...oidf.uncheckedRegistries
      ]
    }
  }
}
