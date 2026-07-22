/**
 * QueryByExample matching. The type-and-issuer matcher itself moved to
 * `@interop/wallet-core/request` (operating on plain `IVerifiableCredential`s);
 * this wrapper maps Freewallet's `StoredCredential` records down to their VCs,
 * runs the shared matcher, and maps the matches back so the share screen keeps
 * working with stored records (preserving each credential's `cid`).
 */
import type { StoredCredential } from '@/types/credential'
import { vcMatchesFor as vcMatchesForVcs } from '@interop/wallet-core/request'
import type { IQueryByExample } from './types'

export {
  hasTypedExample,
  requestsCredentialType
} from '@interop/wallet-core/request'

/**
 * The stored credentials matching any of the given QueryByExample queries by
 * the shared type-and-issuer algorithm.
 *
 * @param options {object}
 * @param options.credentials {StoredCredential[]}
 * @param options.queries {IQueryByExample[]}
 * @returns {StoredCredential[]}
 */
export function vcMatchesFor({
  credentials,
  queries
}: {
  credentials: StoredCredential[]
  queries: IQueryByExample[]
}): StoredCredential[] {
  const matched = vcMatchesForVcs({
    credentials: credentials.map(({ vc }) => vc),
    queries
  })
  return credentials.filter(({ vc }) => matched.includes(vc))
}
