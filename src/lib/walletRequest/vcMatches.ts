/**
 * QueryByExample matching: filters stored credentials to those satisfying a
 * request's `QueryByExample` queries. Resolves the long-standing "list all
 * credentials" TODO -- when a request specifies an example `type`, the share
 * screen shows only the credentials that actually match it.
 */
import type { StoredCredential } from '@/types/credential'
import { credentialQueriesOf } from './classify'
import type { ICredentialQuery, IQueryByExample } from './types'

/**
 * Normalizes a `type` value (string or array) to an array of strings.
 */
function typeArray(type: unknown): string[] {
  if (typeof type === 'string') {
    return [type]
  }
  return Array.isArray(type)
    ? (type.filter(entry => typeof entry === 'string') as string[])
    : []
}

/**
 * Extracts a DID / id string from an issuer value that may be a string or an
 * `{ id }` object.
 */
function issuerId(issuer: unknown): string | undefined {
  if (typeof issuer === 'string') {
    return issuer
  }
  if (issuer && typeof issuer === 'object' && 'id' in issuer) {
    const { id } = issuer as { id?: unknown }
    return typeof id === 'string' ? id : undefined
  }
  return undefined
}

/**
 * Whether a stored VC matches a single QueryByExample `example`: every type
 * listed in `example.type` must appear in the VC's `type`, and -- when the
 * example pins an `issuer` -- the VC's issuer must equal it.
 *
 * @param options {object}
 * @param options.credential {StoredCredential}
 * @param options.example {ICredentialQuery['example']}
 * @returns {boolean}
 */
function matchesExample({
  credential,
  example
}: {
  credential: StoredCredential
  example: ICredentialQuery['example']
}): boolean {
  const wantedTypes = typeArray(example.type)
  const credentialTypes = typeArray(credential.vc.type)
  const typesMatch = wantedTypes.every(type => credentialTypes.includes(type))
  if (!typesMatch) {
    return false
  }
  const wantedIssuer = issuerId(example.issuer)
  if (wantedIssuer) {
    return issuerId(credential.vc.issuer) === wantedIssuer
  }
  return true
}

/**
 * The credentials matching any of the given QueryByExample queries. Only
 * queries whose `example` carries a `type` constrain the result; a query with
 * no example type matches nothing here (the caller keeps the list-all behavior
 * when *no* query specifies a type -- see `WalletGetPage`).
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
  const examples = typedExamplesOf(queries)
  if (examples.length === 0) {
    return []
  }
  return credentials.filter(credential =>
    examples.some(example => matchesExample({ credential, example }))
  )
}

/**
 * The example credential shapes pinned by a query set: every `credentialQuery`
 * detail carrying an example `type`. Only these constrain the share list.
 *
 * @param queries {IQueryByExample[]}
 * @returns {ICredentialQuery['example'][]}
 */
function typedExamplesOf(
  queries: IQueryByExample[]
): Array<ICredentialQuery['example']> {
  return queries
    .flatMap(query => credentialQueriesOf(query))
    .map(({ example }) => example)
    .filter(
      (example): example is ICredentialQuery['example'] =>
        !!example && typeArray(example.type).length > 0
    )
}

/**
 * Whether any of the QueryByExample queries pins an example `type` (and so
 * should filter the share list). When false, the caller keeps showing all
 * stored credentials.
 *
 * @param queries {IQueryByExample[]}
 * @returns {boolean}
 */
export function hasTypedExample(queries: IQueryByExample[]): boolean {
  return typedExamplesOf(queries).length > 0
}

/**
 * Whether any typed example in the query set explicitly lists the given
 * credential `type`. Lets the caller distinguish a request that actually asks
 * for a particular type (e.g. a LoginCredential) from a generic, untyped
 * "any VC" request.
 *
 * @param options {object}
 * @param options.queries {IQueryByExample[]}
 * @param options.type {string}
 * @returns {boolean}
 */
export function requestsCredentialType({
  queries,
  type
}: {
  queries: IQueryByExample[]
  type: string
}): boolean {
  return typedExamplesOf(queries).some(example =>
    typeArray(example.type).includes(type)
  )
}
