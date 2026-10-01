/**
 * Small readers over a zcap's optional caveats and its target, so the app's
 * many call sites share one shape assertion instead of restating it.
 */
import type { IZcap } from '@interop/data-integrity-core'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv'
import { parseSpaceTarget } from '@interop/was-client/paths'

/**
 * A zcap's `expires` caveat, or `undefined` when it carries none.
 *
 * `IZcap` covers the root form too, which has no `expires`, so reading the
 * caveat means asserting the delegated shape. That assertion lives here once
 * rather than at every reader.
 *
 * @param [zcap] {IZcap}   the capability to read
 * @returns {string | undefined}   the caveat's XML-schema timestamp
 */
export function zcapExpires(zcap?: IZcap): string | undefined {
  return (zcap as { expires?: string } | undefined)?.expires
}

/**
 * The WAS collection id a grant zcap targets, when its `invocationTarget`
 * addresses a Collection of the given Space, classified by was-client's path
 * grammar. Returns undefined for anything else -- a resource or reserved
 * sub-endpoint, another Space, or a foreign URL.
 *
 * @param options {object}
 * @param options.invocationTarget {string}
 * @param options.serverUrl {string}   the storage server's base URL
 * @param options.spaceId {string}
 * @returns {string | undefined}
 */
export function collectionIdFromTarget({
  invocationTarget,
  serverUrl,
  spaceId
}: {
  invocationTarget: string
  serverUrl: string
  spaceId: string
}): string | undefined {
  const parsed = parseSpaceTarget({ serverUrl, target: invocationTarget })
  if (parsed?.kind !== 'collection' || parsed.spaceId !== spaceId) {
    return undefined
  }
  return parsed.collectionId
}

/**
 * The key-agreement recipient id a grantee's did:key derives, the id a
 * collection's key epoch lists it under, derived the way provisioning
 * derives it. Undefined for a controller the derivation cannot handle: such
 * a controller was never escrowed anywhere, so there is nothing to rotate
 * and no epoch can be read as excluding it.
 *
 * @param controller {string}   the grantee did:key
 * @returns {string | undefined}
 */
export function granteeRecipientId(controller: string): string | undefined {
  try {
    return x25519RecipientFromDidKey({ did: controller }).id
  } catch {
    return undefined
  }
}
