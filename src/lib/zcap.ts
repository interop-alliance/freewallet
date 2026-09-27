/**
 * Small readers over a zcap's optional caveats and its target, so the app's
 * many call sites share one shape assertion instead of restating it.
 */
import type { IZcap } from '@interop/data-integrity-core'
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
