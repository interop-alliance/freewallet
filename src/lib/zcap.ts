/**
 * Small readers over a zcap's optional caveats, so the app's many call sites
 * share one shape assertion instead of restating it.
 */
import type { IZcap } from '@interop/data-integrity-core'

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
