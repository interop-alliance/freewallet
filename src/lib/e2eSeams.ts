/**
 * The non-production remember-this-browser seam the auth pages read at
 * submit time: forces the durable route (the programmatic
 * remember-this-browser entry) when a test sets the window flag. Read at
 * submit rather than render, so a spec can set it with `page.evaluate` after
 * the page is up. The cold-browser self-enrollment specs and the durable
 * signup fixtures use it until the forms grow the remember-this-browser
 * choice. Always `false` in production builds.
 */

/**
 * Whether a test has forced the durable (remember-this-browser) route.
 *
 * @returns {boolean}
 */
export function forcedRememberBrowser(): boolean {
  if (import.meta.env.MODE === 'production') {
    return false
  }
  return Boolean(
    (window as unknown as { __E2E_REMEMBER_BROWSER__?: boolean })
      .__E2E_REMEMBER_BROWSER__
  )
}
