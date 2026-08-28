/**
 * The non-production remember-this-browser seam the auth pages read at
 * submit time: forces the remembered route (the programmatic
 * remember-this-browser entry) when a test sets the window flag. Read at
 * submit rather than render, so a spec can set it with `page.evaluate` after
 * the page is up. The cold-browser self-enrollment specs and the remembered
 * signup fixtures use it until the forms grow the remember-this-browser
 * choice. Always `false` in production builds.
 */

/**
 * Whether a test has forced the remembered (remember-this-browser) route.
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

/**
 * Whether a test has asked the remembered signup to tear itself between the
 * credential-anchored establishment and the remembered-login half. The
 * torn-signup e2e sets the window flag to prove both later entries work: a
 * transient login (the standing record is complete) and a remembered login
 * (the resume, which self-enrolls from the record). Read from
 * `signUpWithPassphrase` (which unit tests run in a node environment, hence
 * the `window` guard). Always `false` in production builds.
 *
 * @returns {boolean}
 */
export function forcedSignupTearAfterEstablishment(): boolean {
  if (import.meta.env.MODE === 'production') {
    return false
  }
  if (typeof window === 'undefined') {
    return false
  }
  return Boolean(
    (window as unknown as { __E2E_TEAR_SIGNUP_AFTER_ESTABLISHMENT__?: boolean })
      .__E2E_TEAR_SIGNUP_AFTER_ESTABLISHMENT__
  )
}

/**
 * Whether a test has asked the credential-anchored establishment to tear
 * itself between the record re-bind (and the registry write) and the
 * controller promotion -- the one-request window whose torn state a later
 * login mends through the shared mend ceremony's promotion arm. Read from
 * the signup's `beforePromotion` hook (unit tests run it in a node
 * environment, hence the `window` guard). Always `false` in production
 * builds.
 *
 * @returns {boolean}
 */
export function forcedEstablishmentTearBeforePromotion(): boolean {
  if (import.meta.env.MODE === 'production') {
    return false
  }
  if (typeof window === 'undefined') {
    return false
  }
  return Boolean(
    (
      window as unknown as {
        __E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__?: boolean
      }
    ).__E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__
  )
}

/**
 * Whether a test has forced the connect-this-browser card open. In
 * production the card opens only for the remembered path's own two-client
 * states (a torn enrollment's roster-unwrap failure, or a no-WAS plain
 * pointer record), and a healthy WAS account's default login simply
 * succeeds -- so the two-party enrollment e2e, which needs the enrollee's
 * card from a cold browser, opens it through this flag: the login submit
 * becomes the planned connect-this-browser entry (the card with the typed
 * passphrase, no login attempted) until the form grows its own. Always
 * `false` in production builds.
 *
 * @returns {boolean}
 */
export function forcedConnectOffer(): boolean {
  if (import.meta.env.MODE === 'production') {
    return false
  }
  return Boolean(
    (window as unknown as { __E2E_OFFER_CONNECT_CARD__?: boolean })
      .__E2E_OFFER_CONNECT_CARD__
  )
}
