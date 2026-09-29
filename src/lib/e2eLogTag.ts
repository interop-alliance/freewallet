/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * The e2e page-tag contract shared by the app's logging seam and the
 * Playwright ceremony-event fixture. A test's init script sets the global on
 * the page, and the app logs one marker event naming the tag, so the fixture
 * can pick that page's lines out of the shared dev log. Side-effect free, so
 * tests can import it without running the logging wiring.
 */

/**
 * The global a Playwright init script sets to tag a page for the e2e
 * ceremony-event fixture.
 */
export const E2E_LOG_TAG_GLOBAL = '__E2E_LOG_TAG__'

/**
 * The message of the marker event the app logs on a tagged page, with the
 * tag in `data.tag`.
 */
export const E2E_LOG_TAG_MSG = 'e2e page tag'
