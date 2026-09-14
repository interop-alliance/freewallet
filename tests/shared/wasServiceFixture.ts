/**
 * The service description unit tests hand to the code paths that now take
 * one, and the one place this repo's tests pin the provisional
 * `https://w3id.org/pws` / `0.5` spec-and-version pair. Every `WasClient`
 * the app builds is given the discovered description, so no client makes
 * its own `HEAD` probe and a test that drives such a path has to supply a
 * stand-in. Minimal on purpose -- nothing under test reads past `url` and
 * the WAS version entry.
 */
import type { ServiceDescription } from '@interop/was-client'

export const TEST_SERVICE_DESCRIPTION: ServiceDescription = {
  url: 'http://localhost/service',
  specs: {
    'https://w3id.org/pws': [
      { version: '0.5', spaces: 'http://localhost/spaces/' }
    ]
  }
}

/**
 * The module factory for `vi.mock('@/lib/wasService', ...)`: the memoized
 * discovery resolved to the fixture. Registered once, in
 * `tests/shared/setup.wasService.ts`.
 *
 * @returns {object}   the mocked module's exports
 */
export function wasServiceModuleMock() {
  return {
    wasServiceDescription: async () => TEST_SERVICE_DESCRIPTION,
    wasServiceDescriptionIfReachable: async () => TEST_SERVICE_DESCRIPTION
  }
}
