/**
 * The one registration of the service-discovery module mock, run for every
 * test file through vitest's `test.setupFiles`. Only the discovery exports
 * are replaced; the module's `PwsClient` factory stays real, so a test that
 * mocks `@interop/pws-client` still sees its own `PwsClient` built.
 * `vi.mock` is hoisted within this file and the registration lands in the
 * module registry before the test file's own imports resolve, so no test
 * file repeats the preamble. A test that wants the real module opts out with
 * `vi.unmock('@/lib/wasService')` at its own top level.
 */
import { vi } from 'vitest'

vi.mock('@/lib/wasService', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/wasService')>()),
  ...(await import('./wasServiceFixture')).wasServiceModuleMock()
}))
