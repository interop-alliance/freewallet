import { defineConfig } from 'vitest/config'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const dirname = path.dirname(fileURLToPath(import.meta.url))

/**
 * The cross-replica sync conformance exercise (`tests/conformance/`): both
 * wallets' replication engines driven against a real in-process
 * `was-teaching-server`. Kept out of the default `test:unit` include -- it
 * needs the sibling `../was-teaching-server` checkout built (`WAS_SERVER_DIR`
 * overrides the location). Run via `pnpm run test:conformance`.
 */
export default defineConfig({
  resolve: {
    alias: { '@': path.resolve(dirname, 'src') }
  },
  test: {
    environment: 'node',
    include: ['tests/conformance/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000
  }
})
