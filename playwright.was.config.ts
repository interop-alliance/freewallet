import { defineConfig, devices } from '@playwright/test'
import { WAS_E2E_DATA_DIR } from './tests/e2e-was/wasDataDir'

const APP_PORT = 5274
const WAS_PORT = 3002
const APP_URL = `http://localhost:${APP_PORT}`
const WAS_URL = `http://localhost:${WAS_PORT}`
// The dev-log file the app's dev server writes, kept off the live dev
// session's file. Set on this process too, so the test workers (which
// inherit it) read the file the ceremony-event fixture scopes.
const DEV_LOG_FILE = 'test-results/dev-logs/app.ndjson'
process.env.INTEROP_LOGGER_FILE = DEV_LOG_FILE
// Sibling checkout; override for non-standard layouts.
const WAS_SERVER_DIR = process.env.WAS_SERVER_DIR ?? '../was-teaching-server'

export default defineConfig({
  testDir: './tests/e2e-was',
  // Empties WAS_E2E_DATA_DIR before the teaching server starts, so the run
  // begins against an empty store.
  globalSetup: './tests/e2e-was/wasDataDir.ts',
  fullyParallel: false,
  // One shared teaching server (dev mode, single process) serves every test,
  // and it fully re-verifies the did:webvh log per zcap request -- parallel
  // workers contend on its CPU and push the ceremony-heavy signups past
  // their timeouts. One worker keeps the suite deterministic.
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'html',
  use: {
    baseURL: APP_URL,
    trace: 'on-first-retry'
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ],
  webServer: [
    {
      // Local WAS teaching server (FileSystem backend).
      command: 'pnpm run dev',
      cwd: WAS_SERVER_DIR,
      url: WAS_URL,
      reuseExistingServer: !process.env.CI,
      // SERVER_URL is the server's own base URL; the server derives the
      // expected invocation-target host from it, and the app's
      // VITE_WAS_SERVER_URL below is the Spaces Repository URL under it.
      // WAS_DATA_DIR keeps the run's Spaces out of the server checkout's own
      // data/ directory, which would otherwise accumulate every past run's.
      // It only applies to a server this config starts: `reuseExistingServer`
      // hands an already-running dev server (and its own store) to the run
      // instead.
      env: {
        PORT: String(WAS_PORT),
        SERVER_URL: WAS_URL,
        WAS_DATA_DIR: WAS_E2E_DATA_DIR
      },
      timeout: 60_000
    },
    {
      // App in remote (WAS) mode, pointed at the local teaching server.
      // `--host` also answers on 127.0.0.1, the cross-site top level the
      // saved-login popup spec embeds the wallet from.
      command: `pnpm exec vite --cors --host --port ${APP_PORT} --strictPort`,
      url: APP_URL,
      reuseExistingServer: false,
      env: {
        VITE_WAS_SERVER_URL: `${WAS_URL}/spaces/`,
        INTEROP_LOGGER_FILE: DEV_LOG_FILE
      }
    }
  ]
})
