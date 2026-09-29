import { defineConfig, devices } from '@playwright/test'

const APP_PORT = 5273
const BASE_URL = `http://localhost:${APP_PORT}`
// The dev-log file the app's dev server writes, kept off the live dev
// session's file. Set on this process too, so the test workers (which
// inherit it) read the file the ceremony-event fixture scopes.
const DEV_LOG_FILE = 'test-results/dev-logs/app.ndjson'
process.env.INTEROP_LOGGER_FILE = DEV_LOG_FILE

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // Retry once locally too (CI retries twice): the multi-step auth flows have
  // rare dev-server/StrictMode remount timing races that a retry absorbs.
  retries: process.env.CI ? 2 : 1,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry'
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ],
  webServer: {
    // Start a fresh server on a dedicated port (never reuse / collide with a
    // dev server the user may have running on :5173).
    command: `pnpm exec vite --cors --port ${APP_PORT} --strictPort`,
    url: BASE_URL,
    reuseExistingServer: false,
    env: {
      // Pin local (IndexedDB) mode; override any VITE_WAS_SERVER_URL leaked
      // from the surrounding shell or a separately-running dev server.
      VITE_WAS_SERVER_URL: '',
      INTEROP_LOGGER_FILE: DEV_LOG_FILE
    }
  }
})
