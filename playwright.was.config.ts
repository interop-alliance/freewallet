import { defineConfig, devices } from '@playwright/test'

const APP_PORT = 5274
const WAS_PORT = 3002
const APP_URL = `http://localhost:${APP_PORT}`
const WAS_URL = `http://localhost:${WAS_PORT}`
// Sibling checkout; override for non-standard layouts.
const WAS_SERVER_DIR = process.env.WAS_SERVER_DIR ?? '../was-teaching-server'

export default defineConfig({
  testDir: './tests/e2e-was',
  fullyParallel: false,
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
      // SERVER_URL must exactly match the URL the client signs ZCap requests
      // against (VITE_WAS_SERVER_URL below); the server derives the expected
      // invocation-target host from it.
      env: { PORT: String(WAS_PORT), SERVER_URL: WAS_URL },
      timeout: 60_000
    },
    {
      // App in remote (WAS) mode, pointed at the local teaching server.
      // `--host` also answers on 127.0.0.1, the cross-site top level the
      // saved-login popup spec embeds the wallet from.
      command: `pnpm exec vite --cors --host --port ${APP_PORT} --strictPort`,
      url: APP_URL,
      reuseExistingServer: false,
      env: { VITE_WAS_SERVER_URL: WAS_URL }
    }
  ]
})
