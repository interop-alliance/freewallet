import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { execSync } from 'node:child_process'
import { interopLoggerPlugin } from '@interop/logger/vite'

const appVersion = execSync('git describe --tags --always --dirty').toString().trim()

// https://vite.dev/config/
export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('node_modules')) {
            // Keep react, react-dom, scheduler and the router together — they
            // share internals and must not be split across chunks.
            if (
              /[\\/]node_modules[\\/](react|react-dom|react-router|scheduler)[\\/]/.test(
                id
              )
            ) {
              return 'react-vendor'
            }
            if (id.includes('@mui') || id.includes('@emotion')) {
              return 'mui-vendor'
            }
          }
        }
      }
    }
  },
  optimizeDeps: {
    // Pre-bundle the password-strength engine's (large) zxcvbn dictionaries at
    // dev-server start instead of on first demand. They are loaded lazily by
    // PasswordStrengthMeter, so without this the dev server bundles them
    // on-the-fly the first time the signup page needs a score -- a cold-start
    // stall that can run to tens of seconds under load (and flakes the
    // signup-driven e2e tests). Dev-only: production still lazy-loads them.
    include: [
      '@zxcvbn-ts/core',
      '@zxcvbn-ts/language-common',
      '@zxcvbn-ts/language-en',
      '@zxcvbn-ts/language-es-es'
    ]
  },
  plugins: [
    react(),
    // Dev-server NDJSON log endpoint (POST /__interop-logger ->
    // .dev-logs/app.ndjson, rotated on start). The e2e configs start their
    // own vite servers in this cwd and point INTEROP_LOGGER_FILE at a
    // scratch path so they never reset a live dev session's file.
    interopLoggerPlugin({ file: process.env.INTEROP_LOGGER_FILE })
  ],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src')
    }
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'tests/unit/**/*.test.ts']
  },
  server: {
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      ...(process.env.VITE_ALLOWED_HOST ? [process.env.VITE_ALLOWED_HOST] : [])
    ]
  }
})
