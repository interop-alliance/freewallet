import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'
import { execSync } from 'child_process'

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
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
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
