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
