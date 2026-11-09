import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'url'

export default defineConfig({
  test: {
    globals: true, // upstream's suites use mocha-style describe/it
    include: ['test/**/*Suite.ts', 'test/**/*.test.ts'],
    testTimeout: 30000,
    fileParallelism: false // upstream suites share test/temp-data
  },
  resolve: {
    alias: { mocha: fileURLToPath(new URL('./test/mocha-shim.ts', import.meta.url)) }
  }
})
