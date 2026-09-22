import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // The WebCrypto backend is the thing under test, and it needs `crypto.subtle`
    // plus IndexedDB. Node 20+ ships the former globally; `fake-indexeddb` in
    // the setup file supplies the latter.
    environment: 'node',
    include: ['guest-js/**/*.test.ts'],
    setupFiles: ['guest-js/test-setup.ts'],
  },
})
