import { readFileSync } from 'node:fs'

import typescript from '@rollup/plugin-typescript'

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'))

export default {
  input: 'guest-js/index.ts',
  output: [
    { file: pkg.exports.import, format: 'esm' },
    { file: pkg.exports.require, format: 'cjs' },
  ],
  plugins: [
    typescript({
      tsconfig: './tsconfig.json',
      declaration: true,
      declarationDir: 'dist-js',
      // The tests and their setup are type-checked by `npm run typecheck`, but
      // they must not reach the bundle: `test-setup.ts` imports a fake
      // IndexedDB, and shipping that to a consumer would replace the browser's.
      exclude: ['**/*.test.ts', 'guest-js/test-setup.ts'],
    }),
  ],
  // `@tauri-apps/api` is a peer of the host app, not something to inline: two
  // copies of it in one bundle means two `isTauri()` implementations reading
  // two different module-scope caches.
  external: [/^@tauri-apps\/api/],
}
