import { defineConfig } from 'vite'

// Fixed port and no auto-open: the Tauri CLI waits on `beforeDevCommand` and
// then points the WebView at `devUrl`, so the two must agree and Vite must not
// wander to 5174 when something else holds 5173.
export default defineConfig({
  clearScreen: false,
  server: { port: 5173, strictPort: true },
})
