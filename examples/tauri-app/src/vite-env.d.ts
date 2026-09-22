/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Set to `1` at build time to run the whole sequence on load.
   *
   * A bundled build has no URL to hang `?autorun` off, and some platforms — an
   * iOS simulator, for one — offer no way to inject a tap, so this is the only
   * way to exercise the plugin there unattended.
   */
  readonly VITE_AUTORUN?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
