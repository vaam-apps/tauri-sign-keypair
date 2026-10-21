// The vaam-apps house theme: Material 3, configured in ../config.ts, plus a
// <Mermaid> component for the explainer series' diagrams.
import Md3Theme from "@vaam-apps/vitepress-md3";
import type { Theme } from "vitepress";
import Mermaid from "./Mermaid.vue";

export default {
  extends: Md3Theme,
  enhanceApp({ app }) {
    app.component("Mermaid", Mermaid);
  },
} satisfies Theme;
