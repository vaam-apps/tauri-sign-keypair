import { dirname, posix } from "node:path";
import { defineMd3Config } from "@vaam-apps/vitepress-md3/config";

// Served from GitHub Pages at /tauri-sign-keypair/. The docs workflow passes
// the path Pages reports in DOCS_BASE, and an empty string on PR builds —
// hence `||`, so an empty value still falls back to the project path.
const base = process.env.DOCS_BASE || "/tauri-sign-keypair/";
const repo = "https://github.com/vaam-apps/tauri-sign-keypair";
const branch = "main";

export default defineMd3Config({
  base,
  lang: "en",
  title: "tauri-plugin-sign-keypair",
  titleTemplate: ":title · sign-keypair",
  description:
    "Hardware-backed ECDSA P-256 (ES256) signing for device-bound authentication in Tauri v2 apps.",
  cleanUrls: true,
  lastUpdated: true,
  // A link to a page that does not exist fails the build.
  ignoreDeadLinks: false,
  head: [["link", { rel: "icon", type: "image/svg+xml", href: `${base}logo.svg` }]],

  markdown: {
    config(md) {
      // The explainer series draws its diagrams in Mermaid. Hand each
      // ```mermaid fence to the <Mermaid> component (theme/Mermaid.vue),
      // which renders it in the browser in the site's own colours.
      const fence = md.renderer.rules.fence;
      md.renderer.rules.fence = (tokens, idx, options, env, self) => {
        const token = tokens[idx];
        if (token?.info.trim() === "mermaid") {
          return `<Mermaid code="${encodeURIComponent(token.content)}" />`;
        }
        return fence ? fence(tokens, idx, options, env, self) : self.renderToken(tokens, idx, options);
      };

      // The pages are also read on GitHub, where a link such as
      // `../MIGRATION.md` is right. On the site anything outside docs/ is a
      // dead link, so rewrite those at build time instead of in the files:
      // MIGRATION.md has its own page here, everything else goes to GitHub.
      md.core.ruler.push("links-outside-docs", (state) => {
        const from = dirname((state.env as { relativePath?: string }).relativePath ?? "index.md");
        for (const block of state.tokens) {
          for (const token of block.children ?? []) {
            if (token.type !== "link_open") continue;
            const href = token.attrGet("href");
            if (!href || /^[a-z][a-z0-9+.-]*:|^[#/]/i.test(href)) continue;
            const [path = "", hash = ""] = href.split(/(?=#)/);
            const target = posix.normalize(posix.join(from, path));
            if (!target.startsWith("../")) continue;
            const inRepo = target.slice(3);
            token.attrSet(
              "href",
              inRepo === "MIGRATION.md"
                ? `${posix.relative(from, "migration.md") || "migration.md"}${hash}`
                : `${repo}/blob/${branch}/${inRepo}${hash}`,
            );
          }
        }
      });
    },
  },

  themeConfig: {
    md3: {
      style: "expressive",
      seed: "#b45309",
    },

    logo: "/logo.svg",
    siteTitle: "sign-keypair",

    nav: [
      { text: "Get started", link: "/getting-started" },
      { text: "Explainer", link: "/README", activeMatch: "^/(README|0\\d-)" },
      { text: "Migration", link: "/migration" },
      {
        text: "More",
        items: [
          { text: "Changelog", link: `${repo}/blob/${branch}/CHANGELOG.md` },
          { text: "flutter-sign-keypair", link: "https://github.com/vaam-apps/flutter-sign-keypair" },
          { text: "All vaam-apps docs", link: "https://vaam-apps.github.io/vitepress-md3/projects/" },
        ],
      },
    ],

    sidebar: [
      {
        text: "Using the plugin",
        items: [
          { text: "Introduction", link: "/" },
          { text: "Getting started", link: "/getting-started" },
          { text: "Migrating existing devices", link: "/migration" },
        ],
      },
      {
        text: "Understanding it, in order",
        items: [
          { text: "Overview & vocabulary", link: "/README" },
          { text: "1 · The problem", link: "/01-the-problem" },
          { text: "2 · How it works", link: "/02-how-it-works" },
          { text: "3 · Platforms", link: "/03-platforms" },
          { text: "4 · The two-key model", link: "/04-two-key-model" },
          { text: "5 · How we know it works", link: "/05-verification" },
          { text: "6 · Build log", link: "/06-build-log" },
          { text: "7 · Linux TPM", link: "/07-linux-tpm" },
          { text: "8 · Attestation", link: "/08-attestation" },
        ],
      },
      {
        text: "Related",
        items: [
          { text: "flutter-sign-keypair", link: "https://github.com/vaam-apps/flutter-sign-keypair" },
          { text: "Changelog", link: `${repo}/blob/${branch}/CHANGELOG.md` },
        ],
      },
    ],

    outline: { level: [2, 3] },
    search: { provider: "local" },
    socialLinks: [{ icon: "github", link: repo }],
    editLink: {
      pattern: `${repo}/edit/${branch}/docs/:path`,
      text: "Edit this page on GitHub",
    },
    footer: {
      message: "Released under the MIT License.",
    },
  },
});
