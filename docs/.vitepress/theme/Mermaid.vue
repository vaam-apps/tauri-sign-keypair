<script setup lang="ts">
// Renders one ```mermaid fence (see the fence rule in ../config.ts) in the
// browser, coloured from the page's Material 3 tokens so a diagram follows the
// seed colour and the light/dark switch like everything else on the page.
import { useData } from "vitepress";
import { nextTick, onMounted, ref, watch } from "vue";

const props = defineProps<{ code: string }>();
const { isDark } = useData();

const svg = ref("");
const failed = ref(false);
const host = ref<HTMLElement>();
const source = decodeURIComponent(props.code);
const id = `mermaid-${Math.random().toString(36).slice(2, 10)}`;
let renders = 0;

function token(style: CSSStyleDeclaration, name: string) {
  return style.getPropertyValue(`--md-sys-color-${name}`).trim();
}

function themeVariables() {
  const s = getComputedStyle(document.documentElement);
  const t = (name: string) => token(s, name);
  return {
    darkMode: isDark.value,
    fontFamily: getComputedStyle(document.body).fontFamily,
    background: t("surface"),
    textColor: t("on-surface"),
    lineColor: t("on-surface-variant"),
    primaryColor: t("secondary-container"),
    primaryTextColor: t("on-secondary-container"),
    primaryBorderColor: t("outline"),
    secondaryColor: t("tertiary-container"),
    tertiaryColor: t("surface-container-high"),
    clusterBkg: t("surface-container-low"),
    clusterBorder: t("outline-variant"),
    edgeLabelBackground: t("surface-container"),
    titleColor: t("on-surface"),
    actorBkg: t("secondary-container"),
    actorBorder: t("outline"),
    actorTextColor: t("on-secondary-container"),
    actorLineColor: t("outline"),
    signalColor: t("on-surface"),
    signalTextColor: t("on-surface"),
    labelBoxBkgColor: t("surface-container-high"),
    labelBoxBorderColor: t("outline"),
    labelTextColor: t("on-surface"),
    loopTextColor: t("on-surface"),
    noteBkgColor: t("tertiary-container"),
    noteTextColor: t("on-tertiary-container"),
    noteBorderColor: t("outline-variant"),
    activationBkgColor: t("surface-container-highest"),
    activationBorderColor: t("outline"),
  };
}

// The diagrams pin some nodes to fixed pastel fills (`style X fill:#e8f5e9`).
// Those stay pastel in dark mode, so give their labels dark text whenever the
// fill is light, and light text when it is dark.
function fixPinnedFills(root: HTMLElement) {
  for (const group of root.querySelectorAll<SVGGElement>("g.node, g.cluster")) {
    const styled = group.querySelector("[style*='fill:#']");
    const hex = styled?.getAttribute("style")?.match(/fill:\s*#([0-9a-f]{6}|[0-9a-f]{3})\b/i)?.[1];
    if (!hex) continue;
    const full = hex.length === 3 ? [...hex].map((c) => c + c).join("") : hex;
    const [r, g, b] = [0, 2, 4].map((i) => Number.parseInt(full.slice(i, i + 2), 16) / 255);
    const light = 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.5;
    const ink = light ? "#1f1b16" : "#f8efe7";
    for (const label of group.querySelectorAll<HTMLElement | SVGElement>("span, p, div, text, tspan")) {
      label.style.color = ink;
      label.style.fill = ink;
    }
  }
}

async function render() {
  try {
    const { default: mermaid } = await import("mermaid");
    // Mermaid sizes each box by measuring its label, so measure in the font
    // the label will finally be drawn in.
    await document.fonts.ready;
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      themeVariables: themeVariables(),
      // Several subgraph titles here run to two lines, which Mermaid does not
      // make room for; leave space under every title instead.
      flowchart: { subGraphTitleMargin: { top: 4, bottom: 24 } },
    });
    const result = await mermaid.render(`${id}-${renders++}`, source);
    svg.value = result.svg;
    failed.value = false;
    await nextTick();
    if (host.value) fixPinnedFills(host.value);
  } catch {
    failed.value = true;
  }
}

onMounted(render);
// The tokens change with the theme; wait a frame so the new ones are applied.
watch(isDark, () => requestAnimationFrame(() => void render()));
</script>

<template>
  <pre v-if="failed" class="mermaid-fallback"><code>{{ source }}</code></pre>
  <div v-else ref="host" class="mermaid-diagram" role="img" :aria-label="'Diagram'" v-html="svg" />
</template>

<style scoped>
.mermaid-diagram {
  display: flex;
  justify-content: center;
  margin: 16px 0;
  padding: 16px;
  min-height: 48px;
  overflow-x: auto;
  border-radius: 16px;
  background: var(--md-sys-color-surface-container-low);
}

.mermaid-diagram :deep(svg) {
  height: auto;
}

/* Mermaid measures labels outside the page, at the body's line height; the
   doc's own paragraph rules would make them taller than their boxes. */
.mermaid-diagram :deep(foreignObject p) {
  margin: 0;
  line-height: 1.5;
}

.mermaid-fallback {
  overflow-x: auto;
}
</style>
