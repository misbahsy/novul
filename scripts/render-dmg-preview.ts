import { Resvg } from "@resvg/resvg-js";
import { readFileSync, writeFileSync } from "node:fs";

const [, , appsIcon, out] = process.argv;
const root = new URL("../", import.meta.url).pathname;
const b64 = (p: string) => readFileSync(p).toString("base64");
const bg = b64(root + "design/dmg/bg@2x.png");
const app = b64(root + "src-tauri/icons/icon.png");
const folder = b64(appsIcon);
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="700" height="460" viewBox="0 0 700 460" font-family="Avenir Next">
  <rect width="700" height="460" fill="#2a2a2e"/>
  <rect x="10" y="20" width="680" height="430" rx="14" fill="#000" opacity="0.35" filter="blur(6)"/>
  <g transform="translate(20 20)">
    <clipPath id="w"><rect width="660" height="420" rx="12"/></clipPath>
    <g clip-path="url(#w)">
      <image href="data:image/png;base64,${bg}" width="660" height="420"/>
      <image href="data:image/png;base64,${app}" x="${170 - 64 - 6}" y="${130 - 64 - 6}" width="140" height="140"/>
      <image href="data:image/png;base64,${folder}" x="${490 - 64}" y="${130 - 64}" width="128" height="128"/>
      <g font-size="12" fill="#fff" text-anchor="middle"><text x="170" y="214">NoVul</text><text x="490" y="214">Applications</text></g>
    </g>
    <rect width="660" height="420" rx="12" fill="none" stroke="#ffffff" stroke-opacity="0.18"/>
    <circle cx="18" cy="14" r="6" fill="#ff5f57"/><circle cx="38" cy="14" r="6" fill="#febc2e"/><circle cx="58" cy="14" r="6" fill="#28c840"/>
  </g>
</svg>`;
writeFileSync(out, new Resvg(svg, { fitTo: { mode: "zoom", value: 2 }, font: { fontFiles: ["/System/Library/Fonts/Avenir Next.ttc"], loadSystemFonts: false, defaultFontFamily: "Avenir Next" } }).render().asPng());
