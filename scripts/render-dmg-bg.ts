import { Resvg } from "@resvg/resvg-js";
import { readFileSync, writeFileSync } from "node:fs";

const dir = new URL("../design/dmg/", import.meta.url).pathname;
const svg = readFileSync(dir + "background.svg", "utf8");
const fonts = ["/System/Library/Fonts/Avenir Next.ttc"];

for (const [scale, name] of [[1, "bg.png"], [2, "bg@2x.png"]] as const) {
  const png = new Resvg(svg, {
    fitTo: { mode: "zoom", value: scale },
    font: { fontFiles: fonts, loadSystemFonts: false, defaultFontFamily: "Avenir Next" },
  }).render().asPng();
  writeFileSync(dir + name, png);
}
