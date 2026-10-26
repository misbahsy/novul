import { isTauri, saveImage } from "./backend";
import { PRIORITIES, bandTotals, centerOf, emphasize, type Headline, type Model } from "./model";
import { BW, C, R, R0, dotsOf, spokesPath, ticksPath } from "./radar";

const W = 1200, H = 630;
const FONT = `-apple-system, "SF Pro Text", system-ui, "Helvetica Neue", Arial, sans-serif`;
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const css = (v: string) => getComputedStyle(document.documentElement).getPropertyValue(v.replace(/^var\(|\)$/g, "")).trim() || "#ffffff";

/** The card as an SVG string. Dots and bands only: no project names, paths or package names. */
export function cardSvg(m: Model, hl: Headline, date: string): string {
  const ink = css("--ink"), text = css("--text"), muted = css("--muted"), teal = css("--teal"), hair = css("--hair");
  const sev = Object.fromEntries(PRIORITIES.map((p) => [p, css(`--s-${p}`)]));

  // headline text, sized to fit the 500px column
  const chars = Math.max(...hl.title.map((l) => l.reduce((n, p) => n + p.t.length, 0)));
  const tf = Math.min(46, Math.floor(500 / (chars * 0.56)));
  const title = hl.title
    .map((line, i) => `<text x="64" y="${176 + i * tf * 1.2}" font-size="${tf}" font-weight="600" letter-spacing="-0.5" fill="${text}">${line.map((p) => `<tspan${p.c ? ` fill="${css(p.c)}"` : ""}>${esc(p.t)}</tspan>`).join("")}</text>`)
    .join("");
  // wrap the subline between its parts, never inside one
  const subLines: string[][] = [];
  for (const part of hl.sub) {
    const last = subLines[subLines.length - 1];
    if (last && last.join(" · ").length + part.length + 3 <= 52) last.push(part);
    else subLines.push([part]);
  }
  const rich = (part: string) => emphasize(part).map((p) => (p.c ? `<tspan font-weight="600" fill="${css(p.c)}">${esc(p.t)}</tspan>` : esc(p.t))).join("");
  const sy = 176 + (hl.title.length - 1) * tf * 1.2 + 46;
  const sub = subLines
    .map((l, i) => `<text x="64" y="${sy + i * 29}" font-size="${Math.min(19, Math.floor(520 / (l.join(" · ").length * 0.53)))}" fill="${muted}">${l.map(rich).join(" · ")}</text>`)
    .join("");

  const mal = m.counts[0];
  const bandColor = [mal ? sev.malicious : sev.exploited, sev.critical, sev.high, sev.low];
  const names = ["Act now", "Critical", "High", "Later"];
  const bands = bandTotals(m.counts)
    .map((n, b) => `<g transform="translate(${64 + b * 128} 468)">
      <rect width="108" height="3" rx="1.5" fill="${bandColor[b]}" opacity="${n ? 1 : 0.3}"/>
      <text y="38" font-size="30" font-weight="600" fill="${n ? text : muted}">${n.toLocaleString("en-US")}</text>
      <text y="60" font-size="13" letter-spacing="1.4" fill="${muted}">${names[b].toUpperCase()}</text></g>`)
    .join("");

  // radar
  const sectors = m.sectors;
  const dots = dotsOf(sectors);
  const grads = PRIORITIES.map(
    (p) => `<radialGradient id="g-${p}"><stop offset="0" stop-color="${sev[p]}"/><stop offset=".36" stop-color="${sev[p]}"/><stop offset=".4" stop-color="${sev[p]}" stop-opacity=".5"/><stop offset=".7" stop-color="${sev[p]}" stop-opacity=".12"/><stop offset="1" stop-color="${sev[p]}" stop-opacity="0"/></radialGradient>`,
  ).join("");
  const rings = [1, 2, 3].map((k) => `<circle cx="${C}" cy="${C}" r="${R0 + BW * k}" fill="none" stroke="${hair}"/>`).join("");
  const edge = `stroke="${teal}" stroke-opacity=".32"`;
  const center = centerOf(m.counts, m.total);
  const centre = center
    ? `<text x="${C}" y="${C + 6}" text-anchor="middle" font-size="${center.big.length > 4 ? 36 : 46}" font-weight="600" fill="${css(center.color)}">${center.big}</text>
       <text x="${C}" y="${C + 28}" text-anchor="middle" font-size="13" letter-spacing="1.3" fill="${muted}">${center.label.toUpperCase()}</text>`
    : `<path d="M${C - 14} ${C - 12}l9 9l19 -19" fill="none" stroke="${teal}" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
       <text x="${C}" y="${C + 24}" text-anchor="middle" font-size="19" font-weight="600" fill="${teal}">All clear</text>`;
  const k = 1.12;
  const radar = `<g transform="translate(${900 - C * k} ${315 - C * k}) scale(${k})">
    <circle cx="${C}" cy="${C}" r="${R}" fill="${teal}" fill-opacity=".05"/>
    ${rings}
    <circle cx="${C}" cy="${C}" r="${R}" fill="none" ${edge}/><circle cx="${C}" cy="${C}" r="${R0}" fill="none" ${edge}/>
    <path d="${ticksPath()}" fill="none" ${edge}/>
    <path d="${spokesPath(sectors.length)}" fill="none" stroke="${hair}" opacity=".7"/>
    ${dots.map((d) => `<circle cx="${d.x.toFixed(1)}" cy="${d.y.toFixed(1)}" r="${(d.r / 0.38).toFixed(1)}" fill="url(#g-${d.p})"/>`).join("")}
    ${centre}</g>`;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family='${FONT}'>
  <defs>
    <radialGradient id="vig" cx=".26" cy=".48" r=".9"><stop offset="0" stop-color="#131a2e"/><stop offset=".55" stop-color="${ink}"/><stop offset="1" stop-color="#0a0d18"/></radialGradient>
    ${grads}
  </defs>
  <rect width="${W}" height="${H}" fill="url(#vig)"/>
  <g transform="translate(64 62)" fill="none" stroke="${teal}" stroke-width="1.6" stroke-linecap="round">
    <circle cx="12" cy="12" r="9.5" opacity=".55"/><circle cx="12" cy="12" r="5.2" opacity=".55"/><path d="M12 12 19 6.2"/><circle cx="12" cy="12" r="1.4" fill="${teal}" stroke="none"/></g>
  <text x="96" y="80" font-size="16" font-weight="600" letter-spacing=".3" fill="${muted}">NoVul</text>
  ${title}${sub}${bands}
  <text x="64" y="${H - 40}" font-size="15" fill="${muted}">Scanned locally with NoVul · ${esc(date)}</text>
  ${radar}
</svg>`;
}

const toBase64 = (s: string) => {
  let bin = "";
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
};

/** SVG -> 2x canvas -> PNG. */
export async function renderPng(svg: string): Promise<{ dataUrl: string; blob: Blob }> {
  const img = new Image();
  img.src = `data:image/svg+xml;base64,${toBase64(svg)}`;
  await img.decode();
  const canvas = document.createElement("canvas");
  canvas.width = W * 2;
  canvas.height = H * 2;
  canvas.getContext("2d")!.drawImage(img, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise<Blob>((res, rej) => canvas.toBlob((b) => (b ? res(b) : rej(new Error("no image"))), "image/png"));
  return { dataUrl: canvas.toDataURL("image/png"), blob };
}

/** Saves the card to the Desktop (and the clipboard when allowed). In a plain browser, opens it in a new tab. */
export async function shareCard(svg: string): Promise<{ file: string | null; copied: boolean }> {
  const tab = isTauri ? null : window.open("", "_blank");
  const png = renderPng(svg);
  if (!isTauri) {
    const { dataUrl } = await png;
    tab?.document.write(`<title>NoVul snapshot</title><body style="margin:0;background:#05070d"><img src="${dataUrl}" style="max-width:100%;display:block;margin:auto">`);
    return { file: null, copied: false };
  }
  // Start the clipboard write inside the click so WebKit still counts it as a user gesture.
  let copied: Promise<boolean> = Promise.resolve(false);
  try {
    copied = navigator.clipboard.write([new ClipboardItem({ "image/png": png.then((p) => p.blob) })]).then(() => true, () => false);
  } catch {}
  const path = await saveImage((await png).dataUrl);
  return { file: path.split("/").pop() || path, copied: await copied };
}
