import { PRIORITIES, type Sector } from "./model";

// Radar geometry in a 520x520 box, shared by the on-screen radar and the share card.
export const VB = 520, C = 260, R0 = 74, R = 240, BW = (R - R0) / 4, TAU = Math.PI * 2;
export const pt = (r: number, a: number) => `${(C + r * Math.sin(a)).toFixed(1)} ${(C - r * Math.cos(a)).toFixed(1)}`;
export const annular = (r0: number, r1: number, a0: number, a1: number) => {
  const big = a1 - a0 > Math.PI ? 1 : 0;
  return `M${pt(r1, a0)}A${r1} ${r1} 0 ${big} 1 ${pt(r1, a1)}L${pt(r0, a1)}A${r0} ${r0} 0 ${big} 0 ${pt(r0, a0)}Z`;
};
export const spokesPath = (n: number) =>
  Array.from({ length: n }, (_, i) => `M${pt(R0, (i * TAU) / n)}L${pt(R, (i * TAU) / n)}`).join("");
export const ticksPath = () =>
  Array.from({ length: 72 }, (_, i) => `M${pt(R + 2, (i * TAU) / 72)}L${pt(R + (i % 3 ? 5 : 8), (i * TAU) / 72)}`).join("");

export function dotsOf(sectors: Sector[]) {
  const w = TAU / Math.max(1, sectors.length);
  return sectors.flatMap((s, i) =>
    s.cells.flatMap((c, b) => {
      if (!c) return [];
      const rr = R0 + BW * (b + 0.5);
      const a = (i + 0.5) * w;
      return [{ i, b, x: C + rr * Math.sin(a), y: C - rr * Math.cos(a), r: Math.min(10, 4 + 1.5 * Math.sqrt(c.pkgs)), p: PRIORITIES[c.worst], mal: c.worst === 0 }];
    }),
  );
}
