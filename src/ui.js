"use strict";
/* Prism CLI kit — tiny zero-dependency terminal helpers */
const tty = process.stdout.isTTY;
const useColor = process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== "0" : !process.env.NO_COLOR && tty;
const wrap = (o, c) => (s) => (useColor ? `\x1b[${o}m${s}\x1b[${c}m` : String(s));
const c = {
  bold: wrap(1, 22), dim: wrap(2, 22), italic: wrap(3, 23), under: wrap(4, 24),
  red: wrap(31, 39), green: wrap(32, 39), yellow: wrap(33, 39), blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39), gray: wrap(90, 39),
  accent: (s) => (useColor ? `\x1b[38;2;0;210;255m${s}\x1b[39m` : String(s)),
  accent2: (s) => (useColor ? `\x1b[38;2;108;99;255m${s}\x1b[39m` : String(s)),
};
const strip = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, "");
const width = (s) => [...strip(s)].length;
const pad = (s, n, right = false) => { const w = width(s); return w >= n ? s : right ? " ".repeat(n - w) + s : s + " ".repeat(n - w); };
function table(rows, { head, align = [] } = {}) {
  const all = head ? [head, ...rows] : rows;
  const cols = Math.max(...all.map((r) => r.length));
  const ws = Array.from({ length: cols }, (_, i) => Math.max(...all.map((r) => width(r[i] ?? ""))));
  const line = (r) => r.map((v, i) => pad(String(v ?? ""), ws[i], align[i] === "right")).join("  ");
  const out = [];
  if (head) { out.push(c.bold(line(head))); out.push(c.dim(ws.map((w) => "─".repeat(w)).join("  "))); }
  rows.forEach((r) => out.push(line(r)));
  return out.join("\n");
}
const header = (name, sub = "") => `${c.accent("◆")} ${c.bold(name)}${sub ? " " + c.dim(sub) : ""}`;
const bar = (frac, n = 20) => { const f = Math.round(Math.max(0, Math.min(1, frac)) * n); return c.accent("█".repeat(f)) + c.dim("░".repeat(n - f)); };
const bytes = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(2)} MB`);
const plural = (n, w, pl) => `${n} ${n === 1 ? w : pl || w + "s"}`;
module.exports = { c, strip, width, pad, table, header, bar, bytes, plural, useColor };
