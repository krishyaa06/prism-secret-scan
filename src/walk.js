"use strict";
/* Gitignore-aware file walker (zero deps) */
const fs = require("node:fs");
const path = require("node:path");
const ALWAYS = [".git", "node_modules", ".next", "dist", "build", ".turbo", ".vercel", "coverage", ".cache", "__pycache__", ".venv", "venv", "target", ".DS_Store"];
function globToRe(g) {
  let re = "", i = 0;
  while (i < g.length) {
    const ch = g[i];
    if (ch === "*") { if (g[i + 1] === "*") { re += g[i + 2] === "/" ? "(?:.*/)?" : ".*"; i += g[i + 2] === "/" ? 3 : 2; continue; } re += "[^/]*"; }
    else if (ch === "?") re += "[^/]";
    else if ("\\^$+.()|{}[]".includes(ch)) re += "\\" + ch;
    else re += ch;
    i++;
  }
  return re;
}
function parseIgnore(text) {
  return String(text).split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => {
    const neg = l.startsWith("!"); if (neg) l = l.slice(1);
    const dirOnly = l.endsWith("/"); if (dirOnly) l = l.slice(0, -1);
    const anchored = l.includes("/"); if (l.startsWith("/")) l = l.slice(1);
    const re = new RegExp(`${anchored ? "^" : "(?:^|/)"}${globToRe(l)}(?:/|$)`);
    return { neg, dirOnly, re };
  });
}
function ignored(rel, isDir, rules) {
  let ig = false;
  for (const r of rules) { if (r.dirOnly && !isDir) continue; if (r.re.test(rel)) ig = !r.neg; }
  return ig;
}
function walk(root, { extraIgnore = [], useGitignore = true, maxFiles = 50000 } = {}) {
  root = path.resolve(root);
  let rules = parseIgnore([...ALWAYS, ...extraIgnore].join("\n"));
  if (useGitignore) { try { rules = rules.concat(parseIgnore(fs.readFileSync(path.join(root, ".gitignore"), "utf8"))); } catch {} }
  const out = [];
  (function rec(dir) {
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    ents.sort((a, b) => a.name.localeCompare(b.name));
    for (const e of ents) {
      if (out.length >= maxFiles) return;
      const abs = path.join(dir, e.name), rel = path.relative(root, abs).split(path.sep).join("/");
      if (e.isSymbolicLink()) continue;
      const isDir = e.isDirectory();
      if (ignored(rel, isDir, rules)) continue;
      if (isDir) rec(abs); else if (e.isFile()) out.push(rel);
    }
  })(root);
  return out;
}
function isBinary(buf) { const n = Math.min(buf.length, 8000); for (let i = 0; i < n; i++) if (buf[i] === 0) return true; return false; }
module.exports = { walk, parseIgnore, ignored, globToRe, isBinary, ALWAYS };
