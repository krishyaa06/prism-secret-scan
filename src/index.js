"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const RULES = require("./rules");
const { walk, isBinary, parseIgnore, ignored } = require("./walk");

function entropy(s) { const f = {}; for (const ch of s) f[ch] = (f[ch] || 0) + 1; let e = 0; for (const k in f) { const p = f[k] / s.length; e -= p * Math.log2(p); } return e; }

// Placeholder markers. These are matched against the SECRET only. Matching the whole
// line used to drop real findings whenever the surrounding code happened to contain a
// word like "example", "sample" or "dummy".
const FAKE = /(x{5,}|\*{4,}|your[_-]?|example|sample|dummy|placeholder|changeme|test(ing)?[_-]?key|fake|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv|import\.meta\.env|0{8,}|1234567890|abcdef(gh)?ij|lorem|redacted|\.\.\.)/i;
const SKIP_FILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|composer\.lock|Cargo\.lock|poetry\.lock|go\.sum)$|\.(min\.js|map|png|jpe?g|gif|webp|ico|pdf|zip|gz|woff2?|ttf|eot|mp4|mp3)$/;
const mask = (s) => s.length <= 8 ? "•".repeat(s.length) : s.slice(0, 4) + "•".repeat(Math.min(16, s.length - 8)) + s.slice(-4);

// A fingerprint identifies a SECRET, not a location: the same key on another line, in
// another file or in another commit must hit the same baseline entry.
const fingerprint = (rule, secret) => crypto.createHash("sha256").update(rule + ":" + secret).digest("hex").slice(0, 16);

const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
const MAX_FILE_BYTES = 2 << 20;
const MAX_LINE = 4000;

/**
 * Scan one blob of text.
 * @returns {Array<object>} findings
 */
function scanText(text, file, { minEntropy = 3.5, stats } = {}) {
  const out = [];
  // Strip ANSI colour codes and a leading BOM: both used to hide a key from every
  // detector because they sit right next to the token.
  const clean = String(text).replace(ANSI, "").replace(/^\uFEFF/, "");
  clean.split("\n").forEach((rawLine, i) => {
    const line = rawLine.replace(/\r$/, "");
    if (line.length > MAX_LINE || /secretscan:ignore|gitleaks:allow|nosec|pragma: allowlist secret/i.test(line)) return;
    const hitHere = new Set();
    for (const [id, name, re, sev] of RULES) {
      // Rules are shared between lines, so a sticky/global flag would leak state.
      re.lastIndex = 0;
      const m = re.exec(line); if (!m) continue;
      const secret = m[1] || m[0];
      if (hitHere.has(secret)) continue;
      if (FAKE.test(secret)) continue;
      if (id === "generic-secret" && (entropy(secret) < minEntropy || /^[a-z_]+$/i.test(secret) || /^(true|false|null|none)$/i.test(secret))) continue;
      // Docs are allowed to show non-critical example keys; real secrets are still caught.
      if (/\.(md|mdx|rst|txt)$/i.test(file) && sev !== "critical") continue;
      hitHere.add(secret);
      out.push({ file, line: i + 1, col: m.index + 1, rule: id, name, severity: sev, secret, masked: mask(secret), fingerprint: fingerprint(id, secret), entropy: +entropy(secret).toFixed(2) });
    }
  });
  if (stats) stats.lines += clean.split("\n").length;
  return out;
}

function loadIgnoreRules(root) {
  const rules = [];
  for (const name of [".secretscanignore", ".gitignore"]) {
    try { rules.push(...parseIgnore(fs.readFileSync(path.join(root, name), "utf8"))); } catch {}
  }
  return rules;
}

function isIgnored(rel, rules) {
  if (!rules.length) return false;
  if (ignored(rel, false, rules)) return true;
  const parts = rel.split("/");
  for (let i = 1; i < parts.length; i++) if (ignored(parts.slice(0, i).join("/"), true, rules)) return true;
  return false;
}

function scanDir(root, { extraIgnore = [] } = {}) {
  const rules = [...loadIgnoreRules(root), ...parseIgnore(extraIgnore.join("\n"))];
  const findings = [];
  const stats = { files: 0, skippedLarge: [], skippedBinary: 0 };
  for (const rel of walk(root, { extraIgnore, useGitignore: false })) {
    if (SKIP_FILES.test(rel) || isIgnored(rel, rules)) continue;
    const abs = path.join(root, rel); let buf;
    try { buf = fs.readFileSync(abs); } catch { continue; }
    if (isBinary(buf)) { stats.skippedBinary++; continue; }
    // Large files are reported instead of vanishing without a word.
    if (buf.length > MAX_FILE_BYTES) { stats.skippedLarge.push({ file: rel, bytes: buf.length }); continue; }
    stats.files++;
    findings.push(...scanText(buf.toString("utf8"), rel));
  }
  return { findings, files: stats.files, skippedLarge: stats.skippedLarge, skippedBinary: stats.skippedBinary };
}

/**
 * Scan added lines in git history.
 * `extraIgnore` and the repository's `.secretscanignore` / `.gitignore` are honoured
 * here too — a path you asked the tool to skip must be skipped in every mode.
 */
function scanHistory(root, { max = 5000, extraIgnore = [] } = {}) {
  const rules = [...loadIgnoreRules(root), ...parseIgnore(extraIgnore.join("\n"))];
  let out;
  try {
    out = execFileSync("git", ["log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", `-n${max}`, "--format=\x1e%H\x1f%an\x1f%aI"], { cwd: root, encoding: "utf8", maxBuffer: 512 << 20 });
  } catch (e) {
    const msg = String(e.stderr || e.message).trim().split("\n")[0];
    const err = new Error(/not a git repository/i.test(msg) ? "Not a git repository — --history needs a repo" : msg);
    err.code = "EGIT";
    throw err;
  }
  const findings = []; const seen = new Set(); let commits = 0;
  for (const chunk of out.split("\x1e")) {
    if (!chunk.trim()) continue; commits++;
    const [head, ...rest] = chunk.split("\n"); const [sha, author, date] = head.split("\x1f");
    let file = null, ln = 0; const added = {};
    for (const l of rest) {
      if (l.startsWith("+++ ")) { file = l.slice(4).replace(/^b\//, ""); continue; }
      const h = /^@@ -\S+ \+(\d+)/.exec(l); if (h) { ln = +h[1]; continue; }
      if (file && l.startsWith("+") && !SKIP_FILES.test(file) && !isIgnored(file, rules)) { (added[file] ??= []).push([ln, l.slice(1)]); ln++; }
    }
    for (const [f, lines] of Object.entries(added)) for (const [n, text] of lines) for (const x of scanText(text, f)) {
      if (seen.has(x.fingerprint)) continue; seen.add(x.fingerprint);
      findings.push({ ...x, line: n, commit: sha.slice(0, 8), author, date });
    }
  }
  return { findings, commits };
}

function loadBaseline(file) { try { return new Set(JSON.parse(fs.readFileSync(file, "utf8")).fingerprints || []); } catch { return new Set(); } }
function writeBaseline(file, findings) { fs.writeFileSync(file, JSON.stringify({ note: "Known / accepted findings. Generated by secretscan --baseline.", fingerprints: [...new Set(findings.map((f) => f.fingerprint))].sort() }, null, 2) + "\n"); }
function toSarif(findings) {
  return { version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: "secretscan", informationUri: "https://github.com/krishyaa06/prism-secret-scan", rules: RULES.map(([id, name]) => ({ id, shortDescription: { text: name } })) } }, results: findings.map((f) => ({ ruleId: f.rule, level: f.severity === "low" ? "note" : f.severity === "medium" ? "warning" : "error", message: { text: `${f.name}: ${f.masked}` }, locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line, startColumn: f.col } } }], partialFingerprints: { secret: f.fingerprint } })) }] };
}
module.exports = { scanText, scanDir, scanHistory, entropy, mask, fingerprint, loadBaseline, writeBaseline, toSarif, isIgnored, loadIgnoreRules, RULES, MAX_FILE_BYTES };


