#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { parseArgs } = require("node:util");
const S = require("../src");
const { c, header, plural } = require("../src/ui");
const pkg = require("../package.json");

const HELP = `${header("secretscan", "find leaked keys before attackers do")}

${c.bold("Usage")}
  secretscan [dir]              scan files in the working tree
  secretscan --history          scan every commit (keys you "deleted" are still there)
  secretscan --list             show all ${S.RULES.length} detectors

${c.bold("Options")}
      --baseline [file]   accept current findings (writes .secretscan-baseline.json)
      --severity <lvl>    minimum: low | medium | high | critical  (default: low)
      --show              print secrets unmasked (careful)
      --json | --sarif    machine output (SARIF for GitHub code scanning)
  -e, --exclude <glob>    extra ignore patterns (or use .secretscanignore)
  -v, --version / -h, --help

Silence a line with ${c.cyan("secretscan:ignore")}. Exit code 1 when secrets are found.`;

let a;
try { a = parseArgs({ allowPositionals: true, options: { history: { type: "boolean" }, list: { type: "boolean" }, baseline: { type: "boolean" }, "baseline-file": { type: "string", default: ".secretscan-baseline.json" }, severity: { type: "string", default: "low" }, show: { type: "boolean" }, json: { type: "boolean" }, sarif: { type: "boolean" }, exclude: { type: "string", short: "e", multiple: true }, version: { type: "boolean", short: "v" }, help: { type: "boolean", short: "h" } } }); }
catch (e) { console.error(c.red(`✖ ${e.message}`)); process.exit(2); }
const o = a.values;
if (o.help) { console.log(HELP); process.exit(0); }
if (o.version) { console.log(pkg.version); process.exit(0); }
const SEV = { low: 0, medium: 1, high: 2, critical: 3 };
const SC = { critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.gray };
if (o.list) { console.log(header("secretscan", `${S.RULES.length} detectors`)); for (const [id, name, , sev] of S.RULES) console.log(`  ${SC[sev](sev.padEnd(9))} ${c.bold(id.padEnd(18))} ${c.dim(name)}`); process.exit(0); }
if (!(o.severity in SEV)) { console.error(c.red("✖ --severity must be low, medium, high or critical")); process.exit(2); }
const root = path.resolve(a.positionals[0] || ".");
if (!fs.existsSync(root)) { console.error(c.red(`✖ No such directory: ${root}`)); process.exit(2); }
const blFile = path.join(root, o["baseline-file"]);

let res;
try { res = o.history ? S.scanHistory(root) : S.scanDir(root, { extraIgnore: [...(o.exclude || []), path.basename(blFile)] }); }
catch (e) { console.error(c.red(`✖ ${String(e.stderr || e.message).trim().split("\n")[0]}`)); process.exit(2); }
if (o.baseline) { S.writeBaseline(blFile, res.findings); console.log(`${c.green("✔")} Baselined ${plural(res.findings.length, "finding")} → ${c.bold(path.relative(process.cwd(), blFile) || blFile)}`); process.exit(0); }
const base = S.loadBaseline(blFile);
const findings = res.findings.filter((f) => SEV[f.severity] >= SEV[o.severity] && !base.has(f.fingerprint)).sort((x, y) => SEV[y.severity] - SEV[x.severity]);
const skipped = res.findings.length - findings.length;
if (o.sarif) { console.log(JSON.stringify(S.toSarif(findings), null, 2)); process.exit(findings.length ? 1 : 0); }
if (o.json) { console.log(JSON.stringify(findings.map(({ secret, ...f }) => (o.show ? { ...f, secret } : f)), null, 2)); process.exit(findings.length ? 1 : 0); }

console.log(header("secretscan", o.history ? `${plural(res.commits, "commit")} of history` : `${plural(res.files, "file")} in ${path.basename(root)}`));
if (!findings.length) { console.log(`\n${c.green("✔")} No secrets found.${skipped ? c.dim(` (${skipped} baselined / below --severity)`) : ""}`); process.exit(0); }
console.log();
for (const f of findings) {
  console.log(`  ${SC[f.severity]((f.severity === "critical" ? "✖ " : "⚠ ") + f.severity.toUpperCase().padEnd(8))} ${c.bold(f.name)}`);
  console.log(`    ${c.cyan(`${f.file}:${f.line}:${f.col}`)}${f.commit ? c.dim(`  in ${f.commit} by ${f.author}, ${f.date.slice(0, 10)}`) : ""}`);
  console.log(`    ${o.show ? c.red(f.secret) : c.gray(f.masked)}`);
}
const by = (s) => findings.filter((f) => f.severity === s).length;
console.log(`\n${c.red(`✖ ${plural(findings.length, "secret")}`)} ${c.dim(`(${["critical", "high", "medium", "low"].filter(by).map((s) => `${by(s)} ${s}`).join(", ")})`)}${skipped ? c.dim(` · ${skipped} baselined`) : ""}`);
console.log(c.dim(o.history ? "Rotate these keys now — removing them from the code does not remove them from git history." : "Rotate leaked keys, move them to .env (gitignored), then re-run. False positive? add secretscan:ignore"));
process.exit(1);
