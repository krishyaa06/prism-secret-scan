const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execSync, spawnSync } = require("node:child_process");
const S = require("../src");
const demo = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "leaky-")), "app");
execSync(`node ${path.join(__dirname, "../examples/make-leaky-app.js")} ${demo}`);
const bin = path.join(__dirname, "../bin/secretscan.js");
const ids = (t, f = "a.js") => S.scanText(t, f).map((x) => x.rule);
const gh = ["gh", "p_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"].join("");

test("detectors", () => {
  assert.deepEqual(ids(`const t = "${gh}"`), ["github-token"]);
  assert.deepEqual(ids("-----BEGIN OPENSSH PRIVATE KEY-----"), ["private-key"]);
  assert.deepEqual(ids(`db = "${["mongodb", "+srv://me:", "Sup3rS3cret", "@cluster0.x.mongodb.net/app"].join("")}"`), ["db-url"]);
  assert.deepEqual(ids('const password = "h7Gk2pQ9zLx4Vb8N"'), ["generic-secret"]);
});
test("no false positives", () => {
  assert.deepEqual(ids('const password = "password1234"'), []);
  assert.deepEqual(ids("const key = process.env.OPENAI_API_KEY"), []);
  assert.deepEqual(ids(`KEY="${"sk_" + "live_" + "x".repeat(24)}"`), []);
  assert.deepEqual(ids("postgres://user:password@localhost/your_db"), []);
  assert.deepEqual(ids(`t = "${gh}" // secretscan:ignore`), []);
  assert.deepEqual(ids('token: "aaaaaaaaaaaaaaaa"'), []);
});
test("demo dir", () => {
  const r = S.scanDir(demo);
  assert.deepEqual([...new Set(r.findings.map((f) => f.rule))].sort(), ["aws-access-key", "aws-secret-key", "db-url", "discord-token", "groq-key", "openai-key", "stripe-secret"]);
  assert.ok(r.findings.every((f) => f.masked.includes("•")));
});
test("history finds deleted keys + baseline", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "ss-"));
  const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  execSync("git init -q", { cwd: d });
  fs.writeFileSync(path.join(d, "a.js"), `const t = "${gh}";\n`); execSync("git add -A && git commit -qm add", { cwd: d, env });
  fs.writeFileSync(path.join(d, "a.js"), "const t = process.env.GH;\n"); execSync("git add -A && git commit -qm remove", { cwd: d, env });
  assert.equal(spawnSync("node", [bin, d]).status, 0);
  const h = spawnSync("node", [bin, d, "--history", "--json"], { encoding: "utf8" });
  assert.equal(h.status, 1); assert.equal(JSON.parse(h.stdout)[0].rule, "github-token");
  fs.writeFileSync(path.join(d, "b.js"), `x = "${gh}"\n`);
  assert.equal(spawnSync("node", [bin, d]).status, 1);
  spawnSync("node", [bin, d, "--baseline"]);
  assert.equal(spawnSync("node", [bin, d]).status, 0);
});
test("sarif", () => { const s = S.toSarif(S.scanDir(demo).findings); assert.equal(s.version, "2.1.0"); assert.ok(s.runs[0].results.length >= 7); });

// ── regression: a real key next to other characters is still found (v1.1) ──────
test("ansi escapes, BOM and CRLF do not hide a key", () => {
  assert.deepEqual(ids(`\x1b[31m${gh}\x1b[0m`), ["github-token"]);
  assert.deepEqual(ids(`\uFEFF${gh}`), ["github-token"]);
  assert.deepEqual(ids(`KEY=${gh}\r`), ["github-token"]);
  assert.deepEqual(ids(`curl https://x.dev/?key=${gh}`), ["github-token"]);
  assert.deepEqual(ids(`{"token":"${gh}"}`), ["github-token"]);
});

test("a placeholder word elsewhere on the line no longer hides a real key", () => {
  assert.deepEqual(ids(`// example config\nconst t = "${gh}"`), ["github-token"]);
  assert.deepEqual(ids(`const sample = 1, t = "${gh}"`), ["github-token"]);
});

test("placeholder secrets are still ignored", () => {
  assert.deepEqual(ids(`KEY="your-key-here-${"x".repeat(30)}"`), []);
  assert.deepEqual(ids(`KEY="<YOUR_TOKEN_HERE>"`), []);
  assert.deepEqual(ids(`KEY="\${GITHUB_TOKEN}"`), []);
});

// ── regression: --history must honour ignore rules and --exclude (v1.1) ────────
const tmpRepo = (name) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), name));
  execSync("git init -q", { cwd: d });
  return d;
};
const GIT_ENV = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };

test("history honours .secretscanignore", () => {
  const d = tmpRepo("ss-ignore-");
  fs.writeFileSync(path.join(d, "leak.js"), `const t = "${gh}";\n`);
  fs.writeFileSync(path.join(d, ".secretscanignore"), "leak.js\n");
  execSync("git add -A && git commit -qm add", { cwd: d, env: GIT_ENV });
  assert.equal(spawnSync("node", [bin, d, "--history", "--json"]).status, 0, "ignored path must not be reported");
});

test("history honours --exclude", () => {
  const d = tmpRepo("ss-excl-");
  fs.writeFileSync(path.join(d, "leak.js"), `const t = "${gh}";\n`);
  execSync("git add -A && git commit -qm add", { cwd: d, env: GIT_ENV });
  assert.equal(spawnSync("node", [bin, d, "--history", "-e", "leak.js", "--json"]).status, 0);
  assert.equal(spawnSync("node", [bin, d, "--history", "--json"]).status, 1);
});

test("baseline survives the secret moving to another line", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "ss-move-"));
  fs.writeFileSync(path.join(d, "a.js"), `const t = "${gh}";\n`);
  spawnSync("node", [bin, d, "--baseline"]);
  assert.equal(spawnSync("node", [bin, d]).status, 0);
  fs.writeFileSync(path.join(d, "a.js"), `\n\n\nconst t = "${gh}";\n`);
  assert.equal(spawnSync("node", [bin, d]).status, 0, "same secret, new line: still baselined");
});

test("oversized files are announced", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "ss-big-"));
  fs.writeFileSync(path.join(d, "big.txt"), "a".repeat((2 << 20) + 10));
  const r = spawnSync("node", [bin, d], { encoding: "utf8" });
  assert.match(r.stdout, /skipped big\.txt/);
});

test("history outside a git repo explains itself", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "ss-norepo-"));
  const r = spawnSync("node", [bin, d, "--history"], { encoding: "utf8" });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Not a git repository/);
});
