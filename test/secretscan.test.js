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
