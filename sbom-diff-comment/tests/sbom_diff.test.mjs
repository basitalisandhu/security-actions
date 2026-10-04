// node --test tests for sbom-diff-comment. The GitHub API is a loopback HTTP server; no outbound network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { detectFormat, normalize, diff, renderMarkdown, truncate, upsertComment, readInputs, prNumberFromEvent, run } from "../src/sbom_diff.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (name) => join(here, "fixtures", name);
const load = (name) => JSON.parse(readFileSync(fx(name), "utf8"));

function startServer(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}
const readBody = (req) => new Promise((resolve) => { const c = []; req.on("data", (x) => c.push(x)); req.on("end", () => resolve(Buffer.concat(c).toString("utf8"))); });

function fakeGitHub(initialComments = []) {
  const state = { comments: [...initialComments], requests: [], nextId: 100 };
  const handler = async (req, res) => {
    state.requests.push({ method: req.method, url: req.url, auth: req.headers.authorization, version: req.headers["x-github-api-version"] });
    const json = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    const m = /^\/repos\/([^/]+\/[^/]+)\/issues\/(\d+)\/comments(\?.*)?$/.exec(req.url);
    const c = /^\/repos\/([^/]+\/[^/]+)\/issues\/comments\/(\d+)$/.exec(req.url);
    if (m && req.method === "GET") {
      const page = Number(new URLSearchParams(m[3] || "").get("page") || 1);
      return json(200, page === 1 ? state.comments : []);
    }
    if (m && req.method === "POST") {
      const { body } = JSON.parse(await readBody(req));
      const comment = { id: state.nextId++, body, html_url: `https://github.invalid/c/${state.nextId - 1}` };
      state.comments.push(comment);
      return json(201, comment);
    }
    if (c && req.method === "PATCH") {
      const { body } = JSON.parse(await readBody(req));
      const comment = state.comments.find((x) => x.id === Number(c[2]));
      if (!comment) return json(404, { message: "not found" });
      comment.body = body;
      return json(200, comment);
    }
    return json(404, { message: "no route" });
  };
  return { state, handler };
}

function tmpEnv(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sbom-"));
  const env = { GITHUB_OUTPUT: join(dir, "out"), GITHUB_STEP_SUMMARY: join(dir, "summary"), ...extra };
  writeFileSync(env.GITHUB_OUTPUT, "");
  writeFileSync(env.GITHUB_STEP_SUMMARY, "");
  return { dir, env };
}
const outputs = (env) => Object.fromEntries(readFileSync(env.GITHUB_OUTPUT, "utf8").trim().split("\n").filter(Boolean).map((l) => l.split("=")));

test("detectFormat recognises CycloneDX and SPDX and rejects other JSON", () => {
  assert.equal(detectFormat(load("base.cdx.json")), "cyclonedx");
  assert.equal(detectFormat(load("base.spdx.json")), "spdx");
  assert.throws(() => detectFormat(load("not-an-sbom.json")), /not a CycloneDX/);
});

test("normalize keys CycloneDX components by purl without version, including nested ones", () => {
  const { components } = normalize(load("head.cdx.json"));
  assert.deepEqual([...components.keys()].sort(), ["library/no-purl-lib", "pkg:npm/%40scope/widget", "pkg:npm/axios", "pkg:npm/follow-redirects", "pkg:npm/lodash", "pkg:pypi/requests"]);
  assert.deepEqual(components.get("library/no-purl-lib").licenses, ["MIT OR Apache-2.0"]);
  assert.equal(components.get("pkg:npm/%40scope/widget").name, "@scope/widget");
});

test("normalize reads SPDX packages, skips the described root and NOASSERTION", () => {
  const { components } = normalize(load("base.spdx.json"));
  assert.deepEqual([...components.keys()].sort(), ["pkg:npm/left-pad", "pkg:npm/lodash"]);
  assert.deepEqual(components.get("pkg:npm/lodash").licenses, ["MIT"]);
});

test("diff reports added, removed, version and licence changes", () => {
  const d = diff(normalize(load("base.cdx.json")), normalize(load("head.cdx.json")));
  assert.deepEqual(d.added.map((a) => a.name), ["axios", "follow-redirects"]);
  assert.deepEqual(d.removed.map((r) => r.name), ["left-pad"]);
  assert.deepEqual(d.changed, [{ name: "lodash", from: "4.17.20", to: "4.17.21" }]);
  assert.deepEqual(d.licenseChanges, [{ name: "@scope/widget", from: ["MIT"], to: ["GPL-3.0-only"], version: "2.0.0" }]);
  assert.equal(d.baseCount, 5);
  assert.equal(d.headCount, 6);
});

test("diff works across formats (SPDX base vs CycloneDX head)", () => {
  const d = diff(normalize(load("base.spdx.json")), normalize(load("head.cdx.json")));
  assert.ok(d.added.some((a) => a.name === "axios"));
  assert.deepEqual(d.removed.map((r) => r.name), ["left-pad"]);
  assert.deepEqual(d.changed, [{ name: "lodash", from: "4.17.20", to: "4.17.21" }]);
});

test("diff of identical SBOMs is empty and renders a no-change message", () => {
  const d = diff(normalize(load("base.cdx.json")), normalize(load("base.cdx.json")));
  assert.deepEqual([d.added, d.removed, d.changed, d.licenseChanges], [[], [], [], []]);
  const md = renderMarkdown(d);
  assert.match(md, /No component differences/);
  assert.ok(md.startsWith("<!-- sbom-diff-comment:default -->\n## SBOM diff"));
});

test("renderMarkdown escapes pipes and caps rows", () => {
  const d = {
    added: Array.from({ length: 60 }, (_, i) => ({ name: `pkg|${i}`, version: "1", licenses: [] })), removed: [], changed: [], licenseChanges: [],
    baseCount: 0, headCount: 60,
  };
  const md = renderMarkdown(d, { title: "Deps", marker: "npm" });
  assert.ok(md.startsWith("<!-- sbom-diff-comment:npm -->\n## Deps"));
  assert.match(md, /pkg\\\|0/);
  assert.match(md, /and 10 more/);
  assert.match(md, /_none declared_/);
});

test("truncate keeps the comment under the GitHub limit", () => {
  const big = "x".repeat(70000);
  const t = truncate(big);
  assert.ok(t.length <= 65000);
  assert.match(t, /truncated/);
  assert.equal(truncate("short"), "short");
});

test("upsertComment creates then updates the marked comment with bounded, versioned requests", async () => {
  const gh = fakeGitHub([{ id: 1, body: "unrelated comment" }]);
  const { server, base } = await startServer(gh.handler);
  try {
    const first = await upsertComment({ apiUrl: base, token: "t0k", repo: "o/r", prNumber: "7", marker: "default", body: "<!-- sbom-diff-comment:default -->\nv1" });
    assert.equal(first.action, "created");
    const second = await upsertComment({ apiUrl: base, token: "t0k", repo: "o/r", prNumber: "7", marker: "default", body: "<!-- sbom-diff-comment:default -->\nv2" });
    assert.equal(second.action, "updated");
    assert.equal(second.id, first.id);
    assert.equal(gh.state.comments.length, 2);
    assert.equal(gh.state.comments[1].body, "<!-- sbom-diff-comment:default -->\nv2");
    assert.deepEqual(gh.state.requests.map((r) => r.method), ["GET", "POST", "GET", "PATCH"]);
    assert.ok(gh.state.requests.every((r) => r.auth === "Bearer t0k" && r.version === "2022-11-28"));
    const other = await upsertComment({ apiUrl: base, token: "t0k", repo: "o/r", prNumber: "7", marker: "python", body: "<!-- sbom-diff-comment:python -->\nx" });
    assert.equal(other.action, "created");
  } finally {
    server.close();
  }
});

test("upsertComment surfaces API errors", async () => {
  const { server, base } = await startServer((req, res) => { res.writeHead(403); res.end("forbidden"); });
  try {
    await assert.rejects(upsertComment({ apiUrl: base, token: "t", repo: "o/r", prNumber: "1", marker: "m", body: "b" }), /listing comments failed: 403/);
  } finally {
    server.close();
  }
});

test("readInputs and prNumberFromEvent", () => {
  const { dir } = tmpEnv();
  const ev = join(dir, "event.json");
  writeFileSync(ev, JSON.stringify({ pull_request: { number: 42 } }));
  const inputs = readInputs({ INPUT_BASE: "a", INPUT_HEAD: "b", GITHUB_TOKEN: "envtok", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_PATH: ev });
  assert.equal(inputs.token, "envtok");
  assert.equal(inputs.comment, true);
  assert.equal(inputs.failOn, "none");
  assert.equal(inputs.apiUrl, "https://api.github.com");
  assert.equal(prNumberFromEvent(ev), "42");
  writeFileSync(ev, JSON.stringify({ issue: { number: 9, pull_request: {} } }));
  assert.equal(prNumberFromEvent(ev), "9");
  writeFileSync(ev, JSON.stringify({ push: {} }));
  assert.equal(prNumberFromEvent(ev), "");
  assert.equal(prNumberFromEvent(""), "");
});

test("run without comment writes the markdown file, summary and outputs", async () => {
  const { dir, env } = tmpEnv();
  const md = join(dir, "diff.md");
  const inputs = readInputs({ INPUT_BASE: fx("base.cdx.json"), INPUT_HEAD: fx("head.cdx.json"), INPUT_COMMENT: "false", INPUT_MARKDOWN_FILE: md });
  const code = await run({ inputs, env, fetchImpl: async () => { throw new Error("no network expected"); }, log: () => {} });
  assert.equal(code, 0);
  const out = outputs(env);
  assert.deepEqual([out["added-count"], out["removed-count"], out["changed-count"], out["license-change-count"]], ["2", "1", "1", "1"]);
  assert.equal(out["comment-url"], "");
  assert.match(readFileSync(md, "utf8"), /### Licence changes/);
  assert.match(readFileSync(env.GITHUB_STEP_SUMMARY, "utf8"), /^## SBOM diff/);
});

test("run posts the comment on a pull request event", async () => {
  const gh = fakeGitHub();
  const { server, base } = await startServer(gh.handler);
  const { dir, env } = tmpEnv();
  const ev = join(dir, "event.json");
  writeFileSync(ev, JSON.stringify({ pull_request: { number: 5 } }));
  try {
    const inputs = readInputs({ INPUT_BASE: fx("base.spdx.json"), INPUT_HEAD: fx("head.spdx.json"), INPUT_MARKDOWN_FILE: join(dir, "d.md"), GITHUB_TOKEN: "tok", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_PATH: ev, GITHUB_API_URL: base });
    assert.equal(await run({ inputs, env, log: () => {} }), 0);
    assert.equal(gh.state.comments.length, 1);
    assert.match(gh.state.comments[0].body, /axios/);
    assert.equal(outputs(env)["comment-url"], "https://github.invalid/c/100");
  } finally {
    server.close();
  }
});

test("run skips the comment outside pull requests and fails when the API refuses", async () => {
  const { dir, env } = tmpEnv();
  const logs = [];
  const inputs = readInputs({ INPUT_BASE: fx("base.cdx.json"), INPUT_HEAD: fx("head.cdx.json"), INPUT_MARKDOWN_FILE: join(dir, "d.md"), GITHUB_TOKEN: "tok", GITHUB_REPOSITORY: "o/r" });
  assert.equal(await run({ inputs, env, fetchImpl: async () => { throw new Error("no network expected"); }, log: (m) => logs.push(m) }), 0);
  assert.ok(logs.some((m) => m.includes("comment skipped")));
  const { server, base } = await startServer((req, res) => { res.writeHead(401); res.end("bad credentials"); });
  try {
    const inputs2 = readInputs({ INPUT_BASE: fx("base.cdx.json"), INPUT_HEAD: fx("head.cdx.json"), INPUT_MARKDOWN_FILE: join(dir, "d.md"), INPUT_PR_NUMBER: "3", GITHUB_TOKEN: "tok", GITHUB_REPOSITORY: "o/r", GITHUB_API_URL: base });
    assert.equal(await run({ inputs: inputs2, env, log: (m) => logs.push(m) }), 1);
  } finally {
    server.close();
  }
});

test("run honours fail-on and reports usage errors", async () => {
  const { dir, env } = tmpEnv();
  const base = { INPUT_BASE: fx("base.cdx.json"), INPUT_HEAD: fx("head.cdx.json"), INPUT_COMMENT: "false", INPUT_MARKDOWN_FILE: join(dir, "d.md") };
  assert.equal(await run({ inputs: readInputs({ ...base, INPUT_FAIL_ON: "any-change" }), env, log: () => {} }), 1);
  assert.equal(await run({ inputs: readInputs({ ...base, INPUT_FAIL_ON: "license-change" }), env, log: () => {} }), 1);
  assert.equal(await run({ inputs: readInputs({ ...base, INPUT_HEAD: fx("base.cdx.json"), INPUT_FAIL_ON: "any-change" }), env, log: () => {} }), 0);
  assert.equal(await run({ inputs: readInputs({ INPUT_BASE: fx("base.cdx.json") }), env, log: () => {} }), 2);
  assert.equal(await run({ inputs: readInputs({ ...base, INPUT_HEAD: fx("not-an-sbom.json") }), env, log: () => {} }), 2);
  assert.equal(await run({ inputs: readInputs({ ...base, INPUT_HEAD: fx("missing.json") }), env, log: () => {} }), 2);
});
