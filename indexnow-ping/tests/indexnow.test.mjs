// node --test tests for indexnow-ping. Everything runs against a loopback HTTP server; no outbound network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { gzipSync } from "node:zlib";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { parseSitemap, parseDuration, selectUrls, buildPayload, fetchSitemapUrls, submit, readInputs, run, MAX_URLS_PER_REQUEST } from "../src/indexnow.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => readFileSync(join(here, "fixtures", name), "utf8");

function startServer(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

function tmpEnv() {
  const dir = mkdtempSync(join(tmpdir(), "indexnow-"));
  const env = { GITHUB_OUTPUT: join(dir, "out"), GITHUB_STEP_SUMMARY: join(dir, "summary") };
  writeFileSync(env.GITHUB_OUTPUT, "");
  writeFileSync(env.GITHUB_STEP_SUMMARY, "");
  return env;
}

const outputs = (env) => Object.fromEntries(readFileSync(env.GITHUB_OUTPUT, "utf8").trim().split("\n").filter(Boolean).map((l) => l.split("=")));

test("parseSitemap reads urlset entries with lastmod and decodes entities", () => {
  const { kind, entries } = parseSitemap(fixture("sitemap.xml"));
  assert.equal(kind, "urlset");
  assert.equal(entries.length, 4);
  assert.deepEqual(entries[0], { loc: "https://www.example.org/", lastmod: "2026-10-01T10:00:00+00:00" });
  assert.equal(entries[2].loc, "https://www.example.org/search?q=a&b=c");
  assert.equal(entries[3].lastmod, null);
});

test("parseSitemap recognises a sitemap index", () => {
  const { kind, entries } = parseSitemap(fixture("sitemap-index.xml"));
  assert.equal(kind, "index");
  assert.deepEqual(entries.map((e) => e.loc), ["https://www.example.org/sitemap-a.xml", "https://www.example.org/sitemap-b.xml.gz"]);
});

test("parseDuration accepts ISO dates and relative durations", () => {
  const now = Date.parse("2026-10-03T12:00:00Z");
  assert.equal(parseDuration("24h", now).toISOString(), "2026-10-02T12:00:00.000Z");
  assert.equal(parseDuration("7d", now).toISOString(), "2026-09-26T12:00:00.000Z");
  assert.equal(parseDuration("2026-10-01T00:00:00Z", now).toISOString(), "2026-10-01T00:00:00.000Z");
  assert.equal(parseDuration("", now), null);
  assert.throws(() => parseDuration("yesterday", now), /ISO 8601/);
});

test("selectUrls filters by host, lastmod and duplicates", () => {
  const entries = [
    { loc: "https://www.example.org/a", lastmod: "2026-10-02" },
    { loc: "https://www.example.org/a", lastmod: "2026-10-02" },
    { loc: "https://www.example.org/old", lastmod: "2025-01-01" },
    { loc: "https://www.example.org/nodate", lastmod: null },
    { loc: "https://other.example.org/x", lastmod: "2026-10-02" },
    { loc: "not a url", lastmod: null },
    { loc: "ftp://www.example.org/f", lastmod: "2026-10-02" },
  ];
  const r = selectUrls(entries, { host: "www.example.org", since: new Date("2026-10-01") });
  assert.deepEqual(r.selected, ["https://www.example.org/a"]);
  assert.equal(r.skippedOld, 1);
  assert.equal(r.skippedNoDate, 1);
  assert.equal(r.skippedHost, 3);
  const all = selectUrls(entries, { host: "WWW.example.org" });
  assert.deepEqual(all.selected, ["https://www.example.org/a", "https://www.example.org/old", "https://www.example.org/nodate"]);
});

test("buildPayload includes keyLocation only when given", () => {
  assert.deepEqual(buildPayload({ host: "h", key: "k", urls: ["u"] }), { host: "h", key: "k", urlList: ["u"] });
  assert.deepEqual(buildPayload({ host: "h", key: "k", keyLocation: "https://h/k.txt", urls: ["u"] }), { host: "h", key: "k", urlList: ["u"], keyLocation: "https://h/k.txt" });
});

test("fetchSitemapUrls follows a sitemap index and gunzips children", async () => {
  const { server, base } = await startServer((req, res) => {
    if (req.url === "/sitemap.xml") {
      res.writeHead(200, { "content-type": "application/xml" });
      res.end(fixture("sitemap-index.xml").replaceAll("https://www.example.org", base));
    } else if (req.url === "/sitemap-a.xml") {
      res.writeHead(200, { "content-type": "application/xml" });
      res.end(fixture("sitemap.xml"));
    } else if (req.url === "/sitemap-b.xml.gz") {
      res.writeHead(200, { "content-type": "application/gzip" });
      res.end(gzipSync(Buffer.from('<?xml version="1.0"?><urlset><url><loc>https://www.example.org/gz</loc></url></urlset>')));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  try {
    const entries = await fetchSitemapUrls(`${base}/sitemap.xml`);
    assert.equal(entries.length, 5);
    assert.equal(entries[4].loc, "https://www.example.org/gz");
  } finally {
    server.close();
  }
});

test("fetchSitemapUrls fails loudly on a non-200 answer", async () => {
  const { server, base } = await startServer((req, res) => { res.writeHead(500); res.end(); });
  try {
    await assert.rejects(fetchSitemapUrls(`${base}/sitemap.xml`), /answered 500/);
  } finally {
    server.close();
  }
});

test("submit posts JSON and retries once on 429", async () => {
  let calls = 0;
  const bodies = [];
  const { server, base } = await startServer(async (req, res) => {
    calls += 1;
    bodies.push({ method: req.method, type: req.headers["content-type"], body: await readBody(req) });
    if (calls === 1) {
      res.writeHead(429, { "retry-after": "1" });
      res.end("slow down");
    } else {
      res.writeHead(200);
      res.end();
    }
  });
  try {
    const result = await submit({ endpoint: `${base}/indexnow`, payload: { host: "h", key: "k", urlList: ["https://h/a"] }, sleep: async () => {} });
    assert.equal(result.status, 200);
    assert.equal(calls, 2);
    assert.equal(bodies[0].method, "POST");
    assert.match(bodies[0].type, /application\/json/);
    assert.deepEqual(JSON.parse(bodies[1].body), { host: "h", key: "k", urlList: ["https://h/a"] });
  } finally {
    server.close();
  }
});

test("submit does not retry client errors", async () => {
  let calls = 0;
  const { server, base } = await startServer((req, res) => { calls += 1; res.writeHead(403); res.end("bad key"); });
  try {
    const result = await submit({ endpoint: `${base}/indexnow`, payload: {}, sleep: async () => {} });
    assert.equal(result.status, 403);
    assert.equal(result.text, "bad key");
    assert.equal(calls, 1);
  } finally {
    server.close();
  }
});

test("readInputs maps INPUT_ variables and defaults", () => {
  const inputs = readInputs({ INPUT_HOST: "www.example.org", INPUT_KEY: "k", INPUT_KEY_LOCATION: "", INPUT_DRY_RUN: "true", INPUT_MAX_URLS: "5" });
  assert.equal(inputs.host, "www.example.org");
  assert.equal(inputs.keyLocation, "");
  assert.equal(inputs.dryRun, true);
  assert.equal(inputs.maxUrls, 5);
  assert.equal(inputs.endpoint, "https://api.indexnow.org/indexnow");
  assert.equal(inputs.timeout, 30);
});

test("run: usage errors exit 2 without network", async () => {
  const log = [];
  const fetchImpl = async () => { throw new Error("must not be called"); };
  assert.equal(await run({ inputs: readInputs({}), env: {}, fetchImpl, log: (m) => log.push(m) }), 2);
  assert.equal(await run({ inputs: readInputs({ INPUT_HOST: "h" }), env: {}, fetchImpl, log: (m) => log.push(m) }), 2);
  assert.equal(await run({ inputs: readInputs({ INPUT_HOST: "h", INPUT_KEY: "k" }), env: {}, fetchImpl, log: (m) => log.push(m) }), 2);
  assert.equal(await run({ inputs: readInputs({ INPUT_HOST: "h", INPUT_KEY: "k", INPUT_URLS: "https://h/a", INPUT_CHANGED_SINCE: "soon" }), env: {}, fetchImpl, log: (m) => log.push(m) }), 2);
  assert.ok(log.every((m) => m.startsWith("::error::")));
});

test("run: dry run selects URLs, writes outputs and summary, sends nothing", async () => {
  const env = tmpEnv();
  const fetchImpl = async () => { throw new Error("must not be called"); };
  const inputs = readInputs({ INPUT_HOST: "www.example.org", INPUT_DRY_RUN: "true", INPUT_URLS: "https://www.example.org/a\nhttps://www.example.org/b\nhttps://elsewhere.invalid/c\n" });
  const code = await run({ inputs, env, fetchImpl, log: () => {} });
  assert.equal(code, 0);
  const out = outputs(env);
  assert.equal(out["url-count"], "2");
  assert.equal(out["submitted-count"], "0");
  assert.equal(out["skipped-count"], "1");
  assert.match(readFileSync(env.GITHUB_STEP_SUMMARY, "utf8"), /Dry run/);
});

test("run: end to end against a loopback sitemap and endpoint", async () => {
  const received = [];
  const { server, base } = await startServer(async (req, res) => {
    if (req.url === "/sitemap.xml") {
      res.writeHead(200, { "content-type": "application/xml" });
      res.end(fixture("sitemap.xml"));
    } else if (req.url === "/indexnow" && req.method === "POST") {
      received.push(JSON.parse(await readBody(req)));
      res.writeHead(200);
      res.end();
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  const env = tmpEnv();
  try {
    const inputs = readInputs({
      INPUT_HOST: "www.example.org", INPUT_KEY: "abc123", INPUT_KEY_LOCATION: "https://www.example.org/abc123.txt",
      INPUT_SITEMAP_URL: `${base}/sitemap.xml`, INPUT_ENDPOINT: `${base}/indexnow`, INPUT_CHANGED_SINCE: "2026-09-30T00:00:00Z",
    });
    const code = await run({ inputs, env, log: () => {}, now: Date.parse("2026-10-03T00:00:00Z") });
    assert.equal(code, 0);
    assert.equal(received.length, 1);
    assert.deepEqual(received[0], {
      host: "www.example.org", key: "abc123", keyLocation: "https://www.example.org/abc123.txt",
      urlList: ["https://www.example.org/", "https://www.example.org/docs/"],
    });
    const out = outputs(env);
    assert.equal(out["submitted-count"], "2");
    assert.equal(out["status-code"], "200");
    assert.equal(out["skipped-count"], "2");
  } finally {
    server.close();
  }
});

test("run: endpoint rejection exits 1 and records the status", async () => {
  const { server, base } = await startServer((req, res) => { res.writeHead(422); res.end("host mismatch"); });
  const env = tmpEnv();
  const log = [];
  try {
    const inputs = readInputs({ INPUT_HOST: "www.example.org", INPUT_KEY: "k", INPUT_URLS: "https://www.example.org/x", INPUT_ENDPOINT: `${base}/indexnow` });
    assert.equal(await run({ inputs, env, log: (m) => log.push(m) }), 1);
    assert.equal(outputs(env)["status-code"], "422");
    assert.ok(log.some((m) => m.includes("422")));
  } finally {
    server.close();
  }
});

test("run: urls are batched at the IndexNow limit", async () => {
  const sizes = [];
  const { server, base } = await startServer(async (req, res) => { sizes.push(JSON.parse(await readBody(req)).urlList.length); res.writeHead(202); res.end(); });
  const env = tmpEnv();
  try {
    const urls = Array.from({ length: MAX_URLS_PER_REQUEST + 3 }, (_, i) => `https://www.example.org/p/${i}`).join("\n");
    const inputs = readInputs({ INPUT_HOST: "www.example.org", INPUT_KEY: "k", INPUT_URLS: urls, INPUT_ENDPOINT: `${base}/indexnow`, INPUT_MAX_URLS: String(MAX_URLS_PER_REQUEST + 3) });
    assert.equal(await run({ inputs, env, log: () => {} }), 0);
    assert.deepEqual(sizes, [MAX_URLS_PER_REQUEST, 3]);
    assert.equal(outputs(env)["submitted-count"], String(MAX_URLS_PER_REQUEST + 3));
  } finally {
    server.close();
  }
});
