// Property, regression and scaling tests for indexnow-ping. No network: fetch is a stub.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseSitemap, selectUrls, readInputs, run } from "../src/indexnow.mjs";

function rng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1103515245 + 12345) % 2147483648) / 2147483648);
}
const PIECES = ["<url>", "</url>", "<url >", "</URL>", "<loc>", "</loc>", "https://x.org/a", "https://x.org/b?q=1&amp;r=2", "<lastmod>",
  "2026-10-28", "not a date", "</lastmod>", "<sitemapindex>", "<sitemap>", "</sitemap>", "&lt;", "<!-- c -->", "\n", "<loc></loc>"];

test("parseSitemap and selectUrls never throw on scrambled XML", () => {
  const r = rng(20261028);
  for (let i = 0; i < 3000; i += 1) {
    const xml = Array.from({ length: 1 + Math.floor(r() * 30) }, () => PIECES[Math.floor(r() * PIECES.length)]).join("");
    const parsed = parseSitemap(xml);
    assert.ok(["index", "urlset"].includes(parsed.kind));
    for (const e of parsed.entries) assert.equal(typeof e.loc, "string");
    selectUrls(parsed.entries, { host: "x.org", since: new Date(0) });
  }
});

test("parseSitemap keeps the entries before a truncated tail", () => {
  const xml = "<urlset><url><loc>https://x.org/a</loc></url><url><loc>https://x.org/b</loc></url><url><loc>https://x.org/c</loc>";
  assert.deepEqual(parseSitemap(xml).entries.map((e) => e.loc), ["https://x.org/a", "https://x.org/b"]);
});

function timed(fn) {
  let best = Infinity;
  for (let i = 0; i < 3; i += 1) {
    const t = performance.now();
    fn();
    best = Math.min(best, performance.now() - t);
  }
  return Math.max(best, 0.5);
}

test("parseSitemap is linear on a truncated sitemap full of unclosed <url> tags", () => {
  // The lazy-regex version rescanned to the end of the document for each unclosed tag: 50,000 took seconds.
  const small = timed(() => parseSitemap("<urlset>" + "<url><loc>https://x.org/a</loc>".repeat(5000)));
  const large = timed(() => parseSitemap("<urlset>" + "<url><loc>https://x.org/a</loc>".repeat(50000)));
  assert.ok(large / small < 40, `5,000 tags: ${small.toFixed(1)} ms, 50,000: ${large.toFixed(1)} ms`);
});

test("run applies changed-since to sitemap entries without lastmod even when urls are also given", async () => {
  // Sitemap entries without <lastmod> used to be mistaken for explicit URLs whenever `urls` was set,
  // so they skipped the changed-since filter and were submitted.
  const sitemap = "<urlset><url><loc>https://x.org/undated</loc></url><url><loc>https://x.org/new</loc><lastmod>2026-10-28</lastmod></url></urlset>";
  const fetchImpl = async () => new Response(sitemap, { status: 200 });
  const log = [];
  const inputs = { ...readInputs({ INPUT_HOST: "x.org", INPUT_DRY_RUN: "true", INPUT_URLS: "https://x.org/explicit", INPUT_SITEMAP_URL: "https://x.org/sitemap.xml", INPUT_CHANGED_SINCE: "2026-10-01T00:00:00Z" }) };
  assert.equal(await run({ inputs, env: {}, fetchImpl, log: (m) => log.push(m) }), 0);
  assert.match(log.join("\n"), /2 URL\(s\) selected for x\.org \(0 older than changed-since, 1 without lastmod/);
});

test("run reports a missing or unreadable urls-file in one line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "indexnow-robust-"));
  mkdirSync(join(dir, "folder"));
  for (const [file, pattern] of [[join(dir, "missing.txt"), /no such file/], [join(dir, "folder"), /EISDIR|directory/]]) {
    const log = [];
    const inputs = readInputs({ INPUT_HOST: "x.org", INPUT_DRY_RUN: "true", INPUT_URLS_FILE: file });
    assert.equal(await run({ inputs, env: {}, log: (m) => log.push(m) }), 2);
    assert.equal(log.length, 1);
    assert.match(log[0], /^::error::indexnow-ping: cannot read urls-file /);
    assert.match(log[0], pattern);
  }
});

test("run rejects a timeout or max-urls that is not a number", async () => {
  for (const [env, pattern] of [[{ INPUT_TIMEOUT: "soon" }, /timeout must be a number/], [{ INPUT_TIMEOUT: "0" }, /timeout must be a number/], [{ INPUT_MAX_URLS: "lots" }, /max-urls must be a whole number/]]) {
    const log = [];
    const inputs = readInputs({ INPUT_HOST: "x.org", INPUT_DRY_RUN: "true", INPUT_URLS: "https://x.org/", ...env });
    assert.equal(await run({ inputs, env: {}, log: (m) => log.push(m) }), 2);
    assert.match(log[0], pattern);
  }
});
