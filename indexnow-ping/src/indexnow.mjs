#!/usr/bin/env node
// Submit changed URLs to IndexNow after a site deploy.
//
// URLs come from an explicit list (--urls, newline separated, or --urls-file) or from a sitemap
// (--sitemap-url; sitemap index files are followed one level deep, gzip is handled). They are
// filtered to the configured host, optionally to entries whose <lastmod> is newer than --changed-since,
// de-duplicated and sent in batches of at most 10,000 (the IndexNow limit per request) as
// POST { host, key, keyLocation?, urlList } to the endpoint (default https://api.indexnow.org/indexnow).
//
// Outputs ($GITHUB_OUTPUT): url-count, submitted-count, status-code, skipped-count.
// Exit codes: 0 submitted (or dry run), 1 the endpoint rejected the request, 2 usage error.
// No dependencies. Node 18 or later (global fetch).
import { readFileSync, appendFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

export const DEFAULT_ENDPOINT = "https://api.indexnow.org/indexnow";
export const MAX_URLS_PER_REQUEST = 10000;
export const MAX_SITEMAP_CHILDREN = 50;
const USER_AGENT = "indexnow-ping/1.0.0 (+https://github.com/basitalisandhu/security-actions)";

const STATUS_TEXT = {
  200: "OK, URLs submitted",
  202: "Accepted, key validation pending",
  400: "Bad request (invalid format)",
  403: "Forbidden (key not valid, for example key not found at key location)",
  422: "Unprocessable (URLs do not belong to the host or key does not match the schema)",
  429: "Too many requests (potential spam)",
};

export function parseDuration(value, now = Date.now()) {
  // ISO 8601 timestamp, or a relative duration such as 24h, 7d, 90m.
  if (!value) return null;
  const m = /^(\d+)\s*([mhdw])$/.exec(value.trim());
  if (m) {
    const unit = { m: 60e3, h: 3600e3, d: 86400e3, w: 7 * 86400e3 }[m[2]];
    return new Date(now - Number(m[1]) * unit);
  }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) throw new Error(`changed-since must be an ISO 8601 date or a duration like 24h, got ${value}`);
  return d;
}

function decodeXml(s) {
  return s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").trim();
}

export function parseSitemap(xml) {
  // Returns { kind: "index" | "urlset", entries: [{ loc, lastmod }] }
  const isIndex = /<sitemapindex[\s>]/i.test(xml);
  const blockRe = isIndex ? /<sitemap[\s>][\s\S]*?<\/sitemap>/gi : /<url[\s>][\s\S]*?<\/url>/gi;
  const entries = [];
  for (const block of xml.match(blockRe) || []) {
    const loc = /<loc>\s*([\s\S]*?)\s*<\/loc>/i.exec(block);
    if (!loc) continue;
    const lastmod = /<lastmod>\s*([\s\S]*?)\s*<\/lastmod>/i.exec(block);
    entries.push({ loc: decodeXml(loc[1]), lastmod: lastmod ? decodeXml(lastmod[1]) : null });
  }
  return { kind: isIndex ? "index" : "urlset", entries };
}

async function fetchWithTimeout(fetchImpl, url, init, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchSitemapUrls(sitemapUrl, { fetchImpl = fetch, timeoutMs = 30000, log = () => {} } = {}) {
  const fetchText = async (url) => {
    const res = await fetchWithTimeout(fetchImpl, url, { headers: { "user-agent": USER_AGENT, accept: "application/xml, text/xml, */*" } }, timeoutMs);
    if (!res.ok) throw new Error(`sitemap ${url} answered ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const gz = url.endsWith(".gz") || (buf[0] === 0x1f && buf[1] === 0x8b);
    return (gz ? gunzipSync(buf) : buf).toString("utf8");
  };
  const top = parseSitemap(await fetchText(sitemapUrl));
  if (top.kind === "urlset") return top.entries;
  const out = [];
  const children = top.entries.slice(0, MAX_SITEMAP_CHILDREN);
  if (top.entries.length > children.length) log(`sitemap index lists ${top.entries.length} sitemaps; only the first ${MAX_SITEMAP_CHILDREN} are read`);
  for (const child of children) {
    const parsed = parseSitemap(await fetchText(child.loc));
    if (parsed.kind === "urlset") out.push(...parsed.entries);
    else log(`nested sitemap index ${child.loc} skipped (only one level is followed)`);
  }
  return out;
}

export function selectUrls(entries, { host, since = null }) {
  const wanted = host.toLowerCase();
  const seen = new Set();
  const selected = [];
  let skippedHost = 0;
  let skippedOld = 0;
  let skippedNoDate = 0;
  for (const { loc, lastmod } of entries) {
    let u;
    try {
      u = new URL(loc);
    } catch {
      skippedHost += 1;
      continue;
    }
    if (u.hostname.toLowerCase() !== wanted || !/^https?:$/.test(u.protocol)) {
      skippedHost += 1;
      continue;
    }
    if (since) {
      if (!lastmod) {
        skippedNoDate += 1;
        continue;
      }
      const d = new Date(lastmod);
      if (Number.isNaN(d.getTime()) || d < since) {
        skippedOld += 1;
        continue;
      }
    }
    const key = u.href;
    if (seen.has(key)) continue;
    seen.add(key);
    selected.push(key);
  }
  return { selected, skippedHost, skippedOld, skippedNoDate };
}

export function buildPayload({ host, key, keyLocation, urls }) {
  const payload = { host, key, urlList: urls };
  if (keyLocation) payload.keyLocation = keyLocation;
  return payload;
}

export async function submit({ endpoint, payload, fetchImpl = fetch, timeoutMs = 30000, retries = 1, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  let last;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const res = await fetchWithTimeout(fetchImpl, endpoint, {
      method: "POST",
      headers: { "content-type": "application/json; charset=utf-8", "user-agent": USER_AGENT },
      body: JSON.stringify(payload),
    }, timeoutMs);
    last = { status: res.status, text: (await res.text()).slice(0, 500) };
    if (res.status !== 429 && res.status < 500) return last;
    if (attempt < retries) {
      const retryAfter = Number(res.headers.get("retry-after")) || 5;
      await sleep(Math.min(retryAfter, 60) * 1000);
    }
  }
  return last;
}

export function readInputs(env = process.env) {
  const get = (name, fallback = "") => {
    const v = env[`INPUT_${name.toUpperCase().replace(/-/g, "_")}`];
    return v === undefined || v === "" ? fallback : v;
  };
  return {
    host: get("host"),
    key: get("key"),
    keyLocation: get("key-location"),
    sitemapUrl: get("sitemap-url"),
    urls: get("urls"),
    urlsFile: get("urls-file"),
    changedSince: get("changed-since"),
    endpoint: get("endpoint", DEFAULT_ENDPOINT),
    maxUrls: Number(get("max-urls", String(MAX_URLS_PER_REQUEST))),
    timeout: Number(get("timeout", "30")),
    dryRun: get("dry-run", "false") === "true",
  };
}

function setOutputs(values, env = process.env) {
  if (!env.GITHUB_OUTPUT) return;
  appendFileSync(env.GITHUB_OUTPUT, Object.entries(values).map(([k, v]) => `${k}=${v}\n`).join(""));
}

function appendSummary(text, env = process.env) {
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, text);
}

export async function run({ inputs, env = process.env, fetchImpl = fetch, log = console.log, now = Date.now() }) {
  if (!inputs.host) {
    log("::error::indexnow-ping: host is required (for example www.example.com)");
    return 2;
  }
  if (!inputs.key && !inputs.dryRun) {
    log("::error::indexnow-ping: key is required (store it as a repository secret or variable)");
    return 2;
  }
  if (!inputs.sitemapUrl && !inputs.urls && !inputs.urlsFile) {
    log("::error::indexnow-ping: give sitemap-url, urls or urls-file");
    return 2;
  }
  let since;
  try {
    since = parseDuration(inputs.changedSince, now);
  } catch (err) {
    log(`::error::indexnow-ping: ${err.message}`);
    return 2;
  }
  const timeoutMs = Math.max(1, inputs.timeout) * 1000;
  const entries = [];
  if (inputs.urls) entries.push(...inputs.urls.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).map((loc) => ({ loc, lastmod: null })));
  if (inputs.urlsFile) entries.push(...readFileSync(inputs.urlsFile, "utf8").split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#")).map((loc) => ({ loc, lastmod: null })));
  if (inputs.sitemapUrl) {
    try {
      entries.push(...await fetchSitemapUrls(inputs.sitemapUrl, { fetchImpl, timeoutMs, log: (m) => log(`::warning::indexnow-ping: ${m}`) }));
    } catch (err) {
      log(`::error::indexnow-ping: could not read the sitemap: ${err.message}`);
      return 1;
    }
  }
  // Explicit URLs are always submitted; the lastmod filter applies to sitemap entries only.
  const explicit = entries.filter((e) => e.lastmod === null && (inputs.urls || inputs.urlsFile));
  const fromSitemap = entries.filter((e) => !explicit.includes(e));
  const a = selectUrls(explicit, { host: inputs.host });
  const b = selectUrls(fromSitemap, { host: inputs.host, since });
  const urls = [...new Set([...a.selected, ...b.selected])].slice(0, Math.max(0, inputs.maxUrls));
  const skipped = a.skippedHost + b.skippedHost + b.skippedOld + b.skippedNoDate;
  log(`indexnow-ping: ${urls.length} URL(s) selected for ${inputs.host} (${b.skippedOld} older than changed-since, ${b.skippedNoDate} without lastmod, ${a.skippedHost + b.skippedHost} on other hosts)`);

  const lines = ["## IndexNow", "", `Host: \`${inputs.host}\`. Selected ${urls.length} URL(s), skipped ${skipped}.`, ""];
  if (urls.length === 0) {
    lines.push("Nothing to submit.");
    appendSummary(lines.join("\n") + "\n", env);
    setOutputs({ "url-count": 0, "submitted-count": 0, "status-code": "", "skipped-count": skipped }, env);
    return 0;
  }
  if (inputs.dryRun) {
    lines.push("Dry run: no request was sent.", "", ...urls.slice(0, 50).map((u) => `- ${u}`));
    if (urls.length > 50) lines.push(`- and ${urls.length - 50} more`);
    appendSummary(lines.join("\n") + "\n", env);
    setOutputs({ "url-count": urls.length, "submitted-count": 0, "status-code": "", "skipped-count": skipped }, env);
    return 0;
  }
  let submitted = 0;
  let lastStatus = 0;
  for (let i = 0; i < urls.length; i += MAX_URLS_PER_REQUEST) {
    const batch = urls.slice(i, i + MAX_URLS_PER_REQUEST);
    const payload = buildPayload({ host: inputs.host, key: inputs.key, keyLocation: inputs.keyLocation, urls: batch });
    let result;
    try {
      result = await submit({ endpoint: inputs.endpoint, payload, fetchImpl, timeoutMs });
    } catch (err) {
      log(`::error::indexnow-ping: request to ${inputs.endpoint} failed: ${err.message}`);
      lines.push(`Request failed: ${err.message}`);
      appendSummary(lines.join("\n") + "\n", env);
      setOutputs({ "url-count": urls.length, "submitted-count": submitted, "status-code": "", "skipped-count": skipped }, env);
      return 1;
    }
    lastStatus = result.status;
    const meaning = STATUS_TEXT[result.status] || "unexpected status";
    if (result.status === 200 || result.status === 202) {
      submitted += batch.length;
      log(`indexnow-ping: batch of ${batch.length} URL(s) accepted (${result.status} ${meaning})`);
    } else {
      log(`::error::indexnow-ping: endpoint answered ${result.status} ${meaning}${result.text ? `: ${result.text}` : ""}`);
      lines.push(`Endpoint answered **${result.status}** (${meaning}).`);
      appendSummary(lines.join("\n") + "\n", env);
      setOutputs({ "url-count": urls.length, "submitted-count": submitted, "status-code": result.status, "skipped-count": skipped }, env);
      return 1;
    }
  }
  lines.push(`Submitted ${submitted} URL(s) to \`${inputs.endpoint}\` (status ${lastStatus}).`, "", ...urls.slice(0, 50).map((u) => `- ${u}`));
  if (urls.length > 50) lines.push(`- and ${urls.length - 50} more`);
  appendSummary(lines.join("\n") + "\n", env);
  setOutputs({ "url-count": urls.length, "submitted-count": submitted, "status-code": lastStatus, "skipped-count": skipped }, env);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run({ inputs: readInputs() }).then((code) => process.exit(code), (err) => {
    console.log(`::error::indexnow-ping: ${err.message}`);
    process.exit(2);
  });
}
