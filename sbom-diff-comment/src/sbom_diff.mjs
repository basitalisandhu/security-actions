#!/usr/bin/env node
// Diff two SBOM files (CycloneDX JSON or SPDX JSON) and post or update one pull request comment.
//
// Components are keyed by package URL without its version (or type/group/name when no purl exists), so a
// version bump shows as "changed" rather than one removal plus one addition. Licence sets are compared
// per component; a component whose licences differ between base and head is listed under licence changes.
//
// GitHub REST calls go through fetch with a bounded timeout, at most 5 pages of 100 comments when looking
// for the previous comment, and a body truncated to GitHub's 65,536 character limit.
//
// Outputs ($GITHUB_OUTPUT): added-count, removed-count, changed-count, license-change-count, comment-url, markdown-file.
// Exit codes: 0, 1 when fail-on matches or the comment could not be posted, 2 usage error. Node 18 or later.
import { readFileSync, writeFileSync, appendFileSync } from "node:fs";

const MARKER_PREFIX = "<!-- sbom-diff-comment";
const MAX_COMMENT_CHARS = 65000;
const MAX_ROWS = 50;
export const COLLAPSE_AFTER = 10; // sections with more rows than this are folded into <details>
const USER_AGENT = "sbom-diff-comment/1.0.0 (+https://github.com/basitalisandhu/security-actions)";

// SBOMs come from many generators; treat a field of the wrong JSON type as absent instead of crashing.
const str = (v) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");
const arr = (v) => (Array.isArray(v) ? v : []);
const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);

export function detectFormat(doc) {
  if (!obj(doc)) throw new Error(`expected a JSON object at the top level, found ${Array.isArray(doc) ? "an array" : doc === null ? "null" : typeof doc}`);
  if (doc && doc.bomFormat === "CycloneDX") return "cyclonedx";
  if (doc && (typeof doc.spdxVersion === "string" || doc.SPDXID === "SPDXRef-DOCUMENT")) return "spdx";
  throw new Error("not a CycloneDX JSON (bomFormat) or SPDX JSON (spdxVersion) document");
}

function stripPurlVersion(purl) {
  // pkg:type/namespace/name@version?qualifiers#subpath -> pkg:type/namespace/name
  const noFragment = purl.split("#")[0].split("?")[0];
  const at = noFragment.lastIndexOf("@");
  return at > "pkg:".length ? noFragment.slice(0, at) : noFragment;
}

function cycloneLicenses(c) {
  const out = [];
  for (const l of arr(c.licenses)) {
    if (!obj(l)) continue;
    if (str(l.expression)) out.push(str(l.expression));
    else if (obj(l.license)) out.push(str(l.license.id) || str(l.license.name));
  }
  return out.filter(Boolean);
}

function spdxLicenses(p) {
  const out = [];
  for (const v of [p.licenseConcluded, p.licenseDeclared]) {
    if (typeof v === "string" && v && v !== "NOASSERTION" && v !== "NONE") out.push(v);
  }
  return [...new Set(out)];
}

export function normalize(doc) {
  const format = detectFormat(doc);
  const items = [];
  if (format === "cyclonedx") {
    const walk = (components) => {
      for (const c of arr(components)) {
        if (!obj(c) || !str(c.name)) continue;
        const purl = str(c.purl);
        const group = str(c.group);
        const key = purl ? stripPurlVersion(purl) : `${str(c.type) || "library"}/${group ? `${group}/` : ""}${str(c.name)}`;
        items.push({ key, name: group ? `${group}/${str(c.name)}` : str(c.name), version: str(c.version), licenses: cycloneLicenses(c).sort(), purl });
        if (Array.isArray(c.components)) walk(c.components);
      }
    };
    walk(doc.components);
  } else {
    const packages = arr(doc.packages);
    const described = new Set(arr(doc.documentDescribes)); // a Set: includes() per package was quadratic
    for (const p of packages) {
      if (!obj(p) || !str(p.name)) continue;
      if (p.SPDXID && described.has(p.SPDXID) && packages.length > 1) continue; // the root package
      const ref = arr(p.externalRefs).find((r) => obj(r) && r.referenceType === "purl" && typeof r.referenceLocator === "string");
      const purl = ref ? ref.referenceLocator : "";
      const key = purl ? stripPurlVersion(purl) : `spdx/${str(p.name)}`;
      items.push({ key, name: str(p.name), version: str(p.versionInfo), licenses: spdxLicenses(p).sort(), purl });
    }
  }
  const byKey = new Map();
  for (const it of items) {
    const existing = byKey.get(it.key);
    if (!existing) byKey.set(it.key, { ...it, versions: new Set([it.version]) });
    else existing.versions.add(it.version);
  }
  return { format, components: byKey };
}

export function diff(base, head) {
  const added = [];
  const removed = [];
  const changed = [];
  const licenseChanges = [];
  const vs = (c) => [...c.versions].filter(Boolean).sort().join(", ");
  for (const [key, h] of head.components) {
    const b = base.components.get(key);
    if (!b) {
      added.push({ name: h.name, version: vs(h), licenses: h.licenses });
      continue;
    }
    if (vs(b) !== vs(h)) changed.push({ name: h.name, from: vs(b), to: vs(h) });
    if (b.licenses.join("|") !== h.licenses.join("|")) licenseChanges.push({ name: h.name, from: b.licenses, to: h.licenses, version: vs(h) });
  }
  for (const [key, b] of base.components) {
    if (!head.components.has(key)) removed.push({ name: b.name, version: vs(b), licenses: b.licenses });
  }
  const byName = (a, b) => a.name.localeCompare(b.name);
  return {
    added: added.sort(byName), removed: removed.sort(byName), changed: changed.sort(byName), licenseChanges: licenseChanges.sort(byName),
    baseCount: base.components.size, headCount: head.components.size,
  };
}

const esc = (s) => String(s).replace(/\|/g, "\\|").replace(/</g, "&lt;");
const lic = (l) => (l.length ? l.map((x) => `\`${esc(x)}\``).join(", ") : "_none declared_");

function table(headers, rows, render) {
  if (!rows.length) return ["_None._", ""];
  const out = [`| ${headers.join(" | ")} |`, `|${headers.map(() => "---").join("|")}|`];
  for (const r of rows.slice(0, MAX_ROWS)) out.push(`| ${render(r).join(" | ")} |`);
  if (rows.length > MAX_ROWS) out.push(`| and ${rows.length - MAX_ROWS} more |${" |".repeat(headers.length - 1)}`);
  out.push("");
  return out;
}

function section(title, headers, rows, render) {
  const body = table(headers, rows, render);
  if (rows.length <= COLLAPSE_AFTER) return [`### ${title}`, "", ...body];
  return [`### ${title}`, "", `<details><summary>${title} (${rows.length})</summary>`, "", ...body, "</details>", ""];
}

export function renderMarkdown(d, { title = "SBOM diff", marker = "default", baseLabel = "base", headLabel = "head" } = {}) {
  const lines = [
    `${MARKER_PREFIX}:${marker} -->`,
    `## ${title}`,
    "",
    `${headLabel} has **${d.headCount}** components (${baseLabel}: ${d.baseCount}): ` +
      `**${d.added.length}** added, **${d.removed.length}** removed, **${d.changed.length}** version changes, **${d.licenseChanges.length}** licence changes.`,
    "",
  ];
  if (!d.added.length && !d.removed.length && !d.changed.length && !d.licenseChanges.length) {
    lines.push("No component differences between the two SBOMs.", "");
    return lines.join("\n");
  }
  if (d.licenseChanges.length) {
    lines.push(...section("Licence changes", ["Component", "Was", "Now"], d.licenseChanges, (r) => [`${esc(r.name)} ${esc(r.version)}`, lic(r.from), lic(r.to)]));
  }
  lines.push(...section("Added", ["Component", "Version", "Licences"], d.added, (r) => [esc(r.name), esc(r.version), lic(r.licenses)]));
  lines.push(...section("Removed", ["Component", "Version", "Licences"], d.removed, (r) => [esc(r.name), esc(r.version), lic(r.licenses)]));
  lines.push(...section("Version changes", ["Component", "From", "To"], d.changed, (r) => [esc(r.name), esc(r.from), esc(r.to)]));
  return lines.join("\n");
}

export function truncate(body) {
  if (body.length <= MAX_COMMENT_CHARS) return body;
  const note = "\n\n_Comment truncated; the full diff is in the job summary and the markdown-file output._\n";
  return body.slice(0, MAX_COMMENT_CHARS - note.length) + note;
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

export async function upsertComment({ apiUrl, token, repo, prNumber, marker, body, fetchImpl = fetch, timeoutMs = 30000, maxPages = 5 }) {
  const headers = {
    authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28",
    "user-agent": USER_AGENT, "content-type": "application/json",
  };
  const base = `${apiUrl.replace(/\/$/, "")}/repos/${repo}/issues/${prNumber}/comments`;
  const needle = `${MARKER_PREFIX}:${marker} -->`;
  let existing = null;
  for (let page = 1; page <= maxPages && !existing; page += 1) {
    const res = await fetchWithTimeout(fetchImpl, `${base}?per_page=100&page=${page}`, { headers }, timeoutMs);
    if (!res.ok) throw new Error(`listing comments failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
    const comments = await res.json();
    existing = comments.find((c) => typeof c.body === "string" && c.body.startsWith(needle)) || null;
    if (comments.length < 100) break;
  }
  const payload = JSON.stringify({ body: truncate(body) });
  const res = existing
    ? await fetchWithTimeout(fetchImpl, `${apiUrl.replace(/\/$/, "")}/repos/${repo}/issues/comments/${existing.id}`, { method: "PATCH", headers, body: payload }, timeoutMs)
    : await fetchWithTimeout(fetchImpl, base, { method: "POST", headers, body: payload }, timeoutMs);
  if (!res.ok) throw new Error(`${existing ? "updating" : "creating"} the comment failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  return { action: existing ? "updated" : "created", id: data.id, url: data.html_url || "" };
}

export function readInputs(env = process.env) {
  const get = (name, fallback = "") => {
    const v = env[`INPUT_${name.toUpperCase().replace(/-/g, "_")}`];
    return v === undefined || v === "" ? fallback : v;
  };
  return {
    base: get("base"), head: get("head"), comment: get("comment", "true") === "true", token: get("token", env.GITHUB_TOKEN || ""),
    prNumber: get("pr-number"), title: get("title", "SBOM diff"), marker: get("marker", "default"),
    failOn: get("fail-on", "none"), markdownFile: get("markdown-file", "sbom-diff.md"), timeout: Number(get("timeout", "30")),
    apiUrl: env.GITHUB_API_URL || "https://api.github.com", repo: env.GITHUB_REPOSITORY || "", eventPath: env.GITHUB_EVENT_PATH || "",
  };
}

export function prNumberFromEvent(eventPath) {
  if (!eventPath) return "";
  try {
    const ev = JSON.parse(readFileSync(eventPath, "utf8"));
    const n = (ev.pull_request && ev.pull_request.number) || (ev.issue && ev.issue.pull_request && ev.issue.number) || (ev.workflow_run && ev.workflow_run.pull_requests && ev.workflow_run.pull_requests[0] && ev.workflow_run.pull_requests[0].number);
    return n ? String(n) : "";
  } catch {
    return "";
  }
}

export function readSbom(path, label) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(`cannot read ${label} SBOM ${path}: ${err.code === "ENOENT" ? "no such file" : err.code === "EISDIR" ? "is a directory" : err.message}`);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`${label} SBOM ${path} is not valid JSON (${err.message})`);
  }
  try {
    return normalize(doc);
  } catch (err) {
    throw new Error(`${label} SBOM ${path}: ${err.message}`);
  }
}

function setOutputs(values, env) {
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, Object.entries(values).map(([k, v]) => `${k}=${v}\n`).join(""));
}

export async function run({ inputs, env = process.env, fetchImpl = fetch, log = console.log }) {
  if (!inputs.base || !inputs.head) {
    log("::error::sbom-diff-comment: base and head are required");
    return 2;
  }
  if (!Number.isFinite(inputs.timeout) || inputs.timeout <= 0) {
    log(`::error::sbom-diff-comment: timeout must be a number of seconds greater than 0, got ${inputs.timeout}`);
    return 2;
  }
  let d;
  try {
    const base = readSbom(inputs.base, "base");
    const head = readSbom(inputs.head, "head");
    d = diff(base, head);
    log(`sbom-diff-comment: ${base.format} base (${d.baseCount}) vs ${head.format} head (${d.headCount}): +${d.added.length} -${d.removed.length} ~${d.changed.length}, ${d.licenseChanges.length} licence change(s)`);
  } catch (err) {
    log(`::error::sbom-diff-comment: ${err.message}`);
    return 2;
  }
  const body = renderMarkdown(d, { title: inputs.title, marker: inputs.marker });
  writeFileSync(inputs.markdownFile, body + "\n");
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, body.split("\n").slice(1).join("\n") + "\n");
  const outputs = {
    "added-count": d.added.length, "removed-count": d.removed.length, "changed-count": d.changed.length,
    "license-change-count": d.licenseChanges.length, "comment-url": "", "markdown-file": inputs.markdownFile,
  };
  let rc = 0;
  if (inputs.comment) {
    const prNumber = inputs.prNumber || prNumberFromEvent(inputs.eventPath);
    if (!prNumber) {
      log("::notice::sbom-diff-comment: not a pull request and no pr-number given; comment skipped");
    } else if (!inputs.token || !inputs.repo) {
      log("::error::sbom-diff-comment: a token and GITHUB_REPOSITORY are needed to comment");
      rc = 1;
    } else {
      try {
        const result = await upsertComment({ apiUrl: inputs.apiUrl, token: inputs.token, repo: inputs.repo, prNumber, marker: inputs.marker, body, fetchImpl, timeoutMs: Math.max(1, inputs.timeout) * 1000 });
        outputs["comment-url"] = result.url;
        log(`sbom-diff-comment: ${result.action} comment ${result.id}${result.url ? ` ${result.url}` : ""}`);
      } catch (err) {
        log(`::error::sbom-diff-comment: ${err.message}`);
        rc = 1;
      }
    }
  }
  setOutputs(outputs, env);
  const anyChange = d.added.length + d.removed.length + d.changed.length + d.licenseChanges.length > 0;
  if (inputs.failOn === "any-change" && anyChange) {
    log("::error::sbom-diff-comment: SBOM changed and fail-on is any-change");
    rc = 1;
  } else if (inputs.failOn === "license-change" && d.licenseChanges.length) {
    log(`::error::sbom-diff-comment: ${d.licenseChanges.length} licence change(s) and fail-on is license-change`);
    rc = 1;
  }
  return rc;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run({ inputs: readInputs() }).then((code) => process.exit(code), (err) => {
    console.log(`::error::sbom-diff-comment: ${err.message}`);
    process.exit(2);
  });
}
