// Property and scaling tests for sbom-diff-comment: malformed SBOMs end with a clear message, never a
// TypeError, and diffing stays linear in the number of components. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { normalize, diff, renderMarkdown, readSbom, run, COLLAPSE_AFTER } from "../src/sbom_diff.mjs";

// Small deterministic generator, so a failure reproduces from its seed.
function rng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1103515245 + 12345) % 2147483648) / 2147483648);
}
const KEYS = ["bomFormat", "spdxVersion", "components", "packages", "name", "group", "version", "purl", "licenses", "license",
  "expression", "id", "SPDXID", "documentDescribes", "externalRefs", "referenceType", "referenceLocator", "versionInfo", "licenseConcluded", "type"];
function value(r, depth = 0) {
  const pick = (a) => a[Math.floor(r() * a.length)];
  const c = Math.floor(r() * (depth < 4 ? 9 : 5));
  if (c === 0) return pick([null, true, false]);
  if (c === 1) return Math.floor(r() * 10) - 5;
  if (c === 2) return pick(["", "CycloneDX", "SPDX-2.3", "pkg:npm/a@1", "MIT", "pkg:", "@"]);
  if (c === 3) return 1.5;
  if (c === 4) return "s";
  if (c < 7) return Array.from({ length: Math.floor(r() * 4) }, () => value(r, depth + 1));
  const o = {};
  for (let i = 0; i < Math.floor(r() * 5); i += 1) o[pick(KEYS)] = value(r, depth + 1);
  return o;
}

test("normalize, diff and renderMarkdown never throw a TypeError on malformed SBOMs", () => {
  const r = rng(20261028);
  for (let i = 0; i < 3000; i += 1) {
    const make = () => {
      const v = value(r);
      if (v && typeof v === "object" && !Array.isArray(v)) v[r() < 0.5 ? "bomFormat" : "spdxVersion"] = r() < 0.5 ? "CycloneDX" : "SPDX-2.3";
      return v;
    };
    let base;
    let head;
    try {
      base = normalize(make());
      head = normalize(make());
    } catch (err) {
      assert.match(err.message, /^(expected a JSON object|not a CycloneDX)/, `case ${i}: ${err.stack}`);
      continue;
    }
    const md = renderMarkdown(diff(base, head));
    assert.ok(md.startsWith("<!-- sbom-diff-comment:"), `case ${i}`);
  }
});

test("components with fields of the wrong type are read, not crashed on", () => {
  const n = normalize({ bomFormat: "CycloneDX", components: [{ name: 7, version: 2, purl: 5, licenses: [null, { expression: true }, { license: { id: "MIT" } }] }, null, "x"] });
  assert.equal(n.components.size, 1);
  const [c] = n.components.values();
  assert.equal(c.name, "7");
  assert.deepEqual(c.licenses, ["MIT"]);
  const s = normalize({ spdxVersion: "SPDX-2.3", documentDescribes: [{}], packages: [{ name: "a", externalRefs: [null, 4] }] });
  assert.equal(s.components.size, 1);
});

test("a top-level array or null is a clear error", () => {
  assert.throws(() => normalize([]), /expected a JSON object at the top level, found an array/);
  assert.throws(() => normalize(null), /found null/);
});

test("readSbom names the file and the problem", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbom-robust-"));
  writeFileSync(join(dir, "bad.json"), "{ not json");
  writeFileSync(join(dir, "list.json"), "[1, 2]");
  mkdirSync(join(dir, "folder.json"));
  assert.throws(() => readSbom(join(dir, "missing.json"), "base"), /cannot read base SBOM .*missing\.json: no such file/);
  assert.throws(() => readSbom(join(dir, "folder.json"), "head"), /cannot read head SBOM .*folder\.json: is a directory/);
  assert.throws(() => readSbom(join(dir, "bad.json"), "base"), /base SBOM .*bad\.json is not valid JSON/);
  assert.throws(() => readSbom(join(dir, "list.json"), "head"), /head SBOM .*list\.json: expected a JSON object/);
});

test("run exits 2 with one ::error:: line for unreadable input and a bad timeout", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sbom-robust-"));
  writeFileSync(join(dir, "bad.json"), "{");
  const log = [];
  const inputs = { base: join(dir, "bad.json"), head: join(dir, "bad.json"), comment: false, timeout: 30, markdownFile: join(dir, "out.md"), failOn: "none" };
  assert.equal(await run({ inputs, env: {}, log: (m) => log.push(m) }), 2);
  assert.equal(log.length, 1);
  assert.match(log[0], /^::error::sbom-diff-comment: base SBOM .* is not valid JSON/);
  const log2 = [];
  assert.equal(await run({ inputs: { ...inputs, timeout: Number("soon") }, env: {}, log: (m) => log2.push(m) }), 2);
  assert.match(log2[0], /timeout must be a number of seconds greater than 0/);
});

function spdx(n, version) {
  return {
    spdxVersion: "SPDX-2.3",
    documentDescribes: Array.from({ length: n }, (_, i) => `SPDXRef-root-${i}`),
    packages: Array.from({ length: n }, (_, i) => ({ name: `c${i}`, SPDXID: `SPDXRef-${i}`, versionInfo: version, licenseConcluded: "MIT" })),
  };
}
function timed(fn) {
  let best = Infinity;
  for (let i = 0; i < 3; i += 1) {
    const t = performance.now();
    fn();
    best = Math.min(best, performance.now() - t);
  }
  return Math.max(best, 0.5);
}

test("diffing scales linearly: ten times the components takes far less than a hundred times as long", () => {
  // documentDescribes.includes() per package made this quadratic: 50,000 packages took seconds.
  const small = timed(() => diff(normalize(spdx(2000, "1")), normalize(spdx(2000, "2"))));
  const large = timed(() => diff(normalize(spdx(20000, "1")), normalize(spdx(20000, "2"))));
  assert.ok(large / small < 40, `2,000 packages: ${small.toFixed(1)} ms, 20,000: ${large.toFixed(1)} ms`);
});

function delta(added) {
  return { added: Array.from({ length: added }, (_, i) => ({ name: `p${i}`, version: "1", licenses: ["MIT"] })), removed: [], changed: [], licenseChanges: [], baseCount: 0, headCount: added };
}

test(`a section with more than ${COLLAPSE_AFTER} rows is folded into <details>; shorter ones are not`, () => {
  const long = renderMarkdown(delta(COLLAPSE_AFTER + 1));
  assert.ok(long.startsWith("<!-- sbom-diff-comment:default -->"));
  assert.match(long, new RegExp(`### Added\\n\\n<details><summary>Added \\(${COLLAPSE_AFTER + 1}\\)</summary>\\n\\n\\| Component`));
  assert.match(long, /\| p10 \| 1 \| `MIT` \|\n\n<\/details>/);
  const short = renderMarkdown(delta(COLLAPSE_AFTER));
  assert.doesNotMatch(short, /<details>/);
  assert.match(short, /### Added\n\n\| Component/);
});

test("the 50-row cap still applies inside <details>", () => {
  const md = renderMarkdown(delta(120));
  assert.match(md, /<summary>Added \(120\)<\/summary>/);
  assert.match(md, /\| and 70 more \|/);
  assert.doesNotMatch(md, /\| p50 \|/);
});
