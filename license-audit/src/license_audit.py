#!/usr/bin/env python3
"""Flag dependency licences that are not in an allowlist.

Reads one or more of:
  package-lock.json   lockfile v2/v3 "packages" entries (their "license" field, falling back to the installed
                      node_modules/<name>/package.json), or v1 "dependencies" (node_modules fallback only)
  requirements.txt    requirement names (with -r includes, extras, markers and specifiers stripped), resolved
                      against installed distribution metadata (License-Expression, License, or the
                      "License :: OSI Approved :: ..." classifiers); packages that are not installed are unknown
  CycloneDX JSON      components[].licenses (id, name or expression)
  SPDX JSON           packages[].licenseConcluded / licenseDeclared

Licence strings are normalised to SPDX ids where the mapping is unambiguous (aliases such as "Apache 2.0",
"GPLv3", "BSD License", deprecated ids such as GPL-3.0 and GPL-3.0+), and expressions with AND, OR, WITH and
parentheses are evaluated: an OR passes when any alternative is allowed, an AND needs every part allowed.

Statuses: allowed, disallowed (recognised licence outside the allowlist), denied (in the denylist), unknown
(no licence information, or an id that is neither recognised nor listed).

Outputs: SARIF 2.1.0 (--sarif), JSON (--json), Markdown summary to $GITHUB_STEP_SUMMARY (or --summary FILE),
$GITHUB_OUTPUT entries package-count, disallowed-count, unknown-count, sarif-file, gate.
Exit codes: 0, 1 when the gate fails (--fail-on disallowed or unknown), 2 usage error. Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path

TOOL_NAME = "license-audit"
TOOL_URI = "https://github.com/basitalisandhu/security-actions/tree/main/license-audit"
VERSION = "1.0.0"

DEFAULT_ALLOWLIST = [
    "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "ISC", "Unlicense", "CC0-1.0", "BlueOak-1.0.0",
    "Zlib", "PSF-2.0", "Python-2.0", "MPL-2.0", "CC-BY-4.0", "BSL-1.0", "Artistic-2.0", "OFL-1.1", "PostgreSQL", "Unicode-DFS-2016",
    "Unicode-3.0", "WTFPL", "MIT-CMU", "X11", "HPND",
]
# Canonical case for recognised SPDX ids (lookup is case-insensitive).
KNOWN_IDS = set(DEFAULT_ALLOWLIST) | {
    "GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "AGPL-1.0-only", "AGPL-3.0-only", "AGPL-3.0-or-later", "MPL-1.1", "MPL-1.0", "EPL-1.0", "EPL-2.0", "EUPL-1.1", "EUPL-1.2",
    "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "CC-BY-3.0", "CC-BY-SA-3.0", "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0",
    "SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "OSL-3.0", "AFL-3.0", "Apache-1.1", "Artistic-1.0", "BSD-4-Clause", "BSD-3-Clause-Clear",
    "BSD-2-Clause-Patent", "BSD-1-Clause", "Ruby", "NCSA", "ODbL-1.0", "OpenSSL", "Vim", "Zend-2.0", "Beerware", "curl", "ImageMagick",
    "LPPL-1.3c", "MS-PL", "MS-RL", "NPOSL-3.0", "OFL-1.0", "PHP-3.01", "Sleepycat", "UPL-1.0", "W3C", "LicenseRef-Proprietary",
}
KNOWN_LOWER = {k.lower(): k for k in KNOWN_IDS}
DEPRECATED = {
    "gpl-1.0": "GPL-1.0-only", "gpl-1.0+": "GPL-1.0-or-later", "gpl-2.0": "GPL-2.0-only", "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-3.0": "GPL-3.0-only", "gpl-3.0+": "GPL-3.0-or-later", "lgpl-2.0": "LGPL-2.0-only", "lgpl-2.0+": "LGPL-2.0-or-later",
    "lgpl-2.1": "LGPL-2.1-only", "lgpl-2.1+": "LGPL-2.1-or-later", "lgpl-3.0": "LGPL-3.0-only", "lgpl-3.0+": "LGPL-3.0-or-later",
    "agpl-3.0": "AGPL-3.0-only", "agpl-3.0+": "AGPL-3.0-or-later", "agpl-1.0": "AGPL-1.0-only",
}
ALIASES = {
    "mit license": "MIT", "the mit license": "MIT", "the mit license (mit)": "MIT", "expat": "MIT", "mit/x11": "MIT", "x11 license": "X11",
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache2": "Apache-2.0", "apache 2": "Apache-2.0", "apache": "Apache-2.0",
    "apache license": "Apache-2.0", "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0", "apache software license": "Apache-2.0", "asl 2.0": "Apache-2.0", "apache-2.0 license": "Apache-2.0",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause", "new bsd": "BSD-3-Clause", "new bsd license": "BSD-3-Clause", "modified bsd": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd 3-clause license": "BSD-3-Clause", "3-clause bsd": "BSD-3-Clause", "bsd3": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause", "simplified bsd license": "BSD-2-Clause", "bsd-2": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause",
    "2-clause bsd": "BSD-2-Clause", "freebsd": "BSD-2-Clause", "bsd2": "BSD-2-Clause", "bsd zero clause license": "0BSD", "zero-clause bsd": "0BSD",
    "isc license": "ISC", "isc license (iscl)": "ISC",
    "gplv2": "GPL-2.0-only", "gpl v2": "GPL-2.0-only", "gpl2": "GPL-2.0-only", "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later", "gpl v2+": "GPL-2.0-or-later", "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gplv3": "GPL-3.0-only", "gpl v3": "GPL-3.0-only", "gpl3": "GPL-3.0-only", "gnu general public license v3 (gplv3)": "GPL-3.0-only", "gnu gpl v3": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later", "gpl v3+": "GPL-3.0-or-later", "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu general public license (gpl)": "GPL-2.0-or-later",
    "lgplv2.1": "LGPL-2.1-only", "lgpl v2.1": "LGPL-2.1-only", "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later", "lgplv2.1+": "LGPL-2.1-or-later",
    "lgplv3": "LGPL-3.0-only", "lgpl v3": "LGPL-3.0-only", "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "lgplv3+": "LGPL-3.0-or-later", "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "gnu library or lesser general public license (lgpl)": "LGPL-2.1-or-later", "lgpl": "LGPL-2.1-or-later",
    "agplv3": "AGPL-3.0-only", "agpl v3": "AGPL-3.0-only", "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later", "agplv3+": "AGPL-3.0-or-later",
    "mpl 2.0": "MPL-2.0", "mpl-2": "MPL-2.0", "mpl2": "MPL-2.0", "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
    "psf": "PSF-2.0", "psfl": "PSF-2.0", "python software foundation license": "PSF-2.0", "psf license": "PSF-2.0", "python software foundation": "PSF-2.0",
    "unlicense": "Unlicense", "the unlicense": "Unlicense", "the unlicense (unlicense)": "Unlicense",
    "cc0": "CC0-1.0", "cc0-1.0": "CC0-1.0", "cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0", "cc0 1.0 universal": "CC0-1.0",
    "zlib/libpng": "Zlib", "zlib/libpng license": "Zlib", "zlib license": "Zlib",
    "boost software license 1.0 (bsl-1.0)": "BSL-1.0", "boost software license": "BSL-1.0",
    "eclipse public license 1.0 (epl-1.0)": "EPL-1.0", "eclipse public license 2.0 (epl-2.0)": "EPL-2.0", "eclipse public license": "EPL-2.0",
    "european union public licence 1.2 (eupl 1.2)": "EUPL-1.2", "artistic license": "Artistic-2.0", "artistic": "Artistic-2.0",
    "sil open font license 1.1 (ofl-1.1)": "OFL-1.1", "creative commons attribution 4.0": "CC-BY-4.0", "cc-by": "CC-BY-4.0",
    "academic free license (afl)": "AFL-3.0", "common development and distribution license 1.0 (cddl-1.0)": "CDDL-1.0",
    "server side public license (sspl)": "SSPL-1.0", "business source license 1.1": "BUSL-1.1", "elastic license 2.0": "Elastic-2.0",
    "proprietary": "LicenseRef-Proprietary", "other/proprietary license": "LicenseRef-Proprietary", "commercial": "LicenseRef-Proprietary",
    "do what the f*ck you want to public license": "WTFPL", "wtfpl": "WTFPL", "public domain": "CC0-1.0",
}
UNKNOWN_STRINGS = {"", "unknown", "unlicensed", "none", "noassertion", "see license", "see licence", "see license in license", "see license.md",
                   "see license.txt", "custom", "other", "undefined", "null", "licence", "license", "tbd", "n/a", "na", "various"}
CLASSIFIER_RE = re.compile(r"^License\s*::\s*(?:OSI Approved\s*::\s*)?(.+?)\s*$")
STATUS_ORDER = ["allowed", "unknown", "disallowed", "denied"]  # OR takes the best (lowest), AND the worst (highest)
TOKEN_RE = re.compile(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|/|,|[^()\s/,]+", re.I)


def canonical(raw: str) -> str | None:
    """Map a licence string to an SPDX id. Returns None when the string carries no licence information."""
    s = (raw or "").strip().strip("\"'").rstrip(".")
    low = s.lower()
    if low in UNKNOWN_STRINGS or low.startswith(("see ", "license in ", "refer to")):
        return None
    if low in DEPRECATED:
        return DEPRECATED[low]
    if low in KNOWN_LOWER:
        return KNOWN_LOWER[low]
    if low in ALIASES:
        return ALIASES[low]
    cm = CLASSIFIER_RE.match(s)
    if cm:
        return canonical(cm.group(1))
    low2 = re.sub(r"\s+", " ", low.replace("licence", "license"))
    if low2 in ALIASES:
        return ALIASES[low2]
    return s


class Policy:
    def __init__(self, allowlist: list[str], denylist: list[str] | None = None):
        self.allow = {a.strip().lower() for a in allowlist if a.strip()}
        self.deny = {d.strip().lower() for d in (denylist or []) if d.strip()}

    def leaf(self, lic: str) -> str:
        c = canonical(lic)
        if c is None:
            return "unknown"
        for candidate in {c.lower(), lic.strip().lower()}:
            if candidate in self.deny:
                return "denied"
        for candidate in {c.lower(), lic.strip().lower()}:
            if candidate in self.allow:
                return "allowed"
        return "disallowed" if c in KNOWN_IDS else "unknown"

    def evaluate(self, expression: str) -> str:
        tokens = [t for t in TOKEN_RE.findall(expression or "") if t.strip()]
        if not tokens:
            return "unknown"
        pos = 0

        def peek():
            return tokens[pos] if pos < len(tokens) else None

        def take():
            nonlocal pos
            pos += 1
            return tokens[pos - 1]

        def parse_or():
            left = parse_and()
            while peek() is not None and (peek().upper() == "OR" or peek() in {"/", ","}):
                take()
                right = parse_and()
                left = min(left, right, key=STATUS_ORDER.index)
            return left

        def parse_and():
            left = parse_factor()
            while peek() is not None and peek().upper() == "AND":
                take()
                right = parse_factor()
                left = max(left, right, key=STATUS_ORDER.index)
            return left

        def parse_factor():
            t = peek()
            if t is None:
                return "unknown"
            if t == "(":
                take()
                inner = parse_or()
                if peek() == ")":
                    take()
                return inner
            if t == ")":
                take()
                return "unknown"
            take()
            lic = t
            if peek() is not None and peek().upper() == "WITH":
                take()
                exc = take() if peek() is not None else ""
                full = f"{lic} WITH {exc}"
                if full.lower() in self.allow:
                    return "allowed"
                if full.lower() in self.deny:
                    return "denied"
            return self.leaf(lic)

        try:
            result = parse_or()
        except RecursionError:
            return "unknown"
        return result


class Package:
    __slots__ = ("name", "version", "licenses", "source", "line", "ecosystem", "dev", "status")

    def __init__(self, name, version, licenses, source, line, ecosystem, dev=False):
        self.name, self.version, self.licenses, self.source, self.line, self.ecosystem, self.dev = name, version, list(licenses), source, line, ecosystem, dev
        self.status = "unknown"

    @property
    def expression(self) -> str:
        parts = [l for l in self.licenses if l and l.strip()]
        if not parts:
            return ""
        return parts[0] if len(parts) == 1 else " AND ".join(f"({p})" if " " in p else p for p in parts)

    def as_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "licenses": self.licenses, "expression": self.expression, "status": self.status,
                "source": self.source, "line": self.line, "ecosystem": self.ecosystem, "dev": self.dev}


# ------------------------------------------------------------------------------- readers
def line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def license_from_package_json(data: dict) -> list[str]:
    lic = data.get("license")
    if isinstance(lic, str):
        return [lic]
    if isinstance(lic, dict) and isinstance(lic.get("type"), str):
        return [lic["type"]]
    lics = data.get("licenses")
    if isinstance(lics, list):
        out = []
        for l in lics:
            if isinstance(l, str):
                out.append(l)
            elif isinstance(l, dict) and isinstance(l.get("type"), str):
                out.append(l["type"])
        if out:
            return [" OR ".join(out)] if len(out) > 1 else out
    return []


def read_package_lock(path: Path, root: Path, include_dev: bool = True) -> list[Package]:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    pkgs: list[Package] = []
    seen: set[tuple[str, str]] = set()
    base_dir = path.parent

    def add(name: str, version: str, licenses: list[str], key: str, dev: bool, install_path: str):
        if (name, version) in seen:
            return
        if not licenses:
            pj = base_dir / install_path / "package.json"
            if pj.is_file():
                try:
                    licenses = license_from_package_json(json.loads(pj.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    licenses = []
        if dev and not include_dev:
            return
        seen.add((name, version))
        pkgs.append(Package(name, version, licenses, rel, line_of(text, f'"{key}"'), "npm", dev))

    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or "node_modules/" not in key:
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
            lic = entry.get("license")
            licenses = [lic] if isinstance(lic, str) else license_from_package_json(entry)
            add(name, str(entry.get("version", "")), licenses, key, bool(entry.get("dev")), key)
        return pkgs

    def walk(deps: dict, prefix: str):
        for name, entry in (deps or {}).items():
            if not isinstance(entry, dict):
                continue
            install = f"{prefix}node_modules/{name}"
            add(name, str(entry.get("version", "")), [], name, bool(entry.get("dev")), install)
            if isinstance(entry.get("dependencies"), dict):
                walk(entry["dependencies"], install + "/")

    walk(data.get("dependencies") or {}, "")
    return pkgs


def normalize_py_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path, _seen: set[Path] | None = None) -> list[tuple[str, Path, int]]:
    """Return (normalized name, file, line) for every requirement, following -r includes."""
    seen = _seen if _seen is not None else set()
    path = path.resolve()
    if path in seen or not path.is_file():
        return []
    seen.add(path)
    out: list[tuple[str, Path, int]] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            inc = line.split(None, 1)[1].strip()
            if line.startswith(("-r", "--requirement")):
                out.extend(parse_requirements(path.parent / inc, seen))
            continue
        if line.startswith("-") or "://" in line or line.startswith((".", "/")):
            continue  # options, URLs and local paths carry no resolvable name
        spec = line.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
        if m:
            out.append((normalize_py_name(m.group(1)), path, n))
    return out


def installed_licenses(search_path: list[str] | None = None) -> dict[str, tuple[str, list[str]]]:
    """Map normalized distribution name -> (version, licence strings) for the installed metadata."""
    found: dict[str, tuple[str, list[str]]] = {}
    dists = importlib_metadata.distributions(path=search_path) if search_path else importlib_metadata.distributions()
    for dist in dists:
        try:
            meta = dist.metadata
            name = meta["Name"]
        except Exception:  # noqa: BLE001 - broken metadata directories are skipped
            continue
        if not name:
            continue
        lics: list[str] = []
        expr = meta.get("License-Expression")
        if expr:
            lics = [expr]
        else:
            lic = meta.get("License")
            if lic and lic.strip().lower() not in UNKNOWN_STRINGS and "\n" not in lic.strip() and len(lic) <= 100:
                lics = [lic.strip()]
            else:
                classifiers = [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
                ids = [canonical(c) for c in classifiers]
                ids = [i for i in ids if i]
                if ids:
                    lics = [" OR ".join(dict.fromkeys(ids))] if len(ids) > 1 else ids
        found[normalize_py_name(name)] = (dist.version or "", lics)
    return found


def read_requirements(path: Path, root: Path, search_path: list[str] | None = None, installed: dict | None = None) -> list[Package]:
    installed = installed if installed is not None else installed_licenses(search_path)
    pkgs: list[Package] = []
    seen: set[str] = set()
    for name, file, line in parse_requirements(path):
        if name in seen:
            continue
        seen.add(name)
        rel = file.relative_to(root).as_posix() if file.is_relative_to(root) else file.as_posix()
        version, lics = installed.get(name, ("", []))
        pkgs.append(Package(name, version, lics, rel, line, "pypi"))
    return pkgs


def read_cyclonedx(path: Path, root: Path, data: dict) -> list[Package]:
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    pkgs: list[Package] = []

    def walk(components):
        for c in components or []:
            if not isinstance(c, dict) or not c.get("name"):
                continue
            lics = []
            for l in c.get("licenses") or []:
                if not isinstance(l, dict):
                    continue
                if l.get("expression"):
                    lics.append(l["expression"])
                elif isinstance(l.get("license"), dict):
                    lics.append(l["license"].get("id") or l["license"].get("name") or "")
            name = f"{c['group']}/{c['name']}" if c.get("group") else c["name"]
            purl = c.get("purl") or ""
            eco = purl.split(":", 1)[1].split("/", 1)[0] if purl.startswith("pkg:") else "sbom"
            needle = f'"purl": "{purl}"' if purl else f'"name": "{c["name"]}"'
            pkgs.append(Package(name, str(c.get("version", "")), [l for l in lics if l], rel, line_of(text, needle), eco))
            walk(c.get("components"))

    walk(data.get("components"))
    return pkgs


def read_spdx(path: Path, root: Path, data: dict) -> list[Package]:
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    pkgs: list[Package] = []
    described = set(data.get("documentDescribes") or [])
    packages = data.get("packages") or []
    for p in packages:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        if p.get("SPDXID") in described and len(packages) > 1:
            continue
        lics = [v for v in (p.get("licenseConcluded"), p.get("licenseDeclared")) if isinstance(v, str) and v.strip().upper() not in {"", "NOASSERTION", "NONE"}]
        lics = list(dict.fromkeys(lics))
        ref = next((r for r in p.get("externalRefs") or [] if isinstance(r, dict) and r.get("referenceType") == "purl"), None)
        purl = ref.get("referenceLocator", "") if ref else ""
        eco = purl.split(":", 1)[1].split("/", 1)[0] if purl.startswith("pkg:") else "sbom"
        pkgs.append(Package(p["name"], str(p.get("versionInfo", "")), lics[:1] if lics and lics[0] == lics[-1] else lics, rel, line_of(text, f'"{p.get("SPDXID", p["name"])}"'), eco))
    return pkgs


def read_any(path: Path, root: Path, include_dev: bool, search_path: list[str] | None) -> list[Package]:
    name = path.name
    if name == "package-lock.json" or name == "npm-shrinkwrap.json":
        return read_package_lock(path, root, include_dev)
    if name.endswith(".txt") or name.endswith(".in"):
        return read_requirements(path, root, search_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
        return read_cyclonedx(path, root, data)
    if isinstance(data, dict) and (data.get("spdxVersion") or data.get("SPDXID")):
        return read_spdx(path, root, data)
    raise ValueError(f"{path}: not a package-lock.json, requirements file, CycloneDX or SPDX document")


def autodetect(root: Path) -> list[Path]:
    found = [p for p in [root / "package-lock.json", root / "requirements.txt"] if p.is_file()]
    for pattern in ["*.cdx.json", "bom.json", "sbom.json", "*.spdx.json", "sbom.cdx.json"]:
        found += [p for p in sorted(root.glob(pattern)) if p.is_file() and p not in found]
    return found


# ------------------------------------------------------------------------------- reporting
RULES = [
    ("LIC-001", "Licence not in the allowlist", "warning", "Add the licence to the allowlist if it is acceptable for this project, or replace the dependency."),
    ("LIC-002", "Licence in the denylist", "error", "Replace the dependency; this licence is explicitly rejected by the policy."),
    ("LIC-003", "Licence unknown or undeclared", "note", "Check the package's repository for its licence and record it (allowlist entry, SBOM licence field, or installed metadata)."),
]
RULE_FOR_STATUS = {"disallowed": "LIC-001", "denied": "LIC-002", "unknown": "LIC-003"}


def to_sarif(packages: list[Package]) -> dict:
    rules = [{"id": rid, "name": rid.replace("-", ""), "shortDescription": {"text": title}, "fullDescription": {"text": title + "."},
              "help": {"text": help_text, "markdown": help_text}, "helpUri": TOOL_URI + "#rules",
              "defaultConfiguration": {"level": level}, "properties": {"tags": ["supply-chain", "license"], "precision": "high"}}
             for rid, title, level, help_text in RULES]
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for p in packages:
        if p.status == "allowed":
            continue
        rid = RULE_FOR_STATUS[p.status]
        expr = p.expression or "no licence declared"
        msg = f"{p.name} {p.version}".strip() + f" ({p.ecosystem}) has licence {expr}: {p.status}. " + RULES[index[rid]][3]
        results.append({
            "ruleId": rid, "ruleIndex": index[rid], "level": rules[index[rid]]["defaultConfiguration"]["level"],
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": p.source, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": max(1, p.line)}}}],
            "partialFingerprints": {"primaryLocationLineHash": hashlib.sha256(f"{rid}|{p.source}|{p.ecosystem}|{p.name}".encode()).hexdigest()},
            "properties": {"package": p.name, "version": p.version, "license": expr, "status": p.status, "dev": p.dev},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": VERSION, "informationUri": TOOL_URI, "rules": rules}},
                      "results": results, "columnKind": "utf16CodeUnits"}]}


def to_summary(packages: list[Package], sources: list[str], max_rows: int = 100) -> str:
    counts = {s: sum(1 for p in packages if p.status == s) for s in STATUS_ORDER}
    lines = ["## Licence audit", "", f"Sources: {', '.join(f'`{s}`' for s in sources) or 'none'}. Packages: **{len(packages)}** "
             f"(allowed {counts['allowed']}, disallowed {counts['disallowed']}, denied {counts['denied']}, unknown {counts['unknown']}).", ""]
    flagged = [p for p in packages if p.status != "allowed"]
    if flagged:
        lines += ["| Status | Package | Version | Licence | Source |", "|---|---|---|---|---|"]
        for p in flagged[:max_rows]:
            lines.append(f"| {p.status} | {p.name}{' (dev)' if p.dev else ''} | {p.version} | `{(p.expression or 'none declared').replace('|', chr(92) + '|')}` | `{p.source}:{p.line}` |")
        if len(flagged) > max_rows:
            lines.append(f"| ... | {len(flagged) - max_rows} more in the SARIF report | | | |")
    else:
        lines.append("Every package licence is in the allowlist.")
    dist: dict[str, int] = {}
    for p in packages:
        dist[p.expression or "none declared"] = dist.get(p.expression or "none declared", 0) + 1
    if dist:
        lines += ["", "<details><summary>Licence distribution</summary>", "", "| Licence | Packages |", "|---|---|"]
        lines += [f"| `{k}` | {v} |" for k, v in sorted(dist.items(), key=lambda kv: (-kv[1], kv[0]))[:40]]
        lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def append_file(env_name: str, text: str, override: str | None = None) -> None:
    target = override or os.environ.get(env_name)
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)


def split_list(raw: str) -> list[str]:
    return [x.strip() for x in re.split(r"[\n,]", raw or "") if x.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="project directory (paths in reports are relative to it)")
    ap.add_argument("--input", action="append", default=[], help="file to read (repeatable); default: auto-detect in --root")
    ap.add_argument("--allowlist", default="", help="comma or newline separated SPDX ids; empty uses the built-in permissive list")
    ap.add_argument("--denylist", default="", help="comma or newline separated SPDX ids that always fail")
    ap.add_argument("--ignore-packages", default="", help="comma or newline separated package names to skip")
    ap.add_argument("--no-dev", action="store_true", help="skip npm dev dependencies")
    ap.add_argument("--site-packages", default="", help="directory with installed Python metadata (default: the running interpreter's)")
    ap.add_argument("--fail-on", choices=["disallowed", "unknown", "none"], default="disallowed")
    ap.add_argument("--sarif", default="license-audit.sarif")
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--summary", default="")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"::error::{TOOL_NAME}: {root} is not a directory", file=sys.stderr)
        return 2
    inputs = [Path(i) if Path(i).is_absolute() else root / i for i in args.input if i.strip()] or autodetect(root)
    if not inputs:
        print(f"::error::{TOOL_NAME}: no package-lock.json, requirements.txt or SBOM found in {root}; pass --input", file=sys.stderr)
        return 2
    policy = Policy(split_list(args.allowlist) or DEFAULT_ALLOWLIST, split_list(args.denylist))
    ignored = {normalize_py_name(x) for x in split_list(args.ignore_packages)}
    search_path = [args.site_packages] if args.site_packages else None
    packages: list[Package] = []
    sources: list[str] = []
    for path in inputs:
        if not path.is_file():
            print(f"::error::{TOOL_NAME}: {path} not found", file=sys.stderr)
            return 2
        try:
            found = read_any(path, root, include_dev=not args.no_dev, search_path=search_path)
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            print(f"::error::{TOOL_NAME}: {exc}", file=sys.stderr)
            return 2
        sources.append(path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path))
        packages.extend(p for p in found if normalize_py_name(p.name) not in ignored)
    for p in packages:
        p.status = policy.evaluate(p.expression)
    packages.sort(key=lambda p: (STATUS_ORDER.index(p.status) * -1, p.source, p.name.lower()))

    Path(args.sarif).write_text(json.dumps(to_sarif(packages), indent=1), encoding="utf-8")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"tool": TOOL_NAME, "version": VERSION, "sources": sources,
                                                    "packages": [p.as_dict() for p in packages]}, indent=1) + "\n", encoding="utf-8")
    append_file("GITHUB_STEP_SUMMARY", to_summary(packages, sources), args.summary or None)
    disallowed = sum(1 for p in packages if p.status in {"disallowed", "denied"})
    unknown = sum(1 for p in packages if p.status == "unknown")
    gate = "pass"
    if args.fail_on == "disallowed" and disallowed:
        gate = "fail"
    elif args.fail_on == "unknown" and (disallowed or unknown):
        gate = "fail"
    append_file("GITHUB_OUTPUT", f"package-count={len(packages)}\ndisallowed-count={disallowed}\nunknown-count={unknown}\nsarif-file={args.sarif}\ngate={gate}\n")
    for p in packages:
        if p.status == "allowed":
            continue
        cmd = {"denied": "error", "disallowed": "warning", "unknown": "notice"}[p.status]
        print(f"::{cmd} file={p.source},line={p.line},title={RULE_FOR_STATUS[p.status]}::{p.name} {p.version}: {p.expression or 'no licence declared'} ({p.status})")
    print(f"{TOOL_NAME}: {len(packages)} package(s), {disallowed} disallowed or denied, {unknown} unknown, gate {gate} (fail-on {args.fail_on})")
    return 1 if gate == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
