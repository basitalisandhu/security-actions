#!/usr/bin/env python3
"""Check that a site serves an llms.txt that follows the convention, or generate one from a docs directory.

The llms.txt convention (llmstxt.org): a Markdown file at /llms.txt that starts with an H1 (the project
name), optionally followed by a blockquote summary, then free-form Markdown without further headings,
then zero or more H2 sections whose content is a list of links "- [name](url): optional notes". A section
named "Optional" marks links that can be skipped when context is short.

check mode     --source DIR_OR_URL   reads DIR/llms.txt, or fetches URL/llms.txt (urllib, bounded timeout)
generate mode  --docs-dir DIR        walks Markdown files and writes --output (default llms.txt), then checks it

Rules: LLMS-001 file missing (error), LLMS-002 first content line is not an H1 (error), LLMS-003 no blockquote
summary (warning), LLMS-004 no H2 link sections (warning), LLMS-005 section without links (warning), LLMS-006
list item that is not a Markdown link (warning), LLMS-007 heading deeper than H2 (warning), LLMS-008 more than
one H1 (error), LLMS-009 relative link that does not resolve in the site directory (warning), LLMS-010 remote
link that does not answer 2xx or 3xx (warning, only with --check-links on a URL source), LLMS-011 empty link
target (warning), LLMS-012 duplicate link target (note), LLMS-013 file is empty (error), LLMS-014 no
llms-full.txt next to it (note).

Outputs: JSON report (--json), Markdown summary appended to $GITHUB_STEP_SUMMARY (or --summary FILE), workflow
annotations on stdout, $GITHUB_OUTPUT entries status, error-count, warning-count, llms-txt-path.
Exit codes: 0 pass, 1 fail according to --fail-on, 2 usage error. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

TOOL_NAME = "llms-txt-check"
VERSION = "1.0.0"
LEVEL_ORDER = ["error", "warning", "note"]
H1_RE = re.compile(r"^#\s+(.+?)\s*$")
H2_RE = re.compile(r"^##\s+(.+?)\s*$")
HEADING_RE = re.compile(r"^(#{1,6})\s+")
LIST_RE = re.compile(r"^\s*[-*+]\s+(.*)$")
LINK_ITEM_RE = re.compile(r"^\[([^\]]*)\]\(([^)\s]*)\)\s*(?::\s*(.*))?$")
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)
TITLE_RE = re.compile(r"(?m)^title\s*:\s*[\"']?(.+?)[\"']?\s*$")
MD_INLINE_RE = re.compile(r"`([^`]*)`|\*\*([^*]+)\*\*|\*([^*]+)\*|\[([^\]]+)\]\([^)]*\)|<[^>]+>")
DEFAULT_TIMEOUT = 10
MAX_REMOTE_LINKS = 50


class Problem:
    __slots__ = ("rule", "level", "message", "line")

    def __init__(self, rule: str, level: str, message: str, line: int | None = None):
        self.rule, self.level, self.message, self.line = rule, level, message, line

    def as_dict(self) -> dict:
        return {"rule": self.rule, "level": self.level, "message": self.message, "line": self.line}


# ----------------------------------------------------------------------------- parsing
def parse(text: str) -> dict:
    """Split an llms.txt into title, summary, preamble and sections [{name, line, links, other}]."""
    doc = {"title": None, "title_line": None, "summary": None, "h1_count": 0, "preamble": [], "sections": [], "deep_headings": []}
    current = None
    in_code = False
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if line.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = H1_RE.match(line)
        if m and not line.startswith("##"):
            doc["h1_count"] += 1
            if doc["title"] is None:
                doc["title"], doc["title_line"] = m.group(1), n
            continue
        m = H2_RE.match(line)
        if m and not line.startswith("###"):
            current = {"name": m.group(1), "line": n, "links": [], "other": []}
            doc["sections"].append(current)
            continue
        hm = HEADING_RE.match(line)
        if hm and len(hm.group(1)) >= 3:
            doc["deep_headings"].append((n, line.strip()))
            continue
        if current is None:
            if doc["title"] is not None and doc["summary"] is None and line.startswith(">"):
                doc["summary"] = line[1:].strip()
            elif line.strip():
                doc["preamble"].append((n, line))
            continue
        lm = LIST_RE.match(line)
        if lm:
            item = LINK_ITEM_RE.match(lm.group(1).strip())
            if item:
                current["links"].append({"line": n, "name": item.group(1), "url": item.group(2), "notes": item.group(3) or ""})
            else:
                current["other"].append((n, line.strip()))
        elif line.strip():
            current["other"].append((n, line.strip()))
    return doc


# ----------------------------------------------------------------------------- checking
def resolve_relative(site_dir: Path, url: str) -> bool:
    target = url.split("#", 1)[0].split("?", 1)[0]
    if not target or target in {"/", "."}:
        return True
    rel = target.lstrip("/")
    candidates = [site_dir / rel]
    if not rel.endswith("/"):
        candidates += [site_dir / (rel + ".md"), site_dir / (rel + ".html"), site_dir / rel / "index.html", site_dir / rel / "index.md"]
    else:
        candidates += [site_dir / rel / "index.html", site_dir / rel / "index.md"]
    return any(c.exists() for c in candidates)


def head_ok(url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except urllib.error.HTTPError as exc:
        if exc.code in {405, 403}:  # some hosts refuse HEAD; try a bounded GET
            try:
                req = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{VERSION}", "Range": "bytes=0-0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return 200 <= resp.status < 400
            except (urllib.error.URLError, OSError, ValueError):
                return False
        return False
    except (urllib.error.URLError, OSError, ValueError):
        return False


def check_text(text: str, site_dir: Path | None = None, base_url: str = "", check_links: bool = False,
               link_checker=head_ok, has_full: bool | None = None) -> list[Problem]:
    problems: list[Problem] = []
    if not text.strip():
        return [Problem("LLMS-013", "error", "llms.txt is empty")]
    doc = parse(text)
    first = next((n for n, l in enumerate(text.splitlines(), 1) if l.strip()), 1)
    if doc["title"] is None or doc["title_line"] != first:
        problems.append(Problem("LLMS-002", "error", "The first line must be an H1 with the project or site name (for example '# Acme Docs')", first))
    if doc["h1_count"] > 1:
        problems.append(Problem("LLMS-008", "error", f"Only one H1 is allowed; found {doc['h1_count']}", doc["title_line"]))
    if doc["title"] is not None and doc["summary"] is None:
        problems.append(Problem("LLMS-003", "warning", "No blockquote summary after the H1 (a line starting with '> ' that says what the site is)", doc["title_line"]))
    for n, h in doc["deep_headings"]:
        problems.append(Problem("LLMS-007", "warning", f"Headings deeper than H2 are not part of the convention: {h}", n))
    if not doc["sections"]:
        problems.append(Problem("LLMS-004", "warning", "No H2 sections with link lists; add sections such as '## Docs' with '- [Title](url): note' entries"))
    seen: dict[str, int] = {}
    remote_checked = 0
    for s in doc["sections"]:
        if not s["links"]:
            problems.append(Problem("LLMS-005", "warning", f"Section '{s['name']}' has no link entries", s["line"]))
        for n, other in s["other"]:
            problems.append(Problem("LLMS-006", "warning", f"Section '{s['name']}' contains a line that is not a '- [name](url): notes' link: {other[:80]}", n))
        for link in s["links"]:
            url = link["url"].strip()
            if not url:
                problems.append(Problem("LLMS-011", "warning", f"Link '{link['name']}' has an empty target", link["line"]))
                continue
            if url in seen:
                problems.append(Problem("LLMS-012", "note", f"Duplicate link target {url} (first at line {seen[url]})", link["line"]))
            seen.setdefault(url, link["line"])
            is_remote = url.startswith(("http://", "https://"))
            if is_remote and base_url and url.startswith(base_url.rstrip("/") + "/") and site_dir is not None:
                url_for_fs = url[len(base_url.rstrip("/")):]
                if not resolve_relative(site_dir, url_for_fs):
                    problems.append(Problem("LLMS-009", "warning", f"Link {url} does not resolve to a file under the site directory", link["line"]))
            elif not is_remote and site_dir is not None:
                if not resolve_relative(site_dir, url):
                    problems.append(Problem("LLMS-009", "warning", f"Relative link {url} does not resolve to a file under the site directory", link["line"]))
            elif is_remote and check_links and remote_checked < MAX_REMOTE_LINKS:
                remote_checked += 1
                if not link_checker(url):
                    problems.append(Problem("LLMS-010", "warning", f"Link {url} did not answer with a 2xx or 3xx status", link["line"]))
    if has_full is False:
        problems.append(Problem("LLMS-014", "note", "No llms-full.txt found next to llms.txt (optional, holds the full documentation text)"))
    problems.sort(key=lambda p: (LEVEL_ORDER.index(p.level), p.line or 0, p.rule))
    return problems


def fetch_text(url: str, timeout: int = DEFAULT_TIMEOUT) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{VERSION}", "Accept": "text/plain, text/markdown, */*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def load_source(source: str, fetcher=fetch_text) -> tuple[str | None, str, Path | None, bool | None]:
    """Return (text, display path, site_dir or None, has llms-full.txt or None when unknown)."""
    if source.startswith(("http://", "https://")):
        base = source.rstrip("/")
        if not base.endswith("/llms.txt"):
            base = base + "/llms.txt"
        text = fetcher(base)
        return text, base, None, None
    p = Path(source)
    if p.is_dir():
        f = p / "llms.txt"
        site = p
    else:
        f = p
        site = p.parent
    if not f.is_file():
        return None, str(f), site, None
    return f.read_text(encoding="utf-8", errors="replace"), str(f), site, (site / "llms-full.txt").is_file()


# ----------------------------------------------------------------------------- generating
def strip_md(s: str) -> str:
    s = MD_INLINE_RE.sub(lambda m: next((g for g in m.groups() if g is not None), ""), s)
    return re.sub(r"\s+", " ", s).strip()


def title_and_excerpt(md: str, fallback: str) -> tuple[str, str]:
    title = None
    fm = FRONTMATTER_RE.match(md)
    body = md
    if fm:
        body = md[fm.end():]
        t = TITLE_RE.search(fm.group(1))
        if t:
            title = t.group(1).strip()
    lines = body.splitlines()
    excerpt = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if title is None and H1_RE.match(line) and not line.startswith("##"):
            title = H1_RE.match(line).group(1).strip()
            continue
        s = line.strip()
        if s.startswith("```"):
            # skip to the closing fence
            while i < len(lines) and not lines[i].strip().startswith("```"):
                i += 1
            i += 1
            continue
        if not s or HEADING_RE.match(s) or s.startswith(("<!--", "|", "- ", "* ", ">", "![", "import ", "export ")):
            continue
        excerpt = strip_md(s)
        break
    if len(excerpt) > 160:
        excerpt = excerpt[:157].rstrip() + "..."
    return (title or fallback), excerpt


def humanize(name: str) -> str:
    return re.sub(r"[-_]+", " ", name).strip().title() or "Docs"


def generate(docs_dir: Path, site_name: str, summary: str, site_url: str = "", link_format: str = "md",
             include: str = "**/*.md", excludes: tuple[str, ...] = ("node_modules", ".git", "_site", "site")) -> str:
    files = sorted(p for p in docs_dir.glob(include) if p.is_file() and not any(part in excludes for part in p.relative_to(docs_dir).parts))
    sections: dict[str, list[tuple[str, str, str]]] = {}
    for p in files:
        rel = p.relative_to(docs_dir)
        section = humanize(rel.parts[0]) if len(rel.parts) > 1 else "Docs"
        md = p.read_text(encoding="utf-8", errors="replace")
        title, excerpt = title_and_excerpt(md, humanize(p.stem))
        link = rel.as_posix()
        if link_format == "html":
            link = re.sub(r"(README|index)\.mdx?$", "index.html", link)
            link = re.sub(r"\.mdx?$", ".html", link)
        elif link_format == "none":
            link = re.sub(r"/(README|index)\.mdx?$", "/", "/" + link).lstrip("/")
            link = re.sub(r"\.mdx?$", "", link)
        if site_url:
            link = site_url.rstrip("/") + "/" + link
        else:
            link = "/" + link
        sections.setdefault(section, []).append((title, link, excerpt))
    out = [f"# {site_name}", "", f"> {summary.strip()}", ""]
    for section in sorted(sections, key=lambda s: (s != "Docs", s)):
        out += [f"## {section}", ""]
        entries = sorted(sections[section], key=lambda e: (not e[1].rstrip("/").endswith(("README.md", "index.md", "index.html", "index")), e[0].lower()))
        for title, link, excerpt in entries:
            out.append(f"- [{title}]({link})" + (f": {excerpt}" if excerpt else ""))
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


# ----------------------------------------------------------------------------- reporting
def to_summary(mode: str, where: str, problems: list[Problem], status: str) -> str:
    counts = {l: sum(1 for p in problems if p.level == l) for l in LEVEL_ORDER}
    lines = [f"## llms.txt {mode}", "", f"Source: `{where}`. Status: **{status}** (errors {counts['error']}, warnings {counts['warning']}, notes {counts['note']}).", ""]
    if problems:
        lines += ["| Level | Rule | Line | Message |", "|---|---|---|---|"]
        for p in problems[:200]:
            lines.append(f"| {p.level} | `{p.rule}` | {p.line or ''} | {p.message.replace('|', chr(92) + '|')} |")
    else:
        lines.append("The file follows the llms.txt convention: an H1, a blockquote summary and H2 sections of links.")
    return "\n".join(lines) + "\n"


def append_file(env_name: str, text: str, override: str | None = None) -> None:
    target = override or os.environ.get(env_name)
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["check", "generate"], default="check")
    ap.add_argument("--source", default=".", help="check: site directory, path to llms.txt, or site URL")
    ap.add_argument("--docs-dir", default="docs", help="generate: directory with Markdown files")
    ap.add_argument("--output", default="llms.txt", help="generate: where to write the file")
    ap.add_argument("--site-name", default="", help="generate: H1 text (default: the repository name)")
    ap.add_argument("--site-url", default="", help="generate: base URL for links (default: root-relative links)")
    ap.add_argument("--summary-text", default="", help="generate: blockquote summary")
    ap.add_argument("--link-format", choices=["md", "html", "none"], default="md", help="generate: keep .md, use .html, or drop the extension")
    ap.add_argument("--check-links", action="store_true", help="check remote links with HEAD requests (bounded to 50)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--fail-on", choices=["error", "warning", "none"], default="error")
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--summary", default="", help="write the Markdown summary here instead of $GITHUB_STEP_SUMMARY")
    args = ap.parse_args(argv)

    base_url = ""
    if args.mode == "generate":
        docs = Path(args.docs_dir)
        if not docs.is_dir():
            print(f"::error::{TOOL_NAME}: docs directory {docs} not found", file=sys.stderr)
            return 2
        name = args.site_name or os.environ.get("GITHUB_REPOSITORY", "Documentation").split("/")[-1]
        summary_text = args.summary_text or f"Documentation for {name}."
        text = generate(docs, name, summary_text, site_url=args.site_url, link_format=args.link_format)
        Path(args.output).write_text(text, encoding="utf-8")
        where = args.output
        site_dir = docs
        base_url = args.site_url
        has_full = None
        print(f"{TOOL_NAME}: wrote {where} ({text.count(chr(10))} lines)")
    else:
        text, where, site_dir, has_full = load_source(args.source, fetcher=lambda u: fetch_text(u, args.timeout))
        base_url = args.source if args.source.startswith(("http://", "https://")) else ""

    if text is None:
        problems = [Problem("LLMS-001", "error", f"llms.txt not found at {where}")]
    else:
        problems = check_text(text, site_dir=site_dir, base_url=base_url, check_links=args.check_links,
                              link_checker=lambda u: head_ok(u, args.timeout), has_full=has_full)
    counts = {l: sum(1 for p in problems if p.level == l) for l in LEVEL_ORDER}
    failed = (args.fail_on == "error" and counts["error"] > 0) or (args.fail_on == "warning" and (counts["error"] + counts["warning"]) > 0)
    status = "fail" if failed else "pass"

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"tool": TOOL_NAME, "version": VERSION, "mode": args.mode, "source": where, "status": status,
                                                    "problems": [p.as_dict() for p in problems]}, indent=1) + "\n", encoding="utf-8")
    append_file("GITHUB_STEP_SUMMARY", to_summary(args.mode, where, problems, status), args.summary or None)
    append_file("GITHUB_OUTPUT", f"status={status}\nerror-count={counts['error']}\nwarning-count={counts['warning']}\nllms-txt-path={where}\n")
    local = where if not where.startswith(("http://", "https://")) else ""
    for p in problems:
        cmd = {"error": "error", "warning": "warning", "note": "notice"}[p.level]
        loc = (f" file={local}" + (f",line={p.line}" if p.line else "")) if local else ""
        print(f"::{cmd}{loc},title={p.rule}::{p.message}" if loc else f"::{cmd} title={p.rule}::{p.message}")
    print(f"{TOOL_NAME}: {status} ({counts['error']} error(s), {counts['warning']} warning(s), {counts['note']} note(s)) for {where}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
