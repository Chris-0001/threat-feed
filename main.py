#!/usr/bin/env python3
"""threat-feed: collect trusted security feeds, then build a static site.

    python main.py collect   # fetch, validate, dedupe, update data/
    python main.py build     # render _site/ from data/archive/

Zero-trust rules:
  * Everything from a feed is untrusted: size-capped, reduced to plain text,
    length-capped, and validated AGAIN at build time (the repo is not trusted
    either).
  * A link is kept only if it is HTTPS and on that feed's own domain allowlist.
  * No LLM, no secrets, no JavaScript on the site, strict CSP.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import time
import warnings
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import urlparse

import feedparser
import requests
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, StrictUndefined

warnings.filterwarnings("ignore", module="bs4")

ROOT = Path(__file__).parent
FEEDS_FILE = ROOT / "data" / "feeds.json"
STATE_FILE = ROOT / "data" / "state.json"
ARCHIVE_DIR = ROOT / "data" / "archive"
SITE_DIR = ROOT / "_site"

MAX_BYTES = 5 * 1024 * 1024      # cap on DECOMPRESSED size (gzip-bomb guard)
TIMEOUT = (5, 15)                # connect, read (seconds)
TOTAL_TIMEOUT = 60               # hard cap per feed (slow-drip guard)
MAX_REDIRECTS = 3
BACKFILL = 20                    # items shown from a feed on its very first run
MAX_PER_RUN = 100                # per feed, so a noisy feed cannot flood the site
MAX_AGE_DAYS = 90                # ignore older items (must be < SEEN_TTL_DAYS)
SEEN_TTL_DAYS = 120
TITLE_MAX, SUMMARY_MAX = 200, 250
PAGE_ITEMS, RSS_ITEMS = 200, 100
UA = "threat-feed/1.0 (personal open-source aggregator)"

CATEGORIES = {  # slug: (label, description)
    "exploited": ("Exploited", "Vulnerabilities confirmed as exploited in the wild."),
    "advisories": ("Advisories", "Official advisories and security notices from CERTs and vendors."),
    "news": ("News", "Reporting from security media."),
    "research": ("Research", "Technical write-ups from researchers."),
}
TRUST = {"official", "vendor", "media"}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
CVE_FULL = re.compile(r"CVE-\d{4}-\d{4,7}")
ID_RE = re.compile(r"[0-9a-f]{16}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
MONTH_RE = re.compile(r"\d{4}-\d{2}")
# control chars, bidi overrides (trojan-source), and chars illegal in XML
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ufffe\uffff]")


def log(msg): print(msg, flush=True)
def warn(msg): print(f"::warning::{msg}", flush=True)
def now_utc(): return datetime.now(timezone.utc)
def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def require(cond, msg):
    if not cond:
        raise SystemExit(f"error: {msg}")


def set_output(key, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n", "utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------- config/state
def load_feeds():
    feeds = json.loads(FEEDS_FILE.read_text("utf-8"))
    names = set()
    for f in feeds:
        require(f["name"] not in names, f"duplicate feed name {f['name']}")
        names.add(f["name"])
        require(f["category"] in CATEGORIES, f"{f['name']}: unknown category")
        require(f["trust"] in TRUST, f"{f['name']}: unknown trust tier")
        require(f.get("type", "rss") in ("rss", "kev"), f"{f['name']}: unknown type")
        require(f["url"].startswith("https://"), f"{f['name']}: feed URL must be HTTPS")
        require(f["link_domains"], f"{f['name']}: link_domains required")
        f.setdefault("type", "rss")
    return feeds


def load_state():
    state = json.loads(STATE_FILE.read_text("utf-8")) if STATE_FILE.exists() else {}
    state.setdefault("feeds", {})      # name -> {etag, last_modified}
    state.setdefault("seen", {})       # item id -> first-seen date
    state.setdefault("kev_cves", [])   # CVEs currently in CISA KEV
    return state


# ------------------------------------------------------------------- sanitizing
def clean_text(raw):
    soup = BeautifulSoup(str(raw or "")[:50000], "html.parser")
    for tag in soup(["script", "style", "iframe", "object", "embed"]):
        tag.decompose()
    text = CTRL_RE.sub("", soup.get_text(" ", strip=True))
    return " ".join(text.split())


def shorten(text, limit):
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    if end >= limit * 0.5:
        return cut[: end + 1]
    return cut.rsplit(" ", 1)[0].rstrip(",;:") + "…"


def safe_link(link, domains):
    """Return the link only if it is plain HTTPS on an allowlisted domain."""
    try:
        u = urlparse(str(link or "").strip())
        host = (u.hostname or "").lower()
    except ValueError:
        return None
    if u.scheme != "https" or u.username or u.password or not host:
        return None
    if not any(host == d or host.endswith("." + d) for d in domains):
        return None
    url = u.geturl()
    if len(url) > 500 or CTRL_RE.search(url) or re.search(r"\s", url):
        return None
    return url


def build_item(feed, title, link, summary_html, published, key):
    title = shorten(clean_text(title), TITLE_MAX)
    link = safe_link(link, feed["link_domains"])
    if not title or not link:
        return None
    summary_full = clean_text(summary_html)
    summary = shorten(summary_full, SUMMARY_MAX)
    if summary.lower() == title.lower():
        summary = ""
    cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {summary_full}")})[:10]
    key = key or f"{title}|{link}|{iso(published)}"
    item_id = hashlib.sha256(f"{feed['name']}|{key}".encode()).hexdigest()[:16]
    return {
        "id": item_id, "title": title, "link": link, "summary": summary,
        "source": feed["name"], "category": feed["category"], "trust": feed["trust"],
        "published": iso(published), "cves": cves, "kev": False,
    }


# ---------------------------------------------------------------------- fetching
def fetch(feed, fs):
    """Conditional, size-capped, HTTPS-only fetch. Returns (body|None, meta)."""
    headers = {"User-Agent": UA, "Accept": "application/xml, application/json, */*;q=0.5"}
    if fs.get("etag"):
        headers["If-None-Match"] = fs["etag"]
    if fs.get("last_modified"):
        headers["If-Modified-Since"] = fs["last_modified"]
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    session.trust_env = False
    deadline = time.monotonic() + TOTAL_TIMEOUT
    with session.get(feed["url"], headers=headers, timeout=TIMEOUT, stream=True) as r:
        if r.status_code == 304:
            return None, fs
        r.raise_for_status()
        hops = [h.url for h in r.history] + [r.url]
        if any(urlparse(u).scheme != "https" for u in hops):
            raise ValueError("redirect to non-HTTPS URL")
        body = bytearray()
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) > MAX_BYTES:
                raise ValueError("response too large")
            if time.monotonic() > deadline:
                raise TimeoutError("feed download too slow")
        meta = {k: v[:200] for k, v in
                (("etag", r.headers.get("ETag")), ("last_modified", r.headers.get("Last-Modified"))) if v}
    return bytes(body), meta


def parse_published(entry):
    now = now_utc()
    for k in ("published_parsed", "updated_parsed"):
        st = entry.get(k)
        if st:
            try:
                return min(datetime(*st[:6], tzinfo=timezone.utc), now)
            except (ValueError, TypeError):
                pass
    return now


def parse_rss(body, feed):
    parsed = feedparser.parse(body)
    if parsed.bozo and not parsed.entries:
        raise ValueError(f"unparseable feed: {parsed.bozo_exception!r}")
    items = []
    for e in parsed.entries:
        summary = e.get("summary") or (e.get("content") or [{}])[0].get("value")
        item = build_item(feed, e.get("title"), e.get("link"), summary, parse_published(e), e.get("id"))
        if item:
            items.append(item)
    return items


def parse_kev(body, feed):
    vulns = json.loads(body).get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("unexpected KEV format")
    cves, items = set(), []
    for v in vulns:
        cve = str(v.get("cveID", "")).upper()
        if not CVE_FULL.fullmatch(cve):
            continue
        cves.add(cve)
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        title = f"{cve}: {v.get('vendorProject', '')} {v.get('product', '')} ({v.get('vulnerabilityName', '')})"
        item = build_item(feed, title, f"https://nvd.nist.gov/vuln/detail/{cve}",
                          v.get("shortDescription"), added, cve)
        if item:
            item["kev"] = True
            items.append(item)
    return cves, items


# ----------------------------------------------------------------------- collect
def collect():
    feeds, state = load_feeds(), load_state()
    now = now_utc()
    cutoff = iso(now - timedelta(days=MAX_AGE_DAYS))
    new, to_mark, new_meta, failed = [], [], {}, 0
    kev_set = set(state["kev_cves"])

    for feed in feeds:
        name = feed["name"]
        first = name not in state["feeds"]
        try:
            body, meta = fetch(feed, state["feeds"].get(name, {}))
            if body is None:
                log(f"{name}: not modified")
                continue
            if feed["type"] == "kev":
                kev_set, entries = parse_kev(body, feed)
            else:
                entries = parse_rss(body, feed)
        except Exception as exc:  # one bad feed must not stop the others
            failed += 1
            warn(f"{name}: {type(exc).__name__}: {exc}")
            continue

        fresh = {i["id"]: i for i in entries
                 if i["id"] not in state["seen"] and i["published"] >= cutoff}
        fresh = sorted(fresh.values(), key=lambda i: i["published"], reverse=True)
        if first:  # mark the whole backlog as seen, but only show the newest few
            to_mark += [i["id"] for i in fresh]
            fresh = fresh[:BACKFILL]
        fresh = fresh[:MAX_PER_RUN]
        if not first:
            to_mark += [i["id"] for i in fresh]
        new_meta[name] = meta
        new += fresh
        log(f"{name}: {len(fresh)} new")
        time.sleep(1)

    if failed == len(feeds):
        set_output("new_items", 0)
        raise SystemExit("error: every feed failed")
    if not new:
        log("No new items. Nothing to write.")
        set_output("new_items", 0)
        return

    for it in new:
        it["kev"] = it["kev"] or bool(set(it["cves"]) & kev_set)
    month = now.strftime("%Y-%m")
    path = ARCHIVE_DIR / f"{month}.json"
    existing = json.loads(path.read_text("utf-8")) if path.exists() else []
    have = {i["id"] for i in existing}
    merged = existing + [i for i in new if i["id"] not in have]
    merged.sort(key=lambda i: (i["published"], i["id"]), reverse=True)
    write_json(path, merged)

    today = now.strftime("%Y-%m-%d")
    keep_after = (now - timedelta(days=SEEN_TTL_DAYS)).strftime("%Y-%m-%d")
    seen = {k: v for k, v in state["seen"].items() if v >= keep_after}
    seen.update({i: today for i in to_mark})
    state["seen"], state["kev_cves"] = seen, sorted(kev_set)
    state["feeds"].update(new_meta)
    write_json(STATE_FILE, state)
    log(f"Wrote {len(new)} new items.")
    set_output("new_items", len(new))


# ------------------------------------------------------------------------- build
def valid_item(it, allowed):
    """Schema check on archived data. Anything odd is dropped, never rendered."""
    try:
        strs = all(isinstance(it[k], str) for k in ("title", "summary", "source", "id", "published"))
        return bool(
            isinstance(it, dict) and strs
            and ID_RE.fullmatch(it["id"]) and DATE_RE.fullmatch(it["published"])
            and it["category"] in CATEGORIES and it["trust"] in TRUST
            and 0 < len(it["title"]) <= TITLE_MAX + 1 and len(it["summary"]) <= SUMMARY_MAX + 1
            and isinstance(it["cves"], list) and len(it["cves"]) <= 10
            and all(isinstance(c, str) and CVE_FULL.fullmatch(c) for c in it["cves"])
            and isinstance(it["kev"], bool)
            and safe_link(it["link"], allowed) is not None
        )
    except (KeyError, TypeError):
        return False


def build():
    feeds = load_feeds()
    allowed = {d for f in feeds for d in f["link_domains"]}
    owner, _, repo = os.environ.get("GITHUB_REPOSITORY", "you/threat-feed").partition("/")
    require(re.fullmatch(r"[\w.-]+", owner) and re.fullmatch(r"[\w.-]+", repo), "bad GITHUB_REPOSITORY")
    site_url = f"https://{owner.lower()}.github.io/{repo}/"

    months, dropped = {}, 0
    for p in sorted(ARCHIVE_DIR.glob("*.json"), reverse=True):
        if not MONTH_RE.fullmatch(p.stem):
            continue
        raw = json.loads(p.read_text("utf-8"))
        good = [i for i in raw if valid_item(i, allowed)]
        dropped += len(raw) - len(good)
        months[p.stem] = sorted(good, key=lambda i: (i["published"], i["id"]), reverse=True)
    if dropped:
        warn(f"{dropped} archived items failed validation and were left out")
    items = sorted((i for m in months.values() for i in m),
                   key=lambda i: (i["published"], i["id"]), reverse=True)

    env = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True,
                      undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    built = now_utc()
    common = dict(categories={k: v[0] for k, v in CATEGORIES.items()}, site_url=site_url,
                  built=built.strftime("%Y-%m-%d %H:%M"), build_rfc=format_datetime(built))

    shutil.rmtree(SITE_DIR, ignore_errors=True)

    def render(path, template, root="", **ctx):
        out = SITE_DIR / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(env.get_template(template).render(root=root, **common, **ctx), "utf-8")

    def rss(slug, title, description, subset):
        subset = [dict(i, pubdate=format_datetime(datetime.strptime(i["published"], "%Y-%m-%dT%H:%M:%SZ")
                                                   .replace(tzinfo=timezone.utc)))
                  for i in subset[:RSS_ITEMS]]
        render(f"feeds/{slug}.xml", "rss.xml.j2", title=title, description=description,
               items=subset, self_url=f"{site_url}feeds/{slug}.xml")

    render("index.html", "list.html.j2", title="Latest", heading="Latest",
           intro="Newest items from every trusted source.", items=items[:PAGE_ITEMS], current="all")
    rss("all", "Threat feed: all", "Every category.", items)
    for slug, (label, desc) in CATEGORIES.items():
        subset = [i for i in items if i["category"] == slug]
        render(f"{slug}.html", "list.html.j2", title=label, heading=label, intro=desc,
               items=subset[:PAGE_ITEMS], current=slug)
        rss(slug, f"Threat feed: {label}", desc, subset)
    render("archive/index.html", "archive.html.j2", root="../", title="Archive", current="archive",
           months=[(m, len(v)) for m, v in months.items()])
    for m, subset in months.items():
        render(f"archive/{m}.html", "list.html.j2", root="../", title=m, heading=m,
               intro=f"{len(subset)} items first seen in {m}.", items=subset, current="archive")
    render("subscribe.html", "subscribe.html.j2", title="Subscribe", current="subscribe")
    shutil.copy(ROOT / "static" / "style.css", SITE_DIR / "style.css")
    log(f"Built site with {len(items)} items in {len(months)} month(s).")


if __name__ == "__main__":
    cmds = {"collect": collect, "build": build}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        raise SystemExit("usage: python main.py [collect|build]")
    cmds[sys.argv[1]]()
