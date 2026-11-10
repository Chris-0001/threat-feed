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
import unicodedata
import warnings
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import quote, urldefrag, urlencode, urljoin, urlparse

import feedparser
import requests
from bs4 import BeautifulSoup
from scanner import scan_url
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from collections import Counter

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
MAX_MB_CAP = 25                  # hard ceiling for a feed's own max_mb setting
WATCH_MAX_LINKS = 60             # links taken from one watched page
MD_LINK_RE = re.compile(r"\[([^\]\n]{1,300})\]\((\S{1,500}?)\)")
ANOMALY_FRESH = 40               # more new items than this in one run => feed skipped
REJECT_MIN, REJECT_RATIO = 5, 0.5  # >50% of entries failing link checks => feed skipped
# shared-hosting domains anyone can publish on: never allowed as a whole
SHARED_HOSTS = {"blogspot.com", "feedburner.com", "github.io", "githubusercontent.com", "medium.com",
                "wordpress.com", "googleusercontent.com", "amazonaws.com", "cloudfront.net",
                "pages.dev", "netlify.app", "herokuapp.com", "vercel.app", "substack.com"}
DOMAIN_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")

CATEGORIES = {  # slug: (label, description)
    "exploited": ("Exploited", "Vulnerabilities confirmed as exploited in the wild."),
    "advisories": ("Advisories", "Official advisories and security notices from CERTs and vendors."),
    "news": ("News", "Reporting from security media."),
    "research": ("Research", "Technical write-ups from researchers."),
    "jobs": ("Jobs", "Currently open positions. Closed or expired postings disappear automatically."),
    "training": ("Training", "Free training and certification programmes from trusted organisations."),
    "warning": ("Warnings", "Suspicious or potentially malicious posts flagged by VirusTotal.")
}
TRUST = {"official", "vendor", "media", "community"}
SNAPSHOT_TYPES = {"watch", "workable"}   # sources that list what is open right now
EMPTY_CLEAR_HOURS = 24           # a snapshot source empty this long => all its items count as closed
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,58}")
SHORTCODE_RE = re.compile(r"[0-9A-Za-z]{5,14}")
ADA_RE = re.compile(r"[0-9A-ZΑ-Ω]{4,14}-[0-9A-ZΑ-Ω]{2,5}")
WORKABLE_API = "https://www.workable.com/api/accounts/"
DIAVGEIA_SEARCH = "https://diavgeia.gov.gr/opendata/search.json"
DIAVGEIA_PARAMS = {"subject", "term", "type", "org", "unit", "tag"}
NOT_IN_LATEST = {"jobs", "training"}   # kept out of the main "Latest" page and all.xml

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
CVE_FULL = re.compile(r"CVE-\d{4}-\d{4,7}")
ID_RE = re.compile(r"[0-9a-f]{16}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
MONTH_RE = re.compile(r"\d{4}-\d{2}")
# control chars, bidi overrides (trojan-source), and chars illegal in XML
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ufffe\uffff]")
# ---- job relevance and priority (jobs only; matched on folded text)
JOB_BLOCK = ["human resources", "hr", "recruit", "talent", "sales", "marketing", "account executive",
             "accountant", "accounting", "finance", "payroll", "legal", "lawyer", "customer support",
             "customer success", "receptionist", "office manager", "administrative", "driver",
             "business development", "procurement", "secretary", "ανθρωπιν", "λογιστ", "γραμματει"]
JOB_SENIOR = ["senior", "sr.", "lead", "principal", "staff", "director", "head of", "manager",
              "architect", "vp", "chief"]
JOB_TECH = ["security", "cyber", "infosec", "soc", "siem", "pentest", "penetration", "vulnerab",
            "malware", "forensic", "cryptograph", "threat", "devsecops", "appsec", "ai",
            "machine learning", "deep learning", "llm", "artificial intelligence", "data scien",
            "research", "scientist", "rf", "radio", "wireless", "sdr", "signal", "dsp", "antenna",
            "5g", "telecom", "spectrum", "hpc", "supercomput", "quantum", "engineer", "developer",
            "devops", "sysadmin", "system administrator", "network", "cloud", "linux", "software",
            "ict", "computer", "informatics", "πληροφορικ", "κυβερνοασφ", "μηχανικ", "ερευνητ",
            "προγραμματιστ"]
SC_DAEDALUS = ["daedalus", "δαιδαλ", "lavrio", "lavrion", "λαυριο"]
SC_HPC = ["eurohpc", "hpc", "supercomput", "quantum", "κβαντικ"]
SC_JUNIOR = ["junior", "entry", "graduate", "trainee", "internship", "apprentice", "αποφοιτ",
             "πρακτικη ασκηση"]
SC_SEC = ["security", "cyber", "infosec", "κυβερνοασφαλ", "ασφαλεια"]
SC_AI = ["ai", "machine learning", "deep learning", "llm", "artificial intelligence"]
SC_RES = ["research", "scientist", "ερευνητ"]
SC_RF = ["rf", "radio", "wireless", "sdr", "antenna", "spectrum", "5g", "dsp", "signal"]
SC_GR = ["greece", "athens", "hellas", "attica", "αθηνα", "ελλαδα"]
SCORED = {"jobs", "training"}

# Diavgeia: only hiring calls with a recognisable technical role survive
DIA_POST = ["προκηρυξ", "προσκληση", "ανακοινωση", "πληρωση", "προσληψ", "στελεχωση",
            "εκδηλωση ενδιαφεροντος", "εκδηλωσης ενδιαφεροντος"]
DIA_NOISE = ["πρακτικ", "αποτελεσμ", "ματαιωσ", "αναθεση", "προμηθει", "προμηθευτ", "πληρωμ", "δαπαν",
             "εξοφληση", "διακηρυξ", "ανακληση", "τροποποιηση", "παρατασ", "πινακ", "εγκριση",
             "θεμα", "εταιρει", "προσφορ", "παροχη υπηρεσιων", "αναδοχ"]
DIA_SENIOR = ["διευθυντ", "προισταμεν", "συντονιστ", "επικεφαλ", "senior", "lead"]
DIA_FIELDS = [("κυβερνοασφαλ", "Cybersecurity"), ("ασφαλειας πληροφορ", "Information Security"),
              ("πληροφορικ", "IT / Informatics"), ("μηχανικων η/υ", "Computer Engineering"),
              ("μηχανικων υπολογιστ", "Computer Engineering"), ("ηλεκτρονικων", "Electronics Engineering"),
              ("ηλεκτρολογων", "Electrical Engineering"), ("τηλεπικοινων", "Telecommunications Engineering"),
              ("δικτυων", "Networks"), ("μαθηματικ", "Mathematics / Data"),
              ("στατιστικ", "Statistics / Data"), ("φυσικ", "Physics / Research")]
DIA_LEVEL_RE = re.compile(r"(?<!\w)(πε|τε|δε)(?!\w)[\s/-]+([^,.;:()]{3,60})")


def job_ok(item):
    title = fold(item["title"])
    text = fold(f"{item['title']} {item['summary']}")
    return not kw_hit(title, JOB_BLOCK) and not kw_hit(title, JOB_SENIOR) and kw_hit(text, JOB_TECH)


def job_score(source, title, summary):
    t = fold(f"{title} {summary}")
    s = 0
    s += 40 if kw_hit(t, SC_DAEDALUS) else 0
    s += 15 if ("grnet" in source.lower() or kw_hit(t, SC_HPC)) else 0
    s += 25 if kw_hit(t, SC_JUNIOR) else 0
    s += 20 if kw_hit(t, SC_SEC) else 0
    s += 15 if (kw_hit(t, SC_AI) and kw_hit(t, SC_RES)) else 0
    s += 15 if kw_hit(t, SC_RF) else 0
    s += 10 if kw_hit(t, SC_GR) else 0
    s += 5 if kw_hit(t, ["free", "δωρεαν"]) else 0
    return min(s, 100)

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
        require(f.get("type", "rss") in ("rss", "kev", "watch", "workable", "diavgeia", "static"),
                f"{f['name']}: unknown type")
        require(f["url"].startswith("https://"), f"{f['name']}: feed URL must be HTTPS")
        domains = f["link_domains"]
        require(isinstance(domains, list) and domains, f"{f['name']}: link_domains required")
        for d in domains:
            require(isinstance(d, str) and DOMAIN_RE.fullmatch(d), f"{f['name']}: bad domain {d!r}")
            require(d not in SHARED_HOSTS, f"{f['name']}: {d} is shared hosting, use a specific host")
        prefixes = f.setdefault("link_prefix", [])
        require(isinstance(prefixes, list), f"{f['name']}: link_prefix must be a list")
        for pre in prefixes:
            u = urlparse(pre) if isinstance(pre, str) else None
            host = (u.hostname or "") if u else ""
            require(u and u.scheme == "https" and u.path.startswith("/") and not u.username
                    and any(host == d or host.endswith("." + d) for d in domains),
                    f"{f['name']}: bad link_prefix {pre!r} (HTTPS, on link_domains, with a path)")
        mb = f.setdefault("max_mb", MAX_BYTES // (1024 * 1024))
        require(isinstance(mb, (int, float)) and not isinstance(mb, bool) and 1 <= mb <= MAX_MB_CAP,
                f"{f['name']}: max_mb must be between 1 and {MAX_MB_CAP}")
        require(isinstance(f.setdefault("upgrade_http", False), bool), f"{f['name']}: upgrade_http must be true/false")
        f.setdefault("type", "rss")
        if f["type"] == "static":
            its = f.get("items")
            require(isinstance(its, list) and 0 < len(its) <= 100 and all(
                isinstance(e, dict) and isinstance(e.get("title"), str) and isinstance(e.get("link"), str)
                for e in its), f"{f['name']}: static feeds need an items list of {{title, link}}")
        require(f["type"] not in ("watch", "workable", "diavgeia") or prefixes,
                f"{f['name']}: {f['type']} feeds require link_prefix")
        for key in ("include", "require", "exclude", "exclude_title", "row_exclude"):
            words = f.setdefault(key, [])
            require(isinstance(words, list) and len(words) <= 40 and
                    all(isinstance(w, str) and 2 <= len(w) <= 60 for w in words),
                    f"{f['name']}: {key} must be a list of up to 40 keywords (2-60 chars)")
        bf = f.setdefault("backfill", 50 if f["type"] in SNAPSHOT_TYPES else BACKFILL)
        require(isinstance(bf, int) and not isinstance(bf, bool) and 0 <= bf <= 50,
                f"{f['name']}: backfill must be an integer 0-50")
        od = f.setdefault("open_days", 0)
        require(isinstance(od, int) and not isinstance(od, bool) and 0 <= od <= 365,
                f"{f['name']}: open_days must be an integer 0-365 (0 = no limit)")
        if f["type"] == "workable":
            slug = f.get("slug", "")
            require(isinstance(slug, str) and SLUG_RE.fullmatch(slug), f"{f['name']}: bad Workable slug")
            require(f["url"] == f"{WORKABLE_API}{slug}?details=true",
                    f"{f['name']}: url must be {WORKABLE_API}<slug>?details=true")
        if f["type"] == "diavgeia":
            require(f["url"] == DIAVGEIA_SEARCH, f"{f['name']}: url must be {DIAVGEIA_SEARCH}")
            params = f.get("params")
            require(isinstance(params, dict) and params and set(params) <= DIAVGEIA_PARAMS
                    and all(isinstance(v, str) and 1 <= len(v) <= 200 for v in params.values()),
                    f"{f['name']}: params must use only {sorted(DIAVGEIA_PARAMS)}")
            wd = f.setdefault("window_days", 30)
            require(isinstance(wd, int) and not isinstance(wd, bool) and 1 <= wd <= 180,
                    f"{f['name']}: window_days must be 1-180")
    return feeds


def load_state():
    state = json.loads(STATE_FILE.read_text("utf-8")) if STATE_FILE.exists() else {}
    state.setdefault("feeds", {})      # name -> {etag, last_modified}
    state.setdefault("seen", {})       # item id -> first-seen date
    state.setdefault("kev_cves", [])   # CVEs currently in CISA KEV
    state.setdefault("live", {})       # snapshot source name -> item ids listed as open right now
    state.setdefault("empty", {})      # snapshot source name -> when its listing first came back empty
    return state


# ------------------------------------------------------------------- sanitizing
def clean_text(raw):
    soup = BeautifulSoup(str(raw or "")[:50000], "html.parser")
    for tag in soup(["script", "style", "iframe", "object", "embed"]):
        tag.decompose()
    text = CTRL_RE.sub("", soup.get_text(" ", strip=True))
def sanitize_text(html_content):
    """Strips all HTML tags to ensure safe, easily digestible plain text."""
    if not html_content:
        return ""
    return BeautifulSoup(html_content, "html.parser").get_text(separator=" ", strip=True)
    return " ".join(text.split())


def shorten(text, limit):
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    if end >= limit * 0.5:
        return cut[: end + 1]
    return cut.rsplit(" ", 1)[0].rstrip(",;:") + "…"


def safe_link(link, domains, prefixes=()):
    """Return the link only if it is plain HTTPS on an allowlisted domain
    (and, when the feed defines link_prefix, starts with one of the prefixes)."""
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
    if prefixes and not any(url.startswith(p) for p in prefixes):
        return None
    return url


def fold(text):
    """Case- and accent-insensitive form (works for Greek tonos and final sigma)."""
    return "".join(c for c in unicodedata.normalize("NFD", text.casefold()) if not unicodedata.combining(c))


def kw_hit(text, words):
    """Plain-word match at a word start (words of 3 chars or less must be whole words)."""
    for w in words:
        w = fold(w)
        end = r"(?!\w)" if len(w) <= 3 else ""
        if re.search(r"(?<!\w)" + re.escape(w) + end, text):
            return True
    return False


def matches(item, feed):
    """Keyword filters from feeds.json. include = any of; require = also any of;
    exclude = none of (title+summary); exclude_title = none of (title only, for seniority words)."""
    text = fold(f"{item['title']} {item['summary']}")
    return bool(
        (not feed["include"] or kw_hit(text, feed["include"]))
        and (not feed["require"] or kw_hit(text, feed["require"]))
        and not kw_hit(text, feed["exclude"])
        and not kw_hit(fold(item["title"]), feed["exclude_title"])
        and (item["category"] != "jobs" or job_ok(item))
    )


def build_item(feed, title, link, summary_html, published, key):
    if urlparse(link).scheme not in ("http", "https"):
        return None
    title = shorten(clean_text(title), TITLE_MAX)
    link = str(link or "").strip()
    if feed["upgrade_http"] and link.startswith("http://"):  # scheme only; allowlist checks still apply
        link = "https://" + link[len("http://"):]
    link = safe_link(link, feed["link_domains"], feed["link_prefix"])
    if not title or not link:
        return None
    summary_full = clean_text(summary_html)
    summary = shorten(sanitize_text(summary_full), SUMMARY_MAX)
    if summary.lower() == title.lower():
        summary = ""
    cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {summary_full}")})[:10]
    key = key or f"{title}|{link}|{iso(published)}"
    item_id = hashlib.sha256(f"{feed['name']}|{key}".encode()).hexdigest()[:16]
    
    vt_data = scan_url(link) if feed["category"] in ["jobs", "training"] else {"scanned": False}
    
    if vt_data.get("malicious") or vt_data.get("new"):
        feed["category"] = "warning"

    return {
        "id": item_id, "title": title, "link": link, "summary": summary,
        "source": feed["name"], "category": feed["category"], "trust": feed["trust"],
        "published": iso(published), "cves": cves, "kev": False,
        "score": job_score(feed["name"], title, summary_full) if feed["category"] in SCORED else 0,
        "scanned": vt_data.get("scanned", False),
        "malicious": vt_data.get("malicious", False),
        "new_domain": vt_data.get("new", False)
    }


# ---------------------------------------------------------------------- fetching
def fetch(feed, fs):
    """Conditional, size-capped, HTTPS-only fetch. Returns (body|None, meta)."""
    headers = {"User-Agent": UA, "Accept": "application/xml, application/json, text/html, text/markdown, */*;q=0.5"}
    if fs.get("etag"):
        headers["If-None-Match"] = fs["etag"]
    if fs.get("last_modified"):
        headers["If-Modified-Since"] = fs["last_modified"]
    session = requests.Session()
    session.max_redirects = 3
    session.trust_env = False
    deadline = time.monotonic() + TOTAL_TIMEOUT
    with session.get(feed["url"], headers=headers, timeout=10, stream=True) as r:
        if r.status_code == 304:
            return None, fs
        r.raise_for_status()
        hops = [h.url for h in r.history] + [r.url]
        if any(urlparse(u).scheme != "https" for u in hops):
            raise ValueError("redirect to non-HTTPS URL")
        body = bytearray()
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) > int(feed["max_mb"] * 1024 * 1024):
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
    return items, len(parsed.entries)


def parse_watch(body, feed):
    """Watch a listing page (HTML or markdown): every link under link_prefix is an item."""
    text = body.decode("utf-8", "replace")
    pairs, anchors = [], BeautifulSoup(text, "html.parser").find_all("a", href=True)
    for a in anchors:
        row = a.find_parent(["tr", "li", "article"]) if feed["row_exclude"] else None
        if row is not None and kw_hit(fold(row.get_text(" ", strip=True)), feed["row_exclude"]):
            continue  # e.g. a table row whose status says "Closed"
        pairs.append((a.get_text(" ", strip=True), a["href"]))
    if not anchors:
        pairs = MD_LINK_RE.findall(text)
    found = {}
    for title, href in pairs:
        try:
            url = urldefrag(urljoin(feed["url"], str(href).strip()))[0]
        except ValueError:
            continue
        if not any(url.startswith(p) for p in feed["link_prefix"]):
            continue
        title = clean_text(title)
        if url not in found or (title and not found[url]):
            found[url] = title
    if not found:
        warn(f"{feed['name']}: no matching links (no openings right now, or the page layout changed)")
    now, items = now_utc(), []
    for url, title in list(found.items())[:WATCH_MAX_LINKS]:
        item = build_item(feed, title, url, "", now, url)
        if item:
            items.append(item)
    return items, min(len(found), WATCH_MAX_LINKS)


def parse_workable(body, feed):
    """Workable's public widget endpoint lists only currently published jobs."""
    data = json.loads(body)
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, list):
        raise ValueError("unexpected Workable format")
    jobs, now, items = jobs[:200], now_utc(), []
    text = lambda d, k: d.get(k).strip() if isinstance(d.get(k), str) else ""
    for j in jobs:
        if not isinstance(j, dict):
            continue
        code = text(j, "shortcode")
        if not SHORTCODE_RE.fullmatch(code):
            continue
        loc = j.get("location") if isinstance(j.get("location"), dict) else {}
        locs = j.get("locations") if isinstance(j.get("locations"), list) else []
        first = locs[0] if locs and isinstance(locs[0], dict) else {}
        where = ", ".join(x for x in (text(j, "city") or text(loc, "city") or text(first, "city"),
                                      text(j, "country") or text(loc, "country") or text(first, "country")
                                      or text(first, "country_name")) if x)
        head = " | ".join(x for x in (where, text(j, "employment_type"), text(j, "experience")) if x)
        summary = f"{head}. {text(j, 'description')}" if head else text(j, "description")
        try:
            published = min(datetime.strptime((text(j, "published_on") or text(j, "created_at"))[:10],
                                              "%Y-%m-%d").replace(tzinfo=timezone.utc), now)
        except ValueError:
            published = now
        link = f"https://apply.workable.com/{feed['slug']}/j/{code}/"
        item = build_item(feed, j.get("title"), link, summary, published, code)
        if item:
            items.append(item)
    return items, len(jobs)


def diavgeia_url(feed, now):
    q = dict(feed["params"], size="500", sort="recent", status="published",
             from_issue_date=(now - timedelta(days=feed["window_days"])).strftime("%Y-%m-%d"),
             to_issue_date=now.strftime("%Y-%m-%d"))
    return f"{DIAVGEIA_SEARCH}?{urlencode(q)}"


def diavgeia_role(subject):
    """Readable role label for a hiring call, or None if the decision is not one."""
    f = fold(subject)
    if not kw_hit(f, DIA_POST) or kw_hit(f, DIA_NOISE) or kw_hit(f, DIA_SENIOR):
        return None
    level = field = None
    for m in DIA_LEVEL_RE.finditer(f):
        for key, label in DIA_FIELDS:
            if fold(key) in m.group(2):
                level, field = m.group(1).upper(), label
                break
        if field:
            break
    if not field and kw_hit(f, ["θεση", "θεσεις", "θεσεων", "προσληψ"]) \
            and kw_hit(f, ["κυβερνοασφαλ", "ασφαλεια πληροφορ"]):
        field = "Cybersecurity"
    if not field:
        return None
    return f"Public sector: {field}" + (f" ({level})" if level else "") + " – hiring call"


def parse_diavgeia(body, feed):
    data = json.loads(body)
    decisions = data.get("decisions") if isinstance(data, dict) else None
    if not isinstance(decisions, list):
        raise ValueError("unexpected Diavgeia format")
    decisions, now, items, considered = decisions[:500], now_utc(), [], 0
    for d in decisions:
        if not isinstance(d, dict):
            continue
        ada = str(d.get("ada", "")).strip()
        if not ADA_RE.fullmatch(ada):
            continue
        subject = clean_text(d.get("subject"))
        role = diavgeia_role(subject)
        if not role:
            continue          # not a hiring call: silently ignored, not counted as "rejected"
        considered += 1
        try:
            published = min(datetime.fromtimestamp(int(d.get("issueDate")) / 1000, tz=timezone.utc), now)
        except (TypeError, ValueError, OverflowError, OSError):
            published = now
        item = build_item(feed, role, "https://diavgeia.gov.gr/decision/view/" + quote(ada, safe=""),
                          f"{subject} (ΑΔΑ: {ada})", published, ada)
        if item:
            items.append(item)
    return items, considered


def parse_static(body, feed):
    """Hand-curated links (free training programmes etc.), validated like everything else."""
    now, items = now_utc(), []
    for e in feed["items"]:
        item = build_item(feed, e.get("title"), e.get("link"), e.get("summary", ""), now, e.get("link"))
        if item:
            items.append(item)
    return items, len(feed["items"])


def parse_kev(body, feed):
    vulns = json.loads(body).get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("unexpected KEV format")
    cves, items = set(), []
    for v in vulns:
        if not isinstance(v, dict):
            continue
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
    return cves, items, len(vulns)


# ----------------------------------------------------------------------- collect
def archived_ids():
    ids = set()
    for p in ARCHIVE_DIR.glob("*.json"):
        if MONTH_RE.fullmatch(p.stem):
            try:
                ids |= {i["id"] for i in json.loads(p.read_text("utf-8")) if isinstance(i, dict) and "id" in i}
            except (OSError, ValueError):
                pass
    return ids


def collect():
    feeds, state = load_feeds(), load_state()
    now = now_utc()
    cutoff = iso(now - timedelta(days=MAX_AGE_DAYS))
    new, to_mark, new_meta, failed = [], [], {}, 0
    kev_set = set(state["kev_cves"])
    archived = archived_ids()
    live_changed = dirty = False
    accept = {n.strip() for n in os.environ.get("ACCEPT_SPIKE", "").split(",") if n.strip()}

    errors = []
    for feed in feeds:
        name = feed["name"]
        first = name not in state["feeds"]
        try:
            dynamic = feed["type"] in SNAPSHOT_TYPES or feed["type"] in ("diavgeia", "static")
            src = dict(feed, url=diavgeia_url(feed, now)) if feed["type"] == "diavgeia" else feed
            if feed["type"] == "static":
                body, meta = b"", {}
            else:
                body, meta = fetch(src, {} if dynamic else state["feeds"].get(name, {}))
            if body is None:
                log(f"{name}: not modified")
                continue
            kev_new = None
            if feed["type"] == "kev":
                kev_new, entries, total = parse_kev(body, feed)
            elif feed["type"] == "watch":
                entries, total = parse_watch(body, feed)
            elif feed["type"] == "workable":
                entries, total = parse_workable(body, feed)
            elif feed["type"] == "diavgeia":
                entries, total = parse_diavgeia(body, feed)
            elif feed["type"] == "static":
                entries, total = parse_static(body, feed)
            else:
                entries, total = parse_rss(body, feed)
        except Exception as exc:  # one bad feed must not stop the others
            failed += 1
            warn(f"{name}: {type(exc).__name__}: {exc}")
            continue

        # Guard 1: links suddenly failing the allowlist (domain change / hijack / format change)
        rejected = total - len(entries)
        if total >= REJECT_MIN and rejected / total > REJECT_RATIO:
            failed += 1
            warn(f"{name}: SKIPPED, {rejected}/{total} entries failed title/link validation")
            continue

        snap = feed["type"] in SNAPSHOT_TYPES
        known = archived if snap else state["seen"]   # open-position lists: new = not shown before
        fresh = {i["id"]: i for i in entries
                 if i["id"] not in known and (snap or i["published"] >= cutoff) and matches(i, feed)}
        fresh = sorted(fresh.values(), key=lambda i: i["published"], reverse=True)

        for item in fresh:
            if feed["category"] in ("jobs", "training"):
                vt_data = scan_url(item["link"], errors)
                if vt_data.get("malicious") or vt_data.get("new"):
                    item["category"] = "warning"

        # Guard 2: sudden flood of new items. Re-run manually with accept_spike=<feed name> if legitimate.
        if not first and len(fresh) > ANOMALY_FRESH and name not in accept:
            failed += 1
            warn(f"{name}: SKIPPED, {len(fresh)} new items in one run (limit {ANOMALY_FRESH})")
            continue

        if kev_new is not None:
            kev_set = kev_new
        if snap:  # remember what is open right now, so closed postings can be hidden
            ids = sorted(i["id"] for i in entries)
            if ids:
                if name in state["empty"]:
                    del state["empty"][name]
                    dirty = True
                if state["live"].get(name) != ids:
                    state["live"][name], live_changed = ids, True
            else:
                since = state["empty"].get(name)
                if not isinstance(since, str):
                    state["empty"][name], dirty = iso(now), True
                elif since <= iso(now - timedelta(hours=EMPTY_CLEAR_HOURS)) and state["live"].get(name):
                    state["live"][name], live_changed = [], True
                    warn(f"{name}: listing empty for {EMPTY_CLEAR_HOURS}h, treating all its items as closed")
        if first:  # mark the whole backlog as seen, but only show the newest few
            to_mark += [i["id"] for i in fresh]
            fresh = fresh[:feed["backfill"]]
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
    if not new and not live_changed and not dirty:
        log("No new items. Nothing to write.")
        set_output("new_items", 0)
        return

    if new:
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
    live_ids = {i for ids in state["live"].values() for i in ids}
    write_json(ROOT / "data" / "errors.json", errors)
    seen = {k: v for k, v in state["seen"].items() if v >= keep_after or k in live_ids}
    seen.update({i: today for i in to_mark})
    state["seen"], state["kev_cves"] = seen, sorted(kev_set)
    state["feeds"].update(new_meta)
    write_json(STATE_FILE, state)
    log(f"Wrote {len(new)} new items.")
    set_output("new_items", len(new) + (1 if live_changed else 0))  # a closed posting also needs a rebuild


# ------------------------------------------------------------------------- build
def valid_item(it, by_source):
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
            and it["source"] in by_source
            and isinstance(it.get("score", 0), int)
            and (by_source[it["source"]]["type"] != "diavgeia" or it["title"].startswith("Public sector:"))
            and isinstance(it.get("scanned", False), bool)
            and isinstance(it.get("malicious", False), bool)
            and isinstance(it.get("new_domain", False), bool)
            and safe_link(it["link"], by_source[it["source"]]["link_domains"],
                          by_source[it["source"]]["link_prefix"]) is not None
        )
    except (KeyError, TypeError):
        return False


def load_live():
    """Ids currently listed as open by each snapshot source. None if state is unreadable."""
    try:
        raw = json.loads(STATE_FILE.read_text("utf-8")).get("live", {})
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(raw, dict):
        return None
    return {n: {i for i in ids if isinstance(i, str) and ID_RE.fullmatch(i)}
            for n, ids in raw.items() if isinstance(n, str) and isinstance(ids, list)}


def is_open(it, feed, live, now):
    """Open-position views: a snapshot item must still be listed; others expire after open_days."""
    if feed["type"] in SNAPSHOT_TYPES:
        listed = (live or {}).get(it["source"])
        return listed is None or it["id"] in listed
    return not feed["open_days"] or it["published"] >= iso(now - timedelta(days=feed["open_days"]))


def build():
    feeds = load_feeds()
    by_source = {f["name"]: f for f in feeds}
    owner, _, repo = os.environ.get("GITHUB_REPOSITORY", "you/threat-feed").partition("/")
    require(re.fullmatch(r"[\w.-]+", owner) and re.fullmatch(r"[\w.-]+", repo), "bad GITHUB_REPOSITORY")
    site_url = f"https://{owner.lower()}.github.io/{repo}/"

    months, dropped, bad = {}, 0, Counter()
    for p in sorted(ARCHIVE_DIR.glob("*.json"), reverse=True):
        if not MONTH_RE.fullmatch(p.stem):
            continue
        raw = json.loads(p.read_text("utf-8"))
        good = []
        for i in raw:
            if valid_item(i, by_source):
                good.append(i)
            else:
                bad[i.get("source", "?") if isinstance(i, dict) else "?"] += 1
        dropped += len(raw) - len(good)
        months[p.stem] = sorted(good, key=lambda i: (i["published"], i["id"]), reverse=True)
    if dropped:
        warn(f"{dropped} archived items failed validation and were left out")
        for src, n in bad.items():
            warn(f"  {n} dropped from source: {src}")
    items = sorted((i for m in months.values() for i in m),
                   key=lambda i: (i["published"], i["id"]), reverse=True)

    built = now_utc()
    live = load_live()
    if live is None:
        warn("state.json unreadable: closed postings may be shown")
    open_items = [i for i in items if is_open(i, by_source[i["source"]], live, built)]
    env = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True,
                      undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
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
           intro="Newest security items from every trusted source (jobs and training have their own pages).",
           items=[i for i in open_items if i["category"] not in NOT_IN_LATEST][:PAGE_ITEMS], current="all")

    rss("all", "Threat feed: all", "Every security category.",
        [i for i in open_items if i["category"] not in NOT_IN_LATEST])
    for slug, (label, desc) in CATEGORIES.items():
        subset = [i for i in open_items if i["category"] == slug]
        if slug in NOT_IN_LATEST:
            subset = sorted(subset, key=lambda i: (i.get("score", 0), i["published"], i["id"]), reverse=True)
        render(f"{slug}.html", "list.html.j2", title=label, heading=label, intro=desc,
               items=subset[:PAGE_ITEMS], current=slug)
        rss(slug, f"Threat feed: {label}", desc, subset)
    render("archive/index.html", "archive.html.j2", root="../", title="Archive", current="archive",
           months=[(m, len(v)) for m, v in months.items()])
    for m, subset in months.items():
        render(f"archive/{m}.html", "list.html.j2", root="../", title=m, heading=m,
               intro=f"{len(subset)} items first seen in {m}.", items=subset, current="archive")
    from stats import generate_graphs
    from collections import defaultdict
    # Compute stats for graphs over last 30 days
    date_counts = defaultdict(int)
    for m, subset in months.items():
        for i in subset:
            d = i["published"][:10]
            date_counts[d] += 1
    sorted_dates = sorted(date_counts.keys())[-30:] if date_counts else [built.strftime("%Y-%m-%d")]
    items_scanned_vals = [date_counts[d] for d in sorted_dates]
    
    errors_file = ROOT / "data" / "errors.json"
    err_list = json.loads(errors_file.read_text("utf-8")) if errors_file.exists() else []
    error_counts_vals = [len(err_list)] * len(sorted_dates) if sorted_dates else [0]
    try:
        generate_graphs(sorted_dates, items_scanned_vals, error_counts_vals)
    except Exception as e:
        warn(f"Failed to generate stats graphs: {e}")

    render("stats.html", "stats.html.j2", title="Statistics", heading="Statistics & System Health",
           intro="Hand-drawn performance and error metrics for the threat feed aggregator.", current="stats")
    shutil.copy(ROOT / "static" / "style.css", SITE_DIR / "style.css")
    log(f"Built site with {len(items)} items in {len(months)} month(s).")


if __name__ == "__main__":
    cmds = {"collect": collect, "build": build}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        raise SystemExit("usage: python main.py [collect|build]")
    cmds[sys.argv[1]]()
