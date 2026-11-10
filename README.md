# Threat Feed

A hardened, hourly-updated cybersecurity feed aggregator publishing a static site and RSS feeds.

## TL;DR

- **Collects**: Security news, advisories, research, exploited vulnerabilities (CISA KEV), open jobs, and free training from a fixed, trusted source list.
- **Validates & Sanitizes**: Enforces strict URL allowlists, HTTPS-only hops, size/timeout caps, XML-bomb defense (`defusedxml`), and HTML tag stripping for clean plain-text reading.
- **Threat Detection**: Optionally scans job and training links using VirusTotal with local caching and rate limiting, flagging suspicious or malicious links under the 'Warnings' category.
- **Static Output**: Builds a static HTML site with category views, monthly archives, a hand-drawn statistics dashboard, and one RSS feed per category.
- **Hourly Automation**: Runs via GitHub Pages and GitHub Actions every hour with zero long-lived credentials and robust concurrency protection.

## Architecture

```mermaid
flowchart TD
    A[Hourly Schedule / Manual Run] --> B[collect job]
    subgraph collect job
        B --> B1[Fetch: HTTPS-only, size cap, redirect limits]
        B1 --> B2[Parse RSS / KEV / Watch / Workable / Static with defusedxml]
        B2 --> B3[Sanitize HTML summaries & Validate allowlist]
        B3 --> B4[Deduplicate & Optional VirusTotal Scan\n(VT_API_KEY secret)]
        B4 --> B5[Commit data/ to repo]
    end
    B5 --> C[build job]
    subgraph build job
        C --> C1[Validate archive data schema]
        C1 --> C2[Render HTML pages, RSS feeds & stats.svg]
    end
    C2 --> D[deploy job]
    D --> E[GitHub Pages Site & RSS Feeds]
    E --> F[Reader / RSS App / Browser]
```

## Features

- **Categories**: Exploited, Advisories, News, Research, Jobs, Training, and Warnings.
- **Jobs Scoring & Top Match**: Ranks job listings based on relevance and highlights top-matching security roles.
- **Warnings Category**: Automatically isolates and flags suspicious links or potential threats.
- **Statistics Dashboard**: Visualizes feed metrics and system health with hand-drawn SVG trend charts (`stats.svg").
- **Subscribe Page**: Easy RSS subscription links for all categories.

## Security Model

- **Zero Trust Feed Data**: Everything from feeds is treated as untrusted, size-capped, reduced to plain text, and validated against strict schemas at build and collect time.
- **Link Allowlist**: Links are retained only if they use plain HTTPS and point to the source's own allowlisted domain (`link_domains").
- **Strict Isolation**: GitHub Actions permissions are locked down (`permissions: {}` by default), with the `VT_API_KEY` secret isolated strictly to the `collect` job.
- **Robust Defenses**: XML entity-expansion/bomb checks, redirect hop validation, and 45-minute workflow timeout protection prevent hangs and memory exhaustion.

## Deploy Your Own

1. Fork this repository and keep it public (private repos have limited free Actions minutes).
2. Go to **Settings > Pages** and set Source to **GitHub Actions**.
3. Go to **Settings > Actions > General** and ensure workflows from outside contributors require approval.
4. Edit `data/feeds.json` to configure your sources, `link_domains`, and keywords.
5. (Optional) Add your `VT_API_KEY` under **Settings > Secrets and variables > Actions** to enable URL threat scanning. Without it, threat scanning is gracefully disabled.
6. Go to the **Actions** tab, select **Threat feed**, and click **Run workflow** to perform the initial build.
7. Subscribe to your feeds using the links on your site's **Subscribe** page.

## Local Development

1. Create a Python 3.12 virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies with hashes:
   ```bash
   pip install --require-hashes -r requirements.txt
   ```
3. Run the collection and build pipeline:
   ```bash
   python main.py collect
   GITHUB_REPOSITORY=owner/repo python main.py build
   ```
4. Serve the generated `_site/` directory locally using any static web server.

## Updating Dependencies

1. Edit `requirements.in` to add or modify packages.
2. Regenerate hashes and locked dependencies:
   ```bash
   pip-compile --generate-hashes requirements.in
   ```
3. Review the diff before committing.

## Notes & Limits

- Keyword filtering rules and scoring logic are fully public.
- The `data/` directory (including error logs and VirusTotal cache) is committed to the repository and publicly visible.
- Unscanned links or skipped scans show no checkmark indicator.
