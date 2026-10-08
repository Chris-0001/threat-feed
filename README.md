# Threat feed

A small, hardened cybersecurity news aggregator. It pulls from a fixed list of
official and media sources, sorts items into categories, and publishes a static
site plus one RSS feed per category on GitHub Pages. No server, no database,
no secrets, no LLM.

## How it works

1. **collect** (hourly, GitHub Actions): fetches each source with conditional
   requests (`ETag` / `If-Modified-Since`), dedupes by stable ID, and appends
   new items to `data/archive/YYYY-MM.json`. If nothing is new, it writes
   nothing and the site is not rebuilt.
2. **build**: renders `_site/` from the archive: category pages, a monthly
   archive, and `feeds/<category>.xml`.
3. **deploy**: publishes `_site/` to GitHub Pages.

Each step is a separate job with minimal permissions. Only `collect` can write
to the repo, and only `deploy` can publish.

## Security model

Feeds are treated as hostile input.

- HTTPS only, 5 MB cap on the decompressed body, connect/read/total timeouts, redirect limit.
- Titles and summaries are reduced to plain text and length-capped. Control and bidi-override characters are removed.
- A link is kept only if it is HTTPS and on that feed's own `link_domains` allowlist.
- Archived data is validated again at build time. Invalid items are dropped.
- Templates use Jinja2 autoescaping. The site has no JavaScript and a strict CSP meta tag.
- Dependencies are installed with `--require-hashes`. Dependabot proposes updates.
- Trust tiers (`official`, `vendor`, `media`) are shown on every item.

Limits: a compromised source can still publish misleading text on its own
domain, and GitHub Pages cannot set HTTP headers (the CSP is a meta tag).

## Setup

```bash
pip install pip-tools
pip-compile --generate-hashes requirements.in      # creates requirements.txt
```

Then commit, and in the GitHub repo:

1. Settings > Pages > Source: **GitHub Actions**.
2. Settings > Actions > General: require approval for workflows from outside contributors.
3. Actions tab > **Threat feed** > Run workflow (the first run builds the site).

Subscribe in an RSS reader using the addresses on the site's Subscribe page.

## Adding a source

Add an entry to `data/feeds.json` with a `category`, a `trust` tier, and the
`link_domains` its article links may point to. Open the feed URL in a browser first.
