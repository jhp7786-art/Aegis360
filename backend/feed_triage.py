"""
backend/feed_triage.py
======================
Cerberus Feed Ingestion & AI Triage Pipeline
--------------------------------------------
Three responsibilities, cleanly separated:

  1. parse_feeds()            — Fetch & parse RSS/Atom from configured sources.
  2. classify_article()       — Call Gemini Flash for a 3-tier HIGH/MEDIUM/LOW verdict.
  3. ingest_and_triage_feeds() — Orchestrate the full pipeline, return summary counts.

The single GEMINI_API_KEY environment variable is used (set via the Athena tab).
All exceptions are handled locally; no call here will ever crash the Streamlit UI.
"""

import os
import re
import requests
from xml.etree import ElementTree as ET

from backend.db import save_feed_article, get_known_feed_urls

# ---------------------------------------------------------------------------
# Feed Definitions
# ---------------------------------------------------------------------------
# RSS format  : articles are <item> elements under <channel>
# Atom format : articles are <entry> elements; CISA uses the Atom namespace
ATOM_NS = "http://www.w3.org/2005/Atom"

FEEDS: list[dict] = [
    {
        "source": "The Hacker News",
        "url":    "https://feeds.feedburner.com/TheHackersNews",
        "format": "rss",
    },
    {
        "source": "BleepingComputer",
        "url":    "https://www.bleepingcomputer.com/feed/",
        "format": "rss",
    },
    {
        "source": "CISA Alerts",
        "url":    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "format": "atom",
    },
]

# Max articles to pull per source per sync cycle
MAX_PER_SOURCE = 10


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _strip_html(text: str, max_len: int = 400) -> str:
    """Remove HTML tags, collapse whitespace, truncate to max_len chars."""
    text = re.sub(r"<[^>]+>", "", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len]


# ---------------------------------------------------------------------------
# Step 1: Feed Parser
# ---------------------------------------------------------------------------

def parse_feeds() -> list[dict]:
    """Fetch and parse all configured RSS/Atom feeds.

    Returns a list of new article dicts: {source, title, url, summary}.
    Articles whose URLs are already in the database are skipped so we never
    re-triage content that has already been classified.
    """
    known_urls: set = get_known_feed_urls()
    articles: list[dict] = []

    for feed_cfg in FEEDS:
        try:
            response = requests.get(
                feed_cfg["url"],
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (compatible; Aegis360/1.0)"},
            )
            response.raise_for_status()
            root = ET.fromstring(response.content)

            if feed_cfg["format"] == "atom":
                # CISA uses the W3C Atom namespace on every tag
                entries = root.findall(f"{{{ATOM_NS}}}entry")[:MAX_PER_SOURCE]
                for entry in entries:
                    title = (entry.findtext(f"{{{ATOM_NS}}}title") or "").strip()
                    link_el = entry.find(f"{{{ATOM_NS}}}link")
                    url = (link_el.get("href") if link_el is not None else "") or ""
                    # Atom summary may be HTML-encoded; strip tags before storing
                    raw_summary = (
                        entry.findtext(f"{{{ATOM_NS}}}summary")
                        or entry.findtext(f"{{{ATOM_NS}}}content")
                        or ""
                    )
                    summary = _strip_html(raw_summary)

                    if title and url and url not in known_urls:
                        articles.append({
                            "source":  feed_cfg["source"],
                            "title":   title,
                            "url":     url,
                            "summary": summary,
                        })
            else:
                # Standard RSS 2.0
                items = root.findall(".//item")[:MAX_PER_SOURCE]
                for item in items:
                    title = (item.findtext("title") or "").strip()
                    url   = (item.findtext("link")  or "").strip()
                    raw_summary = item.findtext("description") or ""
                    summary = _strip_html(raw_summary)

                    if title and url and url not in known_urls:
                        articles.append({
                            "source":  feed_cfg["source"],
                            "title":   title,
                            "url":     url,
                            "summary": summary,
                        })

        except requests.exceptions.Timeout:
            # Non-fatal: one dead feed shouldn't abort the whole sync
            pass
        except requests.exceptions.RequestException:
            pass
        except ET.ParseError:
            pass

    return articles


# ---------------------------------------------------------------------------
# Step 2: AI Triage Classifier
# ---------------------------------------------------------------------------

# Tight, deterministic prompt — temperature=0, maxOutputTokens=5 ensures
# Gemini returns exactly one word with minimal token spend.
_TRIAGE_PROMPT = """\
You are a security triage AI for an enterprise cybersecurity operations center.
Classify the following security headline into exactly one priority tier.

Tier definitions:
  HIGH   — Systemic enterprise risk, cloud provider outages or breaches, \
critical infrastructure attacks, supply chain compromises, data architecture \
vulnerabilities, or any incident affecting major platforms at scale.
  MEDIUM — Active malware campaigns, ransomware operations, zero-day exploits \
with live exploitation, APT/threat actor activity, or mass exploitation events \
with a working proof-of-concept.
  LOW    — Security research papers, general opinion content, minor patch \
advisories without active exploitation, vendor announcements, tool releases, \
conference talks, or general security-awareness material.

Reply with ONE WORD only — HIGH, MEDIUM, or LOW — and nothing else.

Headline: {title}
Summary:  {summary}"""


def classify_article(title: str, summary: str) -> str:
    """Send a single article to Gemini Flash for 3-tier triage.

    Returns "HIGH", "MEDIUM", or "LOW".
    Defaults to "LOW" on any error (fail-safe: never promote unknown content).
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return "LOW"  # no key → assume LOW, skip AI cost

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta"
        f"/models/gemini-2.0-flash:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{
            "parts": [{
                "text": _TRIAGE_PROMPT.format(
                    title=title[:300],
                    summary=summary[:400],
                )
            }]
        }],
        "generationConfig": {
            "temperature":    0.0,   # fully deterministic
            "maxOutputTokens": 5,    # one word is all we need
        },
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=15)
        response.raise_for_status()
        raw = (
            response.json()["candidates"][0]["content"]["parts"][0]["text"]
            .strip()
            .upper()
        )
        if raw in ("HIGH", "MEDIUM", "LOW"):
            return raw
        # Gemini returned something unexpected — default to LOW
        return "LOW"

    except Exception:
        # Network error, quota exceeded, malformed response — always fail LOW
        return "LOW"


# ---------------------------------------------------------------------------
# Step 3: Pipeline Orchestrator
# ---------------------------------------------------------------------------

def ingest_and_triage_feeds() -> dict:
    """Run the full Cerberus pipeline: parse → classify → persist.

    Returns a summary dict consumed by the UI spinner:
        {"high": N, "medium": N, "low": N, "skipped": N, "errors": N}

    "skipped" counts articles that were already in the DB (URL dedup).
    "errors"  counts articles that raised an exception during triage/save.
    """
    counts = {"high": 0, "medium": 0, "low": 0, "skipped": 0, "errors": 0}

    try:
        new_articles = parse_feeds()
    except Exception:
        counts["errors"] += 1
        return counts

    for article in new_articles:
        try:
            priority = classify_article(article["title"], article["summary"])
            save_feed_article(
                source=article["source"],
                title=article["title"],
                url=article["url"],
                summary=article["summary"],
                priority_level=priority,
            )
            counts[priority.lower()] += 1
        except Exception:
            counts["errors"] += 1

    return counts
