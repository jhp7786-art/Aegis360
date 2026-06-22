import datetime
import os
import requests
import duckdb
import pandas as pd
import streamlit as st
from xml.etree import ElementTree as ET

DB_PATH = "aegis360.duckdb"

def fetch_and_store_cloud_status():
    endpoints = {
        "GitHub": "https://www.githubstatus.com/api/v2/status.json",
        "Cloudflare": "https://www.cloudflarestatus.com/api/v2/status.json",
        "Discord": "https://discordstatus.com/api/v2/status.json"
    }
    cloud_statuses = []
    timestamp = datetime.datetime.now().isoformat()
    
    for service_name, url in endpoints.items():
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            payload = response.json()
            raw_status = payload.get("status", {}).get("indicator", "unknown")
            mapped_status = "Operational" if raw_status.lower() == "none" else raw_status.title()
            cloud_statuses.append({"service_name": service_name, "status": mapped_status, "last_updated": timestamp})
        except requests.exceptions.RequestException as e:
            st.sidebar.error(f"Failed to fetch {service_name}: {e}")
            continue

    if not cloud_statuses: return

    try:
        with duckdb.connect(DB_PATH) as conn:
            for status in cloud_statuses:
                conn.execute("""
                    INSERT INTO cloud_status (service_name, status, last_updated)
                    VALUES (?, ?, ?)
                    ON CONFLICT (service_name) DO UPDATE 
                    SET status = EXCLUDED.status, last_updated = EXCLUDED.last_updated
                """, (status["service_name"], status["status"], status["last_updated"]))
        st.sidebar.success("Free cloud status feeds synced successfully.")
        st.cache_data.clear()
    except Exception as e:
        st.sidebar.error(f"Database Ingestion Error: {e}")

# ---------------------------------------------------------------------------
# CERBERUS — Live RSS Intel Fetcher
# Place this call at the TOP of the Hermes page block in app.py, before the
# briefing button, so the feed data is ready to hand off to Gemini.
# ---------------------------------------------------------------------------
@st.cache_data(ttl=3600)
def fetch_live_threat_feeds() -> str:
    """Pull the top-5 headlines from The Hacker News and BleepingComputer
    RSS feeds and return them as a single Markdown string ready for Gemini.

    Cached for 1 hour (ttl=3600) so repeated UI renders don't hammer the feeds.
    Returns an empty string on total failure so the caller can degrade gracefully.
    """
    sources = {
        "The Hacker News":  "https://feeds.feedburner.com/TheHackersNews",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    }

    sections: list[str] = []

    for source_name, feed_url in sources.items():
        try:
            response = requests.get(
                feed_url,
                timeout=8,
                # Mimic a real browser UA so feeds don't return 403
                headers={"User-Agent": "Mozilla/5.0 (compatible; Aegis360/1.0)"},
            )
            response.raise_for_status()

            root = ET.fromstring(response.content)
            # RSS <item> elements live under <channel>
            items = root.findall(".//item")[:5]

            if not items:
                sections.append(f"### {source_name}\n_No articles found in feed._\n")
                continue

            lines = [f"### {source_name}"]
            for item in items:
                title = (item.findtext("title") or "Untitled").strip()
                link  = (item.findtext("link")  or "#").strip()
                lines.append(f"- [{title}]({link})")
            sections.append("\n".join(lines))

        except requests.exceptions.Timeout:
            # Feed timed out — log a warning but don't crash the app
            sections.append(
                f"### {source_name}\n"
                f"_⚠️ Feed timed out. Live headlines unavailable for this source._\n"
            )
        except requests.exceptions.RequestException as req_err:
            sections.append(
                f"### {source_name}\n"
                f"_⚠️ Network error: {req_err}_\n"
            )
        except ET.ParseError as xml_err:
            sections.append(
                f"### {source_name}\n"
                f"_⚠️ Feed parse error: {xml_err}_\n"
            )

    return "\n\n".join(sections)


def generate_morning_briefing(local_threats_df: pd.DataFrame, osint_df: pd.DataFrame) -> str:
    """Generates the CISO briefing via direct REST call."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("API Key is missing. Please enter it in the Deep Analysis tab first.")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    
    # -----------------------------------------------------------------------
    # HERMES — Retrieve the pre-fetched Cerberus feed context.
    # fetch_live_threat_feeds() is cached so this is effectively free;
    # the actual HTTP calls only happen once per hour.
    # -----------------------------------------------------------------------
    live_feed_context = fetch_live_threat_feeds()

    # Build the system-level tactical persona + live intelligence injection
    system_instruction = (
        "You are HERMES, the tactical AI intelligence officer for Aegis360. "
        "Your mission is to synthesize live external threat intelligence with "
        "internal telemetry and deliver a concise, executive-grade morning briefing. "
        "Be precise, use military-style brevity, and prioritise actionable insights. "
        "Format your response using clear Markdown headers and bullet points."
    )

    prompt = f"""
    {system_instruction}

    --- LIVE EXTERNAL THREAT INTELLIGENCE (Cerberus Feed — last 60 min) ---
    {live_feed_context if live_feed_context else "_No live feed data available at this time._"}

    --- INTERNAL TELEMETRY (Local DuckDB — Aegis360 Network Events) ---
    {local_threats_df.to_json(orient='records')}

    --- INGESTED OSINT REPORTS (AI-structured historical intelligence) ---
    {osint_df.to_json(orient='records')}

    Deliver a short executive morning briefing covering:
    1. **Active Internal Incidents** — Events from local telemetry requiring immediate triage.
    2. **Live External Threat Landscape** — Key threats surfaced in today's live feeds and how they map to our posture.
    3. **Recommended Defensive Actions** — Specific, prioritised steps for the next 24 hours.
    """
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3}
    }
    
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    
    data = response.json()
    return data['candidates'][0]['content']['parts'][0]['text']
