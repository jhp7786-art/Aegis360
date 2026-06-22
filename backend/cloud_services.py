import datetime
import os
import requests
import duckdb
import pandas as pd
import streamlit as st

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

def generate_morning_briefing(local_threats_df: pd.DataFrame, osint_df: pd.DataFrame) -> str:
    """Generates the CISO briefing via direct REST call."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("API Key is missing. Please enter it in the Deep Analysis tab first.")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    
    prompt = f"""
    You are the Chief Information Security Officer (CISO) summarizing the morning status for Aegis360.
    Cross-reference our local network telemetry with the latest ingested external intelligence.
    
    Local Threat Telemetry:
    {local_threats_df.to_json(orient='records')}
    
    Ingested OSINT Threat Reports:
    {osint_df.to_json(orient='records')}
    
    Provide a highly professional 3-paragraph situational briefing:
    1. Active Internal Vulnerabilities/Incidents requiring immediate triage.
    2. High-priority global trends or actors mentioned in OSINT that overlap with our current asset posture.
    3. Defensive recommendations for the next 24 hours.
    Use clear Markdown headers and bullet points.
    """
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3}
    }
    
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    
    data = response.json()
    return data['candidates'][0]['content']['parts'][0]['text']
