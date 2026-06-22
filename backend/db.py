import streamlit as st
import pandas as pd
import duckdb
import json

DB_PATH = "aegis360.duckdb"

def init_db():
    """Initializes the DuckDB tables if they do not exist with correct sequencing order."""
    conn = duckdb.connect(DB_PATH)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cloud_status (
            service_name VARCHAR PRIMARY KEY,
            status VARCHAR,
            last_updated TIMESTAMP
        )
    """)
    
    conn.execute("CREATE SEQUENCE IF NOT EXISTS threat_id_seq START 1")
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS local_threats (
            id INTEGER PRIMARY KEY DEFAULT nextval('threat_id_seq'),
            timestamp TIMESTAMP,
            severity VARCHAR,
            source_ip VARCHAR,
            event_type VARCHAR,
            description VARCHAR
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS osint_reports (
            id INTEGER PRIMARY KEY DEFAULT nextval('threat_id_seq'),
            timestamp TIMESTAMP DEFAULT NOW(),
            source_url VARCHAR,
            summary VARCHAR,
            threat_actors VARCHAR[],
            targeted_industries VARCHAR[],
            iocs JSON
        )
    """)

    # threat_feed_articles: persists every article ingested by the Cerberus
    # feed parser. The UNIQUE constraint on `url` prevents double-ingestion
    # across sync cycles — new articles only ever get one AI triage call.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_feed_articles (
            id             INTEGER PRIMARY KEY DEFAULT nextval('threat_id_seq'),
            ingested_at    TIMESTAMP DEFAULT NOW(),
            source         VARCHAR,
            title          VARCHAR,
            url            VARCHAR UNIQUE,
            summary        VARCHAR,
            priority_level VARCHAR
        )
    """)

    count = conn.execute("SELECT COUNT(*) FROM local_threats").fetchone()[0]
    if count == 0:
        conn.execute("""
            INSERT INTO local_threats (timestamp, severity, source_ip, event_type, description) VALUES
            (NOW() - INTERVAL 5 MINUTE, 'High', '192.168.1.105', 'Port Scan', 'Sequential TCP port scanning detected'),
            (NOW() - INTERVAL 12 MINUTE, 'Medium', '10.0.0.4', 'Failed Login', '3 consecutive failed SSH attempts'),
            (NOW() - INTERVAL 45 MINUTE, 'Critical', '172.16.0.8', 'Malware Beaconing', 'Known C2 framework heartbeat matched'),
            (NOW() - INTERVAL 2 HOUR, 'Low', '192.168.1.201', 'Anomalous Traffic', 'Unusual outbound UDP flood to external NTP')
        """)
    conn.close()

@st.cache_data(ttl=30)
def load_query_data(query):
    df = pd.DataFrame()
    try:
        with duckdb.connect(DB_PATH) as conn:
            df = conn.execute(query).df()
    except Exception as e:
        st.error(f"Database Query Error: {e}")
    return df

def save_osint_report(source_url, summary, threat_actors, targeted_industries, iocs_list):
    """Saves threat intelligence OSINT report data to the DuckDB osint_reports table."""
    with duckdb.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO osint_reports (source_url, summary, threat_actors, targeted_industries, iocs)
            VALUES (?, ?, ?, ?, ?)
        """, (
            source_url,
            summary,
            threat_actors,
            targeted_industries,
            json.dumps(iocs_list)
        ))


def save_feed_article(source: str, title: str, url: str, summary: str, priority_level: str):
    """Persists a triaged feed article. ON CONFLICT DO NOTHING is the dedup guard —
    re-syncing the same URL is silently ignored so we never double-charge an AI call."""
    with duckdb.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO threat_feed_articles (source, title, url, summary, priority_level)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (url) DO NOTHING
        """, (source, title, url, summary, priority_level))


def load_feed_articles(priority_level: str) -> pd.DataFrame:
    """Return all feed articles for the given priority tier, newest first."""
    try:
        with duckdb.connect(DB_PATH) as conn:
            return conn.execute("""
                SELECT ingested_at, source, title, url, summary
                FROM   threat_feed_articles
                WHERE  priority_level = ?
                ORDER  BY ingested_at DESC
            """, [priority_level]).df()
    except Exception:
        return pd.DataFrame()


def get_known_feed_urls() -> set:
    """Return the set of every URL already in the DB. Used by the parser to skip
    articles that have already been ingested and triaged on a previous sync."""
    try:
        with duckdb.connect(DB_PATH) as conn:
            rows = conn.execute("SELECT url FROM threat_feed_articles").fetchall()
            return {row[0] for row in rows}
    except Exception:
        return set()
