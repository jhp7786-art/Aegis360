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
