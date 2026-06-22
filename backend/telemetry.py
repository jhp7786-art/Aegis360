import duckdb
import datetime

def log_sandbox_execution(payload: str, response: str, l1_status: str, l3_status: str):
    """
    Layer 4: Persists execution telemetry to a local DuckDB instance.
    Automatically creates the table if this is the first run.
    """
    # Connects to (or creates) a local database file named cyclops_telemetry.db
    conn = duckdb.connect('cyclops_telemetry.db')
    
    try:
        # Ensure the table exists
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                timestamp TIMESTAMP,
                user_payload TEXT,
                agent_response TEXT,
                layer1_status VARCHAR,
                layer3_status VARCHAR
            )
        ''')
        
        # Insert the telemetry record
        now = datetime.datetime.now()
        conn.execute(
            "INSERT INTO security_logs VALUES (?, ?, ?, ?, ?)", 
            [now, payload, response, l1_status, l3_status]
        )
    finally:
        conn.close() # Always close the connection to prevent file locking