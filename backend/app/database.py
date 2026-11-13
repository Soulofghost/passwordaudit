import os
import sqlite3
from backend.app.config import DB_PATH

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        identifier TEXT,
        entropy_score REAL,
        keyspace_bits REAL,
        rating TEXT,
        nist_compliant INTEGER,
        breached INTEGER,
        created_at TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS breach_dictionary (
        hash_sha1_prefix TEXT PRIMARY KEY,
        hash_suffix TEXT,
        count INTEGER
    );
    """)

    conn.commit()
    conn.close()

init_db()
