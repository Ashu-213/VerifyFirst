"""
database.py — SQLite persistence for analysis results.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "verifyfirst.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS analysis_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            risk_score  INTEGER,
            category    TEXT,
            reasons     TEXT,
            analyzed_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_result(url: str, result: dict):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO analysis_log (url, risk_score, category, reasons, analyzed_at) VALUES (?,?,?,?,?)",
            (
                url,
                result.get("risk_score"),
                result.get("category"),
                json.dumps(result.get("reasons", [])),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Log error: {e}")


def get_stats() -> dict:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT category, COUNT(*) FROM analysis_log GROUP BY category")
        rows = c.fetchall()
        conn.close()
        return {row[0]: row[1] for row in rows}
    except Exception:
        return {}
