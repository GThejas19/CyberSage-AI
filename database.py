import json
import sqlite3
from pathlib import Path

DATABASE_FILE = Path(__file__).resolve().parent / "cybersage.db"


def get_connection():
    """Open a connection to the CyberSage scan database."""
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create the scan table and safely add user ownership to older databases."""
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                input_text TEXT NOT NULL,
                risk TEXT,
                score INTEGER,
                prediction TEXT,
                findings TEXT,
                user_id INTEGER DEFAULT NULL
            )
        """)

        # Migrate existing databases without deleting or reassigning old scans.
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scan_history)"
            ).fetchall()
        }

        if "user_id" not in columns:
            connection.execute(
                "ALTER TABLE scan_history ADD COLUMN user_id INTEGER DEFAULT NULL"
            )

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_user_id
            ON scan_history(user_id)
        """)


def save_scan(input_text, result, user_id):
    """Save a new scan for the currently logged-in user."""
    findings = result.get("findings", [])

    if isinstance(findings, (list, dict)):
        findings_text = json.dumps(findings, ensure_ascii=False)
    else:
        findings_text = str(findings or "")

    with get_connection() as connection:
        cursor = connection.execute("""
    INSERT INTO scan_history
        (scanned_at, input_text, risk, score, prediction, findings, user_id)
    VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?)
""", (
    input_text,
    result.get("risk", "Unknown"),
    int(result.get("score", 0)),
    str(result.get("prediction", "Unavailable")),
    findings_text,
    int(user_id),
))
        return cursor.lastrowid


def get_recent_scans(user_id, limit=50):
    """Return only scans owned by this user, newest first."""
    with get_connection() as connection:
        return connection.execute("""
            SELECT id, scanned_at, input_text, risk, score,
                   prediction, findings
            FROM scan_history
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (int(user_id), max(1, min(int(limit), 500)))).fetchall()


def get_scan(scan_id, user_id):
    """Fetch one scan only when it belongs to this user."""
    with get_connection() as connection:
        return connection.execute("""
            SELECT id, scanned_at, input_text, risk, score,
                   prediction, findings
            FROM scan_history
            WHERE id = ? AND user_id = ?
        """, (int(scan_id), int(user_id))).fetchone()


def get_dashboard_stats(user_id):
    """Calculate dashboard statistics using only this user's scans."""
    with get_connection() as connection:
        row = connection.execute("""
            SELECT
                COUNT(*) AS total_scans,
                SUM(CASE
                    WHEN LOWER(COALESCE(prediction, '')) LIKE '%phish%'
                    THEN 1 ELSE 0
                END) AS phishing_count,
                SUM(CASE
                    WHEN LOWER(COALESCE(prediction, '')) LIKE '%legitimate%'
                      OR LOWER(COALESCE(prediction, '')) LIKE '%safe%'
                    THEN 1 ELSE 0
                END) AS legitimate_count,
                SUM(CASE
                    WHEN LOWER(COALESCE(risk, '')) = 'high'
                      OR LOWER(COALESCE(risk, '')) = 'critical'
                    THEN 1 ELSE 0
                END) AS high_risk_count
            FROM scan_history
            WHERE user_id = ?
        """, (int(user_id),)).fetchone()

    return {
        "total_scans": row["total_scans"] or 0,
        "phishing_count": row["phishing_count"] or 0,
        "legitimate_count": row["legitimate_count"] or 0,
        "high_risk_count": row["high_risk_count"] or 0,
    }