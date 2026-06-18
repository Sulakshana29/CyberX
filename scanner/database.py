"""CyberX – SQLite persistence layer.

Two tables:
    scans    — one row per scan job (metadata + status)
    findings — one row per vulnerability found (linked to a scan)

Usage:
    from scanner.database import init_db, save_scan, update_scan_status,
                                  save_findings, get_scan, get_all_scans,
                                  get_findings
"""

import os
import sqlite3
import json
import logging

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict

DB_PATH = Path(os.environ.get('CYBERX_DB_PATH', 'cyberx.db'))
logger = logging.getLogger(__name__)

# ── connection helper ─────────────────────────────────────────────────

@contextmanager
def _get_conn():
    """Yield a thread-safe SQLite connection with WAL mode enabled.

    WAL (Write-Ahead Logging) allows concurrent readers while a write
    is happening — important because background scan threads write
    while Flask request threads read status/results simultaneously.
    """
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row   # rows behave like dicts
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── schema ────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables if they don't already exist.

    Safe to call on every startup — uses CREATE TABLE IF NOT EXISTS.
    """
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    UNIQUE NOT NULL,
                password_hash   TEXT    NOT NULL,
                role            TEXT    NOT NULL DEFAULT 'guest'
            );

            CREATE TABLE IF NOT EXISTS scans (
                scan_id       TEXT PRIMARY KEY,
                user_id       INTEGER REFERENCES users(id),
                status        TEXT    NOT NULL DEFAULT 'running',
                mode          TEXT    NOT NULL DEFAULT 'default',
                urls          TEXT    NOT NULL,          -- JSON array of URLs
                urls_count    INTEGER NOT NULL DEFAULT 0,
                started_at    TEXT    NOT NULL,
                completed_at  TEXT,
                total_findings   INTEGER DEFAULT 0,
                critical_count   INTEGER DEFAULT 0,
                high_count       INTEGER DEFAULT 0,
                medium_count     INTEGER DEFAULT 0,
                low_count        INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT    NOT NULL REFERENCES scans(scan_id),
                owasp_category  TEXT,
                scan_type       TEXT,
                target_url      TEXT,
                severity        TEXT,
                cvss_score      REAL    DEFAULT 0.0,
                details         TEXT,
                evidence        TEXT,
                timestamp       TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan_id
                ON findings(scan_id);

            CREATE INDEX IF NOT EXISTS idx_scans_started_at
                ON scans(started_at DESC);
        """)
        
        # Safe migration for existing databases
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
        except sqlite3.OperationalError as e:
            # Column already exists
            pass


# ── user operations ───────────────────────────────────────────────────

def get_user(user_id: int) -> Optional[Dict]:
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None

def get_user_by_username(username: str) -> Optional[Dict]:
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None

def create_user(username: str, password_hash: str, role: str = 'guest') -> int:
    with _get_conn() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError("Username already exists")

# ── write operations ──────────────────────────────────────────────────

def save_scan(scan_id: str, urls: List[str], mode: str, user_id: Optional[int] = None) -> None:
    """Insert a new scan row when the scan is first created."""
    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO scans
               (scan_id, user_id, status, mode, urls, urls_count, started_at)
               VALUES (?, ?, 'running', ?, ?, ?, ?)""",
            (scan_id, user_id, mode, json.dumps(urls), len(urls), datetime.now().isoformat())
        )


def update_scan_status(scan_id: str, status: str) -> None:
    """Update scan status ('running' → 'completed' or 'error')."""
    completed_at = datetime.now().isoformat() if status != 'running' else None
    with _get_conn() as conn:
        conn.execute(
            """UPDATE scans SET status = ?, completed_at = ?
               WHERE scan_id = ?""",
            (status, completed_at, scan_id)
        )


def save_findings(scan_id: str, results: list) -> None:
    """Bulk-insert all ScanResult objects and update the summary counts.

    Called once when the background scan thread completes.
    """
    if not results:
        update_scan_status(scan_id, 'completed')
        return

    rows = [
        (scan_id,
         r.owasp_category,
         r.scan_type,
         r.target_url,
         r.severity,
         r.cvss_score,
         r.details,
         r.evidence,
         r.timestamp.isoformat())
        for r in results
    ]

    critical = sum(1 for r in results if r.severity == 'CRITICAL')
    high     = sum(1 for r in results if r.severity == 'HIGH')
    medium   = sum(1 for r in results if r.severity == 'MEDIUM')
    low      = sum(1 for r in results if r.severity == 'LOW')

    with _get_conn() as conn:
        conn.executemany(
            """INSERT INTO findings
               (scan_id, owasp_category, scan_type, target_url,
                severity, cvss_score, details, evidence, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows
        )
        conn.execute(
            """UPDATE scans SET
               status          = 'completed',
               completed_at    = ?,
               total_findings  = ?,
               critical_count  = ?,
               high_count      = ?,
               medium_count    = ?,
               low_count       = ?
               WHERE scan_id   = ?""",
            (datetime.now().isoformat(),
             len(results), critical, high, medium, low,
             scan_id)
        )


def mark_scan_error(scan_id: str, error_msg: str) -> None:
    """Mark a scan as errored with a message stored in details."""
    with _get_conn() as conn:
        conn.execute(
            """UPDATE scans SET status = 'error', completed_at = ?
               WHERE scan_id = ?""",
            (datetime.now().isoformat(), scan_id)
        )


# ── read operations ───────────────────────────────────────────────────

def get_all_scans(user_id: Optional[int] = None, limit: int = 50) -> List[Dict]:
    """Return the most recent scans for the history page.

    Args:
        limit: Max number of rows to return (default 50).

    Returns:
        List of dicts with scan metadata — no findings included.
    """
    with _get_conn() as conn:
        query = """SELECT scan_id, status, mode, urls, urls_count,
                          started_at, completed_at,
                          total_findings, critical_count, high_count,
                          medium_count, low_count
                   FROM scans"""
        params = []
        if user_id is not None:
            query += " WHERE user_id = ?"
            params.append(user_id)
            
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(query, tuple(params)).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: str) -> Optional[Dict]:
    """Return metadata for a single scan, or None if not found."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    return dict(row) if row else None


def get_findings(scan_id: str) -> List[Dict]:
    """Return all findings for a given scan_id."""
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT owasp_category, scan_type, target_url,
                      severity, cvss_score, details, evidence, timestamp
               FROM findings
               WHERE scan_id = ?
               ORDER BY cvss_score DESC""",
            (scan_id,)
        ).fetchall()
    return [dict(r) for r in rows]
