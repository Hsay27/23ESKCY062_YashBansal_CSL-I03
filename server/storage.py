"""
storage.py - SQLite storage for verified readings and security events.

Tables
  readings         : every accepted sensor reading
  security_events  : every rejected request and the reason
  device_state     : highest sequence number accepted per device
"""

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

_lock = threading.Lock()   # Flask serves requests in threads
_db_path = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS readings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    temp_c      REAL    NOT NULL,
    humidity    REAL    NOT NULL,
    device_ts   INTEGER,
    received_at TEXT    NOT NULL,
    mode        TEXT    NOT NULL DEFAULT 'secure'
);
CREATE TABLE IF NOT EXISTS security_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    time      TEXT NOT NULL,
    device_id TEXT,
    remote_ip TEXT,
    reason    TEXT NOT NULL,
    detail    TEXT
);
CREATE TABLE IF NOT EXISTS device_state (
    device_id TEXT PRIMARY KEY,
    last_seq  INTEGER NOT NULL
);
"""


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def _db():
    """Open a connection, commit on success / roll back on error, then close."""
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init(db_path):
    global _db_path
    _db_path = db_path
    with _db() as conn:
        conn.executescript(SCHEMA)


def store_if_fresh(device_id, seq, reading):
    """Store a verified reading ONLY if seq is larger than the last accepted
    seq for this device. The check and the insert happen inside one lock and
    one transaction, so two copies of a packet arriving together cannot both
    be stored. Returns (stored: bool, last_seq: int)."""
    with _lock, _db() as conn:
        row = conn.execute("SELECT last_seq FROM device_state WHERE device_id=?",
                           (device_id,)).fetchone()
        last_seq = row["last_seq"] if row else 0
        if seq <= last_seq:
            return False, last_seq
        conn.execute(
            "INSERT INTO readings (device_id, seq, temp_c, humidity, device_ts, received_at, mode)"
            " VALUES (?, ?, ?, ?, ?, ?, 'secure')",
            (device_id, seq, reading["temp_c"], reading["humidity"],
             reading.get("ts"), _now()))
        conn.execute(
            "INSERT INTO device_state (device_id, last_seq) VALUES (?, ?)"
            " ON CONFLICT(device_id) DO UPDATE SET last_seq=excluded.last_seq",
            (device_id, seq))
        return True, last_seq


def store_plain(device_id, reading):
    """Insecure baseline endpoint only - stores without any checks."""
    with _lock, _db() as conn:
        conn.execute(
            "INSERT INTO readings (device_id, seq, temp_c, humidity, device_ts, received_at, mode)"
            " VALUES (?, 0, ?, ?, ?, ?, 'plain')",
            (device_id, reading["temp_c"], reading["humidity"], reading.get("ts"), _now()))


def log_event(device_id, remote_ip, reason, detail=""):
    with _lock, _db() as conn:
        conn.execute(
            "INSERT INTO security_events (time, device_id, remote_ip, reason, detail)"
            " VALUES (?, ?, ?, ?, ?)", (_now(), device_id, remote_ip, reason, detail))


def recent_readings(limit=20):
    with _db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM readings ORDER BY id DESC LIMIT ?", (limit,))]


def recent_events(limit=20):
    with _db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))]


def stats():
    with _db() as conn:
        accepted = conn.execute(
            "SELECT COUNT(*) FROM readings WHERE mode='secure'").fetchone()[0]
        rejected = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        by_reason = {r["reason"]: r["n"] for r in conn.execute(
            "SELECT reason, COUNT(*) AS n FROM security_events GROUP BY reason")}
        devices = conn.execute(
            "SELECT COUNT(DISTINCT device_id) FROM readings").fetchone()[0]
    return {"accepted": accepted, "rejected": rejected,
            "by_reason": by_reason, "devices": devices}
