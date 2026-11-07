"""SQLite storage for events and incidents."""
from __future__ import annotations
import sqlite3
from datetime import datetime

from .models import Alert, LoginEvent

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, user TEXT NOT NULL, ip TEXT NOT NULL, success INTEGER NOT NULL,
  invalid_user INTEGER NOT NULL DEFAULT 0, method TEXT, host TEXT, source TEXT, raw TEXT,
  UNIQUE (ts, user, ip, success, raw));
CREATE INDEX IF NOT EXISTS events_ip_ts ON events (ip, ts);
CREATE INDEX IF NOT EXISTS events_user_ts ON events (user, ts);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY, dedupe_key TEXT UNIQUE NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')), title TEXT NOT NULL, description TEXT NOT NULL,
  user TEXT, ip TEXT, start_ts TEXT NOT NULL, end_ts TEXT NOT NULL, event_count INTEGER NOT NULL, mitre TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolved','false_positive')),
  notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incident_events (
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, PRIMARY KEY (incident_id, event_id));
"""
STATUSES = ("open", "investigating", "resolved", "false_positive")


def connect(path: str = "sentinel.db") -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def insert_events(con: sqlite3.Connection, events: list[LoginEvent]) -> int:
    """Inserts events, ignoring exact duplicates (re-ingesting the same log is safe). Returns new rows."""
    before = con.total_changes
    with con:
        con.executemany(
            "INSERT OR IGNORE INTO events (ts, user, ip, success, invalid_user, method, host, source, raw) VALUES (?,?,?,?,?,?,?,?,?)",
            [(e.timestamp.isoformat(sep=" "), e.user, e.ip, int(e.success), int(e.invalid_user), e.method, e.host, e.source, e.raw) for e in events])
    return con.total_changes - before


def load_events(con: sqlite3.Connection, since: datetime | None = None) -> list[LoginEvent]:
    sql = "SELECT * FROM events" + (" WHERE ts >= ?" if since else "") + " ORDER BY ts, id"
    rows = con.execute(sql, (since.isoformat(sep=" "),) if since else ()).fetchall()
    return [LoginEvent(datetime.fromisoformat(r["ts"]), r["user"], r["ip"], bool(r["success"]), bool(r["invalid_user"]), r["method"] or "", r["host"] or "", r["source"] or "", r["raw"] or "", r["id"]) for r in rows]


def save_alerts(con: sqlite3.Connection, alerts: list[Alert]) -> int:
    """Stores alerts as incidents. Existing incidents (same rule/user/ip/start) are updated, not duplicated."""
    now = datetime.now().isoformat(timespec="seconds")
    created = 0
    with con:
        for a in alerts:
            row = con.execute("SELECT id FROM incidents WHERE dedupe_key = ?", (a.key,)).fetchone()
            if row:
                con.execute("UPDATE incidents SET end_ts=?, event_count=MAX(event_count, ?), severity=?, description=?, updated_at=? WHERE id=?",
                            (a.end.isoformat(sep=" "), a.count, a.severity, a.description, now, row["id"]))
                iid = row["id"]
            else:
                cur = con.execute("INSERT INTO incidents (dedupe_key, rule, severity, title, description, user, ip, start_ts, end_ts, event_count, mitre, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                  (a.key, a.rule, a.severity, a.title, a.description, a.user, a.ip, a.start.isoformat(sep=" "), a.end.isoformat(sep=" "), a.count, a.mitre, now, now))
                iid = cur.lastrowid; created += 1
            con.executemany("INSERT OR IGNORE INTO incident_events VALUES (?,?)", [(iid, eid) for eid in a.event_ids])
    return created


def list_incidents(con: sqlite3.Connection, status: str | None = None, severity: str | None = None) -> list[sqlite3.Row]:
    sql, args = "SELECT * FROM incidents WHERE 1=1", []
    if status:
        sql += " AND status = ?"; args.append(status)
    if severity:
        sql += " AND severity = ?"; args.append(severity)
    sql += " ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, start_ts DESC"
    return con.execute(sql, args).fetchall()


def incident_events(con: sqlite3.Connection, incident_id: int) -> list[sqlite3.Row]:
    return con.execute("SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.id WHERE ie.incident_id = ? ORDER BY e.ts", (incident_id,)).fetchall()


def update_incident(con: sqlite3.Connection, incident_id: int, status: str | None = None, note: str | None = None) -> bool:
    if status and status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    row = con.execute("SELECT notes FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        return False
    notes = row["notes"]
    if note:
        notes = (notes + "\n" if notes else "") + f"[{datetime.now():%Y-%m-%d %H:%M}] {note.strip()[:500]}"
    with con:
        con.execute("UPDATE incidents SET status = COALESCE(?, status), notes = ?, updated_at = ? WHERE id = ?",
                    (status, notes, datetime.now().isoformat(timespec="seconds"), incident_id))
    return True


def stats(con: sqlite3.Connection) -> dict:
    one = lambda sql, *a: con.execute(sql, a).fetchone()[0]
    return {
        "events": one("SELECT COUNT(*) FROM events"),
        "failed": one("SELECT COUNT(*) FROM events WHERE success = 0"),
        "succeeded": one("SELECT COUNT(*) FROM events WHERE success = 1"),
        "unique_ips": one("SELECT COUNT(DISTINCT ip) FROM events"),
        "unique_users": one("SELECT COUNT(DISTINCT user) FROM events"),
        "open_incidents": one("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')"),
        "by_severity": {r[0]: r[1] for r in con.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")},
        "top_failing_ips": [dict(r) for r in con.execute("SELECT ip, COUNT(*) AS failures, COUNT(DISTINCT user) AS users FROM events WHERE success = 0 GROUP BY ip ORDER BY failures DESC LIMIT 10")],
        "first_event": one("SELECT MIN(ts) FROM events"), "last_event": one("SELECT MAX(ts) FROM events"),
    }
