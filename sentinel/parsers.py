"""Parsers for Linux auth.log (sshd), JSON Lines, and CSV login logs."""
from __future__ import annotations
import csv
import io
import ipaddress
import json
import re
from datetime import datetime
from typing import Iterable, Iterator

from .models import LoginEvent

_SYSLOG_PREFIX = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s(?P<msg>.*)$")
_ISO_PREFIX = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s(?P<host>\S+)\s(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s(?P<msg>.*)$")
_FAILED = re.compile(r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
_ACCEPTED = re.compile(r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port \d+)?")
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def parse_auth_log(lines: Iterable[str], year: int | None = None, source: str = "auth.log") -> Iterator[LoginEvent]:
    """Parse sshd lines from /var/log/auth.log or /var/log/secure.

    Classic syslog timestamps have no year, so `year` (default: current year) is applied, and
    a rollover from December to January increments it.
    """
    year = year or datetime.now().year
    last_month = None
    for line in lines:
        line = line.rstrip("\n")
        m = _SYSLOG_PREFIX.match(line)
        if m:
            month = _MONTHS.get(m["mon"])
            if month is None:
                continue
            if last_month == 12 and month == 1:
                year += 1
            last_month = month
            try:
                ts = datetime.strptime(f"{year}-{month:02d}-{int(m['day']):02d} {m['time']}", "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
        else:
            m = _ISO_PREFIX.match(line)
            if not m:
                continue
            try:
                ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                continue
        if not m["proc"].startswith("sshd"):
            continue
        msg, host = m["msg"], m["host"]
        if (f := _FAILED.match(msg)) and _valid_ip(f["ip"]):
            yield LoginEvent(ts, f["user"], f["ip"], False, bool(f["invalid"]), f["method"], host, source, line)
        elif (a := _ACCEPTED.match(msg)) and _valid_ip(a["ip"]):
            yield LoginEvent(ts, a["user"], a["ip"], True, False, a["method"], host, source, line)
        elif (i := _INVALID.match(msg)) and _valid_ip(i["ip"]):
            # "Invalid user" is usually followed by a "Failed password for invalid user" line; record it once there.
            continue


def _truthy(v) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "success", "succeeded", "ok", "accepted"}


def _event_from_record(rec: dict, source: str) -> LoginEvent | None:
    ts_raw = rec.get("timestamp") or rec.get("time") or rec.get("ts")
    user = str(rec.get("user") or rec.get("username") or "").strip()
    ip = str(rec.get("ip") or rec.get("src_ip") or rec.get("source_ip") or "").strip()
    if not ts_raw or not user or not _valid_ip(ip):
        return None
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None
    success = rec.get("success")
    if success is None:
        success = rec.get("result") or rec.get("outcome") or rec.get("status")
    return LoginEvent(ts, user[:64], ip, _truthy(success), _truthy(rec.get("invalid_user", False)), str(rec.get("method", "password"))[:32], str(rec.get("host", ""))[:64], source, json.dumps(rec)[:500])


def parse_jsonl(text: str, source: str = "jsonl") -> Iterator[LoginEvent]:
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and (e := _event_from_record(rec, source)):
            yield e


def parse_csv(text: str, source: str = "csv") -> Iterator[LoginEvent]:
    for rec in csv.DictReader(io.StringIO(text)):
        if e := _event_from_record({k.strip().lower(): v for k, v in rec.items() if k}, source):
            yield e


def parse_file(path: str, year: int | None = None) -> list[LoginEvent]:
    """Detects the format from the file extension and content."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    name = path.lower()
    if name.endswith((".jsonl", ".ndjson", ".json")):
        return list(parse_jsonl(text, source=path))
    if name.endswith(".csv"):
        return list(parse_csv(text, source=path))
    return list(parse_auth_log(text.splitlines(), year=year, source=path))
