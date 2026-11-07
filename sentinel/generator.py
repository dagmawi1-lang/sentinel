"""Synthetic log generator with labeled attack scenarios, for demos and tests.

Uses documentation-only IP ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and private ranges, so generated logs never reference real hosts.
"""
from __future__ import annotations
import json
import random
from datetime import datetime, timedelta

from .models import LoginEvent

USERS = {"alice": ["10.0.0.11", "10.0.0.12"], "bob": ["10.0.0.21"], "carol": ["10.0.0.31", "172.16.4.9"], "dana": ["10.0.0.41"], "eve": ["10.0.0.51"]}
SCENARIOS = {
    "brute_force": "198.51.100.23 guesses bob's password 12 times in 3 minutes",
    "password_spray": "203.0.113.77 tries one password against 6 accounts",
    "compromise": "192.0.2.44 fails 6 times on dana, then succeeds at 02:13 (also new IP + off-hours)",
    "enumeration": "198.51.100.90 probes 8 non-existent usernames",
}


def generate(start: datetime | None = None, days: int = 7, seed: int = 7, attacks: bool = True) -> tuple[list[LoginEvent], dict]:
    rnd = random.Random(seed)
    start = (start or datetime(2026, 11, 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    ev: list[LoginEvent] = []
    add = lambda ts, user, ip, ok, invalid=False: ev.append(LoginEvent(ts, user, ip, ok, invalid, "password", "web01", "synthetic"))
    for d in range(days):
        day = start + timedelta(days=d)
        for user, ips in USERS.items():
            for _ in range(rnd.randint(2, 4)):
                ts = day + timedelta(hours=rnd.randint(8, 18), minutes=rnd.randint(0, 59), seconds=rnd.randint(0, 59))
                ip = rnd.choice(ips)
                if rnd.random() < 0.12:  # an occasional typo
                    add(ts - timedelta(seconds=20), user, ip, False)
                add(ts, user, ip, True)
    truth = {}
    if attacks:
        t = start + timedelta(days=days - 2, hours=14, minutes=5)
        for i in range(12):
            add(t + timedelta(seconds=15 * i), "bob", "198.51.100.23", False)
        truth["brute_force"] = {"ip": "198.51.100.23", "user": "bob"}
        t = start + timedelta(days=days - 2, hours=16)
        for i, u in enumerate(["alice", "bob", "carol", "eve", "admin", "backup"]):
            add(t + timedelta(seconds=40 * i), u, "203.0.113.77", False, u in {"admin", "backup"})
        truth["password_spray"] = {"ip": "203.0.113.77"}
        t = start + timedelta(days=days - 1, hours=2, minutes=10)
        for i in range(6):
            add(t + timedelta(seconds=20 * i), "dana", "192.0.2.44", False)
        add(t + timedelta(minutes=3), "dana", "192.0.2.44", True)
        truth["compromise"] = {"ip": "192.0.2.44", "user": "dana"}
        t = start + timedelta(days=days - 1, hours=11)
        for i, u in enumerate(["root", "oracle", "test", "ubuntu", "pi", "git", "postgres", "ftp"]):
            add(t + timedelta(seconds=9 * i), u, "198.51.100.90", False, True)
        truth["enumeration"] = {"ip": "198.51.100.90"}
    ev.sort(key=lambda e: e.timestamp)
    return ev, truth


def to_auth_log(events: list[LoginEvent]) -> str:
    lines, pid = [], 2000
    for e in events:
        pid += 1
        stamp = f"{e.timestamp:%b} {e.timestamp.day:>2} {e.timestamp:%H:%M:%S}"
        port = 40000 + pid % 20000
        if e.success:
            lines.append(f"{stamp} {e.host or 'web01'} sshd[{pid}]: Accepted {e.method} for {e.user} from {e.ip} port {port} ssh2")
        else:
            if e.invalid_user:
                lines.append(f"{stamp} {e.host or 'web01'} sshd[{pid}]: Invalid user {e.user} from {e.ip} port {port}")
            lines.append(f"{stamp} {e.host or 'web01'} sshd[{pid}]: Failed {e.method} for {'invalid user ' if e.invalid_user else ''}{e.user} from {e.ip} port {port} ssh2")
    return "\n".join(lines) + "\n"


def to_jsonl(events: list[LoginEvent]) -> str:
    return "\n".join(json.dumps({"timestamp": e.timestamp.isoformat(), "user": e.user, "ip": e.ip, "success": e.success, "invalid_user": e.invalid_user, "method": e.method, "host": e.host}) for e in events) + "\n"
