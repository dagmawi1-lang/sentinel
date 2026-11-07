"""Detection rules. Each rule is a small, explainable function over time-ordered login events.

Thresholds live in `Config` so they can be tuned and tested. Rules map to MITRE ATT&CK techniques.
"""
from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from .models import Alert, LoginEvent


@dataclass
class Config:
    brute_force_failures: int = 5
    brute_force_window: timedelta = timedelta(minutes=5)
    spray_distinct_users: int = 4
    spray_window: timedelta = timedelta(minutes=10)
    compromise_prior_failures: int = 3
    compromise_window: timedelta = timedelta(minutes=10)
    enumeration_invalid_users: int = 5
    enumeration_window: timedelta = timedelta(minutes=10)
    baseline_min_successes: int = 5
    off_hours: tuple[int, int] = (0, 5)  # [start, end) local hour
    allowlist_ips: set[str] = field(default_factory=set)


def _sorted(events: list[LoginEvent], cfg: Config) -> list[LoginEvent]:
    return sorted((e for e in events if e.ip not in cfg.allowlist_ips), key=lambda e: e.timestamp)


def _ids(events) -> list[int]:
    return [e.id for e in events if e.id is not None]


def brute_force(events: list[LoginEvent], cfg: Config) -> list[Alert]:
    """Many failed logins for one account from one IP in a short window (T1110.001 Password Guessing)."""
    alerts, windows, active = [], defaultdict(deque), {}
    for e in _sorted(events, cfg):
        key = (e.ip, e.user)
        if e.success:
            windows[key].clear(); active.pop(key, None)
            continue
        w = windows[key]
        w.append(e)
        while w and e.timestamp - w[0].timestamp > cfg.brute_force_window:
            w.popleft()
        if len(w) >= cfg.brute_force_failures:
            if key in active:  # extend the existing burst instead of raising a new alert per attempt
                a = active[key]; a.end = e.timestamp; a.count += 1
                if e.id is not None: a.event_ids.append(e.id)
            else:
                a = Alert("brute_force", "medium", f"Brute-force attempt on '{e.user}'",
                          f"{len(w)} failed logins for '{e.user}' from {e.ip} within {int(cfg.brute_force_window.total_seconds() // 60)} minutes.",
                          w[0].timestamp, e.timestamp, e.user, e.ip, len(w), _ids(w), "T1110.001")
                active[key] = a; alerts.append(a)
    return alerts


def password_spray(events: list[LoginEvent], cfg: Config) -> list[Alert]:
    """One IP failing against many different accounts (T1110.003 Password Spraying)."""
    alerts, windows, active = [], defaultdict(deque), {}
    for e in _sorted(events, cfg):
        if e.success:
            continue
        w = windows[e.ip]
        w.append(e)
        while w and e.timestamp - w[0].timestamp > cfg.spray_window:
            w.popleft()
        users = {x.user for x in w}
        if len(users) >= cfg.spray_distinct_users:
            if e.ip in active and e.timestamp - active[e.ip].end <= cfg.spray_window:
                a = active[e.ip]; a.end = e.timestamp; a.count += 1
                if e.id is not None: a.event_ids.append(e.id)
                a.description = f"{e.ip} failed against {len(users)}+ different accounts (latest: {', '.join(sorted(users)[:6])})."
            else:
                a = Alert("password_spray", "high", f"Password spraying from {e.ip}",
                          f"{e.ip} failed against {len(users)} different accounts within {int(cfg.spray_window.total_seconds() // 60)} minutes: {', '.join(sorted(users)[:6])}.",
                          w[0].timestamp, e.timestamp, None, e.ip, len(w), _ids(w), "T1110.003")
                active[e.ip] = a; alerts.append(a)
    return alerts


def success_after_failures(events: list[LoginEvent], cfg: Config) -> list[Alert]:
    """A successful login right after repeated failures from the same IP: a likely compromised account (T1078)."""
    alerts, recent = [], defaultdict(deque)
    for e in _sorted(events, cfg):
        q = recent[e.ip]
        while q and e.timestamp - q[0].timestamp > cfg.compromise_window:
            q.popleft()
        if not e.success:
            q.append(e)
            continue
        fails = [x for x in q if x.user == e.user]
        if len(fails) >= cfg.compromise_prior_failures:
            alerts.append(Alert("success_after_failures", "critical", f"Possible account compromise: '{e.user}'",
                                f"Successful {e.method} login for '{e.user}' from {e.ip} after {len(fails)} failed attempts in the previous {int(cfg.compromise_window.total_seconds() // 60)} minutes.",
                                fails[0].timestamp, e.timestamp, e.user, e.ip, len(fails) + 1, _ids(fails + [e]), "T1078"))
            q.clear()
    return alerts


def user_enumeration(events: list[LoginEvent], cfg: Config) -> list[Alert]:
    """Attempts against accounts that don't exist (T1087 Account Discovery)."""
    alerts, windows, active = [], defaultdict(deque), {}
    for e in _sorted(events, cfg):
        if not e.invalid_user:
            continue
        w = windows[e.ip]; w.append(e)
        while w and e.timestamp - w[0].timestamp > cfg.enumeration_window:
            w.popleft()
        if len(w) >= cfg.enumeration_invalid_users:
            if e.ip in active and e.timestamp - active[e.ip].end <= cfg.enumeration_window:
                active[e.ip].end = e.timestamp; active[e.ip].count += 1
            else:
                names = sorted({x.user for x in w})
                a = Alert("user_enumeration", "medium", f"Username enumeration from {e.ip}",
                          f"{len(w)} attempts for non-existent accounts from {e.ip} (e.g. {', '.join(names[:5])}).",
                          w[0].timestamp, e.timestamp, None, e.ip, len(w), _ids(w), "T1087")
                active[e.ip] = a; alerts.append(a)
    return alerts


def new_ip_for_user(events: list[LoginEvent], cfg: Config) -> list[Alert]:
    """Successful login from an IP this user has never used before, once a baseline exists."""
    alerts, seen, successes = [], defaultdict(set), defaultdict(int)
    for e in _sorted(events, cfg):
        if not e.success:
            continue
        if successes[e.user] >= cfg.baseline_min_successes and e.ip not in seen[e.user]:
            alerts.append(Alert("new_ip_for_user", "low", f"New login location for '{e.user}'",
                                f"'{e.user}' signed in from {e.ip}, which is not among the {len(seen[e.user])} IPs seen in their previous {successes[e.user]} logins.",
                                e.timestamp, e.timestamp, e.user, e.ip, 1, _ids([e]), "T1078"))
        seen[e.user].add(e.ip); successes[e.user] += 1
    return alerts


def off_hours_login(events: list[LoginEvent], cfg: Config) -> list[Alert]:
    """Successful login during off hours by a user whose baseline has no off-hours logins."""
    start, end = cfg.off_hours
    is_off = lambda t: start <= t.hour < end
    alerts, history = [], defaultdict(list)
    for e in _sorted(events, cfg):
        if not e.success:
            continue
        h = history[e.user]
        if len(h) >= cfg.baseline_min_successes and is_off(e.timestamp) and not any(is_off(t) for t in h):
            alerts.append(Alert("off_hours_login", "low", f"Unusual login time for '{e.user}'",
                                f"'{e.user}' signed in at {e.timestamp:%H:%M}; none of their {len(h)} previous logins were between {start:02d}:00 and {end:02d}:00.",
                                e.timestamp, e.timestamp, e.user, e.ip, 1, _ids([e]), "T1078"))
        h.append(e.timestamp)
    return alerts


RULES = [brute_force, password_spray, success_after_failures, user_enumeration, new_ip_for_user, off_hours_login]


def correlate(alerts: list[Alert]) -> list[Alert]:
    """Escalates related alerts: a new-IP or off-hours login that coincides with a compromise becomes high."""
    compromised = {(a.user, a.ip) for a in alerts if a.rule == "success_after_failures"}
    for a in alerts:
        if a.rule in {"new_ip_for_user", "off_hours_login"} and (a.user, a.ip) in compromised:
            a.severity = "high"
            a.description += " This login also matches a possible compromise."
        if a.rule == "brute_force" and (a.user, a.ip) in compromised:
            a.severity = "high"
    return alerts


def run_all(events: list[LoginEvent], cfg: Config | None = None) -> list[Alert]:
    cfg = cfg or Config()
    out = []
    for rule in RULES:
        out.extend(rule(events, cfg))
    return sorted(correlate(out), key=lambda a: a.start)
