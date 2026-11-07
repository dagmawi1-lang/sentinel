from datetime import datetime, timedelta

import pytest

from sentinel import db
from sentinel.cli import main
from sentinel.detectors import Config, brute_force, new_ip_for_user, off_hours_login, password_spray, run_all, success_after_failures, user_enumeration
from sentinel.generator import generate, to_auth_log, to_jsonl
from sentinel.models import LoginEvent
from sentinel.parsers import parse_auth_log, parse_csv, parse_jsonl

T0 = datetime(2026, 11, 5, 14, 0, 0)


def ev(sec, user, ip, ok, invalid=False, i=None):
    return LoginEvent(T0 + timedelta(seconds=sec), user, ip, ok, invalid, id=i)


# ---------- parsers ----------
def test_parse_auth_log_formats():
    lines = [
        "Nov  5 14:00:01 web01 sshd[101]: Failed password for bob from 198.51.100.23 port 51000 ssh2",
        "Nov  5 14:00:02 web01 sshd[102]: Invalid user admin from 198.51.100.23 port 51001",
        "Nov  5 14:00:02 web01 sshd[102]: Failed password for invalid user admin from 198.51.100.23 port 51001 ssh2",
        "Nov  5 14:00:09 web01 sshd[103]: Accepted publickey for alice from 10.0.0.11 port 51002 ssh2: RSA SHA256:abc",
        "Nov  5 14:00:10 web01 CRON[104]: pam_unix(cron:session): session opened for user root",
        "2026-11-05T14:00:11+00:00 web01 sshd[105]: Accepted password for carol from 2001:db8::5 port 22 ssh2",
        "garbage line", "Nov  5 14:00:12 web01 sshd[106]: Failed password for bob from not-an-ip port 1 ssh2",
    ]
    out = list(parse_auth_log(lines, year=2026))
    assert [(e.user, e.success, e.invalid_user) for e in out] == [("bob", False, False), ("admin", False, True), ("alice", True, False), ("carol", True, False)]
    assert out[2].method == "publickey" and out[3].ip == "2001:db8::5" and out[0].timestamp == datetime(2026, 11, 5, 14, 0, 1)


def test_year_rollover():
    out = list(parse_auth_log(["Dec 31 23:59:59 h sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2", "Jan  1 00:00:01 h sshd[2]: Accepted password for a from 10.0.0.1 port 1 ssh2"], year=2026))
    assert out[0].timestamp.year == 2026 and out[1].timestamp.year == 2027


def test_parse_jsonl_and_csv():
    j = list(parse_jsonl('{"timestamp":"2026-11-05T10:00:00Z","user":"a","ip":"10.0.0.1","success":true}\nnot json\n{"timestamp":"x","user":"a","ip":"10.0.0.1"}\n{"time":"2026-11-05T10:01:00","username":"b","src_ip":"10.0.0.2","result":"failed"}'))
    assert [(e.user, e.success) for e in j] == [("a", True), ("b", False)]
    c = list(parse_csv("Timestamp,User,IP,Success\n2026-11-05T10:00:00,a,10.0.0.1,yes\n2026-11-05T10:00:01,b,999.1.1.1,no\n"))
    assert len(c) == 1 and c[0].success


def test_generator_round_trips_through_both_formats():
    events, _ = generate(days=2, seed=1)
    a = list(parse_auth_log(to_auth_log(events).splitlines(), year=2026))
    j = list(parse_jsonl(to_jsonl(events)))
    assert len(a) == len(j) == len(events)


# ---------- rules ----------
def test_brute_force_threshold_and_single_alert_per_burst():
    cfg = Config()
    assert brute_force([ev(i * 10, "bob", "1.2.3.4", False) for i in range(4)], cfg) == []
    alerts = brute_force([ev(i * 10, "bob", "1.2.3.4", False, i=i) for i in range(12)], cfg)
    assert len(alerts) == 1 and alerts[0].count == 12 and alerts[0].event_ids == list(range(12))
    # failures spread beyond the window don't count
    assert brute_force([ev(i * 120, "bob", "1.2.3.4", False) for i in range(6)], cfg) == []


def test_password_spray():
    cfg = Config()
    hits = password_spray([ev(i * 30, u, "5.6.7.8", False) for i, u in enumerate(["a", "b", "c", "d"])], cfg)
    assert len(hits) == 1 and hits[0].severity == "high"
    assert password_spray([ev(i * 30, u, "5.6.7.8", False) for i, u in enumerate(["a", "b", "c"])], cfg) == []


def test_success_after_failures():
    cfg = Config()
    evs = [ev(i * 10, "dana", "9.9.9.9", False) for i in range(3)] + [ev(60, "dana", "9.9.9.9", True)]
    a = success_after_failures(evs, cfg)
    assert len(a) == 1 and a[0].severity == "critical"
    assert success_after_failures([ev(0, "dana", "9.9.9.9", False), ev(10, "dana", "9.9.9.9", True)], cfg) == []
    # failures for a different user from the same IP don't count
    assert success_after_failures([ev(i, "x", "9.9.9.9", False) for i in range(5)] + [ev(30, "dana", "9.9.9.9", True)], cfg) == []


def test_user_enumeration():
    assert len(user_enumeration([ev(i, f"u{i}", "4.4.4.4", False, True) for i in range(5)], Config())) == 1


def test_baseline_rules_need_history():
    cfg = Config()
    day = lambda d, h, ip="10.0.0.1": LoginEvent(T0.replace(hour=h) + timedelta(days=d), "alice", ip, True)
    assert new_ip_for_user([day(0, 9), day(1, 9, "8.8.8.8")], cfg) == [], "no baseline yet"
    hist = [day(d, 9) for d in range(5)]
    assert len(new_ip_for_user(hist + [day(6, 10, "8.8.8.8")], cfg)) == 1
    assert len(off_hours_login(hist + [day(6, 3)], cfg)) == 1
    assert off_hours_login(hist + [day(6, 13)], cfg) == []


def test_allowlist():
    cfg = Config(allowlist_ips={"1.2.3.4"})
    assert run_all([ev(i, "bob", "1.2.3.4", False) for i in range(20)], cfg) == []


def test_synthetic_data_detects_every_injected_attack_and_nothing_on_clean_traffic():
    events, truth = generate(days=7, seed=7)
    rules = {a.rule: a for a in run_all(events)}
    assert {"brute_force", "password_spray", "success_after_failures", "user_enumeration"} <= set(rules)
    assert rules["success_after_failures"].user == truth["compromise"]["user"]
    clean, _ = generate(days=7, seed=7, attacks=False)
    assert run_all(clean) == [], "no false positives on normal traffic"


# ---------- storage, CLI, web ----------
def test_storage_is_idempotent_and_incidents_update(tmp_path):
    con = db.connect(str(tmp_path / "s.db"))
    events, _ = generate(days=3, seed=3)
    assert db.insert_events(con, events) == len(events)
    assert db.insert_events(con, events) == 0
    alerts = run_all(db.load_events(con))
    n = db.save_alerts(con, alerts)
    assert n == len(alerts) and db.save_alerts(con, run_all(db.load_events(con))) == 0
    inc = db.list_incidents(con)[0]
    assert inc["severity"] == "critical"
    assert len(db.incident_events(con, inc["id"])) == inc["event_count"]
    assert db.update_incident(con, inc["id"], "investigating", "Called the user")
    assert "Called the user" in db.list_incidents(con, status="investigating")[0]["notes"]
    with pytest.raises(ValueError):
        db.update_incident(con, inc["id"], "bogus")
    assert not db.update_incident(con, 9999, "resolved")


def test_cli_demo_and_web(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out)]) == 0
    html = (out / "report.html").read_text()
    assert "Possible account compromise" in html and "<script" not in html
    md = (out / "report.md").read_text()
    assert "## Incidents" in md and "T1110.003" in md
    flask = pytest.importorskip("flask")
    from sentinel.web import create_app
    client = create_app(str(out / "sentinel.db")).test_client()
    r = client.get("/"); assert r.status_code == 200 and b"Possible account compromise" in r.data
    r = client.post("/incident/1", data={"status": "resolved", "note": "<b>blocked</b> at firewall"})
    assert r.status_code == 302
    page = client.get("/incident/1").data
    assert b"&lt;b&gt;blocked&lt;/b&gt;" in page, "notes are HTML-escaped"
    assert client.get("/incident/999").status_code == 404
    assert client.post("/incident/1", data={"status": "nope"}).status_code == 400
