"""Command-line interface: python -m sentinel <command>."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from . import __version__, db
from .detectors import Config, run_all
from .generator import SCENARIOS, generate, to_auth_log, to_jsonl
from .parsers import parse_file
from .report import html_report, markdown


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinel", description="Personal security monitoring: analyze login logs, detect attacks, track incidents.")
    p.add_argument("--db", default="sentinel.db", help="SQLite database path (default: sentinel.db)")
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write synthetic logs with labeled attacks")
    g.add_argument("out"); g.add_argument("--days", type=int, default=7); g.add_argument("--seed", type=int, default=7); g.add_argument("--format", choices=["auth", "jsonl"], default="auth"); g.add_argument("--no-attacks", action="store_true")
    i = sub.add_parser("ingest", help="import auth.log / .jsonl / .csv files"); i.add_argument("files", nargs="+"); i.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    d = sub.add_parser("detect", help="run detection rules and store incidents"); d.add_argument("--allow", action="append", default=[], help="IP to ignore (repeatable)"); d.add_argument("--brute-threshold", type=int, default=5)
    r = sub.add_parser("report", help="write a Markdown or HTML report"); r.add_argument("out"); r.add_argument("--format", choices=["md", "html"])
    ls = sub.add_parser("incidents", help="list incidents"); ls.add_argument("--status"); ls.add_argument("--severity")
    u = sub.add_parser("update", help="change an incident's status or add a note"); u.add_argument("id", type=int); u.add_argument("--status", choices=db.STATUSES); u.add_argument("--note")
    sub.add_parser("stats", help="summary statistics")
    s = sub.add_parser("serve", help="start the web dashboard (needs Flask)"); s.add_argument("--port", type=int, default=8050)
    a = sub.add_parser("demo", help="generate → ingest → detect → report in one step"); a.add_argument("--out", default="demo_output")
    args = p.parse_args(argv)
    con = db.connect(args.db) if args.cmd not in {"generate", "demo"} else None

    if args.cmd == "generate":
        events, truth = generate(days=args.days, seed=args.seed, attacks=not args.no_attacks)
        Path(args.out).write_text(to_auth_log(events) if args.format == "auth" else to_jsonl(events))
        print(f"Wrote {len(events)} events to {args.out}")
        for k in truth: print(f"  injected {k}: {SCENARIOS[k]}")
    elif args.cmd == "ingest":
        for f in args.files:
            evs = parse_file(f, year=args.year)
            print(f"{f}: parsed {len(evs)} login events, {db.insert_events(con, evs)} new")
    elif args.cmd == "detect":
        alerts = run_all(db.load_events(con), Config(brute_force_failures=args.brute_threshold, allowlist_ips=set(args.allow)))
        created = db.save_alerts(con, alerts)
        print(f"{len(alerts)} detections, {created} new incidents")
        for a in alerts: print(f"  [{a.severity.upper():8}] {a.title} ({a.start:%Y-%m-%d %H:%M})")
    elif args.cmd == "report":
        fmt = args.format or ("html" if args.out.endswith(".html") else "md")
        Path(args.out).write_text(html_report(con) if fmt == "html" else markdown(con))
        print(f"Report written to {args.out}")
    elif args.cmd == "incidents":
        rows = db.list_incidents(con, args.status, args.severity)
        for r in rows: print(f"#{r['id']:<4} {r['severity']:<9} {r['status']:<14} {r['start_ts']}  {r['title']}")
        if not rows: print("No incidents.")
    elif args.cmd == "update":
        if not db.update_incident(con, args.id, args.status, args.note):
            print("Incident not found.", file=sys.stderr); return 1
        print("Updated.")
    elif args.cmd == "stats":
        for k, v in db.stats(con).items(): print(f"{k}: {v}")
    elif args.cmd == "serve":
        try:
            from .web import create_app
        except ImportError:
            print("Flask is not installed: pip install flask", file=sys.stderr); return 1
        create_app(args.db).run(host="127.0.0.1", port=args.port)
    elif args.cmd == "demo":
        out = Path(args.out); out.mkdir(exist_ok=True)
        log = out / "auth.log"; dbp = str(out / "sentinel.db")
        Path(dbp).unlink(missing_ok=True)
        main(["generate", str(log)]); main(["--db", dbp, "ingest", str(log), "--year", "2026"]); main(["--db", dbp, "detect"])
        main(["--db", dbp, "report", str(out / "report.html")]); main(["--db", dbp, "report", str(out / "report.md")])
        print(f"\nOpen {out / 'report.html'} or run: python -m sentinel --db {dbp} serve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
