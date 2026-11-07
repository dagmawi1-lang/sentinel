"""Incident reports in Markdown and self-contained HTML."""
from __future__ import annotations
import html
import sqlite3
from datetime import datetime

from . import db

SEV_COLOR = {"critical": "#b42318", "high": "#d9480f", "medium": "#b08800", "low": "#3b6db3"}
ADVICE = {
    "brute_force": "Block or rate-limit the source IP (e.g. fail2ban), confirm the account uses a strong password, and prefer SSH keys.",
    "password_spray": "Block the source IP, check all targeted accounts for successful logins, and enforce MFA or key-only SSH.",
    "success_after_failures": "Treat as a possible compromise: disable or reset the account, end its sessions, and review commands run after the login.",
    "user_enumeration": "Block the source IP. Disable password authentication if possible so usernames can't be probed.",
    "new_ip_for_user": "Confirm with the user that this login was theirs. If not, reset credentials.",
    "off_hours_login": "Confirm with the user. Unexpected late-night access is a common sign of stolen credentials.",
}


def markdown(con: sqlite3.Connection, title: str = "Sentinel security report") -> str:
    s = db.stats(con)
    incs = db.list_incidents(con)
    out = [f"# {title}", f"_Generated {datetime.now():%Y-%m-%d %H:%M}_", "",
           "## Summary", f"- Events analyzed: **{s['events']}** ({s['failed']} failed, {s['succeeded']} successful) from {s['unique_ips']} IPs and {s['unique_users']} accounts",
           f"- Time range: {s['first_event'] or '—'} → {s['last_event'] or '—'}",
           f"- Incidents: **{len(incs)}** ({', '.join(f'{k}: {v}' for k, v in sorted(s['by_severity'].items(), key=lambda kv: -['low','medium','high','critical'].index(kv[0]))) or 'none'}); {s['open_incidents']} open", ""]
    if s["top_failing_ips"]:
        out += ["## Top sources of failed logins", "| IP | Failures | Accounts targeted |", "|---|---:|---:|"]
        out += [f"| {r['ip']} | {r['failures']} | {r['users']} |" for r in s["top_failing_ips"]]
        out.append("")
    out.append("## Incidents")
    if not incs:
        out.append("No incidents detected.")
    for i in incs:
        out += [f"### #{i['id']} [{i['severity'].upper()}] {i['title']}",
                f"- **Rule:** `{i['rule']}` (MITRE ATT&CK {i['mitre'] or 'n/a'}) · **Status:** {i['status']}",
                f"- **When:** {i['start_ts']} → {i['end_ts']} · **Events:** {i['event_count']}",
                f"- **Account:** {i['user'] or '—'} · **Source IP:** {i['ip'] or '—'}",
                f"- {i['description']}", f"- **Recommended action:** {ADVICE.get(i['rule'], 'Review the related events.')}"]
        if i["notes"]:
            out.append("- **Notes:** " + i["notes"].replace("\n", "; "))
        out.append("")
    out += ["---", "Sentinel flags suspicious patterns for a human to review. Detections are heuristics and can produce false positives."]
    return "\n".join(out)


def html_report(con: sqlite3.Connection, title: str = "Sentinel security report") -> str:
    s = db.stats(con)
    incs = db.list_incidents(con)
    e = html.escape
    cards = "".join(f'<div class="card"><b>{v}</b><span>{k}</span></div>' for k, v in [("events", s["events"]), ("failed logins", s["failed"]), ("source IPs", s["unique_ips"]), ("incidents", len(incs)), ("open", s["open_incidents"])])
    rows = "".join(
        f'<tr><td>#{i["id"]}</td><td><span class="sev" style="background:{SEV_COLOR[i["severity"]]}">{i["severity"]}</span></td><td><b>{e(i["title"])}</b><br><small>{e(i["description"])}</small><br><small class="advice">{e(ADVICE.get(i["rule"], ""))}</small></td>'
        f'<td>{e(i["user"] or "—")}</td><td><code>{e(i["ip"] or "—")}</code></td><td>{e(i["start_ts"])}</td><td>{i["event_count"]}</td><td>{e(i["mitre"] or "")}</td><td>{e(i["status"])}</td></tr>' for i in incs)
    top = "".join(f'<tr><td><code>{e(r["ip"])}</code></td><td>{r["failures"]}</td><td>{r["users"]}</td></tr>' for r in s["top_failing_ips"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>
<style>body{{font-family:system-ui,sans-serif;margin:0;background:#0f141b;color:#e6edf3}}main{{max-width:1150px;margin:auto;padding:28px}}h1{{margin:0 0 4px}}.muted{{color:#8b98a8}}
.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:22px 0}}.card{{background:#161d27;border:1px solid #263142;border-radius:12px;padding:14px}}.card b{{font-size:26px;display:block}}.card span{{color:#8b98a8;font-size:12px}}
table{{width:100%;border-collapse:collapse;background:#161d27;border-radius:12px;overflow:hidden;margin-bottom:24px}}th,td{{padding:10px;border-bottom:1px solid #263142;text-align:left;vertical-align:top;font-size:13px}}th{{background:#1b2431;color:#9fb0c3}}
.sev{{color:#fff;border-radius:99px;padding:2px 8px;font-size:11px;font-weight:700;text-transform:uppercase}}small{{color:#9fb0c3}}.advice{{color:#7ee2a8}}code{{color:#ffd580}}
@media(max-width:800px){{.cards{{grid-template-columns:repeat(2,1fr)}}table{{display:block;overflow-x:auto}}}}</style></head>
<body><main><h1>🛡️ {e(title)}</h1><p class="muted">Generated {datetime.now():%Y-%m-%d %H:%M} · events {e(str(s['first_event']))} → {e(str(s['last_event']))}</p>
<div class="cards">{cards}</div><h2>Incidents</h2><table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Account</th><th>Source</th><th>Start</th><th>Events</th><th>ATT&amp;CK</th><th>Status</th></tr></thead><tbody>{rows or '<tr><td colspan=9>No incidents.</td></tr>'}</tbody></table>
<h2>Top sources of failed logins</h2><table><thead><tr><th>IP</th><th>Failures</th><th>Accounts targeted</th></tr></thead><tbody>{top}</tbody></table>
<p class="muted">Sentinel flags suspicious patterns for human review. Detections are heuristics and may include false positives.</p></main></body></html>"""
