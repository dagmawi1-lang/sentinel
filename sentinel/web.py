"""Optional Flask dashboard: incident list, incident detail with evidence, status updates, and stats."""
from __future__ import annotations
import html

from flask import Flask, abort, redirect, request, url_for

from . import db
from .report import ADVICE, SEV_COLOR

CSS = """body{font-family:system-ui,sans-serif;margin:0;background:#0f141b;color:#e6edf3}main{max-width:1150px;margin:auto;padding:24px}a{color:#7cc4ff}
nav{display:flex;gap:16px;align-items:center;padding:14px 24px;background:#161d27;border-bottom:1px solid #263142}nav b{font-size:18px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:18px 0}.card{background:#161d27;border:1px solid #263142;border-radius:12px;padding:14px}.card b{font-size:24px;display:block}.card span{color:#8b98a8;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161d27}th,td{padding:9px;border-bottom:1px solid #263142;text-align:left;font-size:13px;vertical-align:top}th{color:#9fb0c3}
.sev{color:#fff;border-radius:99px;padding:2px 8px;font-size:11px;font-weight:700;text-transform:uppercase}.filters a{margin-right:10px}
form{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}select,input,button{background:#0f141b;color:#e6edf3;border:1px solid #33425a;border-radius:8px;padding:8px}button{background:#2f6feb;border-color:#2f6feb;cursor:pointer}
pre{white-space:pre-wrap;background:#0b1016;padding:12px;border-radius:8px;font-size:12px}.muted{color:#8b98a8}"""


def create_app(db_path: str = "sentinel.db") -> Flask:
    app = Flask(__name__)
    e = html.escape

    def page(title: str, body: str) -> str:
        return f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{e(title)} · Sentinel</title><style>{CSS}</style></head><body><nav><b>🛡️ Sentinel</b><a href='/'>Incidents</a><a href='/report'>Report</a></nav><main>{body}</main></body></html>"

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @app.get("/")
    def index():
        con = db.connect(db_path)
        status, sev = request.args.get("status") or None, request.args.get("severity") or None
        s = db.stats(con)
        cards = "".join(f"<div class=card><b>{v}</b><span>{k}</span></div>" for k, v in [("events", s["events"]), ("failed logins", s["failed"]), ("source IPs", s["unique_ips"]), ("open incidents", s["open_incidents"]), ("critical", s["by_severity"].get("critical", 0))])
        filt = "<div class=filters>Status: " + " ".join(f"<a href='?status={x}'>{x}</a>" for x in db.STATUSES) + " · <a href='/'>all</a></div>"
        rows = "".join(f"<tr><td><a href='/incident/{i['id']}'>#{i['id']}</a></td><td><span class=sev style='background:{SEV_COLOR[i['severity']]}'>{i['severity']}</span></td><td><a href='/incident/{i['id']}'>{e(i['title'])}</a></td><td>{e(i['user'] or '—')}</td><td>{e(i['ip'] or '—')}</td><td>{e(i['start_ts'])}</td><td>{e(i['status'])}</td></tr>" for i in db.list_incidents(con, status, sev))
        return page("Incidents", f"<h1>Incidents</h1><div class=cards>{cards}</div>{filt}<table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Account</th><th>IP</th><th>Start</th><th>Status</th></tr>{rows or '<tr><td colspan=7>No incidents.</td></tr>'}</table>")

    @app.get("/incident/<int:iid>")
    def incident(iid: int):
        con = db.connect(db_path)
        i = con.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone()
        if not i:
            abort(404)
        evs = "".join(f"<tr><td>{e(r['ts'])}</td><td>{e(r['user'])}</td><td>{e(r['ip'])}</td><td>{'✅ success' if r['success'] else '❌ failed'}</td><td class=muted>{e((r['raw'] or '')[:140])}</td></tr>" for r in db.incident_events(con, iid))
        opts = "".join(f"<option {'selected' if s == i['status'] else ''}>{s}</option>" for s in db.STATUSES)
        return page(f"Incident #{iid}", f"""<p><a href='/'>← All incidents</a></p><h1>#{iid} {e(i['title'])}</h1>
<p><span class=sev style='background:{SEV_COLOR[i['severity']]}'>{i['severity']}</span> · rule <code>{e(i['rule'])}</code> · ATT&amp;CK {e(i['mitre'] or '')} · status <b>{e(i['status'])}</b></p>
<p>{e(i['description'])}</p><p><b>Recommended:</b> {e(ADVICE.get(i['rule'], ''))}</p>
<form method=post action='/incident/{iid}'><select name=status aria-label=Status>{opts}</select><input name=note placeholder='Add an investigation note' size=40 maxlength=500><button>Update</button></form>
<pre>{e(i['notes'] or 'No notes yet.')}</pre><h2>Evidence ({i['event_count']} events)</h2><table><tr><th>Time</th><th>Account</th><th>IP</th><th>Result</th><th>Raw</th></tr>{evs}</table>""")

    @app.post("/incident/<int:iid>")
    def update(iid: int):
        con = db.connect(db_path)
        try:
            if not db.update_incident(con, iid, request.form.get("status") or None, request.form.get("note") or None):
                abort(404)
        except ValueError:
            abort(400)
        return redirect(url_for("incident", iid=iid))

    @app.get("/report")
    def report():
        from .report import html_report
        return html_report(db.connect(db_path))

    return app
