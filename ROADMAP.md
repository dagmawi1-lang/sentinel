# Sentinel roadmap

## Done (v1.0.0)
- [x] Import and analyze security logs (auth.log, JSONL, CSV)
- [x] Detect unusual login activity (new IP, off-hours, correlation)
- [x] Identify repeated failed logins (brute force, spraying, enumeration, success-after-failures)
- [x] Store incidents in SQLite with evidence links and a status workflow
- [x] Generate incident reports (Markdown and HTML)
- [x] Dashboard for reviewing alerts (Flask)
- [x] 13 automated tests, including a zero-false-positive check on clean data

## Planned improvements
- [ ] GeoIP / ASN enrichment and "impossible travel" detection
- [ ] Windows Security Event Log (4624/4625) parser
- [ ] Live tail mode (`sentinel watch /var/log/auth.log`)
- [ ] Export alerts as fail2ban/iptables block suggestions
- [ ] Charts on the dashboard (failed logins over time)
