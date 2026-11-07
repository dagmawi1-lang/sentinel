# Test results — 2026-11-07

```
.............                                                            [100%]
13 passed in 0.12s
```

## Demo run (`python -m sentinel demo`)
```
/tmp/sd2/auth.log: parsed 148 login events, 148 new
8 detections, 8 new incidents
  [MEDIUM  ] Brute-force attempt on 'bob' (2026-11-06 14:05)
  [HIGH    ] Password spraying from 203.0.113.77 (2026-11-06 16:00)
  [HIGH    ] Brute-force attempt on 'dana' (2026-11-07 02:10)
  [CRITICAL] Possible account compromise: 'dana' (2026-11-07 02:10)
  [HIGH    ] New login location for 'dana' (2026-11-07 02:13)
  [HIGH    ] Unusual login time for 'dana' (2026-11-07 02:13)
  [HIGH    ] Password spraying from 198.51.100.90 (2026-11-07 11:00)
  [MEDIUM  ] Username enumeration from 198.51.100.90 (2026-11-07 11:00)
Report written to /tmp/sd2/report.html
Report written to /tmp/sd2/report.md

Open /tmp/sd2/report.html or run: python -m sentinel --db /tmp/sd2/sentinel.db serve
```

Every injected scenario was detected. Clean traffic produced 0 alerts (see `test_synthetic_data_detects_every_injected_attack_and_nothing_on_clean_traffic`).
