# Detection logic and tuning notes

All rules use **sliding time windows** over events sorted by time (a `deque` per key that drops events older than the window). This makes each rule O(n) and easy to explain.

- **Brute force**, keyed by (ip, user): a successful login resets the window. Once the threshold is reached, later failures extend the same alert instead of creating new ones.
- **Password spray**, keyed by ip: counts *distinct* usernames in the window. A slow spray (one attempt every 15 minutes) evades this on purpose. Catching it would need a longer window and more false positives.
- **Success after failures**: keeps recent failures per IP. If a success for the same user follows ≥3 failures, it is the highest-severity finding, because the attack may have worked.
- **Baselines** (new IP, off-hours): only fire after a user has 5 successful logins, so brand-new users don't trigger alerts.
- **Correlation**: escalates low-severity baseline alerts when they match a compromise.

## Tuning trade-offs
| Lower thresholds | Higher thresholds |
|---|---|
| Catch slower or smaller attacks | Fewer false alarms from users mistyping passwords |
| More alert fatigue | Attackers can stay just under the limit |

Use `--allow` for trusted scanners or jump hosts, and `--brute-threshold` to tune.
