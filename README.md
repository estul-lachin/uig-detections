# uig-detections

Detection-as-code for SSH and Telnet attacks: [Sigma](https://sigmahq.io/) rules, tested against attack
and look-alike events, converted to Splunk SPL and Microsoft Sentinel KQL. Published at
**https://detections.uig.me**.

The behaviour comes from a live [Cowrie honeypot](https://github.com/estul-lachin/uig-honeypot)
([honeypot.uig.me](https://honeypot.uig.me)); the rules use Cowrie's JSON field names (`eventid`, `src_ip`,
`session`, `input`, `username`, `password`).

```
rules/<name>.yml           Sigma rule (a correlation file also holds its named base rules)
tests/<name>/match.jsonl   events the rule must detect
tests/<name>/nomatch.jsonl look-alike events it must not detect
dist/spl/<name>.spl        generated Splunk search (index=honeypot sourcetype=cowrie:json)
dist/kql/<name>.kql        generated KQL for a Sentinel custom table Cowrie_CL
dist/sentinel/<name>.json  generated Sentinel scheduled analytics rule (ID = the Sigma rule ID)
tools/build.py             validate, test, convert, render the site
tools/sigma_eval.py        the evaluator the tests run on
tools/splunk_check.py      run the generated SPL in a real Splunk on the same test events
tools/sentinel_check.py    run the generated KQL in Microsoft Sentinel on the same test events
tools/sentinel_deploy.py   deploy dist/sentinel/ as analytics rules (updates in place)
tools/soar_e2e.py          end-to-end test of the SOAR chain on the real workspace
tools/soar_stats.py        count what SOAR did with the incidents (soar.json on the site)
soar/                      Sentinel playbooks and their infrastructure in Bicep (see soar/README.md)
```

## Seen on the honeypot

The site build also publishes `rules.json`, the detection logic as plain JSON. Every hour the honeypot
(uig-honeypot's `vps/detect.py`) downloads it, runs the rules on the last 30 days of raw logs with a verbatim
copy of `tools/sigma_eval.py`, and publishes `detections.json` to the public data repo: per rule the sessions
and alerts, the first and last day, and the most common matching command, defanged and without source IPs.
CI rebuilds the site every 6 hours with `--hits` pointing at that file, so every rule page shows whether the
rule fires on real attacks. If the file can't be read, the site is built without that section.
After changing `tools/sigma_eval.py`, copy it to uig-honeypot's `vps/sigma_eval.py`.

## Pipeline

1. **Validate**: pySigma's 31 core validators, including ATT&CK tags against the current ATT&CK release,
   and a check that every regex is RE2-safe, since KQL runs RE2 (no backreferences or lookarounds).
2. **Test**: `tools/sigma_eval.py` runs each rule on its test events. Single-event rules must match every
   event in `match.jsonl` and none in `nomatch.jsonl`; correlations must fire on the first and not the
   second. The negatives are the point: commands that look like the attack but aren't (`crontab -l`,
   `cat ~/.bash_history`, `sh x.sh`, the right passwords spread over two time buckets).
3. **Convert**: SPL with pySigma's Splunk backend, KQL with the Kusto backend. The Kusto backend has no
   correlation support, so `kql_correlation()` in `build.py` writes those with `summarize ... by bin()`
   and `union`. The output is committed in `dist/`; CI fails if it's out of date.
4. **Splunk check** (local, needs a running Splunk with the `cowrie:json` sourcetype, e.g. uig-honeypot's
   `./hp siem up`): `tools/splunk_check.py` indexes the test events into a throwaway index, runs the
   generated SPL and requires the same result as the evaluator. This catches conversion bugs that the
   evaluator alone can't.
5. **Sentinel check**: `tools/sentinel_check.py` uploads the test events to a separate `Cowrie_Test_CL`
   table through their own data collection rule, runs each rule's KQL scoped to that rule's events, and
   requires the same result. All 14 rules agree with the evaluator in both Splunk and Sentinel.
6. **Deploy**: `tools/sentinel_deploy.py` creates or updates one scheduled analytics rule per Sigma rule.
   The honeypot ships new events every 10 minutes (uig-honeypot's `vps/sentinel.py`), so each hourly run
   looks at what was *ingested* in the last hour (`ingestion_time()`) instead of a TimeGenerated window
   that would miss late events. Each run raises one alert per source IP (the IP is mapped as an entity
   and named in the alert title, with the match count and first/last time as custom details), and the
   same rule firing again for the same IP within a day joins the open incident instead of opening a new one.

```
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tools/build.py                 # validate + test + update dist/
.venv/bin/python tools/build.py --site _site    # also render the website
.venv/bin/python tools/build.py --site _site --hits detections.json   # with honeypot hits (file or URL)
SPLUNK_PASSWORD=... .venv/bin/python tools/splunk_check.py
.venv/bin/python tools/sentinel_check.py         # needs az login
.venv/bin/python tools/sentinel_deploy.py
```

## Adding a rule

Write `rules/<name>.yml`, add `tests/<name>/match.jsonl` and `nomatch.jsonl` (one Cowrie JSON event per
line, documentation IP ranges only), run `tools/build.py`, then `tools/splunk_check.py`, and commit the rule,
the tests and the regenerated `dist/` together.

## Known limits

- Correlations use fixed time buckets (Splunk `bin`, KQL `bin()`), not sliding windows, so a burst that
  straddles a bucket boundary can be missed. The evaluator uses the same buckets, so tests and production agree.
- `temporal_ordered` isn't supported by the Splunk backend; *Login Followed By Tool Transfer* uses
  `temporal` grouped by session, which is equivalent for Cowrie (commands only exist after a login).
- Technique IDs follow ATT&CK v20, where Defense Evasion became *Stealth* and *Defense Impairment*
  (T1562 → T1685/T1686).
- Sentinel's API (through 2025-10-01-preview) has no value yet for those two tactics, but already checks
  techniques against v20. The Sentinel rules therefore leave out the two tactics and the techniques that
  belong only to them; the Sigma rules keep the full tags.

The OG image is rendered from `assets/og-image.html` with headless Chrome, like the other uig.me sites.
