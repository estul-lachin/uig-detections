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
tools/build.py             validate, test, convert, render the site
tools/sigma_eval.py        the evaluator the tests run on
tools/splunk_check.py      run the generated SPL in a real Splunk on the same test events
```

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

The KQL is converted but has not run in Sentinel yet.

```
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tools/build.py                 # validate + test + update dist/
.venv/bin/python tools/build.py --site _site    # also render the website
SPLUNK_PASSWORD=... .venv/bin/python tools/splunk_check.py
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

The OG image is rendered from `assets/og-image.html` with headless Chrome, like the other uig.me sites.
