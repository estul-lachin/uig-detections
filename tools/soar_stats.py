#!/usr/bin/env python3
"""Count what the SOAR playbooks did with the Sentinel incidents, for the website.

Reads SecurityIncident for the last 30 days (never before the enrichment automation went live),
leaving out incidents tagged soar:legacy (closed in bulk at that switch) and soar:e2e-test. Writes only
counts and times: no IPs, titles, comments or names. Uses the Azure CLI's login; in CI that is an OIDC
login whose only role is Log Analytics Reader on the workspace.

  python tools/soar_stats.py --out soar.json [--resource-group rg-uig-sentinel] [--workspace law-uig-honeypot]
"""

import argparse
import datetime
import json
import statistics
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter

# The "enrich every new incident" automation rule went live at this time; rules had been raising one
# alert per source IP since 15:26, and the two incidents in between were never enriched automatically.
SINCE = "2026-11-09T15:47:00Z"
DAYS = 30
BUCKETS = ("0", "1-24", "25-74", "75-100", "unknown")

QUERY = f"""
SecurityIncident
| where CreatedTime >= max_of(datetime({SINCE}), ago({DAYS}d))
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend L = tostring(Labels)
| where not(L contains '"soar:legacy"' or L contains '"soar:e2e-test"')
| mv-apply c = Comments on (
    where tostring(c.author.name) contains "pb-uig-enrich"
    | summarize EnrichedAt = min(todatetime(c.createdTimeUtc)))
| project Day = format_datetime(CreatedTime, "yyyy-MM-dd"), Severity, Status,
    Enriched = L contains '"soar:enriched"', AutoClosed = L contains '"soar:auto-closed"',
    Notified = L contains '"soar:notified"', Abuse = extract(@'"abuse:([0-9-]+|unknown)"', 1, L),
    EnrichSeconds = datetime_diff("second", EnrichedAt, CreatedTime)
"""


def az(*args):
    r = subprocess.run(["az", *args, "-o", "tsv"], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def query(rg, ws):
    sub = az("account", "show", "--query", "id")
    tok = az("account", "get-access-token", "--resource", "https://management.azure.com", "--query", "accessToken")
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/"
           f"Microsoft.OperationalInsights/workspaces/{ws}/api/query?api-version=2020-08-01")
    req = urllib.request.Request(url, data=json.dumps({"query": QUERY, "timespan": f"P{DAYS + 1}D"}).encode(),
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"query failed: {e.code} {e.read()[:400]!r}") from e
    # ARM's query endpoint capitalizes the keys (Tables, Columns, ColumnName); Log Analytics' does not
    table = (res.get("Tables") or res.get("tables"))[0]
    cols = [c.get("ColumnName") or c.get("name") for c in (table.get("Columns") or table.get("columns"))]
    return [dict(zip(cols, row)) for row in (table.get("Rows") or table.get("rows") or [])]


def pct(n, d):
    return round(100 * n / d) if d else 0


def stats(rows, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    n = len(rows)
    secs = sorted(r["EnrichSeconds"] for r in rows if r["EnrichSeconds"] is not None and r["EnrichSeconds"] >= 0)
    high = [r for r in rows if r["Severity"] == "High"]
    auto = sum(1 for r in rows if r["AutoClosed"])
    days = Counter(r["Day"] for r in rows)
    auto_days = Counter(r["Day"] for r in rows if r["AutoClosed"])
    return {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "since": max(SINCE[:10], (now - datetime.timedelta(days=DAYS)).strftime("%Y-%m-%d")),
        "incidents": n,
        "by_severity": {s: sum(1 for r in rows if r["Severity"] == s) for s in ("High", "Medium", "Low")},
        "enriched": sum(1 for r in rows if r["Enriched"]),
        "enriched_pct": pct(sum(1 for r in rows if r["Enriched"]), n),
        "enrich_seconds_median": round(statistics.median(secs)) if secs else None,
        "enrich_seconds_p90": secs[min(len(secs) - 1, int(0.9 * len(secs)))] if secs else None,
        "auto_closed": auto,
        "auto_closed_pct": pct(auto, n),
        "high": len(high),
        "high_notified": sum(1 for r in high if r["Notified"]),
        "open": sum(1 for r in rows if r["Status"] != "Closed"),
        "closed_by_analyst": sum(1 for r in rows if r["Status"] == "Closed" and not r["AutoClosed"]),
        "abuse": {b: sum(1 for r in rows if (r["Abuse"] or "unknown") == b) for b in BUCKETS},
        "daily": [{"day": d, "incidents": days[d], "auto_closed": auto_days[d]} for d in sorted(days)],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--resource-group", default="rg-uig-sentinel")
    ap.add_argument("--workspace", default="law-uig-honeypot")
    a = ap.parse_args(argv)
    try:
        s = stats(query(a.resource_group, a.workspace))
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=1)
        f.write("\n")
    print(f"{s['incidents']} incidents since {s['since']}: {s['enriched_pct']}% enriched "
          f"(median {s['enrich_seconds_median']} s), {s['auto_closed_pct']}% auto-closed, "
          f"{s['high_notified']}/{s['high']} High sent to Telegram, {s['open']} open")
    return 0


if __name__ == "__main__":
    sys.exit(main())
