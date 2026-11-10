#!/usr/bin/env python3
"""Run the generated KQL in Microsoft Sentinel against the test events.

The Sentinel counterpart of splunk_check.py. Uploads every rule's test events
to the Cowrie_Test_CL and Suricata_Test_CL tables (through their own data
collection rule; uig-honeypot's `azure/suricata.sh --test` adds the Suricata
one), runs each rule's KQL scoped to one rule's events, and requires the same
result as the evaluator: every positive event (single-event rules) or at least one group
(correlations) for match.jsonl, nothing for nomatch.jsonl.

Uses the Azure CLI's login (`az login`); the signed-in user needs the
Monitoring Metrics Publisher role on the test DCR. Test events are moved to
yesterday by whole days, which keeps their time buckets, because the
workspace only accepts recent TimeGenerated values.

  python tools/sentinel_check.py [--resource-group rg-uig-sentinel] [--workspace law-uig-honeypot]
"""

import argparse
import datetime
import gzip
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import build  # noqa: E402

# Per log source (build.SOURCES): the test table, its stream on the test DCR, and its columns.
TEST = {
    "cowrie": {"table": "Cowrie_Test_CL", "stream": "Custom-CowrieRaw", "fields": {
        "timestamp": str, "eventid": str, "src_ip": str, "src_port": int, "dst_port": int, "session": str,
        "protocol": str, "username": str, "password": str, "input": str, "url": str, "shasum": str,
        "version": str, "sensor": str}},
    "suricata": {"table": "Suricata_Test_CL", "stream": "Custom-SuricataRaw", "fields": {
        "timestamp": str, "flow_id": int, "src_ip": str, "src_port": int, "dest_ip": str, "dest_port": int,
        "proto": str, "app_proto": str, "signature_id": int, "rev": int, "signature": str, "category": str,
        "severity": int, "signature_severity": str, "cve": str, "mitre_tactic": str, "mitre_technique": str,
        "sensor": str}},
}


def az(*args):
    r = subprocess.run(["az", *args, "-o", "tsv"], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def token(resource):
    return az("account", "get-access-token", "--resource", resource, "--query", "accessToken")


def http(url, body, tok, gz=False):
    data = json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
    if gz:
        data, headers["Content-Encoding"] = gzip.compress(data), "gzip"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{url.split('?')[0]}: {e.code} {e.read()[:400]!r}") from e
    return json.loads(raw) if raw else None


class Workspace:
    def __init__(self, rg, ws):
        self.customer_id = az("monitor", "log-analytics", "workspace", "show", "-g", rg, "-n", ws,
                              "--query", "customerId")
        sub = az("account", "show", "--query", "id")
        base = f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights"
        self.dce = az("rest", "--method", "get", "--url",
                      f"{base}/dataCollectionEndpoints/dce-uig-honeypot?api-version=2023-03-11",
                      "--query", "properties.logsIngestion.endpoint")
        self.dcr = az("rest", "--method", "get", "--url",
                      f"{base}/dataCollectionRules/dcr-uig-cowrie-test?api-version=2023-03-11",
                      "--query", "properties.immutableId")
        self.ingest_tok = token("https://monitor.azure.com")
        self.query_tok = token("https://api.loganalytics.io")

    def upload(self, stream, rows):
        url = f"{self.dce}/dataCollectionRules/{self.dcr}/streams/{stream}?api-version=2023-01-01"
        for i in range(0, len(rows), 500):
            http(url, rows[i:i + 500], self.ingest_tok, gz=True)

    def count(self, kql):
        res = http(f"https://api.loganalytics.io/v1/workspaces/{self.customer_id}/query",
                   {"query": kql + "\n| count", "timespan": "P7D"}, self.query_tok)
        return int(res["tables"][0]["rows"][0][0])


def shift(events, days):
    out = []
    for ev in events:
        ts = datetime.datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00")) + datetime.timedelta(days=days)
        out.append({**ev, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--resource-group", default="rg-uig-sentinel")
    ap.add_argument("--workspace", default="law-uig-honeypot")
    a = ap.parse_args(argv)
    ws = Workspace(a.resource_group, a.workspace)
    rules = build.load_rules()
    run_id = f"t{int(time.time())}"
    data = {(rf.name, kind): build.read_events(build.TESTS / rf.name / f"{kind}.jsonl")
            for rf in rules for kind in ("match", "nomatch")}
    oldest = min(datetime.date.fromisoformat(e["timestamp"][:10]) for evs in data.values() for e in evs)
    yesterday = datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=1)
    days = (yesterday - oldest).days
    rows = {source: [] for source in TEST}
    for (name, kind), evs in data.items():
        for ev in shift(evs, days):
            source = build.event_source(ev)
            row = {k: t(ev[k]) for k, t in TEST[source]["fields"].items() if k in ev}
            row["sensor"] = f"{run_id}:{name}/{kind}"
            rows[source].append(row)
    total = sum(map(len, rows.values()))
    print(f"uploading {total} test events (run {run_id}, shifted {days} days)")
    for source, r in rows.items():
        if r:
            ws.upload(TEST[source]["stream"], r)

    scope_all = "union " + ", ".join(f'({t["table"]} | where sensor startswith "{run_id}:")'
                                     for t in TEST.values())
    for _ in range(90):  # ingestion takes a few minutes
        if ws.count(scope_all) >= total:
            break
        time.sleep(10)
    else:
        print("test events did not arrive within 15 minutes", file=sys.stderr)
        return 1

    failures = 0
    for rf in rules:
        want = build.run_tests(rf)
        got = {}
        for kind in ("match", "nomatch"):
            scoped = "".join(f'let T_{source} = {t["table"]} | where sensor == "{run_id}:{rf.name}/{kind}";\n'
                             for source, t in TEST.items())
            got[kind] = ws.count(scoped + build.to_kql(rf, {source: f"T_{source}" for source in TEST}))
        if rf.is_correlation:
            ok = got["match"] >= 1 and got["nomatch"] == 0
        else:
            ok = got["match"] == want["positive_events"] and got["nomatch"] == 0
        failures += not ok
        print(f"  {'ok ' if ok else 'FAIL'} {rf.name:34} match={got['match']} nomatch={got['nomatch']}")
    print(f"{len(rules) - failures}/{len(rules)} rules agree with Sentinel.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
