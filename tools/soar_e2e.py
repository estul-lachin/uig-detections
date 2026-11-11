#!/usr/bin/env python3
"""End-to-end test of the SOAR chain in soar/, on the real Sentinel workspace.

Writes one synthetic Cowrie event, marked with sensor "soar-e2e:<run>" and a source IP from the
192.0.2.0/24 documentation range, to Cowrie_Test_CL. The "SOAR end-to-end test" analytics rule (in
soar/main.bicep) turns it into a Low incident, and the script then checks what SOAR did with it:

  - the enrich playbook commented on it and tagged it soar:enriched and abuse:<range>
    (a documentation IP has no AbuseIPDB record, so the tag also exercises the lookup's fallback)
  - it is not auto-closed: auto-close needs abuse:75-100
  - it was not sent to Telegram: only High incidents are
  - the test rule raises it once (no duplicate incident on its next run)

Then it closes the incident as a test (Benign Positive, tag soar:e2e-test), so the published numbers
can leave test incidents out. Takes 25 to 35 minutes: ingestion, the rule's 5-minute schedule, and the playbook's 10-minute wait
(the documentation IP has no honeypot sessions, so it waits for one more Cowrie batch).
Uses the Azure CLI's login.

  python tools/soar_e2e.py [--resource-group rg-uig-sentinel] [--workspace law-uig-honeypot]
"""

import argparse
import datetime
import json
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from sentinel_check import TEST, Workspace, az, token  # noqa: E402

API = "api-version=2025-09-01"
WAIT_INCIDENT = 25 * 60
WAIT_ENRICH = 16 * 60  # a source with no honeypot sessions waits 10 minutes for Cowrie data first


def arm(method, url, tok, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {url.split('?')[0]}: {e.code} {e.read()[:400]!r}") from e
    return json.loads(raw) if raw else None


def wait(what, seconds, probe, every=20):
    end = time.time() + seconds
    while time.time() < end:
        got = probe()
        if got:
            return got
        time.sleep(every)
    raise TimeoutError(f"{what}: nothing after {seconds // 60} minutes")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--resource-group", default="rg-uig-sentinel")
    ap.add_argument("--workspace", default="law-uig-honeypot")
    a = ap.parse_args(argv)

    ws = Workspace(a.resource_group, a.workspace)
    sub = az("account", "show", "--query", "id")
    incidents = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{a.resource_group}"
                 f"/providers/Microsoft.OperationalInsights/workspaces/{a.workspace}"
                 f"/providers/Microsoft.SecurityInsights/incidents")
    tok = token("https://management.azure.com")

    run = f"soar-e2e:{int(time.time())}"
    ip = f"192.0.2.{random.randint(1, 254)}"
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(minutes=1)
    ws.upload(TEST["cowrie"]["stream"], [{"timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "eventid": "cowrie.command.input",
                "src_ip": ip, "src_port": 50000, "dst_port": 22, "session": run.split(":")[1],
                "protocol": "ssh", "input": "echo soar end-to-end test", "sensor": run}])
    print(f"wrote a test event from {ip} ({run}); waiting for the incident")

    def find_incident():
        nonlocal tok
        tok = token("https://management.azure.com")  # tokens last about an hour; this run can be long
        stamp = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        flt = urllib.parse.quote(f"properties/createdTimeUtc gt {stamp}")
        res = arm("GET", f"{incidents}?{API}&$filter={flt}", tok)
        return next((i for i in res["value"] if i["properties"]["title"].endswith(f"from {ip}")), None)

    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}")

    try:
        inc = wait("incident", WAIT_INCIDENT, find_incident, every=30)
    except TimeoutError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return 1
    inc_name = inc["name"]
    url = f"{incidents}/{inc_name}"
    print(f"incident #{inc['properties']['incidentNumber']}: {inc['properties']['title']}")

    def labels():
        return [x["labelName"] for x in arm("GET", f"{url}?{API}", tok)["properties"].get("labels", [])]

    try:
        wait("soar:enriched tag", WAIT_ENRICH, lambda: "soar:enriched" in labels())
    except TimeoutError as e:
        check("enriched", False, str(e))
    time.sleep(30)  # let the update-triggered rules act before judging them
    inc = arm("GET", f"{url}?{API}", tok)
    tags = [x["labelName"] for x in inc["properties"].get("labels", [])]
    comments = [c["properties"]["message"] for c in arm("GET", f"{url}/comments?{API}", tok)["value"]]

    check("tagged soar:enriched", "soar:enriched" in tags, ", ".join(tags))
    check("tagged abuse:<range>", any(t.startswith("abuse:") for t in tags))
    check("enrichment comment", any(c.startswith(f"<p><b>SOAR enrichment for {ip}</b>") for c in comments))
    check("not auto-closed", inc["properties"]["status"] != "Closed", inc["properties"]["status"])
    check("not sent to Telegram", "soar:notified" not in tags)

    props = inc["properties"]
    props.update(status="Closed", classification="BenignPositive", classificationReason="SuspiciousButExpected",
                 classificationComment=f"End-to-end test {run} (tools/soar_e2e.py)",
                 labels=props.get("labels", []) + [{"labelName": "soar:e2e-test", "labelType": "User"}])
    arm("PUT", f"{url}?{API}", tok, {"etag": inc.get("etag"), "properties": props})
    print("closed the test incident (soar:e2e-test)")

    # The test rule's window must not be longer than its schedule, or the next run raises the same event
    # again, as a new incident because this one is closed. Wait past one more run to be sure.
    print("waiting 6 minutes for a duplicate")
    time.sleep(6 * 60)
    tok = token("https://management.azure.com")
    flt = urllib.parse.quote(f"properties/createdTimeUtc gt {start.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    dups = [i for i in arm("GET", f"{incidents}?{API}&$filter={flt}", tok)["value"]
            if i["properties"]["title"].endswith(f"from {ip}") and i["name"] != inc_name]
    check("no duplicate incident", not dups, ", ".join(f"#{i['properties']['incidentNumber']}" for i in dups))
    for i in dups:  # close them too, so a failed run leaves nothing open
        p = i["properties"]
        p.update(status="Closed", classification="BenignPositive", classificationReason="SuspiciousButExpected",
                 classificationComment=f"Duplicate from end-to-end test {run}",
                 labels=p.get("labels", []) + [{"labelName": "soar:e2e-test", "labelType": "User"}])
        arm("PUT", f"{incidents}/{i['name']}?{API}", tok, {"etag": i.get("etag"), "properties": p})

    ok = all(checks)
    print(f"{sum(checks)}/{len(checks)} checks passed" if ok else f"FAILED: {checks.count(False)} of {len(checks)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
