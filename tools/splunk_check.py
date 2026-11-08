#!/usr/bin/env python3
"""Run the converted SPL against the test events in a real Splunk (local only).

The Python evaluator in build.py proves the Sigma logic; this proves the
pySigma Splunk conversion. Each rule's test files are indexed into a throwaway
index, the generated SPL runs scoped to that index and file, and the result
must agree with the evaluator: every positive event (single-event rules) or at
least one group (correlations) for match.jsonl, nothing for nomatch.jsonl.

Needs a running Splunk container that has the cowrie:json sourcetype, e.g. the
one from uig-honeypot (./hp siem up):

  SPLUNK_PASSWORD=... python tools/splunk_check.py [--container NAME]
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import build  # noqa: E402

SPLUNK = "/opt/splunk/bin/splunk"


class Splunk:
    def __init__(self, container, password):
        self.container, self.auth = container, f"admin:{password}"

    def cli(self, *args, user="splunk"):
        r = subprocess.run(["docker", "exec", "-u", user, self.container, SPLUNK, *args, "-auth", self.auth],
                           capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(f"splunk {args[0]} failed: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout

    def count(self, query):
        out = self.cli("search", query + " | stats count", "-maxout", "1")
        nums = [line.strip() for line in out.splitlines() if line.strip().isdigit()]
        if not nums:
            raise RuntimeError(f"no count in output for: {query}\n{out}")
        return int(nums[-1])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--container", default="uig-honeypot-siem-splunk-1")
    a = ap.parse_args(argv)
    password = os.environ.get("SPLUNK_PASSWORD")
    if not password:
        print("set SPLUNK_PASSWORD", file=sys.stderr)
        return 2
    sp = Splunk(a.container, password)
    rules = build.load_rules()
    index = f"uigdet_{int(time.time())}"
    sp.cli("add", "index", index)
    failures = 0
    try:
        expected_events = 0
        for rf in rules:
            for kind in ("match", "nomatch"):
                src = build.TESTS / rf.name / f"{kind}.jsonl"
                dest = f"/tmp/{index}-{rf.name}-{kind}.jsonl"
                subprocess.run(["docker", "cp", str(src), f"{a.container}:{dest}"], check=True)
                subprocess.run(["docker", "exec", "-u", "root", a.container, "chmod", "644", dest], check=True)
                sp.cli("add", "oneshot", dest, "-index", index, "-sourcetype", "cowrie:json",
                       "-rename-source", f"{rf.name}/{kind}")
                expected_events += len(build.read_events(src))
        for _ in range(60):  # oneshot indexing is asynchronous
            if sp.count(f"index={index} earliest=0") >= expected_events:
                break
            time.sleep(2)
        else:
            raise RuntimeError("test events were not indexed in time")

        for rf in rules:
            want = build.run_tests(rf)
            got = {}
            for kind in ("match", "nomatch"):
                scope = f'index={index} source="{rf.name}/{kind}" earliest=0'
                got[kind] = sp.count(build.to_spl(rf, scope))
            if rf.is_correlation:
                ok = got["match"] >= 1 and got["nomatch"] == 0
            else:
                ok = got["match"] == want["positive_events"] and got["nomatch"] == 0
            failures += not ok
            print(f"  {'ok ' if ok else 'FAIL'} {rf.name:34} match={got['match']} nomatch={got['nomatch']}")
    finally:
        sp.cli("remove", "index", index)
        subprocess.run(["docker", "exec", "-u", "root", a.container, "sh", "-c", f"rm -f /tmp/{index}-*"])
    print(f"{len(rules) - failures}/{len(rules)} rules agree with Splunk.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
