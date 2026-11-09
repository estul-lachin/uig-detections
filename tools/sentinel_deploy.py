#!/usr/bin/env python3
"""Deploy dist/sentinel/*.json as Microsoft Sentinel scheduled analytics rules.

Each rule's ID is its Sigma rule ID, so running this again updates the same
rules instead of adding copies. Rules no longer in dist/ are left alone and
listed, never deleted automatically. Uses the Azure CLI's login.

  python tools/sentinel_deploy.py [--resource-group rg-uig-sentinel] [--workspace law-uig-honeypot] [--dry-run]
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "api-version=2025-09-01"


def az(*args):
    r = subprocess.run(["az", *args], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--resource-group", default="rg-uig-sentinel")
    ap.add_argument("--workspace", default="law-uig-honeypot")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    ws = az("monitor", "log-analytics", "workspace", "show", "-g", a.resource_group, "-n", a.workspace,
            "--query", "id", "-o", "tsv")
    base = f"https://management.azure.com{ws}/providers/Microsoft.SecurityInsights/alertRules"
    failures = 0
    ours = set()
    for path in sorted((ROOT / "dist" / "sentinel").glob("*.json")):
        rule = json.loads(path.read_text(encoding="utf-8"))
        rid = rule.pop("id")
        rule.pop("_comment", None)
        ours.add(rid)
        if a.dry_run:
            print(f"  would deploy {path.stem}")
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(rule, fh)
        try:
            az("rest", "--method", "put", "--url", f"{base}/{rid}?{API}", "--body", f"@{fh.name}", "-o", "none")
            print(f"  ok   {path.stem}")
        except RuntimeError as e:
            failures += 1
            print(f"  FAIL {path.stem}: {str(e).splitlines()[-1] if str(e) else e}")
        finally:
            Path(fh.name).unlink()
    existing = json.loads(az("rest", "--method", "get", "--url", f"{base}?{API}"))["value"]
    others = [r["properties"].get("displayName", r["name"]) for r in existing
              if r["name"] not in ours and r.get("kind") == "Scheduled"]
    if others:
        print("scheduled rules in the workspace that this repo doesn't manage:", ", ".join(others))
    print(f"{len(ours) - failures}/{len(ours)} rules deployed" if not a.dry_run else f"{len(ours)} rules")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
