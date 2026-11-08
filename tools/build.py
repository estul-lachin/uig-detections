#!/usr/bin/env python3
"""Validate, test and convert the Sigma rules; optionally build the website.

  python tools/build.py            validate + test + write dist/spl and dist/kql
  python tools/build.py --check    same, but fail if dist/ is out of date (CI)
  python tools/build.py --site DIR also render the static site into DIR

Steps, any failure exits non-zero:
1. pySigma's core validators, plus a check that every |re pattern is RE2-safe
   (KQL runs RE2: no backreferences or lookarounds).
2. Each rule file runs against tests/<name>/match.jsonl and nomatch.jsonl with
   tools/sigma_eval.py. Single-event rules must match every positive event and
   no negative one; correlation rules must fire on the positives and not on
   the negatives.
3. Conversion: SPL with pySigma's Splunk backend, scoped to the honeypot index;
   KQL with the Kusto backend for single-event rules and kql_correlation() below
   for correlations, which that backend doesn't support.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as CORE_VALIDATORS

sys.path.insert(0, str(Path(__file__).parent))
import sigma_eval  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RULES, TESTS, DIST = ROOT / "rules", ROOT / "tests", ROOT / "dist"
SPL_SCOPE = "index=honeypot sourcetype=cowrie:json"
KQL_TABLE = "Cowrie_CL"
RE2_UNSAFE = re.compile(r"\\[1-9]|\(\?[=!]|\(\?<[=!]|\(\?>|\\[gk]<")


class BuildError(Exception):
    pass


# ---------------------------------------------------------------- loading

class RuleFile:
    """One YAML file: one detection, possibly with base rules for a correlation."""

    def __init__(self, path):
        self.path, self.name = path, path.stem
        self.text = path.read_text(encoding="utf-8")
        self.docs = list(yaml.safe_load_all(self.text))
        self.collection = SigmaCollection.from_yaml(self.text)
        corr = [d for d in self.docs if "correlation" in d]
        if len(corr) > 1:
            raise BuildError(f"{path.name}: one correlation per file")
        self.main = corr[0] if corr else self.docs[-1]
        self.is_correlation = bool(corr)
        self.base = {d["name"]: d for d in self.docs if "correlation" not in d and "name" in d}
        if self.is_correlation and len(self.docs) != len(self.base) + 1:
            raise BuildError(f"{path.name}: base rules of a correlation need a name")

    @property
    def techniques(self):
        return sorted(t.split(".", 1)[1].upper() for t in self.main.get("tags", [])
                      if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t))

    @property
    def tactics(self):
        return [t.split(".", 1)[1] for t in self.main.get("tags", [])
                if t.startswith("attack.") and not re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]


def load_rules():
    return [RuleFile(p) for p in sorted(RULES.glob("*.yml"))]


# ---------------------------------------------------------------- validation

def regex_values(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and "|re" in k:
                yield from (v if isinstance(v, list) else [v])
            else:
                yield from regex_values(v)
    elif isinstance(node, list):
        for x in node:
            yield from regex_values(x)


def validate(rules):
    problems = []
    validator = SigmaValidator(CORE_VALIDATORS.values())
    for rf in rules:
        for issue in validator.validate_rules(rf.collection):
            problems.append(f"{rf.path.name}: {type(issue).__name__}: {issue.description}")
        for d in rf.docs:
            for pattern in regex_values(d.get("detection", {})):
                if RE2_UNSAFE.search(str(pattern)):
                    problems.append(f"{rf.path.name}: regex not RE2-safe (KQL): {pattern}")
                re.compile(str(pattern))
        if not (TESTS / rf.name / "match.jsonl").exists() or not (TESTS / rf.name / "nomatch.jsonl").exists():
            problems.append(f"{rf.path.name}: tests/{rf.name}/match.jsonl and nomatch.jsonl are required")
    if problems:
        raise BuildError("validation failed:\n  " + "\n  ".join(problems))


# ---------------------------------------------------------------- tests

def read_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_tests(rf):
    """Return a summary dict; raise BuildError on a failed expectation."""
    pos = read_events(TESTS / rf.name / "match.jsonl")
    neg = read_events(TESTS / rf.name / "nomatch.jsonl")
    if rf.is_correlation:
        corr = rf.main["correlation"]
        matchers = {n: sigma_eval.compile_rule(rf.base[n]["detection"]) for n in corr["rules"]}
        fired_pos = sigma_eval.correlate(corr, matchers, pos)
        fired_neg = sigma_eval.correlate(corr, matchers, neg)
        if not fired_pos:
            raise BuildError(f"{rf.name}: correlation did not fire on match.jsonl")
        if fired_neg:
            raise BuildError(f"{rf.name}: correlation fired on nomatch.jsonl: {fired_neg}")
        return {"positive_events": len(pos), "negative_events": len(neg), "fired": len(fired_pos)}
    match = sigma_eval.compile_rule(rf.main["detection"])
    missed = [e.get("input", e) for e in pos if not match(e)]
    false_hits = [e.get("input", e) for e in neg if match(e)]
    if missed:
        raise BuildError(f"{rf.name}: missed positive event(s): {missed}")
    if false_hits:
        raise BuildError(f"{rf.name}: matched negative event(s): {false_hits}")
    return {"positive_events": len(pos), "negative_events": len(neg), "fired": len(pos)}


# ---------------------------------------------------------------- conversion

def scope_spl(query, scope):
    """Put the index/sourcetype constraint where Splunk needs it."""
    q = query.strip()
    if q.startswith("| multisearch"):
        return q.replace("[ search ", f"[ search {scope} ")
    return f"{scope}\n{q}" if q.startswith("|") else f"{scope} {q}"


def to_spl(rf, scope=SPL_SCOPE):
    queries = SplunkBackend().convert(rf.collection)
    if len(queries) != 1:
        raise BuildError(f"{rf.name}: expected one Splunk query, got {len(queries)}")
    return re.sub(r"\n{2,}", "\n", scope_spl(queries[0], scope))


def kql_filter(doc):
    out = KustoBackend().convert(SigmaCollection.from_dicts([doc]))
    if len(out) != 1:
        raise BuildError("expected one KQL expression")
    return out[0]


def kql_correlation(rf):
    corr = rf.main["correlation"]
    span, by = corr["timespan"], ", ".join(corr.get("group-by", []))
    names = corr["rules"]
    kind = corr["type"]

    def cond(value_name):
        c = corr["condition"]
        ops = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "=="}
        return " and ".join(f"{value_name} {ops[k]} {v}" for k, v in c.items() if k != "field")

    if kind in ("event_count", "value_count"):
        where = " or ".join(f"({kql_filter(rf.base[n])})" for n in names)
        agg = "count()" if kind == "event_count" else f"dcount({corr['condition']['field']})"
        return (f"{KQL_TABLE}\n| where {where}\n| summarize {kind} = {agg} by bin(TimeGenerated, {span}), {by}"
                f"\n| where {cond(kind)}")
    if kind == "temporal":
        parts = ",\n    ".join(f'({KQL_TABLE} | where {kql_filter(rf.base[n])} | extend event_type = "{n}")'
                               for n in names)
        return (f"union\n    {parts}\n| summarize event_type_count = dcount(event_type) "
                f"by bin(TimeGenerated, {span}), {by}\n| where event_type_count >= {len(names)}")
    raise BuildError(f"{rf.name}: no KQL template for correlation type {kind!r}")


def to_kql(rf):
    if rf.is_correlation:
        return kql_correlation(rf)
    return f"{KQL_TABLE}\n| where {kql_filter(rf.main)}"


def outputs(rules):
    """{dist path: text}. Each file starts with a comment in its own language."""
    out = {}
    for rf in rules:
        note = f"{rf.main['title']}. Generated from rules/{rf.path.name} by tools/build.py; do not edit."
        out[DIST / "spl" / f"{rf.name}.spl"] = f"``` {note} ```\n{to_spl(rf)}\n"
        out[DIST / "kql" / f"{rf.name}.kql"] = f"// {note}\n{to_kql(rf)}\n"
    return out


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if dist/ is out of date")
    ap.add_argument("--site", type=Path, help="render the website into this directory")
    a = ap.parse_args(argv)
    try:
        rules = load_rules()
        validate(rules)
        results = {rf.name: run_tests(rf) for rf in rules}
        out = outputs(rules)
    except BuildError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    stale = [p for p, text in out.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
    known = set(out)
    extra = [p for p in DIST.glob("*/*") if p not in known]
    if a.check:
        for p in stale + extra:
            print(f"out of date: {p.relative_to(ROOT)}", file=sys.stderr)
        if stale or extra:
            print("run: python tools/build.py", file=sys.stderr)
            return 1
    else:
        for p in extra:
            p.unlink()
        for p, text in out.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
    for rf in rules:
        r = results[rf.name]
        print(f"  ok  {rf.name:34} {r['positive_events']:>2} positive, {r['negative_events']:>2} negative events")
    print(f"{len(rules)} rules validated, tested and converted.")
    if a.site:
        import site_gen
        site_gen.render(rules, results, out, a.site)
        print(f"site written to {a.site}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
