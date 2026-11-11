#!/usr/bin/env python3
"""Validate, test and convert the Sigma rules; optionally build the website.

  python tools/build.py            validate + test + write dist/spl and dist/kql
  python tools/build.py --check    same, but fail if dist/ is out of date (CI)
  python tools/build.py --site DIR also render the static site into DIR
      [--hits URL|FILE]             with the honeypot's detections.json ("Seen on the honeypot");
                                    if it can't be read, the site is built without it

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

Two log sources, chosen by each rule's logsource.product (see SOURCES): Cowrie
events and Suricata alerts. A temporal correlation may combine both, grouped by
src_ip, which both use for the remote address.
"""

import argparse
import json
import re
import sys
import urllib.request
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
# Per logsource.product: the Splunk scope, the Sentinel table, and the KQL variable that
# sentinel_rule() binds to that table's newly ingested rows.
SOURCES = {
    "cowrie": {"spl": "index=honeypot sourcetype=cowrie:json", "table": "Cowrie_CL", "new": "CowrieNew"},
    "suricata": {"spl": "index=honeypot sourcetype=suricata:alert", "table": "Suricata_CL",
                 "new": "SuricataNew"},
}
SPL_SCOPE = SOURCES["cowrie"]["spl"]
KQL_TABLE = SOURCES["cowrie"]["table"]
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
        for d in self.docs:
            if "correlation" not in d and product(d) not in SOURCES:
                raise BuildError(f"{path.name}: logsource.product must be one of {sorted(SOURCES)}")

    def product_of(self, name=None):
        """logsource.product of a base rule; without a name, of the rule as a whole (one source)."""
        if name:
            return product(self.base[name])
        if not self.is_correlation:
            return product(self.main)
        if len(self.products) != 1:
            raise BuildError(f"{self.path.name}: reads several log sources; name the base rule")
        return self.products[0]

    @property
    def products(self):
        """The log sources the rule reads, in a stable order."""
        if not self.is_correlation:
            return [self.product_of()]
        return sorted({product(self.base[n]) for n in self.main["correlation"]["rules"]})

    @property
    def techniques(self):
        return sorted(t.split(".", 1)[1].upper() for t in self.main.get("tags", [])
                      if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t))

    @property
    def tactics(self):
        return [t.split(".", 1)[1] for t in self.main.get("tags", [])
                if t.startswith("attack.") and not re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]


def product(doc):
    return (doc.get("logsource") or {}).get("product")


def event_source(ev):
    """Which log source a test event belongs to: Suricata alerts carry a signature_id."""
    return "suricata" if "signature_id" in ev else "cowrie"


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
    """Put the index/sourcetype constraint where Splunk needs it.

    `scope` is one string, or a function from a base rule's name to its scope: a correlation's
    subsearches each end with `eval event_type="<base rule>"`, which says which source it reads.
    """
    q = query.strip()
    pick = scope if callable(scope) else (lambda name: scope)
    if q.startswith("| multisearch"):
        head, *subs = q.split("[ search ")
        out = []
        for sub in subs:
            m = re.search(r'\| eval event_type="([^"]+)" \]', sub)
            if not m:
                raise BuildError("multisearch subsearch without an event_type")
            out.append(f"[ search {pick(m.group(1))} {sub}")
        return head + "".join(out)
    return f"{pick(None)}\n{q}" if q.startswith("|") else f"{pick(None)} {q}"


def to_spl(rf, scopes=None):
    """SPL for the rule; `scopes` maps a product to its scope (default: SOURCES)."""
    scopes = scopes or {p: s["spl"] for p, s in SOURCES.items()}
    queries = SplunkBackend().convert(rf.collection)
    if len(queries) != 1:
        raise BuildError(f"{rf.name}: expected one Splunk query, got {len(queries)}")
    return re.sub(r"\n{2,}", "\n", scope_spl(queries[0], lambda name: scopes[rf.product_of(name)]))


def kql_filter(doc):
    out = KustoBackend().convert(SigmaCollection.from_dicts([doc]))
    if len(out) != 1:
        raise BuildError("expected one KQL expression")
    return out[0]


def kql_tables(tables):
    """{product: table or let-bound name}; a plain string is the table for every product."""
    if tables is None:
        return {p: s["table"] for p, s in SOURCES.items()}
    if isinstance(tables, str):
        return {p: tables for p in SOURCES}
    return tables


def kql_correlation(rf, tables=None, new_only=False):
    """KQL for a correlation. With new_only, the tables carry an Ingested column and only groups
    with an event ingested since the last run are kept (see sentinel_rule)."""
    tables = kql_tables(tables)
    corr = rf.main["correlation"]
    span, by = corr["timespan"], ", ".join(corr.get("group-by", []))
    names = corr["rules"]
    kind = corr["type"]
    # Keep the source IP on every result row, so Sentinel can map it to an entity even when the
    # correlation groups by something else (a session always comes from one IP).
    keep_ip = "" if "src_ip" in corr.get("group-by", []) else ", src_ip = take_any(src_ip)"

    def cond(value_name):
        c = corr["condition"]
        ops = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "=="}
        return " and ".join(f"{value_name} {ops[k]} {v}" for k, v in c.items() if k != "field")

    if kind in ("event_count", "value_count"):
        if len(rf.products) != 1:
            raise BuildError(f"{rf.name}: a {kind} correlation must read one log source")
        table = tables[rf.products[0]]
        where = " or ".join(f"({kql_filter(rf.base[n])})" for n in names)
        agg = "count()" if kind == "event_count" else f"dcount({corr['condition']['field']})"
        return (f"{table}\n| where {where}\n| summarize {kind} = {agg}{keep_ip} by bin(TimeGenerated, {span}), {by}"
                f"\n| where {cond(kind)}")
    if kind == "temporal":
        parts = ",\n    ".join(f'({tables[rf.product_of(n)]} | where {kql_filter(rf.base[n])}'
                               f' | extend event_type = "{n}")' for n in names)
        if len(rf.products) > 1 and "src_ip" not in corr.get("group-by", []):
            raise BuildError(f"{rf.name}: a correlation across log sources must group by src_ip")
        new = f", new_events = countif(Ingested > ago({SENTINEL_WINDOW}))" if new_only else ""
        return (f"union\n    {parts}\n| summarize event_type_count = dcount(event_type){keep_ip}{new} "
                f"by bin(TimeGenerated, {span}), {by}\n| where event_type_count >= {len(names)}"
                + ("\n| where new_events > 0" if new_only else ""))
    raise BuildError(f"{rf.name}: no KQL template for correlation type {kind!r}")


def to_kql(rf, tables=None, new_only=False):
    """KQL for the rule; `tables` maps a product to a table or let-bound name (default: SOURCES)."""
    if rf.is_correlation:
        return kql_correlation(rf, tables, new_only)
    return f"{kql_tables(tables)[rf.product_of()]}\n| where {kql_filter(rf.main)}"


# Sentinel scheduled analytics rules. Events reach the workspace in batches (every 10 minutes from the
# honeypot), so a rule that only looked at TimeGenerated in its window would miss late events. Each run
# instead looks at what was *ingested* since the previous run; the 2 h query period covers their
# TimeGenerated. A correlation across Cowrie and Suricata reads the whole period, see sentinel_rule().
#
# Sentinel runs the query about 5 minutes after the end of its window, with now() set to that end.
# Without the upper bound, events ingested in those 5 minutes were seen by this run and again by the next
# one (12 duplicate alerts in the first three days); with it the windows are back to back.
# Every 15 minutes rather than hourly: a Cowrie batch that arrived just after an hourly run used to wait
# 66 minutes to become an incident.
SENTINEL_FREQUENCY, SENTINEL_PERIOD = "PT15M", "PT2H"
SENTINEL_WINDOW = "15m"  # = SENTINEL_FREQUENCY, in KQL
SENTINEL_SEVERITY = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low",
                     "informational": "Informational"}
# Sentinel's tactic names. Its API (up to 2025-10-01-preview) has no value yet for ATT&CK v20's Stealth
# and Defense Impairment, but it already checks techniques against v20 and refuses e.g. T1685 under
# DefenseEvasion. So those two tactics are left out, along with techniques that belong only to them;
# the Sigma rules keep the full v20 tags.
SENTINEL_TACTICS = {"reconnaissance": "Reconnaissance", "initial-access": "InitialAccess", "execution": "Execution", "persistence": "Persistence",
                    "privilege-escalation": "PrivilegeEscalation", "credential-access": "CredentialAccess",
                    "discovery": "Discovery", "lateral-movement": "LateralMovement", "collection": "Collection",
                    "command-and-control": "CommandAndControl", "exfiltration": "Exfiltration",
                    "impact": "Impact"}


def sentinel_rule(rf):
    m = rf.main
    from sigma.data import mitre_attack
    v20 = mitre_attack.mitre_attack_techniques_tactics_mapping
    tactics = sorted({SENTINEL_TACTICS[t] for t in rf.tactics if t in SENTINEL_TACTICS})
    techniques = sorted({t.split(".")[0] for t in rf.techniques
                         if any(tac in SENTINEL_TACTICS for tac in v20.get(t, []))})
    # One result row, and so one alert, per source IP and run; the playbooks in soar/ enrich and triage
    # per IP. Every query keeps src_ip (correlations carry it with take_any, see kql_correlation).
    # Across log sources the two halves arrive from separate shippers and can land in different
    # runs, so such a rule reads the whole query period and keeps groups with a newly ingested event.
    cross = len(rf.products) > 1
    if cross:
        lets = "".join(f"let {SOURCES[p]['new']} = {SOURCES[p]['table']}"
                       " | extend Ingested = ingestion_time() | where Ingested <= now();\n"
                       for p in rf.products)
        head = "// Groups with at least one event ingested since the last run (see tools/build.py)\n"
    else:
        lets = "".join(f"let {SOURCES[p]['new']} = {SOURCES[p]['table']}"
                       f" | where ingestion_time() > ago({SENTINEL_WINDOW}) and ingestion_time() <= now();\n"
                       for p in rf.products)
        head = "// Only events ingested since the last run (see tools/build.py)\n"
    query = (head + lets + to_kql(rf, {p: SOURCES[p]["new"] for p in rf.products}, new_only=cross)
             + "\n// One alert per source IP\n"
               "| summarize Matches = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)"
               " by src_ip")
    return {"kind": "Scheduled", "properties": {
        "displayName": m["title"],
        "description": " ".join(m.get("description", "").split()),
        "severity": SENTINEL_SEVERITY[m.get("level", "medium")],
        "enabled": True,
        "query": query,
        "queryFrequency": SENTINEL_FREQUENCY,
        "queryPeriod": SENTINEL_PERIOD,
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": tactics,
        "techniques": techniques,
        "entityMappings": [{"entityType": "IP",
                            "fieldMappings": [{"identifier": "Address", "columnName": "src_ip"}]}],
        "customDetails": {"Matches": "Matches", "FirstSeen": "FirstSeen", "LastSeen": "LastSeen"},
        "alertDetailsOverride": {"alertDisplayNameFormat": m["title"] + " from {{src_ip}}"},
        "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        # No incident of its own: incident_per_ip_rule() turns the alerts of all rules into one incident
        # per source IP and severity, so one attack is one ticket instead of one per rule.
        "incidentConfiguration": {"createIncident": False, "groupingConfiguration": {
            "enabled": False, "reopenClosedIncident": False, "lookbackDuration": "P1D",
            "matchingMethod": "AllEntities"}},
    }}


# One incident per source IP. Sentinel groups alerts into incidents only within one analytics rule, so a
# dropper session that five rules catch used to open five incidents (and three Telegram messages). This rule
# reads the detection rules' new alerts every 5 minutes and raises one alert per IP, with the highest
# severity, the rules that fired and their tactics and techniques; it groups by IP and severity over a day.
# Severity is part of the grouping because Sentinel doesn't raise an incident's severity when a more severe
# alert joins it: a High alert for an IP with an open Medium incident opens (and notifies) a High one.
INCIDENT_RULE_ID = "5d0f8f8e-4c1a-4f0e-9a51-6b7e2c9d3a10"
INCIDENT_FREQUENCY, INCIDENT_WINDOW = "PT5M", "5m"


def incident_per_ip_rule(rules):
    ids = ", ".join(f'"{rf.main["id"]}"' for rf in rules)
    query = f"""// The detection rules' alerts ingested since the last run (see tools/build.py)
let rules = dynamic([{ids}]);
SecurityAlert
| where ingestion_time() > ago({INCIDENT_WINDOW}) and ingestion_time() <= now()
| where ProviderName == "ASI Scheduled Alerts" and tostring(split(AlertType, "_")[1]) in (rules)
| mv-expand e = todynamic(Entities) | where tostring(e.Type) == "ip"
| extend src_ip = tostring(e.Address), Rule = tostring(split(AlertName, " from ")[0]),
    Sev = case(AlertSeverity == "High", 3, AlertSeverity == "Medium", 2, AlertSeverity == "Low", 1, 0)
| mv-expand Tactic = split(Tactics, ",") to typeof(string)
| mv-expand Technique = iff(isempty(Techniques), dynamic([""]), todynamic(Techniques)) to typeof(string)
| summarize Sev = max(Sev), Rules = make_set(Rule), TacticSet = make_set_if(trim(" ", Tactic), trim(" ", Tactic) !in ("", "Unknown")),
    TechniqueSet = make_set_if(Technique, isnotempty(Technique)), Alerts = dcount(SystemAlertId),
    FirstSeen = min(StartTime), LastSeen = max(EndTime) by src_ip
| extend Severity = case(Sev == 3, "High", Sev == 2, "Medium", Sev == 1, "Low", "Informational"),
    RuleList = strcat_array(array_sort_asc(Rules), ", "), TacticList = strcat_array(TacticSet, ","),
    Techniques = tostring(TechniqueSet)
| project src_ip, Severity, RuleList, TacticList, Techniques, Alerts, FirstSeen, LastSeen"""
    return {"kind": "Scheduled", "properties": {
        "displayName": "Honeypot activity",
        "description": "One incident per source IP and severity, from the alerts of the detection rules "
                       "(which raise no incidents themselves). Generated by tools/build.py.",
        "severity": "Medium",
        "enabled": True,
        "query": query,
        "queryFrequency": INCIDENT_FREQUENCY,
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT5M",
        "suppressionEnabled": False,
        "tactics": [],
        "techniques": [],
        "entityMappings": [{"entityType": "IP",
                            "fieldMappings": [{"identifier": "Address", "columnName": "src_ip"}]}],
        "customDetails": {"Rules": "RuleList", "Alerts": "Alerts", "FirstSeen": "FirstSeen",
                          "LastSeen": "LastSeen"},
        "alertDetailsOverride": {
            "alertDisplayNameFormat": "Honeypot activity from {{src_ip}}",
            "alertDescriptionFormat": "Rules that fired: {{RuleList}}",
            "alertSeverityColumnName": "Severity",
            "alertTacticsColumnName": "TacticList",
            "alertDynamicProperties": [{"alertProperty": "Techniques", "value": "Techniques"}]},
        "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {
            "enabled": True, "reopenClosedIncident": False, "lookbackDuration": "P1D",
            "matchingMethod": "Selected", "groupByEntities": ["IP"], "groupByAlertDetails": ["Severity"],
            "groupByCustomDetails": []}},
    }}


def outputs(rules):
    """{dist path: text}. Each file starts with a comment in its own language."""
    out = {}
    for rf in rules:
        note = f"{rf.main['title']}. Generated from rules/{rf.path.name} by tools/build.py; do not edit."
        out[DIST / "spl" / f"{rf.name}.spl"] = f"``` {note} ```\n{to_spl(rf)}\n"
        out[DIST / "kql" / f"{rf.name}.kql"] = f"// {note}\n{to_kql(rf)}\n"
        body = sentinel_rule(rf)
        body["properties"] = {k: v for k, v in body["properties"].items() if v is not None}
        out[DIST / "sentinel" / f"{rf.name}.json"] = json.dumps(
            {"id": rf.main["id"], "_comment": note, **body}, indent=2) + "\n"
    out[DIST / "sentinel" / "_incident_per_ip.json"] = json.dumps(
        {"id": INCIDENT_RULE_ID, "_comment": "One incident per source IP. Generated by tools/build.py; do not edit.",
         **incident_per_ip_rule(rules)}, indent=2) + "\n"
    return out


# ---------------------------------------------------------------- main

def load_hits(src):
    """The honeypot's detections.json (written by uig-honeypot's vps/detect.py), or None."""
    try:
        if re.match(r"https?://", src):
            with urllib.request.urlopen(src, timeout=30) as r:
                data = json.load(r)
        else:
            data = json.loads(Path(src).read_text(encoding="utf-8"))
        if not isinstance(data.get("rules"), dict):
            raise ValueError("no rules object")
        return data
    except (OSError, ValueError, AttributeError) as e:
        print(f"warning: no honeypot hits ({src}: {e}); building without them", file=sys.stderr)
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if dist/ is out of date")
    ap.add_argument("--site", type=Path, help="render the website into this directory")
    ap.add_argument("--hits", help="the honeypot's detections.json (URL or file) for the site")
    ap.add_argument("--soar", type=Path, help="tools/soar_stats.py's output, for the site's SOAR section")
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
        soar = json.loads(a.soar.read_text(encoding="utf-8")) if a.soar and a.soar.exists() else None
        site_gen.render(rules, results, out, a.site, load_hits(a.hits) if a.hits else None, soar)
        print(f"site written to {a.site}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
