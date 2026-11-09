"""Render detections.uig.me from the rules, test results and converted queries.

Plain HTML and CSS, no JavaScript. Every value from a rule or from the honeypot is escaped.

Also writes rules.json, the rules as plain data for uig-honeypot's vps/detect.py, which runs
them on the live logs every hour and publishes detections.json; that file, read back at build
time with --hits, fills the "Seen on the honeypot" parts. CI rebuilds the site every 6 hours.
"""

import html
import json
import shutil
from collections import defaultdict
from pathlib import Path

from sigma.data import mitre_attack

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/estul-lachin/uig-detections"
SITE = "https://detections.uig.me"
LEVELS = ["critical", "high", "medium", "low", "informational"]
TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery",
                "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]
e = html.escape


def tactic_name(t):
    return t.replace("-", " ").title().replace("And", "and")


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def page(title, body, depth, description):
    rel = "../" * depth
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(description)}">
<meta property="og:title" content="{e(title)}">
<meta property="og:description" content="{e(description)}">
<meta property="og:type" content="website">
<meta property="og:image" content="{SITE}/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Estul Lachin: detection-as-code">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="{rel}favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{rel}style.css">
</head>
<body>
<header class="site-header">
  <div class="wrap">
    <a class="brand" href="https://uig.me/">Estul Lachin</a>
    <nav>
      <a href="https://lab.uig.me/">Labs</a>
      <a href="https://honeypot.uig.me/">Honeypot</a>
      <a href="{rel or './'}" aria-current="page">Detections</a>
    </nav>
  </div>
</header>
<main class="wrap">
{body}
</main>
<footer class="site-footer">
  <div class="wrap">
    <a href="https://www.linkedin.com/in/estul-lachin">LinkedIn</a> ·
    <a href="https://github.com/estul-lachin">GitHub</a> ·
    <a href="{REPO}">Source</a>
    <p class="credit">MITRE ATT&amp;CK® technique IDs as of ATT&amp;CK v20 · Rules in
      <a href="https://sigmahq.io/">Sigma</a> format</p>
  </div>
</footer>
</body>
</html>
"""


def chips(rf):
    return "".join(f'<a class="chip" href="{technique_url(t)}" rel="noopener">{e(t)}</a>' for t in rf.techniques)


def technique_tactics(tid):
    """Tactics of a technique per ATT&CK (the data pySigma validates against)."""
    tactics = mitre_attack.mitre_attack_techniques_tactics_mapping.get(tid)
    if not tactics:
        raise ValueError(f"{tid}: no tactic in the ATT&CK data")
    return tactics


def seen(rf, hits):
    """This rule's honeypot stats from detections.json, or None (no file, or rule not in it)."""
    if not hits:
        return None
    h = hits["rules"].get(rf.name)
    if not isinstance(h, dict) or h.get("id") != rf.main["id"]:
        return None
    return h


def plural(n, word):
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def seen_badge(rf, hits):
    h = seen(rf, hits)
    if h is None:
        return ""
    n = int(h.get("sessions") or 0)
    if not n:
        return f'<span class="seen none">not seen in {int(hits.get("days", 30))} days</span>'
    return f'<span class="seen">seen in {plural(n, "session")}</span>'


def seen_section(rf, hits):
    h = seen(rf, hits)
    if h is None:
        return ""
    days = int(hits.get("days", 30))
    asof = e(str(hits.get("generated_at", "")).replace("T", " ").replace("Z", " UTC"))
    n = int(h.get("sessions") or 0)
    if not n:
        text = (f"<p>Has not fired in the last {days} days (as of {asof}). The tests above still run on every "
                f"change, so the rule is ready when the behaviour shows up.</p>")
    else:
        alerts = int(h.get("alerts") or 0)
        what = (f"raised {plural(alerts, 'alert')} covering {plural(n, 'session')}" if rf.is_correlation
                else f"fired in {plural(n, 'session')} ({plural(alerts, 'matching command')})")
        text = (f"<p>In the last {days} days (as of {asof}) this rule {what}, first on "
                f"{e(str(h.get('first_seen')))} and last on {e(str(h.get('last_seen')))}.</p>")
        if h.get("example"):
            text += ("<p>Most common matching command (URLs and IP addresses in it are defanged; the "
                     "attackers' source IPs are never published):</p>"
                     f'<pre class="code"><code>{e(str(h["example"]))}</code></pre>')
    return (f'<h2>Seen on the honeypot</h2>\n{text}\n<p class="meta">Counted by running this rule\'s Sigma '
            f'logic on the <a href="https://honeypot.uig.me/">honeypot</a>\'s raw logs every hour.</p>')


def render_index(rules, results, hits=None):
    by_tactic = defaultdict(lambda: defaultdict(list))
    for rf in rules:
        for t in rf.techniques:
            for tac in technique_tactics(t):
                by_tactic[tac][t].append(rf)
    names = mitre_attack.mitre_attack_techniques
    techniques = {t for rf in rules for t in rf.techniques}
    positives = sum(r["positive_events"] for r in results.values())
    fired = [rf for rf in rules if (seen(rf, hits) or {}).get("sessions")]
    seen_stat = ""
    if hits:
        seen_stat = (f'\n  <div class="stat"><span class="num">{len(fired)} of {len(rules)}</span>'
                     f'<span class="label">rules fired on the honeypot, last {int(hits.get("days", 30))} days'
                     f'</span></div>')
    negatives = sum(r["negative_events"] for r in results.values())
    rows = []
    for tac in sorted(by_tactic, key=lambda x: TACTIC_ORDER.index(x) if x in TACTIC_ORDER else 99):
        techs = sorted(by_tactic[tac])
        for i, t in enumerate(techs):
            rule_links = ", ".join(f'<a href="rules/{rf.name}/">{e(rf.main["title"])}</a>'
                                   for rf in by_tactic[tac][t])
            first = f'<th scope="rowgroup" rowspan="{len(techs)}">{e(tactic_name(tac))}</th>' if i == 0 else ""
            rows.append(f'<tr>{first}<td class="tech"><a href="{technique_url(t)}" rel="noopener">{e(t)}</a>'
                        f'<span class="tech-name">{e(names.get(t, ""))}</span></td>'
                        f'<td class="rules-cell">{rule_links}</td></tr>')
    cards = []
    for rf in sorted(rules, key=lambda r: (LEVELS.index(r.main.get("level", "low")), r.main["title"])):
        kind = "correlation" if rf.is_correlation else "single event"
        cards.append(f"""<li class="rule">
  <div class="rule-head"><a href="rules/{rf.name}/">{e(rf.main["title"])}</a>
    <span class="level {e(rf.main.get('level', ''))}">{e(rf.main.get('level', ''))}</span></div>
  <p>{e(rf.main.get("description", "").strip().split(". ")[0].rstrip("."))}.</p>
  <div class="meta">{chips(rf)} <span class="kind">{kind}</span> {seen_badge(rf, hits)}</div>
</li>""")
    body = f"""<section class="intro">
  <h1>Detection-as-code</h1>
  <p class="lead">Detections for SSH and Telnet attacks, written once in <a href="https://sigmahq.io/">Sigma</a> and
    converted to Splunk SPL and Microsoft Sentinel KQL. Every rule is tested in CI against attack events that
    must match and look-alike events that must not. The behaviour comes from the
    <a href="https://honeypot.uig.me/">live honeypot</a>.</p>
</section>
<div class="stats">
  <div class="stat"><span class="num">{len(rules)}</span><span class="label">rules</span></div>
  <div class="stat"><span class="num">{len(techniques)}</span><span class="label">ATT&amp;CK techniques</span></div>
  <div class="stat"><span class="num">{positives}</span><span class="label">attack test events</span></div>
  <div class="stat"><span class="num">{negatives}</span><span class="label">look-alike test events</span></div>{seen_stat}
</div>

<h2>How a rule gets here</h2>
<ol class="pipeline">
  <li><strong>Sigma rule</strong> in <code>rules/</code>, tagged with ATT&amp;CK</li>
  <li><strong>Validation</strong>: pySigma's 31 validators, and every regex checked to be RE2-safe for KQL</li>
  <li><strong>Tests</strong>: an evaluator runs the rule on <code>match.jsonl</code> (must fire) and
    <code>nomatch.jsonl</code> (must not)</li>
  <li><strong>Conversion</strong> to SPL and KQL, committed in <code>dist/</code>; CI fails if they're stale</li>
  <li><strong>Splunk and Sentinel checks</strong>: the generated SPL runs in Splunk and the KQL in Microsoft
    Sentinel on the same test events, and both must agree with the evaluator</li>
  <li><strong>Deploy</strong>: the rules run as Sentinel analytics rules on the live honeypot feed, which
    arrives every 10 minutes</li>
</ol>

<h2>ATT&amp;CK coverage</h2>
<div class="card table-wrap">
<table class="coverage">
  <thead><tr><th scope="col">Tactic</th><th scope="col">Technique</th><th scope="col">Rules</th></tr></thead>
  <tbody>{"".join(rows)}</tbody>
</table>
</div>

<h2>Rules</h2>
<ul class="rules">{"".join(cards)}</ul>
"""
    return page("Detection-as-code · Estul Lachin", body, 0,
                "Sigma detections for SSH and Telnet attacks, tested in CI and converted to Splunk SPL and "
                "Microsoft Sentinel KQL.")


def render_rule(rf, result, spl, kql, hits=None):
    m = rf.main
    fps = "".join(f"<li>{e(x)}</li>" for x in m.get("falsepositives", []))
    kind = "Correlation" if rf.is_correlation else "Single event"
    if rf.is_correlation:
        tested = (f"Fires on {result['positive_events']} attack events in <code>match.jsonl</code> "
                  f"({result['fired']} group{'s' if result['fired'] != 1 else ''}) and stays silent on "
                  f"{result['negative_events']} events in <code>nomatch.jsonl</code>.")
    else:
        tested = (f"Matches all {result['positive_events']} attack events in <code>match.jsonl</code> and none of the "
                  f"{result['negative_events']} look-alike events in <code>nomatch.jsonl</code>.")
    body = f"""<p class="subnav"><a href="../../">All rules</a></p>
<section class="intro">
  <h1>{e(m["title"])}</h1>
  <div class="meta"><span class="level {e(m.get('level', ''))}">{e(m.get('level', ''))}</span>
    <span class="kind">{kind}</span> {chips(rf)}
    <span class="kind">{e(", ".join(tactic_name(t) for t in rf.tactics))}</span></div>
</section>
<div class="prose">
  <p>{"</p><p>".join(e(p.strip()) for p in m.get("description", "").strip().split("\n\n"))}</p>
  <h2>Tested</h2>
  <p>{tested} <a href="{REPO}/tree/main/tests/{rf.name}">See the test events</a>.</p>
  {seen_section(rf, hits)}
  <h2>False positives</h2>
  <ul>{fps}</ul>
</div>

<h2>Sigma</h2>
<pre class="code"><code>{e(rf.text.strip())}</code></pre>
<p class="meta"><a href="{REPO}/blob/main/rules/{rf.path.name}">rules/{e(rf.path.name)}</a></p>

<h2>Splunk SPL</h2>
<pre class="code"><code>{e(spl.strip())}</code></pre>
<p class="meta">Verified in Splunk against the test events. <a href="{REPO}/blob/main/dist/spl/{rf.name}.spl">dist/spl/{e(rf.name)}.spl</a></p>

<h2>Microsoft Sentinel KQL</h2>
<pre class="code"><code>{e(kql.strip())}</code></pre>
<p class="meta">For the custom table <code>Cowrie_CL</code>, which has Cowrie's field names. Verified in
  Microsoft Sentinel against the test events, and deployed there as a scheduled analytics rule that runs hourly
  on the live honeypot feed. <a href="{REPO}/blob/main/dist/kql/{rf.name}.kql">dist/kql/{e(rf.name)}.kql</a> ·
  <a href="{REPO}/blob/main/dist/sentinel/{rf.name}.json">analytics rule</a></p>
"""
    desc = m.get("description", "").strip().split(". ")[0]
    return page(f"{m['title']} · Detections · Estul Lachin", body, 2, desc)


def summary(rules, results):
    """The headline numbers for uig.me (same as the stats on the index page)."""
    return {
        "rules": len(rules),
        "techniques": len({t for rf in rules for t in rf.techniques}),
        "attack_test_events": sum(r["positive_events"] for r in results.values()),
        "lookalike_test_events": sum(r["negative_events"] for r in results.values()),
    }


def rules_export(rules):
    """The detection logic as plain JSON, for the honeypot's vps/detect.py."""
    out = []
    for rf in rules:
        r = {"name": rf.name, "id": rf.main["id"], "title": rf.main["title"], "level": rf.main.get("level")}
        if rf.is_correlation:
            r["correlation"] = rf.main["correlation"]
            r["base"] = {n: d["detection"] for n, d in rf.base.items()}
        else:
            r["detection"] = rf.main["detection"]
        out.append(r)
    return {"version": 1, "rules": out}


def render(rules, results, outputs, out_dir, hits=None):
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    (out / "rules").mkdir(parents=True)
    (out / "index.html").write_text(render_index(rules, results, hits), encoding="utf-8")
    for rf in rules:
        spl = outputs[ROOT / "dist" / "spl" / f"{rf.name}.spl"]
        kql = outputs[ROOT / "dist" / "kql" / f"{rf.name}.kql"]
        d = out / "rules" / rf.name
        d.mkdir()
        (d / "index.html").write_text(render_rule(rf, results[rf.name], spl, kql, hits), encoding="utf-8")
    (out / "rules.json").write_text(json.dumps(rules_export(rules), indent=1) + "\n", encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summary(rules, results), indent=1) + "\n", encoding="utf-8")
    for f in ("style.css", "favicon.svg", "og-image.png", "CNAME", "404.html"):
        src = ROOT / "site" / f
        if src.exists():
            shutil.copyfile(src, out / f)
