# SOAR

Playbooks that work the Sentinel incidents raised by the rules in `dist/sentinel/`. The honeypot only sees
attacks, so nothing here blocks anything: the playbooks enrich, triage and report. Every incident is about one
source IP and holds the alerts of all the rules that fired on it (*Honeypot activity*, see the Deploy step in
the main README), so each playbook works per IP.

```
main.bicep             Key Vault, the Sentinel API connection, and the playbooks (Logic Apps, Consumption)
playbooks/<name>.json  a playbook's workflow definition, loaded by main.bicep
deploy.sh              what-if, then deploy (idempotent: a redeploy shows "NoChange")
grant.sh               role assignments, run by someone who can assign roles
set-secrets.sh         store the API keys in the Key Vault (typed or piped, never as arguments)
grant-ci.sh            let CI read the workspace for the site's numbers (OIDC, no secret)
```

| Playbook | Run by | Does |
|---|---|---|
| `pb-uig-enrich` | automation rule "SOAR: enrich every new incident" | looks the IP up in AbuseIPDB and in the last 30 days of `Cowrie_CL`, writes one comment, adds tags, then triages (below). If the IP has no honeypot sessions yet, it waits 10 minutes and queries once more (see below) |
| `pb-uig-notify` | `pb-uig-enrich`, for High incidents | sends the incident's title, tactics, tags and portal link to Telegram (plain text), tags `soar:notified` |

`pb-uig-enrich` tags: `abuse:0`, `abuse:1-24`, `abuse:25-74`, `abuse:75-100` (or `abuse:unknown` when the
lookup fails), `has-download` when the IP downloaded a file, `tor` for Tor exits, and `soar:enriched`.
A Suricata-only incident can be created before the same IP's Cowrie events arrive (they ship every 10
minutes), so a first query with 0 sessions is repeated once after 10 minutes; the comment says when the data
was queried. Incidents from Cowrie rules always have sessions and are enriched within seconds.
If AbuseIPDB or the query fails, it still comments and tags with what it has. Commands in the comment are
HTML-escaped in the KQL, since attackers choose them.

Triage:

| When | If | Then | Done by |
|---|---|---|---|
| incident created | always | run `pb-uig-enrich` | automation rule, order 10 |
| incident created | severity High | status Active, assigned to the deployer | automation rule, order 20 |
| after enrichment | severity Low and `abuse:75-100` | close as True Positive / Suspicious Activity, tag `soar:auto-closed` | `pb-uig-enrich`, in the same update as the tags |
| after enrichment | severity High | run `pb-uig-notify` | `pb-uig-enrich` |

Everything else stays New for an analyst. The steps that need the enrichment run inside the playbook
rather than as "tag added" automation rules: changes made by a playbook that an automation rule started
do not fire update-triggered rules. (A first version did it that way; it worked when the playbook was run
by hand and never fired on real incidents.)

## Design

- **Managed identities, no stored credentials.** Each playbook has a system-assigned identity. The
  Microsoft Sentinel connection is used only for the incident trigger and signs in with that identity.
- **HTTP actions instead of connector actions.** Sentinel, Log Analytics (through ARM's
  `{workspaceId}/api/query`) and Key Vault are called with the built-in HTTP action and the managed identity.
  A built-in action costs about a fifth of a standard connector call, which matters at about a hundred
  incidents a day on a CAD 5 monthly budget.
- **Secrets stay in Key Vault**, read at run time with secure outputs so they never show in run history.

## Test

`tools/soar_e2e.py` runs the whole chain on the real workspace: it writes one synthetic event (a
192.0.2.0/24 documentation IP, sensor `soar-e2e:<run>`) to `Cowrie_Test_CL`, where the "SOAR end-to-end
test" analytics rule turns it into a Low incident. It then checks that the incident was enriched
(comment, `soar:enriched`, `abuse:*`), was not auto-closed and was not sent to Telegram, and closes it as
Benign Positive with the tag `soar:e2e-test`. It then waits past the rule's next run to check that the
same event does not raise a second incident. Expect 25 to 35 minutes: the test IP has no honeypot
sessions, so the playbook waits its 10 minutes.

```
.venv/bin/python tools/soar_e2e.py
```

## Published numbers

CI runs `tools/soar_stats.py` on main and publishes `soar.json` and an "Automated response" section on
detections.uig.me, plus a `soar` block in `summary.json` that uig.me shows. It logs in with GitHub OIDC
(`soar/grant-ci.sh`: an app registration with a federated credential for `main` and one role, Log
Analytics Reader on the workspace), so no secret is stored. The counts start when the enrichment
automation went live and leave out incidents tagged `soar:legacy` (closed in bulk when the rules switched
to one alert per IP) and `soar:e2e-test`. They hold no IPs, titles or comments. If the login or the query
fails, the site is built without the section.

## Setup

```
soar/deploy.sh          # review the what-if, then confirm
soar/grant.sh           # role assignments (Owner or User Access Administrator)
soar/set-secrets.sh     # abuseipdb-key, telegram-bot-token, telegram-chat-id
soar/grant-ci.sh        # optional: CI login for the published numbers
```

| Who | Role | Scope | Why |
|---|---|---|---|
| each playbook | Microsoft Sentinel Responder | workspace | read incidents, comment, tag, change status |
| each playbook | Log Analytics Reader | workspace | query `Cowrie_CL` for the IP's activity |
| each playbook | Key Vault Secrets User | vault | read the API keys |
| Azure Security Insights | Microsoft Sentinel Automation Contributor | resource group | let automation rules run playbooks |
| you | Key Vault Secrets Officer | vault | set the secrets |
| CI (`uig-detections-ci`) | Log Analytics Reader | workspace | read `SecurityIncident` for `soar.json` |
