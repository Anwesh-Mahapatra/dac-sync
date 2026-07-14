# RUNBOOK: EvidenceForge -> Cribl -> Elasticsearch -> Detection Rule

Repeatable loop for validating `rules/example-encoded-powershell.yml` (and
future rules) against Cisco Talos EvidenceForge synthetic attack data.

## Architecture

```
EvidenceForge (uv/python, host)
  -> eforge/output/data/<host>/windows_event_security.xml
  -> bind-mounted read-only into the cribl container at /data/eforge
  -> Cribl Filesystem Collector "forge_windows_fs" (Full Run, not a tailing source)
  -> Event Breaker "forge-winxml" (splits <Events> blob into one chunk per <Event>)
  -> Route "forge_windows_ecs_route" (source.endsWith('windows_event_security.xml'))
  -> Pipeline "forge_win_ecs" (drop wrapper chunks -> parse XML to ECS -> cleanup)
  -> Destination "forge_windows_ecs" -> Elasticsearch index forge-windows-ecs
  -> Kibana Detection Engine rule lab-win-encoded-powershell (index: winlogbeat-*, forge-*)
```

All Cribl config that matters is checked into `cribl/`:
- `cribl/forge-winxml.breaker.json` — Event Breaker ruleset
- `cribl/winxml_to_ecs.js` — the parser, **tested standalone with `node cribl/winxml_to_ecs.js`**
- `cribl/forge_win_ecs.pipeline.json` — generated from `winxml_to_ecs.js` (see below), not hand-written
- `cribl/forge-windows-ecs.index-template.json` — ES index template (created once, before first ingest)
- `cribl/generate-assets-lookup.js` / `cribl/lookups/forge-assets.csv` — asset enrichment lookup,
  generated from `eforge/attack.yaml`; wired into the pipeline as a Lookup function
- `cribl/outputs/forge_windows_ecs.json` — the Elasticsearch destination config, credentials
  redacted (`auth.password` is a placeholder — the real value lives only in the running Cribl
  instance / `.env`, never in git). Load it with the `curl` commands below after substituting the
  real password. Its `systemFields` is deliberately `[]`: this destination used to leak `cribl_pipe`
  into every indexed document (and briefly `cribl_breaker` too, from a config edit that predated
  this file's existence) — see `CHANGES.md`.

The Filesystem Collector and Route are **not** checked into git (they don't
need code review the way the parser does, and have no equivalent "generate
from source of truth" step) — recreate them with the `curl` commands below
if the Cribl volume is ever wiped.

## One-time setup (already done, here for reference)

```bash
# 1. Clone EvidenceForge alongside this repo and install it
git clone https://github.com/Cisco-Talos/EvidenceForge.git ~/files/EvidenceForge
cd ~/files/EvidenceForge && uv sync

# 2. ES index template (idempotent PUT, safe to rerun)
ELASTIC_PW=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
curl -s -u "elastic:$ELASTIC_PW" -X PUT http://localhost:9200/_index_template/forge-windows-ecs \
  -H 'Content-Type: application/json' --data-binary @cribl/forge-windows-ecs.index-template.json

# 3. docker-compose.yaml already bind-mounts ./eforge/output/data:/data/eforge:ro
#    into the cribl service. If it's ever removed, re-add and:
docker compose up -d --no-deps cribl

# 4. Elasticsearch destination -- load from git, substituting the real password
#    (cribl/outputs/forge_windows_ecs.json has a placeholder, never the real value)
ELASTIC_PW=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
CRIBL_TOKEN=$(curl -s -X POST http://localhost:9000/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"<cribl admin password>"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
python3 -c "
import json
d = json.load(open('cribl/outputs/forge_windows_ecs.json'))
d['auth']['password'] = '$ELASTIC_PW'
print(json.dumps(d))
" | curl -s -X PATCH "http://localhost:9000/api/v1/system/outputs/forge_windows_ecs" \
  -H "Authorization: Bearer $CRIBL_TOKEN" -H 'Content-Type: application/json' --data-binary @-
```

## Regenerate the scenario

The shipped EvidenceForge fixture (`tests/fixtures/scenarios/attack.yaml`) has
historical 2024 timestamps and also requests a `zeek` output group that
requires a network sensor the fixture doesn't define (a pre-existing gap in
the fixture, unrelated to this lab). `eforge/attack.yaml` in this repo is a
copy with:
- `time_window.start` shifted to `now - 4h` (still historical relative to a
  `from: now-6m` rule window — see "Triggering the rule" below for why that's
  fine)
- `output.logs` trimmed to just `windows` (we only build a Windows Event XML
  pipeline; Zeek is out of scope here)

To regenerate with a fresh timestamp:

```bash
cd ~/files/dac-sync
NEW_START=$(date -u -d "-4 hours" +"%Y-%m-%dT%H:%M:%SZ")
sed -i "s/start: \".*\"/start: \"$NEW_START\"/" eforge/attack.yaml

cd ~/files/EvidenceForge
uv run eforge validate /home/anwesh/files/dac-sync/eforge/attack.yaml
uv run eforge generate /home/anwesh/files/dac-sync/eforge/attack.yaml \
  -o /home/anwesh/files/dac-sync/eforge/output --force
uv run eforge eval /home/anwesh/files/dac-sync/eforge/output \
  -s /home/anwesh/files/dac-sync/eforge/attack.yaml -v
```

`eforge/output/GROUND_TRUTH.md` is regenerated every run — it's the source of
truth for what a rule *should* catch.

## Clear the index before a re-run

**Do this before every Full Run**, or replays duplicate documents (the
Filesystem Collector has no dedup/watermark logic — it's a static batch
collector, not a tailing source, so every Full Run re-reads every file):

```bash
ELASTIC_PW=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
curl -s -u "elastic:$ELASTIC_PW" -X POST \
  "http://localhost:9200/forge-windows-ecs/_delete_by_query?conflicts=proceed" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}'
```

## Run a Full Run

```bash
# Authenticate to Cribl (token expires; re-run if you get 401s)
TOKEN=$(curl -s -X POST http://localhost:9000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<cribl admin password>"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Trigger the saved Collector "forge_windows_fs" as an ad hoc Full Run.
# timeRangeType must be "relative" or "absolute" (no literal "full" mode) --
# "relative" with a wide negative "earliest" behaves like a full run since
# the Filesystem Collector's path has no ${_time} template tokens to filter on.
curl -s -X POST http://localhost:9000/api/v1/jobs -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "id": "forge_windows_fs",
    "type": "collection",
    "collector": {"type": "filesystem", "sendToRoutes": true,
      "conf": {"path": "/data/eforge", "recurse": true}, "destructive": false},
    "input": {"type": "collection", "breakerRulesets": ["forge-winxml"], "sendToRoutes": true},
    "run": {"mode": "run", "timeRangeType": "relative", "earliest": -315360000,
      "expression": "true", "logLevel": "info"}
  }'
# -> {"items":["<jobId>"]}

# Poll until it finishes
curl -s "http://localhost:9000/api/v1/jobs/<jobId>" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['items'][0]['status']['state'])"
```

Equivalent in the UI: **Manage Collectors -> forge_windows_fs -> Run -> Full Run**.

## Verify ingest

```bash
ELASTIC_PW=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
curl -s -u "elastic:$ELASTIC_PW" http://localhost:9200/forge-windows-ecs/_count
# Should equal the total line count of all windows_event_security.xml <Event>
# elements across every host directory -- sysmon.xml and other files are
# collected too but routed elsewhere (route filter is
# source.endsWith('windows_event_security.xml')), so they won't inflate this count.
```

## Check the rule

```bash
ELASTIC_PW=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
./dac-sync -kibana http://localhost:5601 -user elastic -pass "$ELASTIC_PW" -rules ./rules -dry-run
./dac-sync -kibana http://localhost:5601 -user elastic -pass "$ELASTIC_PW" -rules ./rules
```

### Triggering the rule against historical data

The rule runs on a 5-minute schedule with `from: now-6m` — correct for
production, but EvidenceForge's scenario data is always somewhat in the past
by the time you've regenerated, ingested, and gotten around to checking it.
Kibana's rule "Preview" REST API exists but its results endpoint isn't
documented/discoverable via the public API; the reliable way to test against
historical data is:

```bash
# 1. Temporarily widen the window
sed -i 's/from: now-6m/from: now-24h/' rules/example-encoded-powershell.yml
./dac-sync -kibana http://localhost:5601 -user elastic -pass "$ELASTIC_PW" -rules ./rules

# 2. Wait for the next scheduled execution (up to 5 min), or check
curl -s -u "elastic:$ELASTIC_PW" \
  "http://localhost:5601/api/detection_engine/rules?rule_id=lab-win-encoded-powershell" \
  -H 'kbn-xsrf: true' | python3 -c "import json,sys; print(json.load(sys.stdin)['execution_summary'])"

# 3. Check alerts, filtering by execution timestamp to isolate this run
curl -s -u "elastic:$ELASTIC_PW" -X GET \
  "http://localhost:9200/.internal.alerts-security.alerts-default-000001/_search" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"kibana.alert.rule.execution.timestamp":{"gte":"<sync timestamp>"}}}}'
# Check kibana.alert.ancestors[0].index on each hit -- this ES instance also
# ingests real winlogbeat/Sysmon telemetry (index winlogbeat-8.14.3) alongside
# forge-windows-ecs, so filter for the index you actually care about.

# 4. Revert
sed -i 's/from: now-24h/from: now-6m/' rules/example-encoded-powershell.yml
./dac-sync -kibana http://localhost:5601 -user elastic -pass "$ELASTIC_PW" -rules ./rules
```

### Diff against GROUND_TRUTH.md

Cross-reference `kibana.alert.original_time` + `host.name` on each alert
against the Timeline table in `eforge/output/GROUND_TRUTH.md`. For the
encoded-PowerShell rule specifically, only the "reconnaissance PowerShell"
storyline event should match (`-enc` in the command line); mimikatz and the
`Import-Module ... Get-DomainUser` DCSync command should *not* match (no
`-enc`/`-EncodedCommand`/`-e` token in their command lines), and no baseline
noise event should match either.

## Known gotchas (why the pipeline is built this way)

- **`ignore_above` on `winlog.event_data.*`**: the index template sets a
  dynamic template raising `ignore_above` to 32766 for
  `winlog.event_data.*` string fields. ES's default (256) would silently
  drop the `.keyword` sub-field for any base64-encoded `CommandLine` over 256
  chars — which the actual encoded-PowerShell payload is (388 chars) — and
  the rule's `CommandLine.keyword: *-enc*` wildcard would never match it.
- **Cribl's Code function wraps your code, don't wrap it yourself.** The
  `code` string in a Code function becomes the *body* of Cribl's own
  `exports.process(__e)` — submitting `function (__e) { ... }` as the whole
  string just defines an inner function that's never called (no error, no
  effect, very hard to notice). `gen_pipeline.js`-style generation from
  `winxml_to_ecs.js`'s `applyToEvent` body (helpers concatenated + inner body
  only) gets this right; hand-editing the pipeline JSON risks reintroducing
  the wrapper.
- **Top-level `return` is rejected by the Code function's validator** even
  though it would work fine at runtime once wrapped — `winxml_to_ecs.js`
  uses nested `if` guards instead of early returns for this reason.
- **`source` is a Cribl-reserved field name that collides with ECS
  `source.ip`/`source.port`.** Cribl's Filesystem Collector sets `source` to
  the file path (the same field the route filter matches on). The `code`
  function captures it into `log.file.path` and explicitly `delete`s it
  *before* possibly reassigning `source` to `{ip, port}` for 4624/4625/4648
  events. The `eval` function only removes `_raw` — it does **not** remove
  `source`, because by eval-time `source` may legitimately be the ECS
  network-source object, not file-path leftovers.
