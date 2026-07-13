#!/usr/bin/env bash
# Applies the forge-windows-ecs index template to the lab cluster.
#
#   ES_URL=http://localhost:9200 ES_USER=elastic ES_PASS=... ./es/apply-templates.sh
#
# Reads ELASTIC_PASSWORD from the environment (or a sourced .env); never prints it.
#
# This COMPOSES rather than clobbers: the template only matches forge-windows-ecs*
# and does not touch winlogbeat-* or any built-in template.
set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"

if [[ -z "$ES_PASS" ]]; then
  echo "error: set ES_PASS or ELASTIC_PASSWORD" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$REPO_ROOT/cribl/forge-windows-ecs.index-template.json"

echo "==> PUT _index_template/forge-windows-ecs"
curl -sS -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' \
  -XPUT "$ES_URL/_index_template/forge-windows-ecs" \
  --data-binary "@$TEMPLATE" | tee /dev/stderr | grep -q '"acknowledged":true'

echo
echo "==> verifying an index built from this template gets the ECS types"
curl -sS -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' \
  -XPOST "$ES_URL/_index_template/_simulate_index/forge-windows-ecs-000001" \
  | python3 -c '
import sys, json
d = json.load(sys.stdin)
if d.get("overlapping"):
    print("    WARNING: overlapping templates:", d["overlapping"])
m = d["template"]["mappings"]["properties"]
cl = m["process"]["properties"]["command_line"]
assert cl["type"] == "wildcard", cl
assert "ignore_above" not in cl, "wildcard must not carry ignore_above"
print("    process.command_line ->", cl["type"], "+ multi-fields", list(cl.get("fields", {})))
print("    event.code           ->", m["event"]["properties"]["code"]["type"])
print("    destination.ip       ->", m["destination"]["properties"]["ip"]["type"])
print("    OK: no ignore_above on command_line -- long command lines can no longer be silently dropped")
'
