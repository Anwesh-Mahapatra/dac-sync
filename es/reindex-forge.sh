#!/usr/bin/env bash
# Non-destructive migration of the legacy forge-windows-ecs index into a new
# backing index built from the updated template. Field types cannot change in
# place, so this reindexes into forge-windows-ecs-000001.
#
#   ES_PASS=... ./es/reindex-forge.sh
#
# It does NOT delete the source index. Once you have confirmed the new index,
# you can drop the old one yourself (see CHANGES.md) -- this script never will.
#
# NOTE: reindexing only re-types the docs that already reached ES. It does NOT
# add the 993 Sysmon events, which never came through Cribl. To get a complete
# dataset (Sysmon + Security, all ECS-normalized) use es/load-forge.js instead,
# which replays the source XML through the tested mapping.
set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
SRC="${SRC:-forge-windows-ecs}"
DST="${DST:-forge-windows-ecs-000001}"

if [[ -z "$ES_PASS" ]]; then
  echo "error: set ES_PASS or ELASTIC_PASSWORD" >&2
  exit 1
fi

curl_es() { curl -sS -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' "$@"; }

echo "==> creating $DST from the forge-windows-ecs template"
curl_es -XPUT "$ES_URL/$DST" -d '{}' >/dev/null || true

echo "==> reindex $SRC -> $DST (dropping Cribl leak fields _time / filter_path)"
curl_es -XPOST "$ES_URL/_reindex?refresh=true&wait_for_completion=true" -d "{
  \"source\": { \"index\": \"$SRC\" },
  \"dest\":   { \"index\": \"$DST\" },
  \"script\": {
    \"source\": \"ctx._source.remove('_time'); ctx._source.remove('filter_path');\"
  }
}" | python3 -c '
import sys, json
r = json.load(sys.stdin)
if r.get("failures"):
    print("    FAILURES:", json.dumps(r["failures"][:2])); sys.exit(1)
print("    reindexed", r.get("total"), "docs; created", r.get("created"))
'

echo "==> $DST now has:"
curl_es "$ES_URL/_cat/indices/$DST?h=index,docs.count,store.size"
