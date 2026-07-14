#!/usr/bin/env bash
# Fails if the forge_win_ecs pipeline deployed in Cribl differs from
# cribl/forge_win_ecs.pipeline.json in git. "node generate-pipeline.js --check"
# only proves the *generator* output matches git; it says nothing about
# whether git matches the pipeline actually running in Cribl. Both checks are
# needed for the claim "testing winxml_to_ecs.js IS testing Cribl" to hold.
#
# Usage: CRIBL_PW=<admin password> ./scripts/check-pipeline-drift.sh
# Env:   CRIBL_URL (default http://localhost:9000), CRIBL_USER (default admin)
set -euo pipefail
cd "$(dirname "$0")/.."

CRIBL_URL="${CRIBL_URL:-http://localhost:9000}"
CRIBL_USER="${CRIBL_USER:-admin}"
: "${CRIBL_PW:?Set CRIBL_PW to the Cribl admin password}"

TOKEN=$(curl -sf -X POST "$CRIBL_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$CRIBL_USER\",\"password\":\"$CRIBL_PW\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

DEPLOYED=$(curl -sf "$CRIBL_URL/api/v1/pipelines/forge_win_ecs" -H "Authorization: Bearer $TOKEN")

python3 - "$DEPLOYED" <<'PYEOF'
import json
import sys

deployed = json.loads(sys.argv[1])['items'][0]
with open('cribl/forge_win_ecs.pipeline.json') as f:
    git = json.load(f)


def normalize(conf):
    # Cribl strips exactly one trailing newline from a Code function's body
    # on save -- cosmetic, not drift. Normalize before comparing.
    conf = dict(conf)
    if 'code' in conf:
        conf['code'] = conf['code'].rstrip('\n')
    return conf


dfns = deployed['conf']['functions']
gfns = git['conf']['functions']

drift = []
if len(dfns) != len(gfns):
    drift.append('function count differs: deployed=%d git=%d' % (len(dfns), len(gfns)))
else:
    for i, (d, g) in enumerate(zip(dfns, gfns)):
        if d['id'] != g['id']:
            drift.append('function %d: id differs: deployed=%r git=%r' % (i, d['id'], g['id']))
            continue
        if normalize(d.get('conf', {})) != normalize(g.get('conf', {})):
            drift.append('function %d (%s): conf differs' % (i, g['id']))

if drift:
    print('PIPELINE DRIFT DETECTED between deployed Cribl pipeline and git:')
    for d in drift:
        print('  -', d)
    sys.exit(1)

print('forge_win_ecs: deployed pipeline matches git (no drift)')
PYEOF
