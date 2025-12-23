#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:5000}"
UI_BASE="${UI_BASE:-http://127.0.0.1:6080}"

echo "[smoke] API_BASE=$API_BASE"

curl -sSf "$API_BASE/health" | grep -q '"healthy"' && echo "[smoke] health OK"

# Minimal issue -> verify -> revoke -> verify
ISSUER_JSON=$(curl -sSf -X POST "$API_BASE/v1/agents" -H 'content-type: application/json' -d '{"name":"smoke-issuer"}')
ISSUER_ID=$(echo "$ISSUER_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin)["id"])')

ISSUED=$(curl -sSf -X POST "$API_BASE/v1/credentials/issue" -H 'content-type: application/json' \
  -d "{\"issuer_agent_id\":\"$ISSUER_ID\",\"subject_did\":\"did:web:example.com:subject:123\",\"credential_type\":\"AgentCredential\"}")
JWT=$(echo "$ISSUED" | python3 -c 'import sys, json; print(json.load(sys.stdin)["jwt"])')
CRED_ID=$(echo "$ISSUED" | python3 -c 'import sys, json; print(json.load(sys.stdin)["credential_id"])')

V1=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" -H 'content-type: application/json' -d "{\"jwt\":\"$JWT\"}")
python3 - <<PY
import json,sys
v=json.loads('''$V1''')
assert v.get('verified') is True, v
print('[smoke] verify before revoke OK')
PY

curl -sSf -X POST "$API_BASE/v1/credentials/$CRED_ID/revoke" -H 'content-type: application/json' -d '{}' >/dev/null

V2=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" -H 'content-type: application/json' -d "{\"jwt\":\"$JWT\"}")
python3 - <<PY
import json,sys
v=json.loads('''$V2''')
assert v.get('verified') is False, v
assert v.get('reason') == 'revoked', v
print('[smoke] verify after revoke OK')
PY

echo "[smoke] PASS"
