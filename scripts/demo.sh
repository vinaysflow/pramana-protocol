#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:5051}"
AUTH_JWT_SECRET="${AUTH_JWT_SECRET:-dev-secret-change}"
AUTH_JWT_ISSUER="${AUTH_JWT_ISSUER:-pramana}"

# Mint token locally (HS256 stub)
TOKEN=$(python3 - <<PY
import os
import time
import jwt
scopes=["agents:create","credentials:issue","credentials:revoke"]
payload={"iss": os.environ.get('AUTH_JWT_ISSUER','pramana'), "sub":"demo", "iat": int(time.time()), "exp": int(time.time())+3600, "scope": scopes}
print(jwt.encode(payload, os.environ.get('AUTH_JWT_SECRET','dev-secret-change'), algorithm='HS256'))
PY
)

HDR_AUTH=( -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" )

echo "PRAMANA PROTOCOL - DRIFT BREACH DEMO"
echo "API: $API_BASE"

echo "[1/6] Creating Walmart issuer agent..."
WALMART=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_AUTH[@]}" -d '{"name":"walmart-procurement-agent"}')
WALMART_DID=$(echo "$WALMART" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')
WALMART_ID=$(echo "$WALMART" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

echo "[2/6] Creating Supplier agent..."
SUPPLIER=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_AUTH[@]}" -d '{"name":"supplier-api-agent"}')
SUPPLIER_DID=$(echo "$SUPPLIER" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')

echo "Walmart:  $WALMART_DID"
echo "Supplier: $SUPPLIER_DID"

echo "[3/6] Issuing capability credential..."
CREDENTIAL=$(curl -sSf -X POST "$API_BASE/v1/credentials/issue" "${HDR_AUTH[@]}" -d "{\"issuer_agent_id\":\"$WALMART_ID\",\"subject_did\":\"$SUPPLIER_DID\",\"credential_type\":\"CapabilityCredential\",\"subject_claims\":{\"capability\":\"negotiate_contracts\",\"max_amount\":100000}}")
VC_JWT=$(echo "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')
CRED_ID=$(echo "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["credential_id"])')

echo "Issued credential: $CRED_ID"

echo "[4/6] Verifying credential (should PASS)..."
VERIFY_BEFORE=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" -H "Content-Type: application/json" -d "{\"jwt\":\"$VC_JWT\"}")
python3 - <<PY
import json
v=json.loads('''$VERIFY_BEFORE''')
assert v.get('verified') is True, v
print('Verify before revoke: PASS')
PY

echo "[5/6] BREACH detected -> revoking credential"
REVOKE=$(curl -sSf -X POST "$API_BASE/v1/credentials/$CRED_ID/revoke" "${HDR_AUTH[@]}" -d '{}')
python3 - <<PY
import json
r=json.loads('''$REVOKE''')
assert r.get('revoked') is True, r
print('Revoked: OK')
PY

echo "[6/6] Verifying again (should be DENIED)..."
VERIFY_AFTER=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" -H "Content-Type: application/json" -d "{\"jwt\":\"$VC_JWT\"}")
python3 - <<PY
import json
v=json.loads('''$VERIFY_AFTER''')
assert v.get('verified') is False, v
assert v.get('reason') == 'revoked', v
print('Verify after revoke: DENIED (revoked)')
PY

echo "DEMO COMPLETE"
