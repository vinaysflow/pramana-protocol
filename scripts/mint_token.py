import os
from core.auth.jwt_auth import issue_admin_token

# Usage:
#   AUTH_JWT_SECRET=... AUTH_JWT_ISSUER=... python3 scripts/mint_token.py

scopes = ["agents:create", "credentials:issue", "credentials:revoke"]
print(issue_admin_token(scopes=scopes, subject="dev", ttl_seconds=3600))
