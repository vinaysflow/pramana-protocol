from __future__ import annotations

import secrets
import time
from typing import Any

import jwt

from core.settings import settings

DEMO_ISSUER = "pramana-demo"


def issue_demo_token(*, tenant_id: str, ttl_seconds: int) -> tuple[str, int]:
    now = int(time.time())
    exp = now + ttl_seconds
    payload: dict[str, Any] = {
        "iss": DEMO_ISSUER,
        "sub": "demo",
        "iat": now,
        "exp": exp,
        "tenant": tenant_id,
        # demo scopes include admin so audit works
        "scope": ["agents:create", "credentials:issue", "credentials:revoke", "tenant:admin"],
        "demo": True,
        "jti": secrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, settings.demo_jwt_secret, algorithm="HS256")
    return token, exp


def verify_demo_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.demo_jwt_secret,
        algorithms=["HS256"],
        issuer=DEMO_ISSUER,
        options={"require": ["iss", "sub", "iat", "exp", "tenant"]},
    )
