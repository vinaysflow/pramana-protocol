from __future__ import annotations

import time
from typing import Any

import jwt

from core.settings import settings


def issue_admin_token(*, scopes: list[str], subject: str = "admin", ttl_seconds: int = 3600, tenant_id: str = "default") -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": settings.auth_jwt_issuer,
        "sub": subject,
        "iat": now,
        "exp": now + ttl_seconds,
        "scope": scopes,
        "tenant": tenant_id,
    }
    return jwt.encode(payload, settings.auth_jwt_secret, algorithm="HS256")


def verify_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.auth_jwt_secret,
        algorithms=["HS256"],
        issuer=settings.auth_jwt_issuer,
        options={"require": ["iss", "sub", "iat", "exp"]},
    )


def extract_scopes(claims: dict[str, Any]) -> set[str]:
    scope = claims.get("scope")
    if isinstance(scope, list):
        return {str(s) for s in scope}
    if isinstance(scope, str):
        return {s for s in scope.split() if s}
    return set()
