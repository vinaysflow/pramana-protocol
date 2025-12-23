from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, Request

from core.auth.verify import auth_context_from_claims, verify_access_token


def get_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = auth.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token


def require_scopes(required: list[str]) -> Callable:
    def _dep(token: str = Depends(get_bearer_token)) -> dict:
        try:
            claims = verify_access_token(token)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

        ctx = auth_context_from_claims(claims)
        scopes = ctx["scopes"]
        missing = [s for s in required if s not in scopes]
        if missing:
            raise HTTPException(status_code=403, detail=f"Missing scopes: {', '.join(missing)}")
        return ctx

    return _dep
