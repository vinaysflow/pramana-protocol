from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Optional

import jwt

from core.settings import settings


def _load_jwks() -> dict[str, Any]:
    if settings.oidc_jwks_json:
        return json.loads(settings.oidc_jwks_json)
    raise ValueError("OIDC_JWKS_JSON not configured (use OIDC_JWKS_URL in production)")


@lru_cache(maxsize=1)
def _jwks_client() -> Optional[jwt.PyJWKClient]:
    if settings.oidc_jwks_url:
        return jwt.PyJWKClient(settings.oidc_jwks_url)
    return None


def verify_oidc_token(token: str) -> dict[str, Any]:
    # Prefer URL-based JWKS client in real deployments
    client = _jwks_client()
    if client is not None:
        signing_key = client.get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            options={"require": ["iss", "sub", "iat", "exp"]},
        )

    # Test/dev fallback: JWKS JSON
    jwks = _load_jwks()
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if not kid:
        raise ValueError("missing kid")

    key = None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            key = k
            break
    if not key:
        raise ValueError("kid not found")

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        options={"require": ["iss", "sub", "iat", "exp"]},
    )


def extract_scopes_from_keycloak(claims: dict[str, Any], *, client_id: Optional[str] = None) -> set[str]:
    scopes: set[str] = set()

    # realm roles
    ra = claims.get("realm_access")
    if isinstance(ra, dict):
        roles = ra.get("roles")
        if isinstance(roles, list):
            scopes |= {str(r) for r in roles}

    # client roles
    if client_id:
        resource_access = claims.get("resource_access")
        if isinstance(resource_access, dict):
            client = resource_access.get(client_id)
            if isinstance(client, dict):
                roles = client.get("roles")
                if isinstance(roles, list):
                    scopes |= {str(r) for r in roles}

    # RFC-style "scope" string
    scope_str = claims.get("scope")
    if isinstance(scope_str, str):
        scopes |= {s for s in scope_str.split() if s}

    return scopes


def extract_tenant_from_groups(claims: dict[str, Any]) -> Optional[str]:
    groups = claims.get("groups")
    if not isinstance(groups, list):
        return None

    for g in groups:
        if not isinstance(g, str):
            continue
        if g.startswith("/tenants/"):
            return g.split("/tenants/", 1)[1].strip("/") or None
    return None
