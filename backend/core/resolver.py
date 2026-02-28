from __future__ import annotations

from typing import Any
from urllib.parse import unquote

import httpx

from core.db import db_session
from core.did import build_did_document_multi
from core.settings import settings
from models import Agent, Key


def did_web_to_url(did: str) -> str:
    # did:web:<domain>[:path...]
    if not did.startswith("did:web:"):
        raise ValueError("Only did:web supported")

    parts = did.split(":")
    if len(parts) < 3:
        raise ValueError("Invalid did:web")

    # Domain in did:web may be percent-encoded (e.g. localhost%3A8000)
    domain = unquote(parts[2])
    path_segments = [unquote(p) for p in parts[3:]]

    if not path_segments:
        return f"{settings.pramana_scheme}://{domain}/.well-known/did.json"

    path = "/".join(path_segments)
    return f"{settings.pramana_scheme}://{domain}/{path}/did.json"


def _resolve_local_did(did: str) -> dict[str, Any] | None:
    # If the DID domain matches this service, resolve from DB rather than HTTP.
    if not did.startswith("did:web:"):
        return None

    parts = did.split(":")
    if len(parts) < 3:
        return None

    did_domain = parts[2]
    if did_domain != settings.pramana_domain:
        return None

    with db_session() as db:
        agent = db.query(Agent).filter(Agent.did == did).one_or_none()
        if agent is None:
            return None
        keys = (
            db.query(Key)
            .filter(Key.agent_id == agent.id)
            .order_by(Key.created_at.asc())
            .all()
        )
        if not keys:
            return None

    return build_did_document_multi(did=agent.did, keys=[{"kid": k.kid, "public_jwk": k.public_jwk} for k in keys])


def resolve_did(did: str) -> dict[str, Any]:
    local = _resolve_local_did(did)
    if local is not None:
        return local

    url = did_web_to_url(did)
    r = httpx.get(url, timeout=10.0, headers={"accept": "application/json"})
    r.raise_for_status()
    return r.json()
