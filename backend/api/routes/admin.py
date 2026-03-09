from __future__ import annotations

from fastapi import APIRouter, Depends

from api.middleware.authz import require_scopes
from core.resolver import flush_cache

router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.post(
    "/cache/flush",
    dependencies=[Depends(require_scopes(["credentials:revoke"]))],
)
def flush_did_cache() -> dict[str, bool]:
    """Clear all cached DID documents from the in-memory resolver cache."""
    flush_cache()
    return {"flushed": True}
