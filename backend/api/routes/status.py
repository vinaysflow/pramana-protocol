from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query

from core.db import db_session
from core.status_list_vc import issue_status_list_vc_jwt
from models import StatusList

router = APIRouter(prefix="/v1/status", tags=["status"])


@router.get("/{status_list_id}")
def get_status_list(status_list_id: uuid.UUID, format: str = Query(default="vc-jwt", pattern="^(vc-jwt|raw)$")):
    with db_session() as db:
        sl = db.query(StatusList).filter(StatusList.id == status_list_id).one_or_none()
        if sl is None:
            raise HTTPException(status_code=404, detail="Status list not found")

    if format == "raw":
        return {
            "id": str(sl.id),
            "purpose": sl.purpose,
            "size": sl.size,
            "bitstring": sl.bitstring,
            "updated_at": sl.updated_at,
        }

    token, vc = issue_status_list_vc_jwt(status_list_id)
    return {"jwt": token, "credential": vc}
