from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from core.db import db_session
from api.middleware.authz import require_scopes
from models import AuditEvent

router = APIRouter(prefix="/v1/audit", tags=["audit"])


class AuditEventOut(BaseModel):
    id: str
    event_type: str
    actor: str
    resource_type: str
    resource_id: str
    payload: dict
    created_at: datetime


@router.get("")
def list_audit_events(
    limit: int = 50,
    include_public: bool = False,
    actor: Optional[str] = None,
    event_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    auth: dict = Depends(require_scopes(["tenant:admin"]))
):
    limit = max(1, min(limit, 500))

    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        q = db.query(AuditEvent)
        if include_public:
            q = q.filter(AuditEvent.tenant_id.in_([tenant_id, "public"]))
        else:
            q = q.filter(AuditEvent.tenant_id == tenant_id)
        if actor:
            q = q.filter(AuditEvent.actor == actor)
        if event_type:
            q = q.filter(AuditEvent.event_type == event_type)
        if resource_type:
            q = q.filter(AuditEvent.resource_type == resource_type)
        if resource_id:
            q = q.filter(AuditEvent.resource_id == resource_id)

        events = q.order_by(AuditEvent.created_at.desc()).limit(limit).all()

    return {
        "events": [
            AuditEventOut(
                id=str(e.id),
                event_type=e.event_type,
                actor=e.actor,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                payload=e.payload_json,
                created_at=e.created_at,
            ).model_dump()
            for e in events
        ]
    }
