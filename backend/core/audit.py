from __future__ import annotations

from typing import Any

from core.db import db_session
from models import AuditEvent


def write_audit(
    *,
    tenant_id: str,
    event_type: str,
    actor: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
) -> None:
    if not tenant_id:
        tenant_id = 'default'

    with db_session() as db:
        evt = AuditEvent(
            tenant_id=tenant_id,
            event_type=event_type,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            payload_json=payload,
        )
        db.add(evt)
        db.commit()
