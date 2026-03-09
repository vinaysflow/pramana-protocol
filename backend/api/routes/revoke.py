from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from api.middleware.authz import require_scopes
from core.audit import write_audit
from core.db import db_session
from core.status_list import set_revoked
from core.webhooks import dispatch_webhook_event
from models import Credential

router = APIRouter(prefix="/v1/credentials", tags=["credentials"])


@router.post("/{credential_id}/revoke")
def revoke(
    credential_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:revoke"])),
):
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        cred = db.query(Credential).filter(Credential.id == credential_id).filter(Credential.tenant_id == tenant_id).one_or_none()
        if cred is None:
            raise HTTPException(status_code=404, detail="Credential not found")

        status_list_id = cred.status_list_id
        index = cred.status_list_index
        issuer_agent_id = str(cred.issuer_agent_id)
        subject_did = cred.subject_did
        jti = cred.jti

    set_revoked(status_list_id, index)

    write_audit(
        tenant_id=tenant_id,
        event_type="credential.revoked",
        actor="revoker",
        resource_type="credential",
        resource_id=str(credential_id),
        payload={"status_list_id": str(status_list_id), "status_list_index": index},
    )

    background_tasks.add_task(
        dispatch_webhook_event,
        tenant_id,
        "credential.revoked",
        {
            "credential_id": str(credential_id),
            "jti": jti,
            "issuer_did": issuer_agent_id,
            "subject_did": subject_did,
            "revoked_at": str(uuid.uuid4()),  # placeholder; real revoked_at would come from DB
        },
    )

    return {"revoked": True, "credential_id": str(credential_id)}
