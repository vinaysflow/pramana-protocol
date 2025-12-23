from __future__ import annotations

import secrets

from fastapi import APIRouter, Response, Depends
from pydantic import BaseModel

from api.middleware.authz import require_scopes
from core.auth.demo import issue_demo_token
from core.settings import settings

router = APIRouter(prefix='/v1/demo', tags=['demo'])


class DemoSessionResponse(BaseModel):
    token: str
    tenant_id: str
    expires_in: int


@router.post('/session', response_model=DemoSessionResponse)
def demo_session(resp: Response):
    # Always available when DEMO_MODE true; safe no-op otherwise.
    if not settings.demo_mode:
        # Still return a token for local testing if explicitly enabled.
        pass

    session_id = secrets.token_urlsafe(16)
    tenant_id = f"demo_{session_id}"

    token, exp = issue_demo_token(tenant_id=tenant_id, ttl_seconds=settings.demo_token_ttl_seconds)

    resp.set_cookie(
        key='pramana_demo_session',
        value=session_id,
        httponly=True,
        secure=False,
        samesite='lax',
        max_age=settings.demo_token_ttl_seconds,
    )

    return DemoSessionResponse(token=token, tenant_id=tenant_id, expires_in=settings.demo_token_ttl_seconds)


@router.post('/reset')
def demo_reset(auth: dict = Depends(require_scopes(['tenant:admin']))):
    tenant_id = auth.get('tenant_id', 'default')

    from core.db import db_session
    from models import Agent, AuditEvent, Credential, Key, StatusList
    from models.tenant import Tenant

    with db_session() as db:
        # delete in FK-safe order
        db.query(Credential).filter(Credential.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(Key).filter(Key.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(Agent).filter(Agent.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(StatusList).filter(StatusList.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(AuditEvent).filter(AuditEvent.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(Tenant).filter(Tenant.id == tenant_id).delete(synchronize_session=False)
        db.commit()

    return {"reset": True, "tenant_id": tenant_id}
