from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from api.middleware.authz import require_scopes
from core import did as did_core
from core.crypto import encrypt_text
from core.db import db_session
from core.tenancy import ensure_tenant
from models import Agent, Key

router = APIRouter(prefix="/v1/agents", tags=["keys"])


@router.post("/{agent_id}/keys/rotate", dependencies=[Depends(require_scopes(["tenant:admin"]))])
def rotate_agent_key(agent_id: uuid.UUID, auth: dict = Depends(require_scopes(["tenant:admin"]))):
    tenant_id = auth.get('tenant_id', 'default')

    with db_session() as db:
        ensure_tenant(db, tenant_id)
        agent = db.query(Agent).filter(Agent.id == agent_id).filter(Agent.tenant_id == tenant_id).one_or_none()
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")

        keys = db.query(Key).filter(Key.agent_id == agent.id).order_by(Key.created_at.asc()).all()
        if not keys:
            raise HTTPException(status_code=404, detail="Key not found")

        # deactivate current active key(s)
        for k in keys:
            if getattr(k, 'active', True):
                k.active = False
                k.rotated_at = datetime.utcnow()
                db.add(k)

        next_n = len(keys) + 1
        private_pem, public_jwk, _ = did_core.generate_ed25519_keypair()
        kid = f"{agent.did}#key-{next_n}"

        new_key = Key(
            agent_id=agent.id,
            tenant_id=tenant_id,
            kid=kid,
            public_jwk=public_jwk,
            private_key_enc=encrypt_text(private_pem),
            active=True,
        )
        db.add(new_key)
        db.commit()
        db.refresh(new_key)

    return {"rotated": True, "agent_id": str(agent_id), "new_kid": kid}
