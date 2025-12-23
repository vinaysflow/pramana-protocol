from __future__ import annotations

from sqlalchemy.orm import Session

from models.tenant import Tenant


def ensure_tenant(db: Session, tenant_id: str) -> None:
    if not tenant_id:
        tenant_id = 'default'
    existing = db.query(Tenant).filter(Tenant.id == tenant_id).one_or_none()
    if existing is None:
        db.add(Tenant(id=tenant_id))
