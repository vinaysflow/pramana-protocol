from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)

    issuer_agent_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("agents.id"), nullable=False)
    subject_did: Mapped[str] = mapped_column(String(600), nullable=False)

    credential_type: Mapped[str] = mapped_column(String(200), nullable=False)
    jti: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    jwt: Mapped[str] = mapped_column(String, nullable=False)

    status_list_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("status_lists.id"), nullable=False)
    status_list_index: Mapped[int] = mapped_column(Integer, nullable=False)

    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
