from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    did: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    # Optional SPIFFE ID — set when agent identity was attested via SPIFFE/SPIRE
    spiffe_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True, unique=True, index=True)
