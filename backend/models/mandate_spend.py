from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import DateTime, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class MandateSpend(Base):
    """Tracks each fulfilled cart mandate to enforce single-use JTI and budget."""
    __tablename__ = "mandate_spends"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    intent_jti: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    cart_jti: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(precision=18, scale=6), nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False)
    merchant_did: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
